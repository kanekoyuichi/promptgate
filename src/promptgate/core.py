from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
import time
import uuid
from typing import FrozenSet, Optional, cast

from promptgate.detectors.classifier import ClassifierDetector
from promptgate.detectors.embedding import EmbeddingDetector
from promptgate.detectors.llm_judge import LLMJudgeDetector
from promptgate.detectors.rule_based import RuleBasedDetector
from promptgate.exceptions import ConfigurationError
from promptgate.providers.anthropic import AnthropicProvider
from promptgate.providers.base import LLMProvider
from promptgate.result import ScanResult

logger = logging.getLogger(__name__)

_VALID_SENSITIVITIES = {"low", "medium", "high"}
_VALID_DETECTORS = {"rule", "embedding", "classifier", "llm_judge"}
_VALID_LANGUAGES = {"ja", "en", "auto"}

_SENSITIVITY_THRESHOLD: dict[str, float] = {
    "low": 0.8,
    "medium": 0.5,
    "high": 0.3,
}

# Tier 1 即時ブロックのデフォルト対象 threat
_DEFAULT_IMMEDIATE_BLOCK_THREATS: FrozenSet[str] = frozenset(
    {"direct_injection", "jailbreak"}
)

# Tier 2: threat 種別ごとの深刻度係数
# risk_score にこの係数を乗じることで、同じ確信度でも脅威の重大性を反映する。
# 係数が低い threat (prompt_leaking) は中程度の確信度では score が下がり、
# 係数が高い threat (direct_injection) は確信度をそのまま維持する。
_THREAT_SEVERITY: dict[str, float] = {
    # 入力 threat: 攻撃者がLLMに送る悪意のある指示
    "direct_injection": 1.00,   # システムプロンプト上書き: 最重大
    "jailbreak": 0.95,          # 安全制約回避: 重大
    "data_exfiltration": 0.85,  # 情報漏洩誘導: 高
    "indirect_injection": 0.80, # 外部データ経由攻撃: 中高
    "prompt_leaking": 0.75,     # 内部プロンプト盗取: 中
    "prompt_injection": 1.00,   # classifier の二値 unsafe 判定
    # 出力 threat: LLMが生成した応答に含まれる危険なコンテンツ
    "credential_leak": 1.00,    # APIキー・パスワード露出: 最重大
    "pii_leak": 0.90,           # 個人情報露出: 重大
    "system_prompt_leak": 0.85, # システムプロンプト内容の露出: 高
}
_DEFAULT_THREAT_SEVERITY: float = 0.80  # 未知の threat タイプへのフォールバック

# Tier 3: 同一 threat の複数検出器コロボレーションブースト
# 「同じ threat を N 個の検出器が独立に検出した」場合のみブーストを加算する。
# 異なる threat を別々の検出器が検出しても偶然の一致と見なしブーストしない。
_SAME_THREAT_BOOST: float = 0.08       # 同一 threat を検出した追加検出器 1 つあたり
_CORROBORATION_MAX_BOOST: float = 0.15  # コロボレーションブーストの上限


class PromptGate:
    def __init__(
        self,
        sensitivity: str = "medium",
        detectors: Optional[list[str]] = None,
        language: str = "auto",
        log_all: bool = False,
        log_input: bool = False,
        tenant_id: Optional[str] = None,
        whitelist_patterns: Optional[list[str]] = None,
        trusted_user_ids: Optional[list[str]] = None,
        trusted_threshold: float = 0.95,
        immediate_block_threats: Optional[set[str]] = None,
        immediate_block_score: float = 0.85,
        classifier_model_dir: Optional[str] = None,
        classifier_max_length: int = 256,
        classifier_threshold: Optional[float] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        llm_on_error: str = "fail_open",
        llm_provider: Optional[LLMProvider] = None,
    ) -> None:
        """
        Args:
            log_all:      True の場合、安全と判定されたスキャンもログ記録する。
            log_input:    True の場合、入力テキストの原文をログに記録する。
                デフォルトは False（SHA-256 ハッシュのみ記録）。
                PII を含む可能性がある入力を扱う場合は False のままにしてください。
            tenant_id:    マルチテナント環境での識別子。全ログエントリに付与される。
            classifier_model_dir: classifier モデルのディレクトリまたは
                Hugging Face model ID。None の場合は PromptGate の既定モデルを使用する。
            classifier_max_length: classifier の最大トークン長。
            classifier_threshold: classifier の unsafe 判定閾値。
                None の場合は sensitivity に応じた閾値を使用する。
            llm_provider: LLMProvider インスタンス。指定した場合 llm_api_key / llm_model
                は無視される。OpenAI 等の非 Anthropic プロバイダーを使う場合に指定。
                指定しない場合は llm_model + llm_api_key から AnthropicProvider を生成する。
        """
        if sensitivity not in _VALID_SENSITIVITIES:
            raise ConfigurationError(
                f"sensitivity must be one of {_VALID_SENSITIVITIES}."
            )
        if language not in _VALID_LANGUAGES:
            raise ConfigurationError(
                f"language must be one of {_VALID_LANGUAGES}."
            )
        if not (0.0 < trusted_threshold <= 1.0):
            raise ConfigurationError(
                "trusted_threshold must be greater than 0.0 and at most 1.0."
            )
        if not (0.0 < immediate_block_score <= 1.0):
            raise ConfigurationError(
                "immediate_block_score must be greater than 0.0 and at most 1.0."
            )
        if classifier_threshold is not None and not (0.0 < classifier_threshold <= 1.0):
            raise ConfigurationError(
                "classifier_threshold must be greater than 0.0 and at most 1.0."
            )

        # デフォルトは rule のみ。embedding は sentence-transformers が必要なため
        # オプション依存であり、明示的に指定した場合のみ有効にする。
        _detectors = detectors if detectors is not None else ["rule"]
        unknown = set(_detectors) - _VALID_DETECTORS
        if unknown:
            raise ConfigurationError(f"Unknown detector(s): {unknown}")
        if "llm_judge" in _detectors and llm_provider is None and llm_model is None:
            raise ConfigurationError(
                "llm_judge detector requires either llm_provider or llm_model."
                " Refer to your provider's documentation and pass the appropriate"
                " model identifier via the llm_model parameter."
            )

        self._sensitivity = sensitivity
        self._detector_names = _detectors
        self._language = language
        self._log_all = log_all
        self._log_input = log_input
        self._tenant_id = tenant_id
        self._whitelist_patterns = whitelist_patterns or []
        self._trusted_user_ids: set[str] = set(trusted_user_ids or [])
        self._trusted_threshold = trusted_threshold
        self._immediate_block_threats: FrozenSet[str] = (
            frozenset(immediate_block_threats)
            if immediate_block_threats is not None
            else _DEFAULT_IMMEDIATE_BLOCK_THREATS
        )
        self._immediate_block_score = immediate_block_score

        self._rule_detector = RuleBasedDetector(
            sensitivity=sensitivity,
            language=language,
            whitelist_patterns=self._whitelist_patterns,
            scan_mode="input",
        )
        # 出力スキャン専用の rule detector（入力とは別の threat モデル）
        # 入力: direct_injection / jailbreak / data_exfiltration / ...
        # 出力: credential_leak / pii_leak / system_prompt_leak
        self._output_rule_detector = RuleBasedDetector(
            sensitivity=sensitivity,
            language=language,
            whitelist_patterns=self._whitelist_patterns,
            scan_mode="output",
            normalize_input=False,
        )

        self._embedding_detector: Optional[EmbeddingDetector] = None
        if "embedding" in _detectors:
            self._embedding_detector = EmbeddingDetector(sensitivity=sensitivity)

        self._classifier_detector: Optional[ClassifierDetector] = None
        if "classifier" in _detectors:
            self._classifier_detector = ClassifierDetector(
                model_dir=classifier_model_dir,
                sensitivity=sensitivity,
                max_length=classifier_max_length,
                threshold=classifier_threshold,
            )

        self._llm_detector: Optional[LLMJudgeDetector] = None
        self._llm_output_detector: Optional[LLMJudgeDetector] = None
        if "llm_judge" in _detectors:
            resolved_provider: LLMProvider = (
                llm_provider
                if llm_provider is not None
                else AnthropicProvider(api_key=llm_api_key, model=llm_model)
            )
            # 入力スキャン用: direct_injection / jailbreak / data_exfiltration 等を検出
            self._llm_detector = LLMJudgeDetector(
                provider=resolved_provider,
                scan_mode="input",
                sensitivity=sensitivity,
                on_error=llm_on_error,
            )
            # 出力スキャン用: credential_leak / pii_leak / system_prompt_leak を検出
            # プロバイダー（API クライアント）は入力用と共有し、system prompt のみ切り替える。
            self._llm_output_detector = LLMJudgeDetector(
                provider=resolved_provider,
                scan_mode="output",
                sensitivity=sensitivity,
                on_error=llm_on_error,
            )

    # ------------------------------------------------------------------
    # 同期 API
    # ------------------------------------------------------------------

    def add_rule(self, name: str, pattern: str, severity: str = "medium") -> None:
        self._rule_detector.add_rule(name, pattern, severity)

    def warmup(self) -> None:
        """埋め込みモデルをあらかじめメモリにロードする。

        embedding 検出器が有効な場合、初回 scan() 呼び出し前にモデルをロードしておくことで
        Lambda コールドスタートや初回リクエストの遅延を回避できる。

        embedding が無効な場合は何もしない。

        Example::

            gate = PromptGate(detectors=["rule", "embedding"])
            gate.warmup()  # Lambda の init フェーズや起動スクリプトで呼ぶ
        """
        if self._embedding_detector is not None:
            self._embedding_detector.warmup()
        if self._classifier_detector is not None:
            self._classifier_detector.warmup()

    def scan(
        self,
        text: str,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ScanResult:
        start = time.monotonic()
        if trace_id is None:
            trace_id = uuid.uuid4().hex[:16]
        is_trusted = user_id is not None and user_id in self._trusted_user_ids

        per_detector: list[tuple[str, ScanResult]] = []

        rule_result = self._rule_detector.scan(text)
        per_detector.append(("rule", rule_result))

        if self._embedding_detector and self._sensitivity in ("medium", "high"):
            emb_result = self._embedding_detector.scan(text)
            per_detector.append(("embedding", emb_result))

        if self._classifier_detector:
            classifier_result = self._classifier_detector.scan(text)
            per_detector.append(("classifier", classifier_result))

        if self._llm_detector:
            llm_result = self._llm_detector.scan(text)
            per_detector.append(("llm_judge", llm_result))

        final = self._aggregate(per_detector, is_trusted=is_trusted)
        final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)

        self._emit_audit_log(
            scan_type="input",
            text=text,
            user_id=user_id,
            trace_id=trace_id,
            is_trusted=is_trusted,
            per_detector=per_detector,
            final=final,
        )
        return final

    def scan_output(
        self,
        text: str,
        trace_id: Optional[str] = None,
    ) -> ScanResult:
        """LLMの出力テキストをスキャンする。

        入力スキャン (scan) とは脅威モデルが異なる:
        - 入力脅威: direct_injection / jailbreak / data_exfiltration / ...
        - 出力脅威: credential_leak / pii_leak / system_prompt_leak
        - 出力専用パターンファイル (*_output.yaml) を使用する
        - trusted_user_ids による閾値緩和は行わない（出力は常に厳格に検査する）
        - 埋め込み検出器はスキップ（出力の意味類似度判定は適合度が低い）
        - LLMジャッジ検出器は実行する（文脈を踏まえた情報漏洩判定に有効）
        """
        start = time.monotonic()
        if trace_id is None:
            trace_id = uuid.uuid4().hex[:16]

        per_detector: list[tuple[str, ScanResult]] = []

        rule_result = self._output_rule_detector.scan(text)
        per_detector.append(("rule_output", rule_result))

        if self._llm_output_detector:
            # 出力スキャン専用インスタンスを使用（credential_leak 等の出力脅威モデル）
            llm_result = self._llm_output_detector.scan(text)
            per_detector.append(("llm_judge", llm_result))

        final = self._aggregate(per_detector, is_trusted=False)
        final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)

        self._emit_audit_log(
            scan_type="output",
            text=text,
            user_id=None,
            trace_id=trace_id,
            is_trusted=False,
            per_detector=per_detector,
            final=final,
        )
        return final

    # ------------------------------------------------------------------
    # 非同期 API
    # ------------------------------------------------------------------

    async def scan_async(
        self,
        text: str,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ScanResult:
        """非同期スキャン。FastAPI / ASGI アプリでイベントループをブロックしない。

        rule-based 検出は軽量なため同期実行。
        embedding 検出はスレッドプールで実行（CPU バウンド）。
        LLM judge 検出はプロバイダーの非同期 HTTP クライアントで実行。
        embedding と LLM judge は asyncio.gather で並行実行する。

        Example::

            @app.post("/chat")
            async def chat(request: ChatRequest):
                result = await gate.scan_async(request.message)
                if not result.is_safe:
                    raise HTTPException(status_code=400, detail={"threats": result.threats})
                return await call_llm(request.message)
        """
        start = time.monotonic()
        if trace_id is None:
            trace_id = uuid.uuid4().hex[:16]
        is_trusted = user_id is not None and user_id in self._trusted_user_ids

        per_detector: list[tuple[str, ScanResult]] = []

        # rule-based is intentionally run inline. It is fast, and avoiding the
        # event loop's default executor prevents lingering worker threads in
        # pytest-asyncio and short-lived ASGI test processes.
        rule_result = self._rule_detector.scan(text)
        per_detector.append(("rule", rule_result))

        # rule が即時ブロック条件を満たした場合、embedding / llm タスクを起動しない。
        # 同期版 scan() と同じ early exit 挙動にすることで API コストを抑える。
        if not is_trusted:
            triggered = set(rule_result.threats) & self._immediate_block_threats
            if triggered and rule_result.risk_score >= self._immediate_block_score:
                final = self._aggregate(per_detector, is_trusted=is_trusted)
                final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)
                self._emit_audit_log(
                    scan_type="input",
                    text=text,
                    user_id=user_id,
                    trace_id=trace_id,
                    is_trusted=is_trusted,
                    per_detector=per_detector,
                    final=final,
                )
                return final

        # embedding + LLM judge を並行実行
        tasks: list[asyncio.Task[ScanResult]] = []
        task_names: list[str] = []

        if self._embedding_detector and self._sensitivity in ("medium", "high"):
            tasks.append(
                asyncio.ensure_future(self._embedding_detector.scan_async(text))
            )
            task_names.append("embedding")

        if self._classifier_detector:
            tasks.append(
                asyncio.ensure_future(self._classifier_detector.scan_async(text))
            )
            task_names.append("classifier")

        if self._llm_detector:
            tasks.append(
                asyncio.ensure_future(self._llm_detector.scan_async(text))
            )
            task_names.append("llm_judge")

        if tasks:
            gathered = await asyncio.gather(*tasks, return_exceptions=True)
            for name, result in zip(task_names, gathered):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, Exception):
                    logger.warning("detector %s failed in scan_async: %s", name, result)
                else:
                    per_detector.append((name, cast(ScanResult, result)))

        final = self._aggregate(per_detector, is_trusted=is_trusted)
        final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)

        self._emit_audit_log(
            scan_type="input",
            text=text,
            user_id=user_id,
            trace_id=trace_id,
            is_trusted=is_trusted,
            per_detector=per_detector,
            final=final,
        )
        return final

    async def scan_output_async(
        self,
        text: str,
        trace_id: Optional[str] = None,
    ) -> ScanResult:
        """非同期出力スキャン。scan_output() の非同期版。"""
        start = time.monotonic()
        if trace_id is None:
            trace_id = uuid.uuid4().hex[:16]

        per_detector: list[tuple[str, ScanResult]] = []

        # Keep lightweight rule scanning inline for the same reason as scan_async().
        rule_result = self._output_rule_detector.scan(text)
        per_detector.append(("rule_output", rule_result))

        if self._llm_output_detector:
            # 出力スキャン専用インスタンスを使用（credential_leak 等の出力脅威モデル）
            llm_result = await self._llm_output_detector.scan_async(text)
            per_detector.append(("llm_judge", llm_result))

        final = self._aggregate(per_detector, is_trusted=False)
        final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)

        self._emit_audit_log(
            scan_type="output",
            text=text,
            user_id=None,
            trace_id=trace_id,
            is_trusted=False,
            per_detector=per_detector,
            final=final,
        )
        return final

    # ------------------------------------------------------------------
    # バッチ API
    # ------------------------------------------------------------------

    async def scan_batch_async(
        self,
        texts: list[str],
        user_id: Optional[str] = None,
        trace_id_prefix: Optional[str] = None,
        max_concurrency: int = 10,
    ) -> list[ScanResult]:
        """複数テキストを並行スキャンする。

        バッチ処理・データパイプラインでのスループット向上に使用する。
        各テキストは独立した asyncio タスクとして並行実行される。

        Args:
            texts:            スキャン対象テキストのリスト。
            user_id:          全テキストに共通のユーザー ID（省略可）。
            trace_id_prefix:  トレース ID のプレフィックス。指定した場合
                              "{prefix}-{index}" の形式でトレース ID が生成される。
            max_concurrency:  同時実行するスキャン数の上限（デフォルト: 10）。
                              llm_judge 有効時は API レート制限を考慮して調整すること。

        Returns:
            texts と同じ順序の ScanResult リスト。

        Example::

            results = await gate.scan_batch_async([
                "ユーザー入力1",
                "ユーザー入力2",
                "ユーザー入力3",
            ])
            blocked = [r for r in results if not r.is_safe]
        """
        def _make_trace_id(i: int) -> Optional[str]:
            if trace_id_prefix is None:
                return None
            return f"{trace_id_prefix}-{i}"

        sem = asyncio.Semaphore(max_concurrency)

        async def _scan_with_sem(text: str, i: int) -> ScanResult:
            async with sem:
                return await self.scan_async(
                    text, user_id=user_id, trace_id=_make_trace_id(i)
                )

        results: list[ScanResult] = list(
            await asyncio.gather(*[_scan_with_sem(t, i) for i, t in enumerate(texts)])
        )
        return results

    # ------------------------------------------------------------------
    # 内部メソッド
    # ------------------------------------------------------------------

    def _emit_audit_log(
        self,
        *,
        scan_type: str,
        text: str,
        user_id: Optional[str],
        trace_id: str,
        is_trusted: bool,
        per_detector: list[tuple[str, ScanResult]],
        final: ScanResult,
    ) -> None:
        """構造化監査ログを出力する。

        ログレベル:
            WARNING: ブロック判定 (is_safe=False)
            INFO:    通過判定 (is_safe=True) のうち log_all=True または信頼済みユーザー

        extra フィールド (構造化ログハンドラで利用可能):
            trace_id        リクエスト追跡 ID（未指定時は自動生成 UUID）
            tenant_id       テナント識別子（PromptGate 初期化時に設定）
            scan_type       "input" または "output"
            input_hash      入力テキストの SHA-256 先頭 16 桁（相関追跡用）
            input_length    入力テキストの文字数
            user_id         スキャン対象ユーザー ID（scan() に渡された値）
            is_trusted      信頼済みユーザーフラグ
            is_safe         最終判定
            risk_score      最終リスクスコア (0.0–1.0)
            threats         検出された脅威タイプのリスト
            detector_scores 検出器別スコア {"rule": 0.9, "llm_judge": 0.85, ...}
            rule_hits       ルール検出器がヒットした threat タイプ（rule_based の生結果）
            latency_ms      スキャン全体の処理時間（ミリ秒）
            input_text      入力テキスト原文（log_input=True 時のみ付与）
        """
        should_log = not final.is_safe or self._log_all or is_trusted
        if not should_log:
            return

        input_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

        rule_hits: list[str] = [
            threat
            for name, r in per_detector
            if name in ("rule", "rule_output")
            for threat in r.threats
        ]
        detector_scores = {name: round(r.risk_score, 4) for name, r in per_detector}

        extra: dict[str, object] = {
            "trace_id": trace_id,
            "tenant_id": self._tenant_id,
            "scan_type": scan_type,
            "input_hash": input_hash,
            "input_length": len(text),
            "user_id": user_id,
            "is_trusted": is_trusted,
            "is_safe": final.is_safe,
            "risk_score": final.risk_score,
            "threats": list(final.threats),
            "detector_scores": detector_scores,
            "rule_hits": rule_hits,
            "latency_ms": round(final.latency_ms, 2),
        }
        if self._log_input:
            extra["input_text"] = text

        verdict = "BLOCKED" if not final.is_safe else "ALLOWED"
        msg = (
            f"promptgate.scan verdict={verdict}"
            f" trace_id={trace_id}"
            f" scan_type={scan_type}"
            f" input_hash={input_hash}"
            f" risk_score={final.risk_score:.4f}"
            f" threats={list(final.threats)}"
        )
        level = logging.WARNING if not final.is_safe else logging.INFO
        logger.log(level, msg, extra=extra)

    def _aggregate(
        self,
        results: list[tuple[str, ScanResult]],
        is_trusted: bool = False,
    ) -> ScanResult:
        if not results:
            return ScanResult(is_safe=True, risk_score=0.0)

        all_threats: set[str] = set()
        detector_names: list[str] = []
        explanations: list[str] = []

        for name, result in results:
            all_threats.update(result.threats)
            detector_names.append(name)
            if result.explanation:
                explanations.append(result.explanation)

        # -------------------------------------------------------------------
        # Tier 1: 即時ブロック
        # 重大 threat かつスコアが即時ブロック閾値を超えた検出器があれば
        # 他検出器の結果を待たずに即座にブロックする。
        # 信頼済みユーザーは緩和閾値での評価を優先するためスキップする。
        # -------------------------------------------------------------------
        if not is_trusted:
            for name, result in results:
                triggered = set(result.threats) & self._immediate_block_threats
                if triggered and result.risk_score >= self._immediate_block_score:
                    triggered_str = ", ".join(sorted(triggered))
                    return ScanResult(
                        is_safe=False,
                        risk_score=round(result.risk_score, 4),
                        threats=tuple(all_threats),
                        explanation=(
                            f"[immediate block: {triggered_str} / score={result.risk_score:.2f}]"
                            f" {' / '.join(explanations)}"
                        ),
                        detector_used="+".join(detector_names),
                        latency_ms=0.0,
                    )

        # -------------------------------------------------------------------
        # Tier 2: threat 深刻度を加味した最大シグナル基準スコア
        # 加重平均を使わず max を基底とし、強いシグナルが低スコア検出器に
        # 希釈されるのを防ぐ。さらに検出された threat の深刻度で score を調整し、
        # 同じ確信度でも脅威の重大性を最終スコアに反映する。
        # -------------------------------------------------------------------
        def _severity_adjusted(result: ScanResult) -> float:
            if not result.threats:
                return result.risk_score
            max_sev = max(
                _THREAT_SEVERITY.get(t, _DEFAULT_THREAT_SEVERITY)
                for t in result.threats
            )
            return result.risk_score * max_sev

        base_score = max(_severity_adjusted(r) for _, r in results)

        # -------------------------------------------------------------------
        # Tier 3: 同一 threat の複数検出器コロボレーションブースト
        # 同じ threat タイプを複数の検出器が独立に検出した場合のみブーストを加算する。
        # 異なる threat の偶然の一致はブーストしない（過検出を避けるため）。
        # -------------------------------------------------------------------
        threat_detector_count: dict[str, int] = {}
        for _, result in results:
            for threat in result.threats:
                threat_detector_count[threat] = (
                    threat_detector_count.get(threat, 0) + 1
                )

        corroboration_boost = min(
            sum(
                (count - 1) * _SAME_THREAT_BOOST
                for count in threat_detector_count.values()
                if count > 1
            ),
            _CORROBORATION_MAX_BOOST,
        )
        final_score = min(base_score + corroboration_boost, 1.0)

        # 信頼済みユーザーは trusted_threshold、それ以外は sensitivity に応じた閾値
        threshold = (
            self._trusted_threshold
            if is_trusted
            else _SENSITIVITY_THRESHOLD.get(self._sensitivity, 0.5)
        )
        is_safe = final_score < threshold

        if is_trusted and explanations:
            explanations.append(
                f"(trusted user: relaxed threshold {self._trusted_threshold} applied)"
            )

        return ScanResult(
            is_safe=is_safe,
            risk_score=round(final_score, 4),
            threats=tuple(all_threats),
            explanation=" / ".join(explanations),
            detector_used="+".join(detector_names),
            latency_ms=0.0,
        )
