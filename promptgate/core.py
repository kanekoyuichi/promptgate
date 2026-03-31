from __future__ import annotations

import dataclasses
import logging
import time
from typing import FrozenSet, Optional

from promptgate.detectors.embedding import EmbeddingDetector
from promptgate.detectors.llm_judge import LLMJudgeDetector
from promptgate.detectors.rule_based import RuleBasedDetector
from promptgate.exceptions import ConfigurationError
from promptgate.result import ScanResult

logger = logging.getLogger(__name__)

_VALID_SENSITIVITIES = {"low", "medium", "high"}
_VALID_DETECTORS = {"rule", "embedding", "llm_judge"}
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

# Tier 3 コンセンサスブースト: この値以上のスコアを「弱いシグナル」と見なす
_CONSENSUS_WEAK_SIGNAL: float = 0.3
# コンセンサスブーストの最大値
_CONSENSUS_MAX_BOOST: float = 0.10


class PromptGate:
    def __init__(
        self,
        sensitivity: str = "medium",
        detectors: Optional[list[str]] = None,
        language: str = "auto",
        log_all: bool = False,
        whitelist_patterns: Optional[list[str]] = None,
        trusted_user_ids: Optional[list[str]] = None,
        trusted_threshold: float = 0.95,
        immediate_block_threats: Optional[set[str]] = None,
        immediate_block_score: float = 0.85,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        llm_on_error: str = "fail_open",
    ) -> None:
        if sensitivity not in _VALID_SENSITIVITIES:
            raise ConfigurationError(
                f"sensitivity は {_VALID_SENSITIVITIES} のいずれかを指定してください。"
            )
        if language not in _VALID_LANGUAGES:
            raise ConfigurationError(
                f"language は {_VALID_LANGUAGES} のいずれかを指定してください。"
            )
        if not (0.0 < trusted_threshold <= 1.0):
            raise ConfigurationError(
                "trusted_threshold は 0.0 より大きく 1.0 以下の値を指定してください。"
            )
        if not (0.0 < immediate_block_score <= 1.0):
            raise ConfigurationError(
                "immediate_block_score は 0.0 より大きく 1.0 以下の値を指定してください。"
            )

        # デフォルトは rule のみ。embedding は sentence-transformers が必要なため
        # オプション依存であり、明示的に指定した場合のみ有効にする。
        _detectors = detectors if detectors is not None else ["rule"]
        unknown = set(_detectors) - _VALID_DETECTORS
        if unknown:
            raise ConfigurationError(f"不明な検出器: {unknown}")
        if "llm_judge" in _detectors and llm_model is None:
            raise ConfigurationError(
                "llm_judge 検出器を使用する場合は llm_model を指定してください。"
                " 利用プロバイダーのドキュメントを参照し、"
                " 適切なモデル識別子を llm_model パラメータに渡してください。"
            )

        self._sensitivity = sensitivity
        self._detector_names = _detectors
        self._language = language
        self._log_all = log_all
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
        )

        self._embedding_detector: Optional[EmbeddingDetector] = None
        if "embedding" in _detectors:
            self._embedding_detector = EmbeddingDetector(sensitivity=sensitivity)

        self._llm_detector: Optional[LLMJudgeDetector] = None
        if "llm_judge" in _detectors:
            self._llm_detector = LLMJudgeDetector(
                api_key=llm_api_key,
                model=llm_model,
                sensitivity=sensitivity,
                on_error=llm_on_error,
            )

    def add_rule(self, name: str, pattern: str, severity: str = "medium") -> None:
        self._rule_detector.add_rule(name, pattern, severity)

    def scan(self, text: str, user_id: Optional[str] = None) -> ScanResult:
        start = time.monotonic()
        is_trusted = user_id is not None and user_id in self._trusted_user_ids

        results: list[tuple[str, ScanResult]] = []

        rule_result = self._rule_detector.scan(text)
        results.append(("rule", rule_result))

        if self._embedding_detector and self._sensitivity in ("medium", "high"):
            emb_result = self._embedding_detector.scan(text)
            results.append(("embedding", emb_result))

        if self._llm_detector:
            llm_result = self._llm_detector.scan(text)
            results.append(("llm_judge", llm_result))

        final = self._aggregate(results, is_trusted=is_trusted)
        final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)

        if is_trusted:
            # 信頼済みユーザーのスキャン結果は log_all 設定に関わらず常に記録する（監査証跡）
            logger.info(
                "trusted_user scan: user_id=%s is_safe=%s risk_score=%.2f threats=%s",
                user_id,
                final.is_safe,
                final.risk_score,
                final.threats,
            )
        elif self._log_all or not final.is_safe:
            logger.warning(
                "scan result: is_safe=%s risk_score=%.2f threats=%s",
                final.is_safe,
                final.risk_score,
                final.threats,
            )

        return final

    def scan_output(self, text: str) -> ScanResult:
        """LLMの出力テキストをスキャンする。

        入力スキャン (scan) との違い:
        - trusted_user_ids による閾値緩和は行わない（出力は常に厳格に検査する）
        - 埋め込み検出器はスキップ（出力スキャンには適合度が低い）
        - LLMジャッジ検出器は実行する（情報漏洩の判定に有効）
        """
        start = time.monotonic()

        results: list[tuple[str, ScanResult]] = []

        rule_result = self._rule_detector.scan(text)
        results.append(("rule", rule_result))

        if self._llm_detector:
            llm_result = self._llm_detector.scan(text)
            results.append(("llm_judge", llm_result))

        final = self._aggregate(results, is_trusted=False)
        final = dataclasses.replace(final, latency_ms=(time.monotonic() - start) * 1000)

        if self._log_all or not final.is_safe:
            logger.warning(
                "output_scan result: is_safe=%s risk_score=%.2f threats=%s",
                final.is_safe,
                final.risk_score,
                final.threats,
            )

        return final

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
                        threats=list(all_threats),
                        explanation=(
                            f"[即時ブロック: {triggered_str} / score={result.risk_score:.2f}]"
                            f" {' / '.join(explanations)}"
                        ),
                        detector_used="+".join(detector_names),
                        latency_ms=0.0,
                    )

        # -------------------------------------------------------------------
        # Tier 2: 最大シグナル基準スコア
        # 加重平均ではなく max を基底とし、強いシグナルが低スコア検出器に
        # 希釈されることを防ぐ。
        # -------------------------------------------------------------------
        base_score = max(r.risk_score for _, r in results)

        # -------------------------------------------------------------------
        # Tier 3: コンセンサスブースト
        # _CONSENSUS_WEAK_SIGNAL 以上のスコアを出した検出器が複数ある場合、
        # 相互補強として小さいブーストを加算する。
        # -------------------------------------------------------------------
        flagging_count = sum(
            1 for _, r in results if r.risk_score >= _CONSENSUS_WEAK_SIGNAL
        )
        consensus_boost = (
            min(_CONSENSUS_MAX_BOOST * (flagging_count - 1), _CONSENSUS_MAX_BOOST)
            if flagging_count > 1
            else 0.0
        )
        final_score = min(base_score + consensus_boost, 1.0)

        # 信頼済みユーザーは trusted_threshold、それ以外は sensitivity に応じた閾値
        threshold = (
            self._trusted_threshold
            if is_trusted
            else _SENSITIVITY_THRESHOLD.get(self._sensitivity, 0.5)
        )
        is_safe = final_score < threshold

        if is_trusted and explanations:
            explanations.append(
                f"(信頼済みユーザー: 緩和閾値 {self._trusted_threshold} 適用)"
            )

        return ScanResult(
            is_safe=is_safe,
            risk_score=round(final_score, 4),
            threats=list(all_threats),
            explanation=" / ".join(explanations),
            detector_used="+".join(detector_names),
            latency_ms=0.0,
        )
