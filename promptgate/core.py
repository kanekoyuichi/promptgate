from __future__ import annotations

import dataclasses
import logging
import time
from typing import Optional

from promptgate.detectors.embedding import EmbeddingDetector
from promptgate.detectors.llm_judge import LLMJudgeDetector
from promptgate.detectors.rule_based import RuleBasedDetector
from promptgate.exceptions import ConfigurationError
from promptgate.result import ScanResult

logger = logging.getLogger(__name__)

_VALID_SENSITIVITIES = {"low", "medium", "high"}
_VALID_DETECTORS = {"rule", "embedding", "llm_judge"}
_VALID_LANGUAGES = {"ja", "en", "auto"}

_DETECTOR_WEIGHTS: dict[str, float] = {
    "rule": 0.4,
    "embedding": 0.35,
    "llm_judge": 0.25,
}

_SENSITIVITY_THRESHOLD: dict[str, float] = {
    "low": 0.8,
    "medium": 0.5,
    "high": 0.3,
}


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
        llm_api_key: Optional[str] = None,
        llm_model: str = "claude-haiku-4-5-20251001",
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

        _detectors = detectors if detectors is not None else ["rule", "embedding"]
        unknown = set(_detectors) - _VALID_DETECTORS
        if unknown:
            raise ConfigurationError(f"不明な検出器: {unknown}")

        self._sensitivity = sensitivity
        self._detector_names = _detectors
        self._language = language
        self._log_all = log_all
        self._whitelist_patterns = whitelist_patterns or []
        self._trusted_user_ids: set[str] = set(trusted_user_ids or [])
        self._trusted_threshold = trusted_threshold

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

        total_weight = 0.0
        weighted_score = 0.0
        all_threats: set[str] = set()
        detector_names: list[str] = []
        explanations: list[str] = []

        for name, result in results:
            weight = _DETECTOR_WEIGHTS.get(name, 0.33)
            weighted_score += result.risk_score * weight
            total_weight += weight
            all_threats.update(result.threats)
            detector_names.append(name)
            if result.explanation:
                explanations.append(result.explanation)

        final_score = weighted_score / total_weight if total_weight > 0 else 0.0

        # 信頼済みユーザーは通常閾値ではなく trusted_threshold を適用する。
        # スキャンをスキップせず「閾値だけ緩和」することで、アカウント侵害時の
        # blast radius を最小化しつつ監査証跡を確保する。
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
