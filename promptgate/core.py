from __future__ import annotations

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


class PromptGate:
    def __init__(
        self,
        sensitivity: str = "medium",
        detectors: Optional[list[str]] = None,
        language: str = "auto",
        log_all: bool = False,
        whitelist_patterns: Optional[list[str]] = None,
        trusted_user_ids: Optional[list[str]] = None,
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
        self._extra_rules: list[dict[str, str]] = []

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
        self._extra_rules.append({"name": name, "pattern": pattern, "severity": severity})
        self._rule_detector = RuleBasedDetector(
            sensitivity=self._sensitivity,
            language=self._language,
            extra_rules=self._extra_rules,
            whitelist_patterns=self._whitelist_patterns,
        )

    def scan(self, text: str, user_id: Optional[str] = None) -> ScanResult:
        start = time.monotonic()

        if user_id and user_id in self._trusted_user_ids:
            return ScanResult(
                is_safe=True,
                risk_score=0.0,
                threats=[],
                explanation="信頼されたユーザーのためスキャンをスキップしました。",
                detector_used="none",
                latency_ms=(time.monotonic() - start) * 1000,
            )

        results: list[tuple[str, ScanResult]] = []

        rule_result = self._rule_detector.scan(text)
        results.append(("rule", rule_result))

        if self._embedding_detector and self._sensitivity in ("medium", "high"):
            emb_result = self._embedding_detector.scan(text)
            results.append(("embedding", emb_result))

        if self._llm_detector:
            llm_result = self._llm_detector.scan(text)
            results.append(("llm_judge", llm_result))

        final = self._aggregate(results)
        final.latency_ms = (time.monotonic() - start) * 1000

        if self._log_all or not final.is_safe:
            logger.info(
                "scan result: is_safe=%s risk_score=%.2f threats=%s",
                final.is_safe,
                final.risk_score,
                final.threats,
            )

        return final

    def scan_output(self, text: str) -> ScanResult:
        return self.scan(text)

    def _aggregate(self, results: list[tuple[str, ScanResult]]) -> ScanResult:
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

        threshold_map = {"low": 0.8, "medium": 0.5, "high": 0.3}
        threshold = threshold_map.get(self._sensitivity, 0.5)
        is_safe = final_score < threshold

        return ScanResult(
            is_safe=is_safe,
            risk_score=round(final_score, 4),
            threats=list(all_threats),
            explanation=" / ".join(explanations),
            detector_used="+".join(detector_names),
            latency_ms=0.0,
        )
