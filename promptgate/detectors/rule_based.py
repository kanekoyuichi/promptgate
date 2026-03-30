from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Optional

import yaml

from promptgate.detectors.base import BaseDetector
from promptgate.exceptions import DetectorError
from promptgate.result import ScanResult

logger = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).parent.parent / "patterns"

_SEVERITY_SCORE: dict[str, float] = {
    "direct_injection": 0.9,
    "jailbreak": 0.85,
    "data_exfiltration": 0.8,
    "indirect_injection": 0.75,
    "prompt_leaking": 0.7,
}

# Aligned with core.py _aggregate threshold_map
_SENSITIVITY_THRESHOLD: dict[str, float] = {
    "low": 0.8,
    "medium": 0.5,
    "high": 0.3,
}

# Whitelist only suppresses results below this score (not high-confidence attacks)
_WHITELIST_MAX_BYPASSABLE_SCORE: float = 0.8

_SEVERITY_TO_SCORE: dict[str, float] = {
    "low": 0.5,
    "medium": 0.7,
    "high": 0.9,
}


def _load_patterns(language: str) -> dict[str, list[str]]:
    langs: list[str]
    if language == "auto":
        langs = ["ja", "en"]
    else:
        langs = [language]

    merged: dict[str, list[str]] = {}
    for lang in langs:
        path = _PATTERNS_DIR / f"{lang}.yaml"
        if not path.exists():
            raise DetectorError(f"パターンファイルが見つかりません: {path}")
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise DetectorError(f"パターンファイルの形式が不正です: {path}")
        for threat, patterns in data.items():
            if isinstance(patterns, list):
                merged.setdefault(threat, []).extend(patterns)
    return merged


class RuleBasedDetector(BaseDetector):
    def __init__(
        self,
        sensitivity: str = "medium",
        language: str = "auto",
        extra_rules: Optional[list[dict[str, str]]] = None,
        whitelist_patterns: Optional[list[str]] = None,
    ) -> None:
        self._threshold = _SENSITIVITY_THRESHOLD.get(sensitivity, 0.5)
        self._patterns = _load_patterns(language)
        self._custom_scores: dict[str, float] = {}
        self._whitelist: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in (whitelist_patterns or [])
        ]
        for rule in extra_rules or []:
            threat = rule.get("name", "custom")
            pattern = rule.get("pattern", "")
            severity = rule.get("severity", "medium")
            if pattern:
                self._patterns.setdefault(threat, []).append(pattern)
                self._custom_scores[threat] = _SEVERITY_TO_SCORE.get(severity, 0.7)

        self._compiled: dict[str, list[re.Pattern[str]]] = {}
        self._compile_all()

    def _compile_all(self) -> None:
        self._compiled = {}
        for threat, patterns in self._patterns.items():
            compiled_list: list[re.Pattern[str]] = []
            for pattern in patterns:
                try:
                    compiled_list.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logger.warning(
                        "パターンのコンパイルに失敗しました (threat=%s, pattern=%r): %s",
                        threat,
                        pattern,
                        e,
                    )
            self._compiled[threat] = compiled_list

    def add_rule(self, name: str, pattern: str, severity: str = "medium") -> None:
        self._patterns.setdefault(name, []).append(pattern)
        self._custom_scores[name] = _SEVERITY_TO_SCORE.get(severity, 0.7)
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._compiled.setdefault(name, []).append(compiled)
        except re.error as e:
            logger.warning(
                "追加ルールのコンパイルに失敗しました (name=%s, pattern=%r): %s",
                name,
                pattern,
                e,
            )

    def scan(self, text: str) -> ScanResult:
        start = time.monotonic()

        detected_threats: list[str] = []
        max_score = 0.0

        for threat, compiled_patterns in self._compiled.items():
            for cpat in compiled_patterns:
                try:
                    if cpat.search(text):
                        detected_threats.append(threat)
                        score = self._custom_scores.get(threat) or _SEVERITY_SCORE.get(threat, 0.7)
                        max_score = max(max_score, score)
                        break
                except re.error as e:
                    logger.warning(
                        "パターンの実行中にエラーが発生しました (threat=%s): %s",
                        threat,
                        e,
                    )

        # Whitelist: suppress result only if not a high-confidence attack
        whitelist_matched = any(wp.search(text) for wp in self._whitelist)
        if whitelist_matched and max_score < _WHITELIST_MAX_BYPASSABLE_SCORE:
            return ScanResult(
                is_safe=True,
                risk_score=0.0,
                threats=[],
                explanation="ホワイトリストパターンに一致しました。",
                detector_used="rule_based",
                latency_ms=(time.monotonic() - start) * 1000,
            )

        is_safe = max_score < self._threshold
        if detected_threats:
            explanation = f"以下の脅威が検出されました: {', '.join(set(detected_threats))}"
        else:
            explanation = "脅威は検出されませんでした。"

        return ScanResult(
            is_safe=is_safe,
            risk_score=max_score,
            threats=list(set(detected_threats)),
            explanation=explanation,
            detector_used="rule_based",
            latency_ms=(time.monotonic() - start) * 1000,
        )
