from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Optional

import yaml

from promptgate.exceptions import DetectorError
from promptgate.result import ScanResult

_PATTERNS_DIR = Path(__file__).parent.parent / "patterns"

_SEVERITY_SCORE: dict[str, float] = {
    "direct_injection": 0.9,
    "jailbreak": 0.85,
    "data_exfiltration": 0.8,
    "indirect_injection": 0.75,
    "prompt_leaking": 0.7,
}

_SENSITIVITY_THRESHOLD: dict[str, float] = {
    "low": 0.8,
    "medium": 0.6,
    "high": 0.4,
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
            data: dict[str, list[str]] = yaml.safe_load(f) or {}
        for threat, patterns in data.items():
            merged.setdefault(threat, []).extend(patterns)
    return merged


class RuleBasedDetector:
    def __init__(
        self,
        sensitivity: str = "medium",
        language: str = "auto",
        extra_rules: Optional[list[dict[str, str]]] = None,
        whitelist_patterns: Optional[list[str]] = None,
    ) -> None:
        self._threshold = _SENSITIVITY_THRESHOLD.get(sensitivity, 0.6)
        self._patterns = _load_patterns(language)
        self._whitelist: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in (whitelist_patterns or [])
        ]
        for rule in extra_rules or []:
            threat = rule.get("name", "custom")
            pattern = rule.get("pattern", "")
            if pattern:
                self._patterns.setdefault(threat, []).append(pattern)

    def scan(self, text: str) -> ScanResult:
        start = time.monotonic()

        for wp in self._whitelist:
            if wp.search(text):
                return ScanResult(
                    is_safe=True,
                    risk_score=0.0,
                    threats=[],
                    explanation="ホワイトリストパターンに一致しました。",
                    detector_used="rule_based",
                    latency_ms=(time.monotonic() - start) * 1000,
                )

        detected_threats: list[str] = []
        max_score = 0.0

        for threat, patterns in self._patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        detected_threats.append(threat)
                        score = _SEVERITY_SCORE.get(threat, 0.7)
                        max_score = max(max_score, score)
                        break
                except re.error:
                    pass

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
