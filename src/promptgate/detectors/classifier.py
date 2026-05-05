"""Fine-tuned classifier detector for prompt injection detection."""

from __future__ import annotations

import time
from typing import Optional

from promptgate.detectors.base import BaseDetector
from promptgate.exceptions import ConfigurationError, DetectorError
from promptgate.result import ScanResult

_DEFAULT_MODEL_ID = "kanekoyuichi/promptgate-classifier-v2"
_ATTACK_LABELS = {
    "1",
    "LABEL_1",
    "ATTACK",
    "INJECTION",
    "MALICIOUS",
    "PROMPT_INJECTION",
    "UNSAFE",
}

_SENSITIVITY_THRESHOLDS: dict[str, float] = {
    "low": 0.80,
    "medium": 0.60,
    "high": 0.40,
}


class ClassifierDetector(BaseDetector):
    """Prompt injection detector using a fine-tuned text classifier.

    Args:
        model_dir: Local model directory or Hugging Face model ID.
            When omitted, the default public classifier model is loaded.
        sensitivity: Detection sensitivity ("low" / "medium" / "high").
        max_length: Maximum token length passed to the tokenizer.
        threshold: Optional attack-probability threshold. Overrides sensitivity.
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,
        sensitivity: str = "medium",
        max_length: int = 256,
        threshold: Optional[float] = None,
    ) -> None:
        if threshold is not None and not (0.0 < threshold <= 1.0):
            raise ConfigurationError(
                "classifier threshold must be greater than 0.0 and at most 1.0."
            )

        self._model_dir = str(model_dir) if model_dir else _DEFAULT_MODEL_ID
        self._threshold = (
            threshold
            if threshold is not None
            else _SENSITIVITY_THRESHOLDS.get(sensitivity, 0.60)
        )
        self._max_length = max_length
        self._pipeline: Optional[object] = None

    def warmup(self) -> None:
        """Load the classifier model before the first scan."""
        self._load()

    def _load(self) -> None:
        if self._pipeline is not None:
            return
        try:
            from transformers import pipeline  # type: ignore
        except ImportError as e:
            raise DetectorError(
                "ClassifierDetector requires transformers and torch. "
                "Install it with: pip install 'promptgate[classifier]'"
            ) from e

        try:
            self._pipeline = pipeline(
                "text-classification",
                model=self._model_dir,
                tokenizer=self._model_dir,
                device=-1,
            )
        except Exception as e:
            raise DetectorError(
                f"Failed to load classifier model '{self._model_dir}'. "
                "If you are offline, either connect to the internet for the first "
                "download or pass classifier_model_dir/model_dir pointing to a local "
                "Transformers model directory."
            ) from e

    @staticmethod
    def _extract_attack_probability(raw: object) -> float:
        # transformers pipeline(top_k=None) may return either
        # [{"label": ..., "score": ...}, ...] or [[{...}, ...]] for one input.
        if not isinstance(raw, list) or not raw:
            return 0.0
        out = raw[0] if isinstance(raw[0], list) else raw
        if not isinstance(out, list):
            return 0.0
        label_to_score = {
            item.get("label"): float(item.get("score", 0.0))
            for item in out
            if isinstance(item, dict)
        }
        for label, score in label_to_score.items():
            if str(label).upper() in _ATTACK_LABELS:
                return score
        return 0.0

    def scan(self, text: str) -> ScanResult:
        start = time.monotonic()
        self._load()

        raw = self._pipeline(  # type: ignore[operator, misc]
            text,
            truncation=True,
            max_length=self._max_length,
            top_k=None,
        )
        attack_prob = self._extract_attack_probability(raw)

        is_safe = attack_prob < self._threshold
        threats = [] if is_safe else ["prompt_injection"]
        explanation = (
            f"Classifier probability {attack_prob:.2f} is below threshold "
            f"{self._threshold:.2f}."
            if is_safe
            else f"Classifier probability {attack_prob:.2f} exceeded threshold "
            f"{self._threshold:.2f}."
        )

        return ScanResult(
            is_safe=is_safe,
            risk_score=round(attack_prob, 4),
            threats=tuple(threats),
            explanation=explanation,
            detector_used="classifier",
            latency_ms=(time.monotonic() - start) * 1000,
        )
