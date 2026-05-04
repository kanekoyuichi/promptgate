"""Fine-tuned classifier detector for prompt injection detection."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from promptgate.detectors.base import BaseDetector
from promptgate.exceptions import DetectorError
from promptgate.result import ScanResult

_DEFAULT_MODEL_DIR = (
    Path(__file__).resolve().parents[3] / "models" / "promptgate-classifier-v1"
)

_SENSITIVITY_THRESHOLDS: dict[str, float] = {
    "low": 0.80,
    "medium": 0.60,
    "high": 0.40,
}


class ClassifierDetector(BaseDetector):
    """Prompt injection detector using a fine-tuned text classifier.

    Args:
        model_dir: Directory containing a Transformers sequence-classification model.
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
            raise DetectorError(
                "classifier threshold must be greater than 0.0 and at most 1.0."
            )

        self._model_dir = str(model_dir) if model_dir else str(_DEFAULT_MODEL_DIR)
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

        self._pipeline = pipeline(
            "text-classification",
            model=self._model_dir,
            tokenizer=self._model_dir,
            device=-1,
        )

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
        return label_to_score.get("LABEL_1", 0.0)

    def scan(self, text: str) -> ScanResult:
        start = time.monotonic()
        self._load()

        raw = self._pipeline(  # type: ignore[operator]
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
            threats=threats,
            explanation=explanation,
            detector_used="classifier",
            latency_ms=(time.monotonic() - start) * 1000,
        )
