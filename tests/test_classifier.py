from __future__ import annotations

import sys
import types
from typing import Any


def test_classifier_uses_default_model_when_model_dir_is_omitted(monkeypatch) -> None:
    from promptgate.detectors import classifier

    calls: dict[str, Any] = {}

    def fake_pipeline(task: str, **kwargs: Any) -> object:
        calls["task"] = task
        calls.update(kwargs)

        def run(*args: Any, **run_kwargs: Any) -> list[dict[str, object]]:
            return [{"label": "LABEL_1", "score": 0.9}]

        return run

    monkeypatch.setitem(
        sys.modules,
        "transformers",
        types.SimpleNamespace(pipeline=fake_pipeline),
    )

    detector = classifier.ClassifierDetector()
    detector.warmup()

    assert calls["task"] == "text-classification"
    assert calls["model"] == classifier._DEFAULT_MODEL_ID
    assert calls["tokenizer"] == classifier._DEFAULT_MODEL_ID
    assert calls["device"] == -1


def test_classifier_uses_custom_model_dir(monkeypatch) -> None:
    from promptgate.detectors.classifier import ClassifierDetector

    calls: dict[str, Any] = {}

    def fake_pipeline(task: str, **kwargs: Any) -> object:
        calls["task"] = task
        calls.update(kwargs)

        def run(*args: Any, **run_kwargs: Any) -> list[dict[str, object]]:
            return [{"label": "LABEL_1", "score": 0.9}]

        return run

    monkeypatch.setitem(
        sys.modules,
        "transformers",
        types.SimpleNamespace(pipeline=fake_pipeline),
    )

    detector = ClassifierDetector(model_dir="/tmp/local-model")
    detector.warmup()

    assert calls["model"] == "/tmp/local-model"
    assert calls["tokenizer"] == "/tmp/local-model"


def test_classifier_reads_named_attack_label() -> None:
    from promptgate.detectors.classifier import ClassifierDetector

    raw = [
        {"label": "BENIGN", "score": 0.08},
        {"label": "INJECTION", "score": 0.92},
    ]

    assert ClassifierDetector._extract_attack_probability(raw) == 0.92
