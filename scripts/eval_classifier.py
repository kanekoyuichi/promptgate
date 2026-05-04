"""Evaluate ClassifierDetector and export FN/FP cases for data improvement.

Usage:
    .venv/bin/python scripts/eval_classifier.py
    .venv/bin/python scripts/eval_classifier.py --thresholds 0.4 0.5 0.6
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from promptgate.detectors.classifier import ClassifierDetector  # noqa: E402
from benchmark_embedding_comparison import DATASET  # noqa: E402

MODEL_DIR = ROOT / "models" / "promptgate-classifier-v1"
REPORT_DIR = ROOT / "reports"


def _language(text: str) -> str:
    return "ja" if any(ord(c) > 0x3000 for c in text) else "en"


def _rows() -> list[dict[str, object]]:
    return [
        {
            "text": text,
            "expected_safe": expected_safe,
            "label": 0 if expected_safe else 1,
            "category": category,
            "language": _language(text),
        }
        for text, expected_safe, category in DATASET
    ]


def _scan_scores(rows: list[dict[str, object]], model_dir: Path) -> list[dict[str, object]]:
    detector = ClassifierDetector(model_dir=str(model_dir), threshold=1.0)
    results: list[dict[str, object]] = []
    for row in rows:
        start = time.monotonic()
        result = detector.scan(str(row["text"]))
        results.append(
            {
                **row,
                "attack_prob": result.risk_score,
                "latency_ms": round((time.monotonic() - start) * 1000, 1),
            }
        )
    return results


def _metrics(scored: list[dict[str, object]], threshold: float) -> dict[str, object]:
    tp = fp = tn = fn = 0
    by_category: dict[str, dict[str, int]] = {}

    for row in scored:
        expected_attack = int(row["label"]) == 1
        predicted_attack = float(row["attack_prob"]) >= threshold
        category = str(row["category"])
        cat = by_category.setdefault(category, {"total": 0, "correct": 0})
        cat["total"] += 1
        cat["correct"] += int(expected_attack == predicted_attack)

        if expected_attack and predicted_attack:
            tp += 1
        elif not expected_attack and predicted_attack:
            fp += 1
        elif not expected_attack and not predicted_attack:
            tn += 1
        else:
            fn += 1

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(scored) if scored else 0.0

    return {
        "threshold": threshold,
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "by_category_accuracy": {
            key: round(value["correct"] / value["total"], 4)
            for key, value in sorted(by_category.items())
        },
    }


def _write_cases(
    path: Path,
    rows: Iterable[dict[str, object]],
    threshold: float,
    *,
    want_fn: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["text", "label", "attack_prob", "category", "language"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            expected_attack = int(row["label"]) == 1
            predicted_attack = float(row["attack_prob"]) >= threshold
            is_fn = expected_attack and not predicted_attack
            is_fp = not expected_attack and predicted_attack
            if (want_fn and is_fn) or (not want_fn and is_fp):
                writer.writerow({field: row[field] for field in fields})


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ClassifierDetector")
    parser.add_argument("--model-dir", default=str(MODEL_DIR))
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=[0.4, 0.5, 0.6, 0.7, 0.8],
    )
    parser.add_argument("--export-threshold", type=float, default=0.6)
    args = parser.parse_args()

    model_dir = Path(args.model_dir)
    if not model_dir.exists():
        raise SystemExit(f"model dir not found: {model_dir}")

    rows = _rows()
    print(f"[eval] model={model_dir}")
    print(f"[eval] cases={len(rows)}")
    scored = _scan_scores(rows, model_dir)

    reports = [_metrics(scored, threshold) for threshold in args.thresholds]
    for report in reports:
        print(
            "[eval] threshold={threshold:.2f} recall={recall:.1%} "
            "specificity={specificity:.1%} precision={precision:.1%} "
            "f1={f1:.4f} TP={tp} FP={fp} TN={tn} FN={fn}".format(**report)
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "classifier_threshold_sweep.json").write_text(
        json.dumps(reports, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_cases(
        REPORT_DIR / "classifier_fn.csv",
        scored,
        args.export_threshold,
        want_fn=True,
    )
    _write_cases(
        REPORT_DIR / "classifier_fp.csv",
        scored,
        args.export_threshold,
        want_fn=False,
    )
    print(f"[eval] wrote {REPORT_DIR / 'classifier_threshold_sweep.json'}")
    print(f"[eval] wrote {REPORT_DIR / 'classifier_fn.csv'}")
    print(f"[eval] wrote {REPORT_DIR / 'classifier_fp.csv'}")


if __name__ == "__main__":
    main()
