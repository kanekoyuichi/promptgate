"""Evaluate PromptGate detectors on a CSV holdout dataset."""

from __future__ import annotations

import argparse
import csv
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from promptgate import PromptGate  # noqa: E402
from promptgate.detectors.classifier import ClassifierDetector  # noqa: E402


@dataclass
class Stats:
    total: int = 0
    correct: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, expected_attack: bool, predicted_attack: bool) -> None:
        self.total += 1
        self.correct += int(expected_attack == predicted_attack)
        if expected_attack and predicted_attack:
            self.tp += 1
        elif not expected_attack and predicted_attack:
            self.fp += 1
        elif not expected_attack and not predicted_attack:
            self.tn += 1
        else:
            self.fn += 1


@dataclass
class EvalResult:
    name: str
    categories: dict[str, Stats] = field(default_factory=dict)
    total_ms: float = 0.0

    def add(self, category: str, expected_attack: bool, predicted_attack: bool, ms: float) -> None:
        self.categories.setdefault(category, Stats()).add(expected_attack, predicted_attack)
        self.total_ms += ms

    @property
    def total(self) -> Stats:
        merged = Stats()
        for stats in self.categories.values():
            merged.total += stats.total
            merged.correct += stats.correct
            merged.tp += stats.tp
            merged.fp += stats.fp
            merged.tn += stats.tn
            merged.fn += stats.fn
        return merged

    @property
    def recall(self) -> float:
        total = self.total
        return total.tp / (total.tp + total.fn) if total.tp + total.fn else 0.0

    @property
    def specificity(self) -> float:
        total = self.total
        return total.tn / (total.tn + total.fp) if total.tn + total.fp else 0.0

    @property
    def precision(self) -> float:
        total = self.total
        return total.tp / (total.tp + total.fp) if total.tp + total.fp else 0.0

    @property
    def accuracy(self) -> float:
        total = self.total
        return total.correct / total.total if total.total else 0.0

    @property
    def avg_ms(self) -> float:
        total = self.total
        return self.total_ms / total.total if total.total else 0.0


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    required = {"text", "label", "category"}
    if not rows or not required.issubset(rows[0]):
        raise SystemExit(f"{path} must contain columns: {sorted(required)}")
    return rows


def evaluate_promptgate(name: str, rows: list[dict[str, str]], detectors: list[str]) -> EvalResult:
    gate = PromptGate(detectors=detectors, sensitivity="medium")
    result = EvalResult(name)
    for row in rows:
        start = time.monotonic()
        scan = gate.scan(row["text"])
        result.add(row["category"], row["label"] == "1", not scan.is_safe, (time.monotonic() - start) * 1000)
    return result


def evaluate_classifier(
    name: str,
    rows: list[dict[str, str]],
    model_dir: str,
    threshold: float,
) -> EvalResult:
    detector = ClassifierDetector(model_dir=model_dir, threshold=threshold)
    result = EvalResult(name)
    for row in rows:
        start = time.monotonic()
        scan = detector.scan(row["text"])
        result.add(row["category"], row["label"] == "1", not scan.is_safe, (time.monotonic() - start) * 1000)
    return result


def print_result(result: EvalResult) -> None:
    total = result.total
    print(f"\n== {result.name} ==")
    print("category        total  correct  TP  FP  TN  FN")
    for category in sorted(result.categories):
        stats = result.categories[category]
        print(
            f"{category:<14} {stats.total:>5} {stats.correct:>8} "
            f"{stats.tp:>3} {stats.fp:>3} {stats.tn:>3} {stats.fn:>3}"
        )
    print(
        "summary         {total:>5} {correct:>8} {tp:>3} {fp:>3} {tn:>3} {fn:>3}".format(
            total=total.total,
            correct=total.correct,
            tp=total.tp,
            fp=total.fp,
            tn=total.tn,
            fn=total.fn,
        )
    )
    print(
        "recall={:.1%} specificity={:.1%} precision={:.1%} accuracy={:.1%} avg_ms={:.1f}".format(
            result.recall,
            result.specificity,
            result.precision,
            result.accuracy,
            result.avg_ms,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate detectors on holdout CSV")
    parser.add_argument("--data", default="data/holdout/classifier_holdout_v1.csv")
    parser.add_argument("--classifier-threshold", type=float, default=0.5)
    args = parser.parse_args()

    rows = load_rows(ROOT / args.data)
    print(f"dataset={args.data} rows={len(rows)}")

    results = [
        evaluate_promptgate("rule only", rows, ["rule"]),
        evaluate_promptgate("embedding only", rows, ["embedding"]),
        evaluate_promptgate("rule + embedding", rows, ["rule", "embedding"]),
        evaluate_classifier(
            f"classifier v1 @ {args.classifier_threshold}",
            rows,
            "models/promptgate-classifier-v1",
            args.classifier_threshold,
        ),
        evaluate_classifier(
            f"classifier v2 @ {args.classifier_threshold}",
            rows,
            "models/promptgate-classifier-v2",
            args.classifier_threshold,
        ),
    ]

    for result in results:
        print_result(result)

    print("\nSUMMARY")
    print("name                 recall  specificity  precision  accuracy  avg_ms")
    for result in results:
        print(
            f"{result.name:<20} {result.recall:>6.1%} {result.specificity:>11.1%} "
            f"{result.precision:>10.1%} {result.accuracy:>9.1%} {result.avg_ms:>7.1f}"
        )


if __name__ == "__main__":
    main()
