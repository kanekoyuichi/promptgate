"""PromptGate 定量評価スクリプト

eval/corpus.jsonl のラベル付きコーパスに対して指定スキャナーを実行し、
FPR（良性誤検知率）・Recall（攻撃検出率）・カテゴリ別 Recall を計測する。

使い方:
    python eval/run_eval.py                  # rule のみ（デフォルト）
    python eval/run_eval.py --detector rule
    python eval/run_eval.py --output-md eval/results/rule_based.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# src レイアウト対応
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from promptgate import PromptGate  # noqa: E402

CORPUS_PATH = Path(__file__).parent / "corpus.jsonl"


def load_corpus(path: Path) -> list[dict]:
    examples = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))
    return examples


def run_evaluation(detector: str) -> dict:
    gate = PromptGate(detectors=[detector], language="auto")
    corpus = load_corpus(CORPUS_PATH)

    benign = [e for e in corpus if e["label"] == "benign"]
    attacks = [e for e in corpus if e["label"] == "attack"]
    languages = sorted({e["language"] for e in corpus})
    categories = sorted({e["category"] for e in attacks})

    results: dict = {
        "detector": detector,
        "overall": {},
        "by_language": {},
        "by_category": {},
    }

    # --- FPR（良性誤検知） ---
    for lang in languages + ["all"]:
        subset = benign if lang == "all" else [e for e in benign if e["language"] == lang]
        if not subset:
            continue
        fp = sum(1 for e in subset if not gate.scan(e["text"]).is_safe)
        fpr = fp / len(subset)
        key = results["overall"] if lang == "all" else results["by_language"].setdefault(lang, {})
        key["fpr"] = round(fpr, 3)
        key["fp"] = fp
        key["benign_total"] = len(subset)

    # --- Recall（攻撃検出） ---
    for lang in languages + ["all"]:
        subset = attacks if lang == "all" else [e for e in attacks if e["language"] == lang]
        if not subset:
            continue
        tp = sum(1 for e in subset if not gate.scan(e["text"]).is_safe)
        recall = tp / len(subset)
        key = results["overall"] if lang == "all" else results["by_language"].setdefault(lang, {})
        key["recall"] = round(recall, 3)
        key["tp"] = tp
        key["attack_total"] = len(subset)

    # --- カテゴリ別 Recall ---
    for cat in categories:
        subset = [e for e in attacks if e["category"] == cat]
        tp = sum(1 for e in subset if not gate.scan(e["text"]).is_safe)
        results["by_category"][cat] = {
            "recall": round(tp / len(subset), 3),
            "tp": tp,
            "total": len(subset),
        }

    return results


def format_markdown(results: dict) -> str:
    detector = results["detector"]
    ov = results["overall"]
    lines = [
        f"## {detector} スキャナー 評価結果",
        "",
        "### 総合",
        "",
        "| 指標 | 値 | 詳細 |",
        "|-----|-----|------|",
        f"| FPR（良性誤検知率） | {ov['fpr']:.1%} | {ov['fp']} / {ov['benign_total']} 件誤検知 |",
        f"| Recall（攻撃検出率） | {ov['recall']:.1%} | {ov['tp']} / {ov['attack_total']} 件検出 |",
        "",
        "### 言語別",
        "",
        "| 言語 | FPR | Recall |",
        "|-----|-----|--------|",
    ]
    for lang, v in sorted(results["by_language"].items()):
        lines.append(f"| {lang} | {v.get('fpr', '-'):.1%} | {v.get('recall', '-'):.1%} |")

    lines += [
        "",
        "### カテゴリ別 Recall",
        "",
        "| カテゴリ | Recall | 検出数 / 総数 |",
        "|---------|--------|-------------|",
    ]
    for cat, v in sorted(results["by_category"].items()):
        lines.append(f"| `{cat}` | {v['recall']:.1%} | {v['tp']} / {v['total']} |")

    lines += [
        "",
        "> **注意**: このコーパスは固定の exemplar セットに対する参考値です。"
        " 実環境での精度はドメイン・攻撃パターンの多様性に依存します。",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="PromptGate 定量評価")
    parser.add_argument("--detector", default="rule", choices=["rule"], help="評価するスキャナー")
    parser.add_argument("--output-md", default=None, help="Markdown 結果の出力先ファイル")
    parser.add_argument("--fail-on-fpr", type=float, default=None, help="FPR がこの値を超えたら非ゼロ終了")
    parser.add_argument("--fail-on-recall", type=float, default=None, help="Recall がこの値を下回ったら非ゼロ終了")
    args = parser.parse_args()

    print(f"評価中: detector={args.detector} corpus={CORPUS_PATH}", flush=True)
    results = run_evaluation(args.detector)
    md = format_markdown(results)
    print(md)

    if args.output_md:
        out = Path(args.output_md)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"\n結果を {out} に保存しました。")

    ov = results["overall"]
    exit_code = 0
    if args.fail_on_fpr is not None and ov["fpr"] > args.fail_on_fpr:
        print(f"\n[FAIL] FPR {ov['fpr']:.1%} > 閾値 {args.fail_on_fpr:.1%}", file=sys.stderr)
        exit_code = 1
    if args.fail_on_recall is not None and ov["recall"] < args.fail_on_recall:
        print(f"\n[FAIL] Recall {ov['recall']:.1%} < 閾値 {args.fail_on_recall:.1%}", file=sys.stderr)
        exit_code = 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
