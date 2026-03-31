from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Optional

import yaml

from promptgate.detectors.base import BaseDetector
from promptgate.exceptions import DetectorError
from promptgate.normalizer import normalize
from promptgate.result import ScanResult

logger = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).parent.parent / "patterns"

_SEVERITY_SCORE: dict[str, float] = {
    # 入力スキャン threat
    "direct_injection": 0.9,
    "jailbreak": 0.85,
    "data_exfiltration": 0.8,
    "indirect_injection": 0.75,
    "prompt_leaking": 0.7,
    # 出力スキャン threat
    "credential_leak": 0.95,
    "pii_leak": 0.80,
    "system_prompt_leak": 0.75,
}

# core.py の _aggregate threshold_map と統一
_SENSITIVITY_THRESHOLD: dict[str, float] = {
    "low": 0.8,
    "medium": 0.5,
    "high": 0.3,
}

# ホワイトリストはこのスコア未満の結果にのみ適用する（高確信度攻撃は免除しない）
_WHITELIST_MAX_BYPASSABLE_SCORE: float = 0.8

_SEVERITY_TO_SCORE: dict[str, float] = {
    "low": 0.5,
    "medium": 0.7,
    "high": 0.9,
}


def _is_safe_pattern(compiled: re.Pattern[str]) -> bool:
    """コンパイル済みパターンが空文字列にマッチしないことを確認する。

    空文字列にマッチするパターン（例: "", ".*", "a*", "a?"）は
    あらゆるテキストにヒットするため、安全性評価が無効化される。
    """
    return compiled.search("") is None


def _load_patterns(language: str, scan_mode: str = "input") -> dict[str, list[str]]:
    suffix = "_output" if scan_mode == "output" else ""
    langs: list[str]
    if language == "auto":
        langs = ["ja", "en"]
    else:
        langs = [language]

    merged: dict[str, list[str]] = {}
    for lang in langs:
        path = _PATTERNS_DIR / f"{lang}{suffix}.yaml"
        if not path.exists():
            raise DetectorError(f"パターンファイルが見つかりません: {path}")
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise DetectorError(f"パターンファイルの形式が不正です: {path}")
        for threat, patterns in data.items():
            if not isinstance(patterns, list):
                continue
            for p in patterns:
                if not isinstance(p, str) or not p.strip():
                    logger.warning(
                        "空または不正なパターンをスキップします: threat=%s, value=%r",
                        threat,
                        p,
                    )
                    continue
                try:
                    compiled = re.compile(p, re.IGNORECASE)
                except re.error as e:
                    logger.warning(
                        "パターンのコンパイルに失敗しました: threat=%s, pattern=%r, error=%s",
                        threat,
                        p,
                        e,
                    )
                    continue
                if not _is_safe_pattern(compiled):
                    logger.warning(
                        "空文字列にマッチするパターンを拒否しました: threat=%s, pattern=%r",
                        threat,
                        p,
                    )
                    continue
                merged.setdefault(threat, []).append(p)
    return merged


class RuleBasedDetector(BaseDetector):
    """YAML 定義の正規表現・フレーズマッチによる攻撃検出器。

    **動作原理**:
    言語別・スキャンモード別の YAML パターンファイルをロードし、
    正規化済みテキストに対して正規表現マッチを行う。
    マッチしたカテゴリをすべて threats として報告する（多ラベル）。

    **性能特性と制約**:
    - 明示的なフレーズを用いた直接的な攻撃を高速・低コストで検出できる。
    - 以下のパターンは検出精度が低下する、または検出できない:
      - 婉曲・間接表現（命令を別の語句で言い換えたもの）
      - 文脈依存のロール移譲（段階的なペルソナ誘導）
      - 長文中に埋め込まれた攻撃意図（フレーズが分散する場合）
      - ツール呼び出しパラメータへの注入
      - YAML パターンに収録されていない新規の攻撃表現
    - 正規化（NFKC / ゼロ幅文字除去 / ドット・ハイフン除去）により
      "i.g.n.o.r.e" 等の単純な文字挿入回避には対応しているが、
      意味レベルの言い換えには無効。

    単独での利用は直接的な既知攻撃の検出に限定し、
    回避耐性を高めるには `embedding` または `llm_judge` との組み合わせを推奨する。
    """

    def __init__(
        self,
        sensitivity: str = "medium",
        language: str = "auto",
        extra_rules: Optional[list[dict[str, str]]] = None,
        whitelist_patterns: Optional[list[str]] = None,
        scan_mode: str = "input",
        normalize_input: bool = True,
    ) -> None:
        self._threshold = _SENSITIVITY_THRESHOLD.get(sensitivity, 0.5)
        # 出力スキャンでは正規化しない: Email・APIキー等の構造を壊さないため。
        # 正規化はインジェクション回避 ("i.g.n.o.r.e" 等) に対抗するためのもので
        # LLM が生成した出力テキストには不要。
        self._normalize_input = normalize_input
        self._patterns = _load_patterns(language, scan_mode)
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
                    c = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.warning(
                        "パターンのコンパイルに失敗しました (threat=%s, pattern=%r): %s",
                        threat,
                        pattern,
                        e,
                    )
                    continue
                if not _is_safe_pattern(c):
                    logger.warning(
                        "空文字列にマッチするパターンをスキップします: threat=%s, pattern=%r",
                        threat,
                        pattern,
                    )
                    continue
                compiled_list.append(c)
            self._compiled[threat] = compiled_list

    def add_rule(self, name: str, pattern: str, severity: str = "medium") -> None:
        self._patterns.setdefault(name, []).append(pattern)
        self._custom_scores[name] = _SEVERITY_TO_SCORE.get(severity, 0.7)
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.warning(
                "追加ルールのコンパイルに失敗しました (name=%s, pattern=%r): %s",
                name,
                pattern,
                e,
            )
            return
        if not _is_safe_pattern(compiled):
            logger.warning(
                "空文字列にマッチするパターンを拒否しました (name=%s, pattern=%r)",
                name,
                pattern,
            )
            return
        self._compiled.setdefault(name, []).append(compiled)

    def scan(self, text: str) -> ScanResult:
        start = time.monotonic()

        normalized = normalize(text) if self._normalize_input else text

        detected_threats: list[str] = []

        for threat, compiled_patterns in self._compiled.items():
            for cpat in compiled_patterns:
                try:
                    if cpat.search(normalized):
                        detected_threats.append(threat)
                        break
                except re.error as e:
                    logger.warning(
                        "パターンの実行中にエラーが発生しました (threat=%s): %s",
                        threat,
                        e,
                    )

        # Fix E: 複合スコアリング（最大スコア + 脅威カテゴリ多様性ボーナス）
        if detected_threats:
            detected_unique = list(set(detected_threats))
            base_score = max(
                self._custom_scores.get(t) or _SEVERITY_SCORE.get(t, 0.7)
                for t in detected_unique
            )
            # 複数の脅威カテゴリが検出された場合、攻撃の複雑さを加味してスコアを加算
            diversity_bonus = min(0.05 * (len(detected_unique) - 1), 0.1)
            final_score = min(base_score + diversity_bonus, 1.0)
        else:
            detected_unique = []
            final_score = 0.0

        # ホワイトリスト: スキャン後チェック（高確信度攻撃は免除しない）
        whitelist_matched = any(wp.search(normalized) for wp in self._whitelist)
        if whitelist_matched and final_score < _WHITELIST_MAX_BYPASSABLE_SCORE:
            return ScanResult(
                is_safe=True,
                risk_score=0.0,
                threats=[],
                explanation="ホワイトリストパターンに一致しました。",
                detector_used="rule_based",
                latency_ms=(time.monotonic() - start) * 1000,
            )

        is_safe = final_score < self._threshold
        explanation = (
            f"以下の脅威が検出されました: {', '.join(detected_unique)}"
            if detected_unique
            else "脅威は検出されませんでした。"
        )

        return ScanResult(
            is_safe=is_safe,
            risk_score=round(final_score, 4),
            threats=detected_unique,
            explanation=explanation,
            detector_used="rule_based",
            latency_ms=(time.monotonic() - start) * 1000,
        )
