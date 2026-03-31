from __future__ import annotations

import re
import unicodedata

# ゼロ幅・不可視文字（ゼロ幅スペース、ゼロ幅非結合子、ゼロ幅結合子、
# ワードジョイナー、BOM、ソフトハイフン、結合用グラフィーム結合子）
_ZERO_WIDTH = re.compile(r"[\u00ad\u034f\u200b-\u200f\u2060\u2061\ufeff]")

# 単語文字の間に挟まれた「非スペース」区切りノイズを除去する。
# スペースは除外することで、通常の単語間スペースを保持する。
# 対象区切り: ピリオド、ハイフン、アンダースコア、カンマ、
#             カタカナ中点(U+30FB)、中点(U+00B7)
# 例: "i.g.n.o.r.e" → "ignore"、"シ・ス・テ・ム" → "システム"
_NOSPC_SEPARATOR = re.compile(
    r"(?<=[a-zA-Z\u3040-\u9fff\uac00-\ud7a3])"
    r"[.\-_,\u00b7\u30fb]+"
    r"(?=[a-zA-Z\u3040-\u9fff\uac00-\ud7a3])"
)

# スペースで区切られた単一文字の連続を結合する。
# 例: "j a i l b r e a k" → "jailbreak"
# 通常の単語("ignore previous")には適用されない（各語が複数文字のため）
_SPACED_SINGLES = re.compile(r"\b[a-z](?: [a-z])+\b", re.IGNORECASE)


def normalize(text: str) -> str:
    """テキストを正規化してパターン回避攻撃への耐性を高める。

    処理順:
    1. Unicode NFKC 正規化（全角英数字→半角、互換文字展開など）
    2. ゼロ幅・不可視文字の除去
    3a. 非スペース区切りノイズの除去（例: "i.g.n.o.r.e" → "ignore"）
    3b. スペース区切り単一文字の結合（例: "j a i l" → "jail"）
    4. 連続する水平空白を単一スペースに統一（改行は保持）
    """
    # 1. NFKC: 全角英数字→半角、互換漢字・記号の展開
    text = unicodedata.normalize("NFKC", text)
    # 2. ゼロ幅・不可視文字除去
    text = _ZERO_WIDTH.sub("", text)
    # 3a. 非スペース区切りノイズ除去（ドット・ハイフン等）
    text = _NOSPC_SEPARATOR.sub("", text)
    # 3b. スペース区切り単一文字を結合
    text = _SPACED_SINGLES.sub(lambda m: m.group(0).replace(" ", ""), text)
    # 4. 連続する水平空白を単一スペースに統一（改行は保持）
    text = re.sub(r"[ \t]+", " ", text).strip()
    return text
