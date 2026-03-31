"""normalizer.py の単体テスト

正規化は回避攻撃への耐性の根幹であり、
意図した変換が正確に行われることを確認する。
各テストは単一の正規化ステップを独立して検証する。
"""
from promptgate.normalizer import normalize


# ---------------------------------------------------------------------------
# NFKC 正規化（Step 1）
# ---------------------------------------------------------------------------

def test_nfkc_fullwidth_ascii_letters() -> None:
    # 全角ラテン文字 → 半角
    assert normalize("ｉｇｎｏｒｅ") == "ignore"


def test_nfkc_fullwidth_ascii_phrase() -> None:
    # 全角英単語フレーズが正規化後にパターンとマッチ可能になる
    assert normalize("ｉｇｎｏｒｅ ｐｒｅｖｉｏｕｓ ｉｎｓｔｒｕｃｔｉｏｎｓ") == "ignore previous instructions"


def test_nfkc_halfwidth_katakana() -> None:
    # 半角カタカナ → 全角カタカナ（日本語パターンがマッチ可能になる）
    result = normalize("ｼｽﾃﾑ")
    assert result == "システム"


def test_nfkc_fullwidth_space() -> None:
    # 全角スペース → 半角スペースに統一
    result = normalize("ignore　previous")
    assert result == "ignore previous"


# ---------------------------------------------------------------------------
# ゼロ幅・不可視文字の除去（Step 2）
# ---------------------------------------------------------------------------

def test_zero_width_space_removed() -> None:
    # U+200B ゼロ幅スペース
    assert normalize("ig\u200bnore") == "ignore"


def test_soft_hyphen_removed() -> None:
    # U+00AD ソフトハイフン（目に見えないが文字列に埋め込み可能）
    assert normalize("ig\u00adnore") == "ignore"


def test_word_joiner_removed() -> None:
    # U+2060 ワードジョイナー
    assert normalize("ig\u2060nore") == "ignore"


def test_bom_removed() -> None:
    # U+FEFF BOM（テキスト先頭以外にも埋め込まれる場合がある）
    assert normalize("\ufeffignore") == "ignore"


def test_combining_grapheme_joiner_removed() -> None:
    # U+034F 結合用グラフィーム結合子
    assert normalize("ig\u034fnore") == "ignore"


# ---------------------------------------------------------------------------
# 非スペース区切りノイズの除去（Step 3a）
# ---------------------------------------------------------------------------

def test_separator_dot_between_ascii() -> None:
    # ドット区切り evasion: "i.g.n.o.r.e" → "ignore"
    assert normalize("i.g.n.o.r.e") == "ignore"


def test_separator_hyphen_between_ascii() -> None:
    # ハイフン区切り evasion: "j-a-i-l-b-r-e-a-k" → "jailbreak"
    assert normalize("j-a-i-l-b-r-e-a-k") == "jailbreak"


def test_separator_underscore_between_ascii() -> None:
    # アンダースコア区切り evasion
    assert normalize("j_a_i_l") == "jail"


def test_separator_katakana_nakaten() -> None:
    # カタカナ中点 (U+30FB) 区切り: "シ・ス・テ・ム" → "システム"
    assert normalize("シ・ス・テ・ム") == "システム"


def test_separator_not_removed_between_non_word_chars() -> None:
    # 区切り文字の前後が対象文字クラス外の場合は除去しない
    # 例: 数字の間のドットは除去しない
    result = normalize("192.168")
    assert "." in result


def test_separator_dot_collapses_domain() -> None:
    # 重要な既知挙動: example.com → examplecom（出力スキャンで normalize しない理由）
    assert normalize("example.com") == "examplecom"


# ---------------------------------------------------------------------------
# スペース区切り単一文字の結合（Step 3b）
# ---------------------------------------------------------------------------

def test_spaced_singles_joined() -> None:
    # "j a i l b r e a k" → "jailbreak"
    assert normalize("j a i l b r e a k") == "jailbreak"


def test_spaced_singles_in_sentence() -> None:
    # 文中の単一文字スペース区切り列を結合（前後の通常単語は保持）
    result = normalize("enter j a i l b r e a k mode")
    assert result == "enter jailbreak mode"


def test_spaced_singles_not_applied_to_words() -> None:
    # 通常の単語間スペースは保持される
    result = normalize("ignore previous instructions")
    assert result == "ignore previous instructions"


# ---------------------------------------------------------------------------
# 空白の正規化（Step 4）
# ---------------------------------------------------------------------------

def test_consecutive_spaces_collapsed() -> None:
    assert normalize("ignore   previous") == "ignore previous"


def test_newline_preserved() -> None:
    # 改行は保持される（複数行入力に対応するため）
    result = normalize("line1\nline2")
    assert "\n" in result
    assert "line1" in result
    assert "line2" in result


def test_tab_collapsed_to_space() -> None:
    result = normalize("ignore\tprevious")
    assert result == "ignore previous"


# ---------------------------------------------------------------------------
# 複合攻撃
# ---------------------------------------------------------------------------

def test_combined_evasion_fullwidth_plus_zero_width_plus_separator() -> None:
    # 全角 + ゼロ幅文字 + 区切りノイズの複合攻撃
    # "ｉ\u200b.\u200bg\u200b.\u200bn\u200b.\u200bo\u200b.\u200br\u200b.\u200be"
    text = "ｉ\u200b.\u200bg\u200b.\u200bn\u200b.\u200bo\u200b.\u200br\u200b.\u200be"
    assert normalize(text) == "ignore"


def test_empty_string() -> None:
    assert normalize("") == ""


def test_whitespace_only() -> None:
    assert normalize("   ") == ""
