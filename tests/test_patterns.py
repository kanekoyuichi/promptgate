"""パターンファイルの整合性テスト

YAML パターンファイルが破損・不正になっていないことを
デプロイ前に検証する。CI で常時実行される。
"""
import re
from pathlib import Path

import pytest
import yaml

PATTERNS_DIR = Path(__file__).parent.parent / "src" / "promptgate" / "patterns"

_INPUT_FILES = ["ja.yaml", "en.yaml"]
_OUTPUT_FILES = ["ja_output.yaml", "en_output.yaml"]
_ALL_FILES = _INPUT_FILES + _OUTPUT_FILES

_REQUIRED_INPUT_THREATS = {
    "direct_injection",
    "jailbreak",
    "data_exfiltration",
    "indirect_injection",
    "prompt_leaking",
}
_REQUIRED_OUTPUT_THREATS = {
    "credential_leak",
    "pii_leak",
    "system_prompt_leak",
}


# ---------------------------------------------------------------------------
# YAML ファイル構造の検証
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname", _ALL_FILES)
def test_pattern_file_is_valid_yaml(fname: str) -> None:
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), f"{fname}: トップレベルが dict ではありません"


@pytest.mark.parametrize("fname", _ALL_FILES)
def test_all_pattern_values_are_lists(fname: str) -> None:
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    for threat, patterns in data.items():
        assert isinstance(patterns, list), f"{fname}/{threat}: list ではありません"
        assert len(patterns) > 0, f"{fname}/{threat}: パターンが空です"


# ---------------------------------------------------------------------------
# 正規表現の有効性
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname", _ALL_FILES)
def test_all_patterns_compile_as_valid_regex(fname: str) -> None:
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    invalid: list[str] = []
    for threat, patterns in data.items():
        for pattern in patterns or []:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                invalid.append(f"  {threat}: {pattern!r} → {e}")

    assert not invalid, "不正な正規表現:\n" + "\n".join(invalid)


@pytest.mark.parametrize("fname", _ALL_FILES)
def test_no_pattern_matches_empty_string(fname: str) -> None:
    # 空文字列にマッチするパターンはあらゆる入力を危険と判定してしまう
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    dangerous: list[str] = []
    for threat, patterns in data.items():
        for pattern in patterns or []:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                if compiled.search("") is not None:
                    dangerous.append(f"  {threat}: {pattern!r}")
            except re.error:
                pass  # 別テストで検出済み

    assert not dangerous, "空文字列にマッチするパターン（過検出の危険）:\n" + "\n".join(dangerous)


@pytest.mark.parametrize("fname", _ALL_FILES)
def test_all_patterns_are_non_empty_strings(fname: str) -> None:
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    bad: list[str] = []
    for threat, patterns in data.items():
        for i, pattern in enumerate(patterns or []):
            if not isinstance(pattern, str) or not pattern.strip():
                bad.append(f"  {threat}[{i}]: {pattern!r}")

    assert not bad, "空・非文字列パターン:\n" + "\n".join(bad)


# ---------------------------------------------------------------------------
# 必須脅威タイプの存在確認
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname", _INPUT_FILES)
def test_input_file_has_required_threat_types(fname: str) -> None:
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    missing = _REQUIRED_INPUT_THREATS - set(data.keys())
    assert not missing, f"{fname}: 不足している脅威タイプ: {missing}"


@pytest.mark.parametrize("fname", _OUTPUT_FILES)
def test_output_file_has_required_threat_types(fname: str) -> None:
    path = PATTERNS_DIR / fname
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    missing = _REQUIRED_OUTPUT_THREATS - set(data.keys())
    assert not missing, f"{fname}: 不足している脅威タイプ: {missing}"


# ---------------------------------------------------------------------------
# 入力/出力ファイル間の脅威タイプ分離
# ---------------------------------------------------------------------------

def test_input_threats_absent_from_output_files() -> None:
    # 出力パターンファイルに入力脅威タイプが混入していないことを確認
    input_only = {"direct_injection", "jailbreak", "indirect_injection"}
    for fname in _OUTPUT_FILES:
        path = PATTERNS_DIR / fname
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        overlap = input_only & set(data.keys())
        assert not overlap, f"{fname}: 入力専用脅威タイプが混入: {overlap}"


def test_output_threats_absent_from_input_files() -> None:
    # 入力パターンファイルに出力脅威タイプが混入していないことを確認
    output_only = {"credential_leak", "pii_leak", "system_prompt_leak"}
    for fname in _INPUT_FILES:
        path = PATTERNS_DIR / fname
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        overlap = output_only & set(data.keys())
        assert not overlap, f"{fname}: 出力専用脅威タイプが混入: {overlap}"
