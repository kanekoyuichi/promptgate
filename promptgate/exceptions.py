class PromptGateError(Exception):
    """PromptGate のベース例外クラス"""


class DetectorError(PromptGateError):
    """検出器の実行中に発生するエラー"""


class ConfigurationError(PromptGateError):
    """設定値が不正な場合のエラー"""
