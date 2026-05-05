class PromptGateError(Exception):
    """PromptGate のベース例外クラス"""


class DetectorError(PromptGateError):
    """検出器の実行中に発生するエラー"""


class ConfigurationError(PromptGateError):
    """設定値が不正な場合のエラー"""


class APITimeoutError(DetectorError):
    """LLM プロバイダーへのリクエストがタイムアウトした"""


class APIAuthenticationError(DetectorError):
    """LLM プロバイダーの認証に失敗した（API キー不正など）"""


class APIRateLimitError(DetectorError):
    """LLM プロバイダーのレート制限に達した"""


class ParseError(DetectorError):
    """LLM レスポンスの解析に失敗した"""
