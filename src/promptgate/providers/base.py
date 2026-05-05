from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from promptgate.exceptions import (
    APIAuthenticationError,
    APIRateLimitError,
    APITimeoutError,
    DetectorError,
)

# Exception class names used to classify provider errors without importing
# optional packages (anthropic / openai) at the base level.
_TIMEOUT_NAMES = frozenset({"APITimeoutError", "TimeoutError", "ReadTimeout", "ConnectTimeout"})
_AUTH_NAMES = frozenset({"AuthenticationError", "PermissionDeniedError"})
_RATE_LIMIT_NAMES = frozenset({"RateLimitError"})


def classify_provider_error(provider_name: str, exc: Exception) -> DetectorError:
    """Convert a raw provider exception to the appropriate DetectorError subclass."""
    cls_name = type(exc).__name__
    msg = f"{provider_name} API call failed: {exc}."
    if cls_name in _TIMEOUT_NAMES:
        return APITimeoutError(msg)
    if cls_name in _AUTH_NAMES:
        return APIAuthenticationError(msg)
    if cls_name in _RATE_LIMIT_NAMES:
        return APIRateLimitError(msg)
    return DetectorError(msg)


class LLMProvider(ABC):
    """LLM API プロバイダーの抽象基底クラス。

    同期・非同期の両方のインターフェースを提供する。
    サブクラスは complete() を実装する必要があり、
    complete_async() はオーバーライド可（デフォルトはスレッドプールで同期版を実行）。

    Example::

        class MyProvider(LLMProvider):
            def complete(self, system: str, user_message: str) -> str:
                # カスタム API 呼び出し
                return my_api.call(system=system, user=user_message)
    """

    @abstractmethod
    def complete(self, system: str, user_message: str) -> str:
        """同期 API 呼び出し。

        Args:
            system:       システムプロンプト文字列。
            user_message: ユーザーメッセージ文字列。

        Returns:
            LLM の応答テキスト（生文字列）。

        Raises:
            DetectorError: API 呼び出しまたはパッケージ不足の場合。
        """

    async def complete_async(self, system: str, user_message: str) -> str:
        """非同期 API 呼び出し。

        デフォルト実装はスレッドプールで complete() を実行する。
        真に非同期な HTTP クライアントを持つプロバイダーはオーバーライドすること。

        Args:
            system:       システムプロンプト文字列。
            user_message: ユーザーメッセージ文字列。

        Returns:
            LLM の応答テキスト（生文字列）。
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.complete, system, user_message)
