from __future__ import annotations

import os
from typing import TYPE_CHECKING, Optional

from promptgate.exceptions import DetectorError
from promptgate.providers.base import LLMProvider

if TYPE_CHECKING:
    import anthropic as anthropic_module


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API プロバイダー。

    pip install anthropic が必要。
    AsyncAnthropic を使った真の非同期呼び出しに対応している。

    Args:
        api_key: Anthropic API キー。None の場合は環境変数 ANTHROPIC_API_KEY を使用。
        model:   モデル識別子。最新の ID は Anthropic ドキュメントを参照。
                 例: "claude-haiku-4-5-20251001"（Anthropic API）
                     "anthropic.claude-3-haiku-20240307-v1:0"（Amazon Bedrock）
                     "claude-3-haiku@20240307"（Google Vertex AI）

    Example::

        from promptgate.providers import AnthropicProvider
        from promptgate import PromptGate

        gate = PromptGate(
            detectors=["rule", "llm_judge"],
            llm_provider=AnthropicProvider(model="claude-haiku-4-5-20251001"),
        )
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        if model is None:
            raise DetectorError(
                "AnthropicProvider には model の指定が必要です。"
                " 最新のモデル ID は Anthropic ドキュメントを参照してください。"
                " 例: 'claude-haiku-4-5-20251001'"
            )
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._model = model
        self._sync_client: Optional[anthropic_module.Anthropic] = None
        self._async_client: Optional[anthropic_module.AsyncAnthropic] = None

    def _get_sync_client(self) -> anthropic_module.Anthropic:
        if self._sync_client is not None:
            return self._sync_client
        try:
            import anthropic
        except ImportError as e:
            raise DetectorError(
                "AnthropicProvider には anthropic パッケージが必要です。"
                " pip install anthropic でインストールしてください。"
            ) from e
        self._sync_client = anthropic.Anthropic(api_key=self._api_key)
        return self._sync_client

    def _get_async_client(self) -> anthropic_module.AsyncAnthropic:
        if self._async_client is not None:
            return self._async_client
        try:
            import anthropic
        except ImportError as e:
            raise DetectorError(
                "AnthropicProvider には anthropic パッケージが必要です。"
                " pip install anthropic でインストールしてください。"
            ) from e
        self._async_client = anthropic.AsyncAnthropic(api_key=self._api_key)
        return self._async_client

    def complete(self, system: str, user_message: str) -> str:
        client = self._get_sync_client()
        try:
            message = client.messages.create(
                model=self._model,
                max_tokens=256,
                system=system,
                messages=[{"role": "user", "content": user_message}],
                timeout=30.0,
            )
            return message.content[0].text.strip()
        except Exception as e:
            raise DetectorError(f"Anthropic API 呼び出しに失敗しました: {e}") from e

    async def complete_async(self, system: str, user_message: str) -> str:
        client = self._get_async_client()
        try:
            message = await client.messages.create(
                model=self._model,
                max_tokens=256,
                system=system,
                messages=[{"role": "user", "content": user_message}],
                timeout=30.0,
            )
            return message.content[0].text.strip()
        except Exception as e:
            raise DetectorError(f"Anthropic API 呼び出しに失敗しました: {e}") from e
