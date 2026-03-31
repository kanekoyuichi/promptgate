from __future__ import annotations

import os
from typing import TYPE_CHECKING, Optional

from promptgate.exceptions import DetectorError
from promptgate.providers.base import LLMProvider

if TYPE_CHECKING:
    import openai as openai_module


class OpenAIProvider(LLMProvider):
    """OpenAI Chat Completions API プロバイダー。

    OpenAI 互換の API（Azure OpenAI、ローカル LLM サーバー等）にも対応。
    pip install openai が必要。
    AsyncOpenAI を使った真の非同期呼び出しに対応している。

    Args:
        api_key:  OpenAI API キー。None の場合は環境変数 OPENAI_API_KEY を使用。
        model:    モデル識別子。例: "gpt-4o-mini", "gpt-4o"
        base_url: API エンドポイント URL。OpenAI 互換 API や Azure OpenAI を使う場合に指定。
                  None の場合は OpenAI 公式エンドポイントを使用。

    Example::

        from promptgate.providers import OpenAIProvider
        from promptgate import PromptGate

        # OpenAI
        gate = PromptGate(
            detectors=["rule", "llm_judge"],
            llm_provider=OpenAIProvider(model="gpt-4o-mini"),
        )

        # OpenAI 互換 API（ローカル LLM 等）
        gate = PromptGate(
            detectors=["rule", "llm_judge"],
            llm_provider=OpenAIProvider(
                model="llama-3-8b",
                base_url="http://localhost:11434/v1",
                api_key="ollama",
            ),
        )
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        if model is None:
            raise DetectorError(
                "OpenAIProvider には model の指定が必要です。"
                " 例: 'gpt-4o-mini', 'gpt-4o'"
            )
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._model = model
        self._base_url = base_url
        self._sync_client: Optional[openai_module.OpenAI] = None
        self._async_client: Optional[openai_module.AsyncOpenAI] = None

    def _import_openai(self) -> openai_module:
        try:
            import openai
            return openai
        except ImportError as e:
            raise DetectorError(
                "OpenAIProvider には openai パッケージが必要です。"
                " pip install openai でインストールしてください。"
            ) from e

    def _get_sync_client(self) -> openai_module.OpenAI:
        if self._sync_client is not None:
            return self._sync_client
        openai = self._import_openai()
        kwargs: dict[str, object] = {"api_key": self._api_key}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        self._sync_client = openai.OpenAI(**kwargs)  # type: ignore[arg-type]
        return self._sync_client

    def _get_async_client(self) -> openai_module.AsyncOpenAI:
        if self._async_client is not None:
            return self._async_client
        openai = self._import_openai()
        kwargs: dict[str, object] = {"api_key": self._api_key}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        self._async_client = openai.AsyncOpenAI(**kwargs)  # type: ignore[arg-type]
        return self._async_client

    def complete(self, system: str, user_message: str) -> str:
        client = self._get_sync_client()
        try:
            response = client.chat.completions.create(
                model=self._model,
                max_tokens=256,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_message},
                ],
                timeout=30.0,
            )
            content = response.choices[0].message.content
            if content is None:
                raise DetectorError("OpenAI API が空のレスポンスを返しました。")
            return content.strip()
        except DetectorError:
            raise
        except Exception as e:
            raise DetectorError(f"OpenAI API 呼び出しに失敗しました: {e}") from e

    async def complete_async(self, system: str, user_message: str) -> str:
        client = self._get_async_client()
        try:
            response = await client.chat.completions.create(
                model=self._model,
                max_tokens=256,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_message},
                ],
                timeout=30.0,
            )
            content = response.choices[0].message.content
            if content is None:
                raise DetectorError("OpenAI API が空のレスポンスを返しました。")
            return content.strip()
        except DetectorError:
            raise
        except Exception as e:
            raise DetectorError(f"OpenAI API 呼び出しに失敗しました: {e}") from e
