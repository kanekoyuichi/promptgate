from __future__ import annotations

from typing import TYPE_CHECKING, Optional, cast

from promptgate.exceptions import DetectorError
from promptgate.providers.base import LLMProvider, classify_provider_error

if TYPE_CHECKING:
    import anthropic as anthropic_module


class AnthropicVertexProvider(LLMProvider):
    """Google Cloud Vertex AI 経由で Claude モデルを呼び出すプロバイダー。

    anthropic SDK の AnthropicVertex / AsyncAnthropicVertex クライアントを使用する。
    GCP 認証はアプリケーションデフォルト認証（ADC）または google-auth ライブラリで行う。

    pip install anthropic が必要。GCP 認証には google-auth パッケージも必要になる場合がある。

    Args:
        model:      Vertex AI のモデル識別子。
                    例: "claude-3-haiku@20240307"
                    最新の ID は Google Cloud ドキュメントを参照してください。
        project_id: GCP プロジェクト ID。None の場合は環境変数 ANTHROPIC_VERTEX_PROJECT_ID
                    または ADC のデフォルトプロジェクトを使用。
        region:     Vertex AI のリージョン。None の場合は "us-east5"（SDK デフォルト）。

    Example::

        from promptgate import PromptGate
        from promptgate.providers import AnthropicVertexProvider

        gate = PromptGate(
            detectors=["rule", "llm_judge"],
            llm_provider=AnthropicVertexProvider(
                model="claude-3-haiku@20240307",
                project_id="my-gcp-project",
                region="us-east5",
            ),
        )
    """

    def __init__(
        self,
        model: Optional[str] = None,
        project_id: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        if model is None:
            raise DetectorError(
                "AnthropicVertexProvider requires a model identifier."
                " Example: 'claude-3-haiku@20240307'"
                " See the Google Cloud documentation for the latest model IDs."
            )
        self._model = model
        self._project_id = project_id
        self._region = region
        self._sync_client: Optional[anthropic_module.AnthropicVertex] = None
        self._async_client: Optional[anthropic_module.AsyncAnthropicVertex] = None

    def _client_kwargs(self) -> dict[str, object]:
        kwargs: dict[str, object] = {}
        if self._project_id is not None:
            kwargs["project_id"] = self._project_id
        if self._region is not None:
            kwargs["region"] = self._region
        return kwargs

    def _get_sync_client(self) -> anthropic_module.AnthropicVertex:
        if self._sync_client is not None:
            return self._sync_client
        try:
            import anthropic
        except ImportError as e:
            raise DetectorError(
                "AnthropicVertexProvider requires the anthropic package."
                " Install it with: pip install anthropic."
            ) from e
        self._sync_client = anthropic.AnthropicVertex(**self._client_kwargs())
        return self._sync_client

    def _get_async_client(self) -> anthropic_module.AsyncAnthropicVertex:
        if self._async_client is not None:
            return self._async_client
        try:
            import anthropic
        except ImportError as e:
            raise DetectorError(
                "AnthropicVertexProvider requires the anthropic package."
                " Install it with: pip install anthropic."
            ) from e
        self._async_client = anthropic.AsyncAnthropicVertex(**self._client_kwargs())
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
            return cast(str, message.content[0].text.strip())
        except Exception as e:
            raise classify_provider_error("Anthropic Vertex AI", e) from e

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
            return cast(str, message.content[0].text.strip())
        except Exception as e:
            raise classify_provider_error("Anthropic Vertex AI", e) from e
