from __future__ import annotations

from typing import TYPE_CHECKING, Optional, cast

from promptgate.exceptions import DetectorError
from promptgate.providers.base import LLMProvider, classify_provider_error

if TYPE_CHECKING:
    import anthropic as anthropic_module


class AnthropicBedrockProvider(LLMProvider):
    """Amazon Bedrock 経由で Claude モデルを呼び出すプロバイダー。

    anthropic SDK の AnthropicBedrock / AsyncAnthropicBedrock クライアントを使用する。
    AWS 認証は明示的な引数・環境変数（AWS_ACCESS_KEY_ID 等）・IAM ロールのいずれかで行う。

    pip install anthropic が必要（Bedrock 向け追加パッケージは不要）。

    Args:
        model:             Bedrock のモデル識別子。
                           例: "anthropic.claude-3-haiku-20240307-v1:0"
                           最新の ID は AWS ドキュメントを参照してください。
        aws_region:        AWS リージョン。None の場合は環境変数 AWS_DEFAULT_REGION を使用。
        aws_access_key:    AWS アクセスキー ID。None の場合は環境変数 AWS_ACCESS_KEY_ID を使用。
        aws_secret_key:    AWS シークレットアクセスキー。None の場合は環境変数を使用。
        aws_session_token: AWS セッショントークン（一時認証情報を使う場合）。

    Example::

        from promptgate import PromptGate
        from promptgate.providers import AnthropicBedrockProvider

        gate = PromptGate(
            detectors=["rule", "llm_judge"],
            llm_provider=AnthropicBedrockProvider(
                model="anthropic.claude-3-haiku-20240307-v1:0",
                aws_region="us-east-1",
            ),
        )
    """

    def __init__(
        self,
        model: Optional[str] = None,
        aws_region: Optional[str] = None,
        aws_access_key: Optional[str] = None,
        aws_secret_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
    ) -> None:
        if model is None:
            raise DetectorError(
                "AnthropicBedrockProvider requires a model identifier."
                " Example: 'anthropic.claude-3-haiku-20240307-v1:0'"
                " See the AWS documentation for the latest model IDs."
            )
        self._model = model
        self._aws_region = aws_region
        self._aws_access_key = aws_access_key
        self._aws_secret_key = aws_secret_key
        self._aws_session_token = aws_session_token
        self._sync_client: Optional[anthropic_module.AnthropicBedrock] = None
        self._async_client: Optional[anthropic_module.AsyncAnthropicBedrock] = None

    def _client_kwargs(self) -> dict[str, object]:
        kwargs: dict[str, object] = {}
        if self._aws_region is not None:
            kwargs["aws_region"] = self._aws_region
        if self._aws_access_key is not None:
            kwargs["aws_access_key"] = self._aws_access_key
        if self._aws_secret_key is not None:
            kwargs["aws_secret_key"] = self._aws_secret_key
        if self._aws_session_token is not None:
            kwargs["aws_session_token"] = self._aws_session_token
        return kwargs

    def _get_sync_client(self) -> anthropic_module.AnthropicBedrock:
        if self._sync_client is not None:
            return self._sync_client
        try:
            import anthropic
        except ImportError as e:
            raise DetectorError(
                "AnthropicBedrockProvider requires the anthropic package."
                " Install it with: pip install anthropic."
            ) from e
        self._sync_client = anthropic.AnthropicBedrock(**self._client_kwargs())
        return self._sync_client

    def _get_async_client(self) -> anthropic_module.AsyncAnthropicBedrock:
        if self._async_client is not None:
            return self._async_client
        try:
            import anthropic
        except ImportError as e:
            raise DetectorError(
                "AnthropicBedrockProvider requires the anthropic package."
                " Install it with: pip install anthropic."
            ) from e
        self._async_client = anthropic.AsyncAnthropicBedrock(**self._client_kwargs())
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
            raise classify_provider_error("Anthropic Bedrock", e) from e

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
            raise classify_provider_error("Anthropic Bedrock", e) from e
