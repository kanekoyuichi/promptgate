"""LLMProvider 実装のユニットテスト。

実際の HTTP 呼び出しはモックで置き換え、プロバイダーの
インターフェース準拠・エラーハンドリングを検証する。
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptgate.exceptions import DetectorError
from promptgate.providers.anthropic import AnthropicProvider
from promptgate.providers.base import LLMProvider
from promptgate.providers.openai import OpenAIProvider


# ---------------------------------------------------------------------------
# LLMProvider 基底クラス
# ---------------------------------------------------------------------------

def test_llm_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        LLMProvider()  # type: ignore[abstract]


def test_llm_provider_default_complete_async_uses_thread() -> None:
    """complete_async のデフォルト実装がスレッドプールで complete を呼ぶことを確認。"""
    import asyncio

    class _SyncOnlyProvider(LLMProvider):
        def complete(self, system: str, user_message: str) -> str:
            return json.dumps({"answer": "ok"})

    provider = _SyncOnlyProvider()
    result = asyncio.get_event_loop().run_until_complete(
        provider.complete_async("sys", "user")
    )
    assert result == json.dumps({"answer": "ok"})


# ---------------------------------------------------------------------------
# AnthropicProvider
# ---------------------------------------------------------------------------

def test_anthropic_provider_requires_model() -> None:
    with pytest.raises(DetectorError, match="model"):
        AnthropicProvider(api_key="key")


def test_anthropic_provider_complete() -> None:
    provider = AnthropicProvider(api_key="test-key", model="test-model")

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text='{"is_attack": false, "threats": []}')]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    provider._sync_client = mock_client

    result = provider.complete("system prompt", "user input")
    assert '"is_attack"' in result
    mock_client.messages.create.assert_called_once()
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "test-model"
    assert call_kwargs["system"] == "system prompt"
    assert call_kwargs["messages"][0]["content"] == "user input"


def test_anthropic_provider_complete_api_error() -> None:
    provider = AnthropicProvider(api_key="test-key", model="test-model")

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = RuntimeError("connection refused")
    provider._sync_client = mock_client

    with pytest.raises(DetectorError, match="Anthropic API"):
        provider.complete("system", "user")


def test_anthropic_provider_requires_package() -> None:
    with patch.dict("sys.modules", {"anthropic": None}):
        provider = AnthropicProvider(api_key="key", model="m")
        with pytest.raises(DetectorError, match="anthropic"):
            provider.complete("sys", "user")


@pytest.mark.asyncio
async def test_anthropic_provider_complete_async() -> None:
    provider = AnthropicProvider(api_key="test-key", model="test-model")

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text='{"is_attack": false}')]
    mock_async_client = AsyncMock()
    mock_async_client.messages.create = AsyncMock(return_value=mock_message)
    provider._async_client = mock_async_client

    result = await provider.complete_async("system", "user input")
    assert '"is_attack"' in result
    mock_async_client.messages.create.assert_called_once()


@pytest.mark.asyncio
async def test_anthropic_provider_complete_async_error() -> None:
    provider = AnthropicProvider(api_key="test-key", model="test-model")

    mock_async_client = AsyncMock()
    mock_async_client.messages.create = AsyncMock(
        side_effect=RuntimeError("network error")
    )
    provider._async_client = mock_async_client

    with pytest.raises(DetectorError, match="Anthropic API"):
        await provider.complete_async("system", "user")


# ---------------------------------------------------------------------------
# OpenAIProvider
# ---------------------------------------------------------------------------

def test_openai_provider_requires_model() -> None:
    with pytest.raises(DetectorError, match="model"):
        OpenAIProvider(api_key="key")


def test_openai_provider_complete() -> None:
    provider = OpenAIProvider(api_key="test-key", model="gpt-4o-mini")

    mock_choice = MagicMock()
    mock_choice.message.content = '{"is_attack": false, "threats": []}'
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response
    provider._sync_client = mock_client

    result = provider.complete("system prompt", "user input")
    assert '"is_attack"' in result
    call_kwargs = mock_client.chat.completions.create.call_args[1]
    assert call_kwargs["model"] == "gpt-4o-mini"
    assert call_kwargs["messages"][0]["role"] == "system"
    assert call_kwargs["messages"][1]["content"] == "user input"


def test_openai_provider_complete_null_content() -> None:
    provider = OpenAIProvider(api_key="test-key", model="gpt-4o-mini")

    mock_choice = MagicMock()
    mock_choice.message.content = None
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response
    provider._sync_client = mock_client

    with pytest.raises(DetectorError, match="空のレスポンス"):
        provider.complete("system", "user")


def test_openai_provider_complete_api_error() -> None:
    provider = OpenAIProvider(api_key="test-key", model="gpt-4o-mini")

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RuntimeError("rate limit")
    provider._sync_client = mock_client

    with pytest.raises(DetectorError, match="OpenAI API"):
        provider.complete("system", "user")


def test_openai_provider_requires_package() -> None:
    with patch.dict("sys.modules", {"openai": None}):
        provider = OpenAIProvider(api_key="key", model="m")
        with pytest.raises(DetectorError, match="openai"):
            provider.complete("sys", "user")


def test_openai_provider_base_url_passed_to_client() -> None:
    """base_url が内部クライアントに渡されることを確認（OpenAI 互換 API 対応）。"""
    mock_openai = MagicMock()
    mock_client_instance = MagicMock()
    mock_openai.OpenAI.return_value = mock_client_instance

    provider = OpenAIProvider(
        api_key="test",
        model="llama-3",
        base_url="http://localhost:11434/v1",
    )

    with patch.dict("sys.modules", {"openai": mock_openai}):
        provider._sync_client = None  # キャッシュクリア
        provider._get_sync_client()
        call_kwargs = mock_openai.OpenAI.call_args[1]
        assert call_kwargs["base_url"] == "http://localhost:11434/v1"


@pytest.mark.asyncio
async def test_openai_provider_complete_async() -> None:
    provider = OpenAIProvider(api_key="test-key", model="gpt-4o-mini")

    mock_choice = MagicMock()
    mock_choice.message.content = '{"is_attack": true}'
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_async_client = AsyncMock()
    mock_async_client.chat.completions.create = AsyncMock(return_value=mock_response)
    provider._async_client = mock_async_client

    result = await provider.complete_async("system", "user")
    assert '"is_attack"' in result


# ---------------------------------------------------------------------------
# AnthropicBedrockProvider
# ---------------------------------------------------------------------------

def test_anthropic_bedrock_provider_requires_model() -> None:
    from promptgate.providers.anthropic_bedrock import AnthropicBedrockProvider

    with pytest.raises(DetectorError, match="model"):
        AnthropicBedrockProvider()


def test_anthropic_bedrock_provider_complete() -> None:
    from promptgate.providers.anthropic_bedrock import AnthropicBedrockProvider

    provider = AnthropicBedrockProvider(
        model="anthropic.claude-3-haiku-20240307-v1:0",
        aws_region="us-east-1",
    )
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text='{"is_attack": false}')]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    provider._sync_client = mock_client

    result = provider.complete("system", "user")
    assert '"is_attack"' in result
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "anthropic.claude-3-haiku-20240307-v1:0"


def test_anthropic_bedrock_provider_aws_kwargs_passed() -> None:
    """AWS 認証情報がクライアントコンストラクタに渡されることを確認。"""
    from promptgate.providers.anthropic_bedrock import AnthropicBedrockProvider

    mock_anthropic = MagicMock()
    mock_anthropic.AnthropicBedrock.return_value = MagicMock()

    provider = AnthropicBedrockProvider(
        model="m",
        aws_region="ap-northeast-1",
        aws_access_key="AKIA...",
        aws_secret_key="secret",
    )
    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        provider._sync_client = None
        provider._get_sync_client()
        call_kwargs = mock_anthropic.AnthropicBedrock.call_args[1]
        assert call_kwargs["aws_region"] == "ap-northeast-1"
        assert call_kwargs["aws_access_key"] == "AKIA..."


def test_anthropic_bedrock_provider_requires_package() -> None:
    from promptgate.providers.anthropic_bedrock import AnthropicBedrockProvider

    with patch.dict("sys.modules", {"anthropic": None}):
        provider = AnthropicBedrockProvider(model="m")
        with pytest.raises(DetectorError, match="anthropic"):
            provider.complete("sys", "user")


# ---------------------------------------------------------------------------
# AnthropicVertexProvider
# ---------------------------------------------------------------------------

def test_anthropic_vertex_provider_requires_model() -> None:
    from promptgate.providers.anthropic_vertex import AnthropicVertexProvider

    with pytest.raises(DetectorError, match="model"):
        AnthropicVertexProvider()


def test_anthropic_vertex_provider_complete() -> None:
    from promptgate.providers.anthropic_vertex import AnthropicVertexProvider

    provider = AnthropicVertexProvider(
        model="claude-3-haiku@20240307",
        project_id="my-project",
        region="us-east5",
    )
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text='{"is_attack": false}')]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    provider._sync_client = mock_client

    result = provider.complete("system", "user")
    assert '"is_attack"' in result
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-3-haiku@20240307"


def test_anthropic_vertex_provider_gcp_kwargs_passed() -> None:
    """GCP プロジェクト情報がクライアントコンストラクタに渡されることを確認。"""
    from promptgate.providers.anthropic_vertex import AnthropicVertexProvider

    mock_anthropic = MagicMock()
    mock_anthropic.AnthropicVertex.return_value = MagicMock()

    provider = AnthropicVertexProvider(
        model="m",
        project_id="my-gcp-project",
        region="us-east5",
    )
    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        provider._sync_client = None
        provider._get_sync_client()
        call_kwargs = mock_anthropic.AnthropicVertex.call_args[1]
        assert call_kwargs["project_id"] == "my-gcp-project"
        assert call_kwargs["region"] == "us-east5"


def test_anthropic_vertex_provider_requires_package() -> None:
    from promptgate.providers.anthropic_vertex import AnthropicVertexProvider

    with patch.dict("sys.modules", {"anthropic": None}):
        provider = AnthropicVertexProvider(model="m")
        with pytest.raises(DetectorError, match="anthropic"):
            provider.complete("sys", "user")


def test_anthropic_vertex_provider_optional_kwargs_omitted() -> None:
    """project_id / region を省略した場合、kwargs に含まれないことを確認。"""
    from promptgate.providers.anthropic_vertex import AnthropicVertexProvider

    mock_anthropic = MagicMock()
    mock_anthropic.AnthropicVertex.return_value = MagicMock()

    provider = AnthropicVertexProvider(model="m")  # project_id / region なし
    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        provider._sync_client = None
        provider._get_sync_client()
        call_kwargs = mock_anthropic.AnthropicVertex.call_args[1]
        assert "project_id" not in call_kwargs
        assert "region" not in call_kwargs


# ---------------------------------------------------------------------------
# プロバイダー経由の end-to-end: LLMJudgeDetector + OpenAIProvider
# ---------------------------------------------------------------------------

def test_llm_judge_with_openai_provider() -> None:
    from promptgate.detectors.llm_judge import LLMJudgeDetector

    provider = OpenAIProvider(api_key="test-key", model="gpt-4o-mini")

    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(
        {"is_attack": True, "threats": ["jailbreak"], "risk_score": 0.9, "reason": "test"}
    )
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response
    provider._sync_client = mock_client

    detector = LLMJudgeDetector(provider=provider)
    result = detector.scan("DAN mode")
    assert result.is_safe is False
    assert "jailbreak" in result.threats
