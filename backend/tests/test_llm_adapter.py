import os
import pytest
from backend.agent.llm_adapter import get_llm_adapter, MockLLMAdapter, ExternalLLMAdapter
from backend.models.schema import Principal


def test_default_llm_adapter_is_offline_mock():
    # By default, external LLM is off
    adapter = get_llm_adapter()
    assert isinstance(adapter, MockLLMAdapter)


def test_external_llm_adapter_flag(monkeypatch):
    monkeypatch.setenv("ENABLE_EXTERNAL_LLM", "true")
    adapter = get_llm_adapter()
    assert isinstance(adapter, ExternalLLMAdapter)
    assert adapter.enabled is True

    # Without an API key, it safely falls back to offline deterministic mode
    principal = Principal(principal_id="test", role="requester", name="Test")
    calls, reply, tainted = adapter.plan_tool_calls(principal, "test prompt", [], [])
    assert calls == []
