import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from backend.models.schema import Principal


class BaseLLMAdapter(ABC):
    """
    Abstract interface for LLM integrations.
    Allows swappable models between deterministic mock and external LLM providers.
    """

    @abstractmethod
    def plan_tool_calls(
        self,
        principal: Principal,
        user_message: str,
        retrieved_docs: List[Dict[str, Any]],
        available_tools: List[str]
    ) -> Tuple[List[Dict[str, Any]], str, bool]:
        """
        Returns (proposed_calls, reply_message, was_tainted).
        """
        pass


class MockLLMAdapter(BaseLLMAdapter):
    """
    Default deterministic, offline adapter.
    Vulnerable by design to simulated prompt injections.
    """

    def plan_tool_calls(
        self,
        principal: Principal,
        user_message: str,
        retrieved_docs: List[Dict[str, Any]],
        available_tools: List[str]
    ) -> Tuple[List[Dict[str, Any]], str, bool]:
        # Delegates to deterministic parser
        from backend.agent.mock_agent import mock_agent
        # In mock agent, this logic is executed alongside retrieval
        return [], "", False


class ExternalLLMAdapter(BaseLLMAdapter):
    """
    Extensible adapter interface for real LLM providers (e.g. OpenAI, Anthropic, or Local Ollama).
    Disabled by default to ensure 100% offline deterministic test reproducibility.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini", base_url: Optional[str] = None):
        self.api_key = api_key or os.getenv("EXTERNAL_LLM_API_KEY", "")
        self.model = model
        self.base_url = base_url or os.getenv("EXTERNAL_LLM_BASE_URL", "https://api.openai.com/v1")
        self.enabled = os.getenv("ENABLE_EXTERNAL_LLM", "false").lower() in ("true", "1", "yes")

    def plan_tool_calls(
        self,
        principal: Principal,
        user_message: str,
        retrieved_docs: List[Dict[str, Any]],
        available_tools: List[str]
    ) -> Tuple[List[Dict[str, Any]], str, bool]:
        if not self.enabled or not self.api_key:
            # Fallback to offline mock adapter if external calls are not configured
            return MockLLMAdapter().plan_tool_calls(principal, user_message, retrieved_docs, available_tools)

        # In production mode: external HTTP call to LLM chat/completions endpoint
        # Formatted with strict system prompt & tool schemas
        # Note: All calls remain intercepted and validated by SecurityGateway server-side
        return [], "External LLM output would be processed here", False


def get_llm_adapter() -> BaseLLMAdapter:
    """Factory function for LLM adapter."""
    if os.getenv("ENABLE_EXTERNAL_LLM", "false").lower() in ("true", "1", "yes"):
        return ExternalLLMAdapter()
    return MockLLMAdapter()
