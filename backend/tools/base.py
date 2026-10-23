import secrets
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from pydantic import BaseModel


class DirectToolInvocationForbidden(Exception):
    """Raised when an attempt is made to call a tool outside gateway.execute()."""
    pass


class GatewayExecutionContext:
    """Internal authorization context generated solely by gateway.execute()."""

    def __init__(self, execution_token: str, request_id: str, principal_role: str):
        self._token = execution_token
        self.request_id = request_id
        self.principal_role = principal_role
        self.is_authorized = True

    def verify_token(self, expected_token: str) -> bool:
        return secrets.compare_digest(self._token, expected_token)


class BaseTool(ABC):
    name: str
    description: str
    is_write: bool = False
    requires_approval: bool = False

    def __init__(self):
        self._gateway_secret: Optional[str] = None

    def _bind_gateway_secret(self, secret: str):
        self._gateway_secret = secret

    def execute(self, args: Dict[str, Any], context: Optional[GatewayExecutionContext] = None, db_session: Any = None) -> Dict[str, Any]:
        """
        Hard Invariant:
        Tools are executable ONLY through gateway.execute().
        Any call without an authorized GatewayExecutionContext with the correct secret raises DirectToolInvocationForbidden.
        """
        if context is None or not isinstance(context, GatewayExecutionContext):
            raise DirectToolInvocationForbidden(
                f"Direct tool invocation forbidden: tool '{self.name}' may only be executed via gateway.execute()."
            )
        if not self._gateway_secret or not context.verify_token(self._gateway_secret):
            raise DirectToolInvocationForbidden(
                f"Invalid execution token: tool '{self.name}' cannot be invoked directly."
            )

        return self._run(args, context, db_session)

    @abstractmethod
    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Any) -> Dict[str, Any]:
        pass
