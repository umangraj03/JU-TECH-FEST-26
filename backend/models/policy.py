from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field


class RolePolicy(BaseModel):
    description: str = ""
    allowed_tools: List[str] = Field(default_factory=list)
    accessible_record_classes: List[str] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    description: str = ""
    is_write: bool = False
    requires_approval: bool = False
    allowed_classes: List[str] = Field(default_factory=list)
    field_allowlist: List[str] = Field(default_factory=list)


class RuleDefinition(BaseModel):
    rule_id: str
    name: str
    action: Literal["ALLOW", "DENY", "BLOCK", "REQUIRE_APPROVAL", "MANDATORY_DENY"]
    description: str = ""


class LimitsDefinition(BaseModel):
    max_tool_calls_per_request: int = 5
    max_retrieval_depth: int = 2
    session_egress_budget_bytes: int = 5000
    approval_validity_seconds: int = 900


class PolicySchema(BaseModel):
    version: str = "1.0.0"
    metadata: Dict[str, object] = Field(default_factory=dict)
    roles: Dict[str, RolePolicy] = Field(default_factory=dict)
    tools: Dict[str, ToolDefinition] = Field(default_factory=dict)
    approved_destinations: List[str] = Field(default_factory=list)
    limits: LimitsDefinition = Field(default_factory=LimitsDefinition)
    rules: List[RuleDefinition] = Field(default_factory=list)
