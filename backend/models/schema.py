from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class Principal(BaseModel):
    principal_id: str
    role: str
    name: str


class AgentRunRequest(BaseModel):
    message: str = Field(..., max_length=65536)
    scenario_id: Optional[str] = None
    session_id: Optional[str] = None


class SecurityFinding(BaseModel):
    rule_id: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str
    score: float


class ToolDecision(BaseModel):
    tool_name: str
    decision: str  # ALLOW, BLOCK, REQUIRE_APPROVAL
    policy_rule_id: str
    explanation: str
    tainted: bool = False
    approval_id: Optional[str] = None
    executed: bool = False
    result: Optional[Any] = None


class AgentRunResponse(BaseModel):
    request_id: str
    session_id: str
    overall_decision: str  # ALLOW, BLOCK, REQUIRE_APPROVAL
    decisions: List[ToolDecision] = Field(default_factory=list)
    response: str
    findings: List[SecurityFinding] = Field(default_factory=list)
    risk_score: float
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL


class ApprovalItem(BaseModel):
    id: str
    request_id: str
    session_id: str
    requester_id: str
    requester_role: str
    tool_name: str
    arguments: Dict[str, Any]
    payload_sha256: str
    affected_data_classes: List[str]
    destination: Optional[str] = None
    risk_reason: str
    policy_rule_id: str
    status: str
    created_at: datetime
    expires_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


class ApprovalActionRequest(BaseModel):
    reason: Optional[str] = None


class AuditLogItem(BaseModel):
    id: int
    entry_id: str
    timestamp: datetime
    request_id: str
    session_id: str
    principal_id: str
    principal_role: str
    category: str
    threat_classification: str
    risk_score: float
    tool_name: Optional[str]
    policy_rule_id: str
    decision: str
    explanation: str
    redacted_payload: Dict[str, Any]
    prev_hash: str
    current_hash: str


class AuditLogListResponse(BaseModel):
    items: List[AuditLogItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditVerifyResponse(BaseModel):
    verified: bool
    total_records: int
    last_verified_entry_id: Optional[str] = None
    broken_entry_id: Optional[str] = None
    message: str


class OverviewStats(BaseModel):
    total_requests: int
    allowed_count: int
    blocked_count: int
    approval_count: int
    avg_risk_score: float
    critical_threats_count: int
    active_pending_approvals: int
    audit_chain_valid: bool
    recent_activity: List[Dict[str, Any]] = Field(default_factory=list)
    risk_distribution: Dict[str, int] = Field(default_factory=dict)
    tool_usage: Dict[str, int] = Field(default_factory=dict)


class ThreatItem(BaseModel):
    category: str
    count: int
    highest_severity: str
    examples: List[str] = Field(default_factory=list)


class ThreatStats(BaseModel):
    total_threats_detected: int
    breakdown_by_category: List[ThreatItem] = Field(default_factory=list)
    top_matched_rules: List[Dict[str, Any]] = Field(default_factory=list)


class ScenarioDefinition(BaseModel):
    id: str
    title: str
    description: str
    expected_decision: str
    target_role: str
    sample_prompt: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None
