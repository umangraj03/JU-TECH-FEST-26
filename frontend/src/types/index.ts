export type Role = 'requester' | 'approver' | 'admin';

export interface Principal {
  principal_id: string;
  role: Role;
  name: string;
}

export interface SecurityFinding {
  rule_id: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: string;
  score: number;
}

export interface ToolDecision {
  tool_name: string;
  decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  policy_rule_id: string;
  explanation: string;
  tainted: boolean;
  approval_id?: string | null;
  executed: boolean;
  result?: any;
}

export interface AgentRunResponse {
  request_id: string;
  session_id: string;
  overall_decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  decisions: ToolDecision[];
  response: string;
  findings: SecurityFinding[];
  risk_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface ApprovalItem {
  id: string;
  request_id: string;
  session_id: string;
  requester_id: string;
  requester_role: string;
  tool_name: string;
  arguments: Record<string, any>;
  payload_sha256: string;
  affected_data_classes: string[];
  destination?: string | null;
  risk_reason: string;
  policy_rule_id: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  created_at: string;
  expires_at: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
}

export interface AuditLogItem {
  id: number;
  entry_id: string;
  timestamp: string;
  request_id: string;
  session_id: string;
  principal_id: string;
  principal_role: string;
  category: string;
  threat_classification: string;
  risk_score: number;
  tool_name?: string | null;
  policy_rule_id: string;
  decision: string;
  explanation: string;
  redacted_payload: Record<string, any>;
  prev_hash: string;
  current_hash: string;
}

export interface AuditLogListResponse {
  items: AuditLogItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface AuditVerifyResponse {
  verified: boolean;
  total_records: number;
  last_verified_entry_id?: string | null;
  broken_entry_id?: string | null;
  message: string;
}

export interface OverviewStats {
  total_requests: number;
  allowed_count: number;
  blocked_count: number;
  approval_count: number;
  avg_risk_score: number;
  critical_threats_count: number;
  active_pending_approvals: number;
  audit_chain_valid: boolean;
  recent_activity: Array<{
    id: number;
    entry_id: string;
    timestamp: string;
    tool: string;
    decision: string;
    threat: string;
    score: number;
    explanation: string;
  }>;
  risk_distribution: Record<string, number>;
  tool_usage: Record<string, number>;
}

export interface ThreatItem {
  category: string;
  count: number;
  highest_severity: string;
  examples: string[];
}

export interface ThreatStats {
  total_threats_detected: number;
  breakdown_by_category: ThreatItem[];
  top_matched_rules: Array<{ rule_id: string; count: number }>;
}

export interface ScenarioDefinition {
  id: string;
  title: string;
  description: string;
  expected_decision: string;
  target_role: string;
  sample_prompt: string;
}
