import {
  Role,
  AgentRunResponse,
  OverviewStats,
  ThreatStats,
  ApprovalItem,
  AuditLogListResponse,
  AuditVerifyResponse,
  ScenarioDefinition
} from '../types';

let currentRole: Role = (localStorage.getItem('user_role') as Role) || 'requester';

export const setStoredRole = (role: Role) => {
  currentRole = role;
  localStorage.setItem('user_role', role);
};

export const getStoredRole = (): Role => currentRole;

const ROLE_TOKENS: Record<Role, string> = {
  requester: 'token-requester-secret-key-101',
  approver: 'token-approver-secret-key-202',
  admin: 'token-admin-secret-key-303'
};

const getHeaders = (extra: Record<string, string> = {}) => {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${ROLE_TOKENS[currentRole]}`,
    'X-Demo-Role': currentRole,
    ...extra
  };
};

export const api = {
  // Agent & Execution
  async runAgent(message: string, scenarioId?: string): Promise<AgentRunResponse> {
    const res = await fetch('/api/agent/run', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ message, scenario_id: scenarioId })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to execute agent workflow');
    }
    return res.json();
  },

  // Stats & Events
  async getOverviewStats(): Promise<OverviewStats> {
    const res = await fetch('/api/stats/overview', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load overview metrics');
    return res.json();
  },

  async getLiveEvents(limit: number = 20, sinceId?: number): Promise<{ events: any[]; count: number }> {
    const url = sinceId !== undefined ? `/api/events?limit=${limit}&since_id=${sinceId}` : `/api/events?limit=${limit}`;
    const res = await fetch(url, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load events');
    return res.json();
  },

  async getThreatStats(): Promise<ThreatStats> {
    const res = await fetch('/api/threats', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load threat analysis');
    return res.json();
  },

  // Policy
  async getPolicy(): Promise<{ version: string; metadata: any; parsed: any; raw_yaml: string }> {
    const res = await fetch('/api/policy', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load policy');
    return res.json();
  },

  async updatePolicy(yamlContent: string): Promise<any> {
    const res = await fetch('/api/policy', {
      method: 'PUT',
      headers: getHeaders({ 'Content-Type': 'text/plain' }),
      body: yamlContent
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to update policy');
    }
    return res.json();
  },

  // Approvals
  async getApprovals(status?: string): Promise<ApprovalItem[]> {
    const url = status ? `/api/approvals?status=${status}` : '/api/approvals';
    const res = await fetch(url, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load approvals');
    return res.json();
  },

  async approveTicket(id: string, reason?: string): Promise<any> {
    const res = await fetch(`/api/approvals/${id}/approve`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to approve action');
    }
    return res.json();
  },

  async rejectTicket(id: string, reason?: string): Promise<any> {
    const res = await fetch(`/api/approvals/${id}/reject`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to reject action');
    }
    return res.json();
  },

  // Audit Logs
  async getAuditLogs(params: {
    decision?: string;
    severity?: string;
    tool?: string;
    q?: string;
    page?: number;
    pageSize?: number;
  }): Promise<AuditLogListResponse> {
    const query = new URLSearchParams();
    if (params.decision) query.append('decision', params.decision);
    if (params.severity) query.append('severity', params.severity);
    if (params.tool) query.append('tool', params.tool);
    if (params.q) query.append('q', params.q);
    if (params.page) query.append('page', String(params.page));
    if (params.pageSize) query.append('page_size', String(params.pageSize));

    const res = await fetch(`/api/audit?${query.toString()}`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load audit logs');
    return res.json();
  },

  async verifyAuditChain(): Promise<AuditVerifyResponse> {
    const res = await fetch('/api/audit/verify', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to verify audit ledger');
    return res.json();
  },

  // Scenarios
  async getScenarios(): Promise<ScenarioDefinition[]> {
    const res = await fetch('/api/scenarios', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load scenarios');
    return res.json();
  },

  async runScenario(id: string): Promise<any> {
    const res = await fetch(`/api/scenarios/${id}/run`, {
      method: 'POST',
      headers: getHeaders()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to execute scenario');
    }
    return res.json();
  },

  // Demo
  async resetDemo(): Promise<any> {
    const res = await fetch('/api/demo/reset', {
      method: 'POST',
      headers: getHeaders()
    });
    if (!res.ok) throw new Error('Failed to reset demo state');
    return res.json();
  }
};
