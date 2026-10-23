import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { ShieldCheck, Code, Globe, Lock, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { api, getStoredRole } from '../api/client';

export const PolicyCenterView: React.FC = () => {
  const [tab, setTab] = useState<'structured' | 'yaml'>('structured');
  const [yamlEdit, setYamlEdit] = useState('');
  const [saveFeedback, setSaveFeedback] = useState<string | null>(null);

  const currentRole = getStoredRole();
  const isAdmin = currentRole === 'admin';

  const { data: policyData, isLoading, refetch } = useQuery({
    queryKey: ['policy'],
    queryFn: async () => {
      const data = await api.getPolicy();
      setYamlEdit(data.raw_yaml);
      return data;
    }
  });

  const updatePolicyMutation = useMutation({
    mutationFn: (content: string) => api.updatePolicy(content),
    onSuccess: (res) => {
      setSaveFeedback('Policy updated and validated successfully!');
      refetch();
    },
    onError: (err: any) => {
      setSaveFeedback(`Update failed: ${err.message}`);
    }
  });

  const parsed = policyData?.parsed;

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            <span>Policy Engine & Access Control Center</span>
          </h2>
          <p className="text-xs text-gray-400">
            Version-controlled policy configuration (policies/default.yaml) defining tools, roles, and mandatory security rules.
          </p>
        </div>

        <div className="flex items-center space-x-2 bg-[#111827] p-1 rounded-lg border border-gray-800 text-xs">
          <button
            onClick={() => setTab('structured')}
            className={`px-3 py-1 rounded font-medium transition ${
              tab === 'structured' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
            }`}
          >
            Structured View
          </button>
          <button
            onClick={() => setTab('yaml')}
            className={`px-3 py-1 rounded font-medium transition ${
              tab === 'yaml' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
            }`}
          >
            Raw YAML {isAdmin && '(Admin Edit)'}
          </button>
        </div>
      </div>

      {saveFeedback && (
        <div className="p-3 rounded-lg bg-blue-950/40 border border-blue-800/60 text-xs text-blue-200 flex items-center justify-between">
          <span>{saveFeedback}</span>
          <button onClick={() => setSaveFeedback(null)} className="font-bold text-blue-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="py-12 text-center text-xs text-gray-500">Loading policy engine specifications...</div>
      ) : tab === 'structured' && parsed ? (
        <div className="space-y-6">
          {/* Roles & Permissions */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Role-Based Access Control (RBAC)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {Object.entries(parsed.roles || {}).map(([roleName, r]: [string, any]) => (
                <div key={roleName} className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-blue-400 capitalize">{roleName}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-300 font-mono">
                      Role
                    </span>
                  </div>
                  <p className="text-xs text-gray-400">{r.description}</p>
                  <div className="pt-2 border-t border-gray-800 space-y-1.5 text-xs">
                    <div>
                      <span className="text-gray-500 text-[10px] uppercase font-semibold block">Allowed Tools:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {r.allowed_tools?.map((t: string) => (
                          <span key={t} className="px-1.5 py-0.5 rounded bg-gray-800 text-[10px] font-mono text-gray-300">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <span className="text-gray-500 text-[10px] uppercase font-semibold block">Record Classes:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {r.accessible_record_classes?.map((c: string) => (
                          <span key={c} className="px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-800/40 text-[10px] font-mono text-blue-300">
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Approved Destinations */}
          <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-2">
            <h3 className="text-xs font-semibold text-gray-300 flex items-center space-x-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              <span>Approved Destination Allowlist (Exact Registrable Domains)</span>
            </h3>
            <p className="text-xs text-gray-400">
              Only outbound communications matching these exact domains are permitted. Lookalikes (e.g. .evil.test), userinfo tricks, and query leaks are rejected.
            </p>
            <div className="flex flex-wrap gap-2 pt-2">
              {parsed.approved_destinations?.map((d: string) => (
                <span key={d} className="px-3 py-1 rounded-lg bg-[#0B0F19] border border-emerald-500/30 text-emerald-400 text-xs font-mono font-semibold">
                  {d}
                </span>
              ))}
            </div>
          </div>

          {/* Active Security Rules */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Enforcement Rules & Precedence Hierarchy
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {parsed.rules?.map((rule: any) => {
                const isMandatory = rule.action === 'MANDATORY_DENY';
                const isAppr = rule.action === 'REQUIRE_APPROVAL';
                return (
                  <div key={rule.rule_id} className="p-3.5 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-gray-200">{rule.rule_id}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isMandatory
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : isAppr
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}
                      >
                        {rule.action}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-gray-300">{rule.name}</div>
                    <p className="text-[11px] text-gray-400">{rule.description}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        /* Raw YAML Tab */
        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-gray-400">policies/default.yaml</span>
            {isAdmin && (
              <button
                onClick={() => updatePolicyMutation.mutate(yamlEdit)}
                disabled={updatePolicyMutation.isPending}
                className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold transition"
              >
                {updatePolicyMutation.isPending ? 'Validating...' : 'Save Policy Changes'}
              </button>
            )}
          </div>
          <textarea
            rows={22}
            value={yamlEdit}
            onChange={(e) => setYamlEdit(e.target.value)}
            disabled={!isAdmin}
            className="w-full p-4 bg-[#0B0F19] border border-gray-800 rounded-lg font-mono text-xs text-gray-200 focus:outline-none focus:border-blue-500 leading-relaxed disabled:opacity-80 resize-y"
          />
        </div>
      )}
    </div>
  );
};
