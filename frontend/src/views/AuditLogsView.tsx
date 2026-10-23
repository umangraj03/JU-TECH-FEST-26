import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { ScrollText, Search, Filter, ShieldCheck, AlertTriangle, CheckCircle2, XCircle, Hash, ChevronLeft, ChevronRight } from 'lucide-react';
import { api } from '../api/client';
import { AuditLogListResponse, AuditVerifyResponse } from '../types';

export const AuditLogsView: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterDecision, setFilterDecision] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 15;

  // Audit Logs query
  const { data, isLoading, refetch } = useQuery<AuditLogListResponse>({
    queryKey: ['auditLogs', searchTerm, filterDecision, filterSeverity, page],
    queryFn: () =>
      api.getAuditLogs({
        q: searchTerm || undefined,
        decision: filterDecision || undefined,
        severity: filterSeverity || undefined,
        page,
        pageSize
      }),
    refetchInterval: 5000
  });

  // Verify Audit Chain Mutation
  const verifyMutation = useMutation<AuditVerifyResponse>({
    mutationFn: () => api.verifyAuditChain(),
  });

  const handleVerify = () => {
    verifyMutation.mutate();
  };

  const logs = data?.items || [];
  const totalPages = data?.total_pages || 1;

  return (
    <div className="space-y-6">
      {/* View Header & Integrity Verification Banner */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between p-4 rounded-xl bg-[#111827]/90 border border-gray-800 gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <ScrollText className="w-5 h-5 text-blue-400" />
            <span>Tamper-Evident Cryptographic Audit Ledger</span>
          </h2>
          <p className="text-xs text-gray-400">
            Immutable SHA-256 hash-chained log of all security evaluations, approvals, and tool executions.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {verifyMutation.data && (
            <div
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold border ${
                verifyMutation.data.verified
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-red-500/10 text-red-400 border-red-500/30'
              }`}
            >
              {verifyMutation.data.verified ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <XCircle className="w-4 h-4 text-red-400" />
              )}
              <span>
                {verifyMutation.data.verified
                  ? `Verified Chain (${verifyMutation.data.total_records} records)`
                  : 'Tamper Detected!'}
              </span>
            </div>
          )}

          <button
            onClick={handleVerify}
            disabled={verifyMutation.isPending}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md transition disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{verifyMutation.isPending ? 'Verifying Hashes...' : 'Verify Ledger Integrity'}</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-lg bg-[#111827] border border-gray-800 text-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setPage(1);
            }}
            placeholder="Search audit logs by explanation, request ID, principal, or rule ID..."
            className="w-full pl-9 pr-4 py-2 bg-[#0B0F19] border border-gray-700/80 rounded-lg text-xs text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-2">
          {/* Decision select */}
          <select
            value={filterDecision}
            onChange={(e) => {
              setFilterDecision(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-[#0B0F19] border border-gray-700/80 rounded-lg text-xs text-gray-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
          </select>

          {/* Severity select */}
          <select
            value={filterSeverity}
            onChange={(e) => {
              setFilterSeverity(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-[#0B0F19] border border-gray-700/80 rounded-lg text-xs text-gray-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
        </div>
      </div>

      {/* Ledger Table */}
      <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800 overflow-hidden space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 uppercase text-[10px] tracking-wider">
                <th className="pb-3 px-2">Timestamp</th>
                <th className="pb-3 px-2">Principal</th>
                <th className="pb-3 px-2">Tool / Action</th>
                <th className="pb-3 px-2">Decision</th>
                <th className="pb-3 px-2">Rule ID</th>
                <th className="pb-3 px-2">Risk</th>
                <th className="pb-3 px-2">Explanation (Sanitized)</th>
                <th className="pb-3 px-2">Chain Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 font-mono text-[11px]">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-gray-500 font-sans">
                    Loading ledger records...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-gray-500 font-sans">
                    No audit records match criteria.
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const isBlock = log.decision === 'BLOCK';
                  const isAppr = log.decision === 'REQUIRE_APPROVAL';
                  return (
                    <tr key={log.id} className="hover:bg-gray-800/30 transition">
                      <td className="py-3 px-2 text-gray-400 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-3 px-2 text-gray-300">
                        {log.principal_id} ({log.principal_role})
                      </td>
                      <td className="py-3 px-2 font-bold text-gray-200">{log.tool_name || 'INSPECTION'}</td>
                      <td className="py-3 px-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isBlock
                              ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                              : isAppr
                              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          }`}
                        >
                          {log.decision}
                        </span>
                      </td>
                      <td className="py-3 px-2 text-blue-400 font-bold">{log.policy_rule_id}</td>
                      <td className="py-3 px-2">
                        <span
                          className={`font-semibold ${
                            log.threat_classification === 'CRITICAL'
                              ? 'text-red-400'
                              : log.threat_classification === 'HIGH'
                              ? 'text-orange-400'
                              : log.threat_classification === 'MEDIUM'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {log.threat_classification} ({log.risk_score})
                        </span>
                      </td>
                      <td className="py-3 px-2 text-gray-300 font-sans max-w-sm truncate" title={log.explanation}>
                        {log.explanation}
                      </td>
                      <td className="py-3 px-2 text-gray-500 text-[10px] truncate max-w-[120px]" title={log.current_hash}>
                        {log.current_hash.substring(0, 12)}...
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between pt-3 border-t border-gray-800 text-xs text-gray-400">
          <div>
            Showing page <span className="font-bold text-white">{page}</span> of{' '}
            <span className="font-bold text-white">{totalPages}</span> ({data?.total || 0} total events)
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg border border-gray-700 bg-gray-800/40 text-gray-300 hover:text-white disabled:opacity-30"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg border border-gray-700 bg-gray-800/40 text-gray-300 hover:text-white disabled:opacity-30"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
