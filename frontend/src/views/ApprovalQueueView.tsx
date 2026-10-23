import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Clock, CheckCircle2, XCircle, ShieldCheck, AlertCircle, Hash, UserCheck } from 'lucide-react';
import { api, getStoredRole } from '../api/client';
import { ApprovalItem } from '../types';

export const ApprovalQueueView: React.FC = () => {
  const queryClient = useQueryClient();
  const [filterStatus, setFilterStatus] = useState<string>('PENDING');
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const currentRole = getStoredRole();

  const { data: approvals = [], isLoading, error } = useQuery<ApprovalItem[]>({
    queryKey: ['approvals', filterStatus],
    queryFn: () => api.getApprovals(filterStatus === 'ALL' ? undefined : filterStatus),
    refetchInterval: 3000
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => api.approveTicket(id),
    onSuccess: (data) => {
      setActionFeedback(`Approved successfully! Result: ${data.message}`);
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      queryClient.invalidateQueries({ queryKey: ['overviewStats'] });
    },
    onError: (err: any) => {
      setActionFeedback(`Approval rejected by gateway: ${err.message}`);
    }
  });

  const rejectMutation = useMutation({
    mutationFn: (id: string) => api.rejectTicket(id),
    onSuccess: (data) => {
      setActionFeedback(`Ticket rejected successfully.`);
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      queryClient.invalidateQueries({ queryKey: ['overviewStats'] });
    },
    onError: (err: any) => {
      setActionFeedback(`Failed to reject ticket: ${err.message}`);
    }
  });

  const isApprover = currentRole === 'approver' || currentRole === 'admin';

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <Clock className="w-5 h-5 text-amber-400" />
            <span>Human Approval Workflow Queue</span>
          </h2>
          <p className="text-xs text-gray-400">
            Cryptographically bound authorization for sensitive state modifications and confidential exports.
          </p>
        </div>

        {/* Role permission alert */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#111827] border border-gray-700 text-xs">
          <UserCheck className="w-4 h-4 text-blue-400" />
          <span className="text-gray-400">Acting Role:</span>
          <span className="font-bold text-white capitalize">{currentRole}</span>
          {!isApprover && (
            <span className="text-amber-400 text-[11px] ml-1">(Switch to Approver role in header to authorize)</span>
          )}
        </div>
      </div>

      {/* Action feedback banner */}
      {actionFeedback && (
        <div className="p-3 rounded-lg bg-blue-950/40 border border-blue-800/60 text-xs text-blue-200 flex items-center justify-between animate-in fade-in">
          <span>{actionFeedback}</span>
          <button onClick={() => setActionFeedback(null)} className="text-blue-400 hover:text-white font-bold ml-3">
            &times;
          </button>
        </div>
      )}

      {/* Status Filter Tabs */}
      <div className="flex items-center space-x-2 border-b border-gray-800 pb-3">
        {['PENDING', 'APPROVED', 'REJECTED', 'ALL'].map((st) => (
          <button
            key={st}
            onClick={() => setFilterStatus(st)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filterStatus === st
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/40'
            }`}
          >
            {st}
          </button>
        ))}
      </div>

      {/* Approvals List */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="py-12 text-center text-xs text-gray-500">Loading approval queue...</div>
        ) : approvals.length === 0 ? (
          <div className="py-12 text-center text-xs text-gray-500 bg-[#111827] rounded-xl border border-gray-800">
            No {filterStatus.toLowerCase()} approval requests found.
          </div>
        ) : (
          approvals.map((appr) => {
            const isPending = appr.status === 'PENDING';
            return (
              <div
                key={appr.id}
                className="p-5 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-4 hover:border-gray-700 transition"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center space-x-3">
                    <span
                      className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${
                        appr.status === 'APPROVED'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : appr.status === 'PENDING'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse'
                          : 'bg-red-500/10 text-red-400 border border-red-500/20'
                      }`}
                    >
                      {appr.status}
                    </span>
                    <h3 className="font-mono text-sm font-bold text-gray-200">{appr.tool_name}</h3>
                    <span className="text-xs text-gray-400 font-mono">[{appr.policy_rule_id}]</span>
                  </div>

                  <div className="text-xs text-gray-400 font-mono flex items-center space-x-3">
                    <span>Ticket: {appr.id}</span>
                    <span>•</span>
                    <span>Expires: {new Date(appr.expires_at).toLocaleTimeString()}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-[#0B0F19] rounded-lg border border-gray-800 space-y-1">
                    <div className="text-gray-500 text-[10px] uppercase font-semibold">Risk Reason & Escalation</div>
                    <div className="text-gray-200 leading-relaxed">{appr.risk_reason}</div>
                    <div className="text-[11px] text-gray-400 mt-1">
                      Requester: <span className="font-mono text-gray-300">{appr.requester_id}</span> ({appr.requester_role})
                    </div>
                  </div>

                  <div className="p-3 bg-[#0B0F19] rounded-lg border border-gray-800 space-y-1 font-mono text-[11px]">
                    <div className="text-gray-500 text-[10px] uppercase font-semibold font-sans">
                      Cryptographic Payload Hash (SHA-256)
                    </div>
                    <div className="text-blue-400 truncate flex items-center space-x-1">
                      <Hash className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">{appr.payload_sha256}</span>
                    </div>
                    <div className="text-gray-400">
                      Destination: <span className="text-gray-200">{appr.destination || 'Internal State'}</span>
                    </div>
                  </div>
                </div>

                {/* Proposed Arguments Preview */}
                <div className="p-3 bg-black/40 rounded-lg border border-gray-800/80 font-mono text-xs text-gray-300">
                  <span className="text-[10px] text-gray-500 font-sans uppercase block mb-1">
                    Canonical Proposed Arguments:
                  </span>
                  <pre className="text-[11px] overflow-x-auto">{JSON.stringify(appr.arguments, null, 2)}</pre>
                </div>

                {/* Approver Actions */}
                {isPending && (
                  <div className="pt-2 border-t border-gray-800 flex items-center justify-end space-x-3">
                    <button
                      onClick={() => rejectMutation.mutate(appr.id)}
                      disabled={!isApprover || rejectMutation.isPending}
                      className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-red-600/10 hover:bg-red-600/20 text-red-400 border border-red-500/30 transition disabled:opacity-40"
                    >
                      Reject Action
                    </button>
                    <button
                      onClick={() => approveMutation.mutate(appr.id)}
                      disabled={!isApprover || approveMutation.isPending}
                      className="flex items-center space-x-1.5 px-4 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-md transition disabled:opacity-40"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Authorize & Execute</span>
                    </button>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
