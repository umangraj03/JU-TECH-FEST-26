import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  Layers,
  ArrowUpRight
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, PieChart, Pie } from 'recharts';
import { api } from '../api/client';
import { OverviewStats } from '../types';

interface OverviewViewProps {
  onNavigate: (tab: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const { data: stats, isLoading, error, refetch } = useQuery<OverviewStats>({
    queryKey: ['overviewStats'],
    queryFn: () => api.getOverviewStats(),
    refetchInterval: 3000
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-sm text-gray-400">Loading security gateway metrics...</p>
        </div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="p-8 bg-red-950/20 border border-red-800/40 rounded-xl text-center space-y-3">
        <ShieldAlert className="w-8 h-8 text-red-400 mx-auto" />
        <h3 className="font-semibold text-red-200">Failed to load metrics</h3>
        <p className="text-xs text-red-300">{(error as any)?.message || 'Service unavailable'}</p>
        <button
          onClick={() => refetch()}
          className="px-4 py-1.5 bg-red-600/30 hover:bg-red-600/50 text-red-200 rounded-lg text-xs"
        >
          Retry
        </button>
      </div>
    );
  }

  // Risk distribution data for chart
  const riskChartData = [
    { name: 'Low', count: stats.risk_distribution['LOW'] || 0, color: '#10B981' },
    { name: 'Medium', count: stats.risk_distribution['MEDIUM'] || 0, color: '#F59E0B' },
    { name: 'High', count: stats.risk_distribution['HIGH'] || 0, color: '#F97316' },
    { name: 'Critical', count: stats.risk_distribution['CRITICAL'] || 0, color: '#EF4444' },
  ];

  // Tool usage data for chart
  const toolChartData = Object.entries(stats.tool_usage).map(([name, count]) => ({
    name: name.replace('_', ' '),
    count
  }));

  return (
    <div className="space-y-6">
      {/* Top Banner / Chain Status */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl bg-gradient-to-r from-blue-950/30 to-indigo-950/20 border border-blue-800/30">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <span>Security Gateway Operations Dashboard</span>
          </h2>
          <p className="text-xs text-gray-400">Live monitoring of AI agent tool execution and data egress</p>
        </div>
        <div className="mt-3 sm:mt-0 flex items-center space-x-3">
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#111827] border border-gray-700/60 text-xs">
            <span className="text-gray-400">Hash Ledger:</span>
            {stats.audit_chain_valid ? (
              <span className="flex items-center space-x-1 text-emerald-400 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Cryptographically Intact</span>
              </span>
            ) : (
              <span className="flex items-center space-x-1 text-red-400 font-bold">
                <XCircle className="w-3.5 h-3.5" />
                <span>Tamper Detected</span>
              </span>
            )}
          </div>
          <button
            onClick={() => onNavigate('playground')}
            className="flex items-center space-x-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md transition"
          >
            <span>Launch Playground</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Inspected */}
        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="flex items-center justify-between text-gray-400 text-xs font-medium mb-2">
            <span>Total Inspected Calls</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.total_requests}</div>
          <div className="flex items-center space-x-2 mt-2 text-[11px] text-gray-400">
            <span className="text-emerald-400">{stats.allowed_count} Allowed</span>
            <span>•</span>
            <span className="text-red-400">{stats.blocked_count} Blocked</span>
          </div>
        </div>

        {/* Blocked Threats */}
        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="flex items-center justify-between text-gray-400 text-xs font-medium mb-2">
            <span>Critical Neutralized</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400">{stats.critical_threats_count}</div>
          <div className="text-[11px] text-gray-400 mt-2">
            Zero payload reached unauthorized execution
          </div>
        </div>

        {/* Avg Risk Score */}
        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="flex items-center justify-between text-gray-400 text-xs font-medium mb-2">
            <span>Average Risk Score</span>
            <Layers className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.avg_risk_score} <span className="text-xs text-gray-500 font-normal">/ 100</span></div>
          <div className="w-full bg-gray-800 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className={`h-full ${
                stats.avg_risk_score > 50 ? 'bg-red-500' : stats.avg_risk_score > 25 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, stats.avg_risk_score)}%` }}
            ></div>
          </div>
        </div>

        {/* Pending Approvals */}
        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="flex items-center justify-between text-gray-400 text-xs font-medium mb-2">
            <span>Pending Approvals</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{stats.active_pending_approvals}</div>
          <div className="flex items-center justify-between mt-2 text-[11px]">
            <span className="text-gray-400">Escalated sensitive actions</span>
            {stats.active_pending_approvals > 0 && (
              <button
                onClick={() => onNavigate('approvals')}
                className="text-amber-400 hover:underline font-medium"
              >
                Review &rarr;
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Level Distribution */}
        <div className="p-5 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">Threat Severity Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskChartData}>
                <XAxis dataKey="name" stroke="#6B7280" fontSize={11} />
                <YAxis stroke="#6B7280" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#F3F4F6' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Tool Invocations */}
        <div className="p-5 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">Tool Invocations by Name</h3>
          <div className="h-48">
            {toolChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={toolChartData} layout="vertical">
                  <XAxis type="number" stroke="#6B7280" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#6B7280" fontSize={10} width={120} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-gray-500">
                No tool executions recorded yet. Run a scenario in Demo Playground.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Activity Ledger Excerpt */}
      <div className="p-5 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-200">Recent Gateway Audit Entries</h3>
          <button
            onClick={() => onNavigate('audit')}
            className="text-xs text-blue-400 hover:text-blue-300 font-medium"
          >
            View Full Ledger &rarr;
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 uppercase text-[10px]">
                <th className="pb-2">Timestamp</th>
                <th className="pb-2">Tool / Target</th>
                <th className="pb-2">Decision</th>
                <th className="pb-2">Severity</th>
                <th className="pb-2">Score</th>
                <th className="pb-2">Policy Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {stats.recent_activity.length > 0 ? (
                stats.recent_activity.map((act) => (
                  <tr key={act.id} className="hover:bg-gray-800/20">
                    <td className="py-2.5 text-gray-400 font-mono text-[11px]">
                      {new Date(act.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 font-mono text-gray-200">{act.tool}</td>
                    <td className="py-2.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          act.decision === 'ALLOW'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : act.decision === 'REQUIRE_APPROVAL'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-red-500/10 text-red-400 border border-red-500/20'
                        }`}
                      >
                        {act.decision}
                      </span>
                    </td>
                    <td className="py-2.5">
                      <span
                        className={`text-[11px] font-medium ${
                          act.threat === 'CRITICAL'
                            ? 'text-red-400'
                            : act.threat === 'HIGH'
                            ? 'text-orange-400'
                            : act.threat === 'MEDIUM'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {act.threat}
                      </span>
                    </td>
                    <td className="py-2.5 font-mono text-gray-300">{act.score}</td>
                    <td className="py-2.5 text-gray-300 max-w-xs truncate">{act.explanation}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-gray-500">
                    No recent events logged yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
