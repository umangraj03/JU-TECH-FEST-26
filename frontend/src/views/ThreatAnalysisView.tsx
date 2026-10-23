import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertOctagon, ShieldAlert, Bug, Target, FileWarning } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { api } from '../api/client';
import { ThreatStats } from '../types';

export const ThreatAnalysisView: React.FC = () => {
  const { data: threats, isLoading, error } = useQuery<ThreatStats>({
    queryKey: ['threatStats'],
    queryFn: () => api.getThreatStats(),
    refetchInterval: 5000
  });

  if (isLoading) {
    return <div className="py-12 text-center text-xs text-gray-500">Compiling threat intelligence...</div>;
  }

  if (error || !threats) {
    return (
      <div className="p-6 bg-red-950/20 border border-red-800/40 rounded-xl text-center text-xs text-red-300">
        Failed to load threat analysis.
      </div>
    );
  }

  const categoryChartData = threats.breakdown_by_category.map((c) => ({
    name: c.category.replace('_', ' '),
    count: c.count
  }));

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <AlertOctagon className="w-5 h-5 text-red-400" />
          <span>Threat Intelligence & Incident Analysis</span>
        </h2>
        <p className="text-xs text-gray-400">
          Aggregated breakdown of blocked prompt injections, delimiter attacks, obfuscated payloads, and data leakage vectors.
        </p>
      </div>

      {/* KPI Highlights */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="text-gray-400 text-xs font-medium mb-1">Total Threats Intercepted</div>
          <div className="text-2xl font-bold text-red-400">{threats.total_threats_detected}</div>
          <div className="text-[11px] text-gray-500 mt-1">High & Critical security events</div>
        </div>

        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="text-gray-400 text-xs font-medium mb-1">Attack Classes Identified</div>
          <div className="text-2xl font-bold text-white">{threats.breakdown_by_category.length}</div>
          <div className="text-[11px] text-gray-500 mt-1">Layered detection active</div>
        </div>

        <div className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800">
          <div className="text-gray-400 text-xs font-medium mb-1">Top Active Defensive Rule</div>
          <div className="text-base font-bold text-blue-400 font-mono mt-1">
            {threats.top_matched_rules[0]?.rule_id || 'RULE-MANDATORY-04'}
          </div>
          <div className="text-[11px] text-gray-500 mt-1">
            {threats.top_matched_rules[0]?.count || 0} hits
          </div>
        </div>
      </div>

      {/* Chart Section */}
      <div className="p-5 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-4">
        <h3 className="text-sm font-semibold text-gray-200">Threat Incursions by Attack Category</h3>
        <div className="h-56">
          {categoryChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryChartData}>
                <XAxis dataKey="name" stroke="#6B7280" fontSize={11} />
                <YAxis stroke="#6B7280" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', borderRadius: '8px' }} />
                <Bar dataKey="count" fill="#EF4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-xs text-gray-500">
              No threat detections recorded yet.
            </div>
          )}
        </div>
      </div>

      {/* Detailed Categories & Examples */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-gray-200">Category Explanations & Caught Evidence</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {threats.breakdown_by_category.map((cat, i) => (
            <div key={i} className="p-4 rounded-xl bg-[#111827]/80 border border-gray-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-gray-200">{cat.category}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
                  {cat.count} Events
                </span>
              </div>
              <div className="text-xs text-gray-400 space-y-1">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider block">Sample Evidence:</span>
                {cat.examples.map((ex, exIdx) => (
                  <p key={exIdx} className="p-2 rounded bg-black/40 font-mono text-[11px] text-gray-300 break-words">
                    {ex}
                  </p>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
