import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Pause, Play, Filter, Hash, Shield } from 'lucide-react';
import { api } from '../api/client';

export const LiveMonitorView: React.FC = () => {
  const [isPaused, setIsPaused] = useState(false);
  const [filterDecision, setFilterDecision] = useState('ALL');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['liveEvents'],
    queryFn: () => api.getLiveEvents(50),
    refetchInterval: isPaused ? false : 2000
  });

  const events = data?.events || [];

  const filteredEvents = events.filter((ev) => {
    if (filterDecision !== 'ALL' && ev.decision !== filterDecision) return false;
    if (filterSeverity !== 'ALL' && ev.threat !== filterSeverity) return false;
    return true;
  });

  return (
    <div className="space-y-5">
      {/* View Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            <span>Live Security Event Monitor</span>
          </h2>
          <p className="text-xs text-gray-400">
            Real-time stream of incoming prompts, gateway decisions, and data access requests (polled every 2s).
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
              isPaused
                ? 'bg-amber-500/20 text-amber-400 border-amber-500/40 hover:bg-amber-500/30'
                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5 fill-current" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-[#111827] border border-gray-800 text-xs">
        <div className="flex items-center space-x-2 text-gray-400">
          <Filter className="w-3.5 h-3.5" />
          <span>Filters:</span>
        </div>

        {/* Decision Filter */}
        <div className="flex items-center space-x-1">
          <span className="text-gray-500">Decision:</span>
          {['ALL', 'ALLOW', 'BLOCK', 'REQUIRE_APPROVAL'].map((d) => (
            <button
              key={d}
              onClick={() => setFilterDecision(d)}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition ${
                filterDecision === d ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {d}
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-gray-800"></div>

        {/* Severity Filter */}
        <div className="flex items-center space-x-1">
          <span className="text-gray-500">Severity:</span>
          {['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => (
            <button
              key={s}
              onClick={() => setFilterSeverity(s)}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition ${
                filterSeverity === s ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Events List */}
      <div className="space-y-2">
        {isLoading && events.length === 0 ? (
          <div className="py-12 text-center text-xs text-gray-500">Connecting to gateway event stream...</div>
        ) : filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-xs text-gray-500 bg-[#111827] rounded-xl border border-gray-800">
            No events match the selected filters.
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isExpanded = expandedId === ev.id;
            const isBlock = ev.decision === 'BLOCK';
            const isAppr = ev.decision === 'REQUIRE_APPROVAL';
            return (
              <div
                key={ev.id}
                className="p-3.5 rounded-xl bg-[#111827]/80 border border-gray-800 hover:border-gray-700 transition space-y-2"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        isBlock
                          ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                          : isAppr
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      }`}
                    >
                      {ev.decision}
                    </span>
                    <span className="text-xs font-mono font-bold text-gray-200">{ev.tool_name || 'INSPECTION'}</span>
                    <span className="text-[10px] font-mono text-gray-500">[{ev.policy_rule_id}]</span>
                    <span className="text-[11px] text-gray-400">by {ev.principal_role}</span>
                  </div>

                  <div className="flex items-center space-x-3 text-xs text-gray-400">
                    <span className="font-mono text-[11px]">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                    <span
                      className={`font-semibold text-[11px] ${
                        ev.threat === 'CRITICAL'
                          ? 'text-red-400'
                          : ev.threat === 'HIGH'
                          ? 'text-orange-400'
                          : ev.threat === 'MEDIUM'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {ev.threat} ({ev.risk_score})
                    </span>
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                      className="text-blue-400 hover:underline text-[11px]"
                    >
                      {isExpanded ? 'Hide' : 'Inspect'}
                    </button>
                  </div>
                </div>

                <p className="text-xs text-gray-300 font-mono leading-relaxed">{ev.explanation}</p>

                {/* Expanded Payload Inspector */}
                {isExpanded && (
                  <div className="pt-2 border-t border-gray-800/80 space-y-2 text-xs">
                    <div className="flex items-center justify-between text-[10px] text-gray-500 font-mono">
                      <span>Entry ID: {ev.entry_id}</span>
                      <span className="flex items-center space-x-1">
                        <Hash className="w-3 h-3 text-blue-400" />
                        <span className="truncate max-w-xs">{ev.current_hash}</span>
                      </span>
                    </div>
                    <div className="p-3 bg-black/60 rounded-lg border border-gray-800 font-mono text-[11px] text-gray-300 overflow-x-auto max-h-48">
                      <pre>{JSON.stringify(ev.payload, null, 2)}</pre>
                    </div>
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
