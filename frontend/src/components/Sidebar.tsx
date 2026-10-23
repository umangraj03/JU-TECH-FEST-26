import React from 'react';
import {
  LayoutDashboard,
  Terminal,
  Activity,
  AlertOctagon,
  Clock,
  ScrollText,
  ShieldCheck
} from 'lucide-react';

export type ViewTab = 'overview' | 'playground' | 'monitor' | 'threats' | 'approvals' | 'audit' | 'policy';

interface SidebarProps {
  activeTab: ViewTab;
  onSelectTab: (tab: ViewTab) => void;
  pendingApprovalsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab, pendingApprovalsCount = 0 }) => {
  const navItems = [
    { id: 'overview' as ViewTab, label: 'Overview', icon: LayoutDashboard },
    { id: 'playground' as ViewTab, label: 'Demo Playground', icon: Terminal, highlight: true },
    { id: 'monitor' as ViewTab, label: 'Live Monitor', icon: Activity },
    { id: 'threats' as ViewTab, label: 'Threat Analysis', icon: AlertOctagon },
    { id: 'approvals' as ViewTab, label: 'Approval Queue', icon: Clock, badge: pendingApprovalsCount },
    { id: 'audit' as ViewTab, label: 'Audit Ledger', icon: ScrollText },
    { id: 'policy' as ViewTab, label: 'Policy Center', icon: ShieldCheck },
  ];

  return (
    <aside className="w-64 border-r border-gray-800 bg-[#0B0F19] flex flex-col justify-between p-4 shrink-0">
      <nav className="space-y-1.5">
        <div className="text-[11px] font-semibold tracking-wider text-gray-500 uppercase px-3 mb-3">
          Security Console
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/40'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-gray-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Trust boundary card */}
      <div className="p-3.5 rounded-xl bg-[#111827]/80 border border-gray-800/80 text-xs text-gray-400 space-y-1.5">
        <div className="flex items-center space-x-1.5 text-gray-300 font-semibold text-[11px]">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
          <span>Security Invariant</span>
        </div>
        <p className="text-[11px] leading-relaxed text-gray-400">
          Tools are isolated and callable strictly through <code className="text-blue-400 font-mono">gateway.execute()</code>.
        </p>
      </div>
    </aside>
  );
};
