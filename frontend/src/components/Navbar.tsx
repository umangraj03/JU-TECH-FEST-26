import React from 'react';
import { Shield, RefreshCw, UserCheck, CheckCircle2 } from 'lucide-react';
import { Role } from '../types';
import { api } from '../api/client';

interface NavbarProps {
  currentRole: Role;
  onRoleChange: (role: Role) => void;
  onRefreshData?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentRole, onRoleChange, onRefreshData }) => {
  const [resetting, setResetting] = React.useState(false);

  const handleReset = async () => {
    if (!confirm('Reset demo state to default seed data?')) return;
    try {
      setResetting(true);
      await api.resetDemo();
      if (onRefreshData) onRefreshData();
      alert('Demo state reset successfully.');
    } catch (e: any) {
      alert(`Reset failed: ${e.message}`);
    } finally {
      setResetting(false);
    }
  };

  return (
    <header className="h-16 border-b border-gray-800 bg-[#0E1526]/80 backdrop-blur sticky top-0 z-30 flex items-center justify-between px-6">
      {/* Brand */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg shadow-blue-500/20 border border-blue-400/30">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-bold text-base text-gray-100 tracking-tight">AI Agent Security Guard</h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
              v1.0.0
            </span>
          </div>
          <p className="text-xs text-gray-400">Explainable Gateway & Defense Pipeline</p>
        </div>
      </div>

      {/* Gateway Status & Controls */}
      <div className="flex items-center space-x-4">
        {/* Live Status Pill */}
        <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>Gateway Active</span>
        </div>

        {/* Role Switcher */}
        <div className="flex items-center bg-[#161F33] rounded-lg p-1 border border-gray-700/60 shadow-inner">
          <UserCheck className="w-4 h-4 text-gray-400 ml-2 mr-1" />
          <span className="text-xs text-gray-400 font-medium mr-2">Principal:</span>
          {(['requester', 'approver', 'admin'] as Role[]).map((r) => (
            <button
              key={r}
              onClick={() => onRoleChange(r)}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-all capitalize ${
                currentRole === r
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/40'
              }`}
            >
              {r}
            </button>
          ))}
        </div>

        {/* Stitch UI Design Link */}
        <a
          href="/stitch_demo.html"
          target="_blank"
          rel="noopener noreferrer"
          title="Open complete high-fidelity Stitch UI design"
          className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-red-200 hover:text-white bg-red-950/40 hover:bg-red-900/60 rounded-lg border border-red-500/40 transition shadow-sm"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
          <span>Stitch UI</span>
          <span className="text-[10px] text-red-300">↗</span>
        </a>

        {/* Demo Reset Button */}
        <button
          onClick={handleReset}
          disabled={resetting}
          title="Reset database to demo seed"
          className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-gray-300 hover:text-white bg-gray-800/60 hover:bg-gray-800 rounded-lg border border-gray-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${resetting ? 'animate-spin text-blue-400' : ''}`} />
          <span className="hidden md:inline">Reset Demo</span>
        </button>
      </div>
    </header>
  );
};
