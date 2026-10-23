import React, { useState } from 'react';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { Role } from './types';
import { getStoredRole, setStoredRole, api } from './api/client';
import { Navbar } from './components/Navbar';
import { Sidebar, ViewTab } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { PlaygroundView } from './views/PlaygroundView';
import { LiveMonitorView } from './views/LiveMonitorView';
import { ThreatAnalysisView } from './views/ThreatAnalysisView';
import { ApprovalQueueView } from './views/ApprovalQueueView';
import { AuditLogsView } from './views/AuditLogsView';
import { PolicyCenterView } from './views/PolicyCenterView';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 2000,
      retry: 1,
    },
  },
});

const AppContent: React.FC = () => {
  const [role, setRole] = useState<Role>(getStoredRole());
  const [activeTab, setActiveTab] = useState<ViewTab>('overview');

  const handleRoleChange = (newRole: Role) => {
    setStoredRole(newRole);
    setRole(newRole);
    queryClient.invalidateQueries();
  };

  // Get pending approvals count for badge
  const { data: approvals = [] } = useQuery({
    queryKey: ['pendingApprovalsCount'],
    queryFn: () => api.getApprovals('PENDING'),
    refetchInterval: 5000,
  });

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col">
      <Navbar
        currentRole={role}
        onRoleChange={handleRoleChange}
        onRefreshData={() => queryClient.invalidateQueries()}
      />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          pendingApprovalsCount={approvals.length}
        />

        <main className="flex-1 overflow-y-auto p-6 md:p-8 bg-[#0B0F19]">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'overview' && <OverviewView onNavigate={setActiveTab} />}
            {activeTab === 'playground' && <PlaygroundView onNavigate={setActiveTab} />}
            {activeTab === 'monitor' && <LiveMonitorView />}
            {activeTab === 'threats' && <ThreatAnalysisView />}
            {activeTab === 'approvals' && <ApprovalQueueView />}
            {activeTab === 'audit' && <AuditLogsView />}
            {activeTab === 'policy' && <PolicyCenterView />}
          </div>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
};

export default App;
