import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { EmailScannerPage } from './pages/EmailScannerPage';
import { WebsiteScannerPage } from './pages/WebsiteScannerPage';
import { QRScannerPage } from './pages/QRScannerPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { AgentActivityPage } from './pages/AgentActivityPage';
import { IncidentManagementPage } from './pages/IncidentManagementPage';
import { QuarantineVaultPage } from './pages/QuarantineVaultPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
        <Navbar />
        <div className="flex flex-1">
          <Sidebar />
          <main className="flex-1 p-6 max-w-7xl mx-auto w-full overflow-y-auto">
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/email" element={<EmailScannerPage />} />
              <Route path="/website" element={<WebsiteScannerPage />} />
              <Route path="/qr" element={<QRScannerPage />} />
              <Route path="/intel" element={<ThreatIntelPage />} />
              <Route path="/agents" element={<AgentActivityPage />} />
              <Route path="/incidents" element={<IncidentManagementPage />} />
              <Route path="/quarantine" element={<QuarantineVaultPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
};

export default App;
