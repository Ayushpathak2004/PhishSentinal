import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Mail, 
  Globe, 
  QrCode, 
  Archive,
  FileText, 
  Settings 
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { label: 'Overview', path: '/', icon: LayoutDashboard },
    { label: 'Email Scanner', path: '/email', icon: Mail },
    { label: 'Website Scanner', path: '/website', icon: Globe },
    { label: 'QR Scanner', path: '/qr', icon: QrCode },
    { label: 'Quarantine Vault', path: '/quarantine', icon: Archive },
    { label: 'Reports', path: '/reports', icon: FileText },
    { label: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          Core Scanners & Telemetry
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/*
      <div className="p-4 border-t border-slate-800/80 m-2 rounded-xl bg-slate-950/60 text-xs text-slate-400 space-y-1.5">
        <div className="flex items-center justify-between text-slate-300 font-medium">
          <span>Security Perimeter</span>
          <span className="text-emerald-400 font-semibold">Active</span>
        </div>
        <div className="text-[11px] text-slate-400">
          SOC Platform v1.0.0
        </div>
      </div>
      */}
    </aside>
  );
};
