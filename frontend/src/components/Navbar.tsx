import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, CheckCircle2, User } from 'lucide-react';
import { authApi } from '../services/api';

interface NavbarProps {
  threatsCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({ threatsCount = 0 }) => {
  const navigate = useNavigate();
  const authenticated = authApi.isAuthenticated();

  const handleAuthClick = () => {
    if (authenticated) {
      authApi.logout();
    }
    navigate('/login');
  };

  return (
    <header className="h-16 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <span className="font-bold text-slate-100 tracking-wide text-base">PHISHSENTINEL</span>
          <span className="ml-2 text-xs font-semibold px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
            MULTI-AGENT AI v1.0
          </span>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/*
        <div className="hidden md:flex items-center space-x-2 text-xs px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700 text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>5/5 Agents Active</span>
        </div>
        <div className="hidden lg:flex items-center space-x-2 text-xs px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700 text-slate-300">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Hybrid Rules + ML + Groq</span>
        </div>
        <div className="flex items-center space-x-1.5 text-xs px-3 py-1.5 rounded-full bg-rose-950/60 border border-rose-800/60 text-rose-300">
          <Bell className="w-3.5 h-3.5 text-rose-400" />
          <span>Active Alerts</span>
        </div>
        */}

        {/* User Pill */}
        <div className="flex items-center space-x-2 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700 text-cyan-400">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden sm:block text-left text-xs">
            <div className="font-medium text-slate-200">SOC Analyst</div>
            <div className="text-slate-400 text-[10px]">Tier-2 Responder</div>
          </div>
        </div>

        <button
          onClick={handleAuthClick}
          className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:border-cyan-500 hover:text-cyan-300 transition-colors"
        >
          {authenticated ? 'Sign out' : 'Sign in'}
        </button>
      </div>
    </header>
  );
};
