import React from 'react';
import { AlertTriangle, AlertCircle, ShieldAlert, Info } from 'lucide-react';
import { ThreatIndicator } from '../types';

interface ThreatIndicatorsListProps {
  indicators: ThreatIndicator[];
}

export const ThreatIndicatorsList: React.FC<ThreatIndicatorsListProps> = ({ indicators }) => {
  const getBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-500/15',
          text: 'text-rose-400',
          border: 'border-rose-500/30',
          icon: ShieldAlert
        };
      case 'HIGH':
        return {
          bg: 'bg-amber-500/15',
          text: 'text-amber-400',
          border: 'border-amber-500/30',
          icon: AlertTriangle
        };
      case 'MEDIUM':
        return {
          bg: 'bg-yellow-500/15',
          text: 'text-yellow-400',
          border: 'border-yellow-500/30',
          icon: AlertCircle
        };
      default:
        return {
          bg: 'bg-blue-500/15',
          text: 'text-blue-400',
          border: 'border-blue-500/30',
          icon: Info
        };
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
        <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center space-x-2">
          <span>Identified Threat Indicators</span>
          <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300">
            {indicators.length}
          </span>
        </h3>
        <span className="text-xs text-slate-400">Explainable Forensics</span>
      </div>

      {indicators.length === 0 ? (
        <div className="p-8 text-center text-slate-400 text-sm">
          No threat indicators detected. Target passed heuristic and lexical checks.
        </div>
      ) : (
        <div className="space-y-3">
          {indicators.map((ind, idx) => {
            const badge = getBadge(ind.severity);
            const Icon = badge.icon;
            return (
              <div
                key={idx}
                className="bg-slate-950/60 border border-slate-800/90 rounded-lg p-3.5 space-y-2 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center space-x-2.5">
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${badge.bg} ${badge.text} ${badge.border} flex items-center space-x-1`}>
                      <Icon className="w-3 h-3" />
                      <span>{ind.severity}</span>
                    </span>
                    <span className="text-sm font-semibold text-slate-200">{ind.title}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">{ind.indicator_type}</span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed pl-1">
                  {ind.description}
                </p>

                {ind.evidence && (
                  <div className="mt-2 text-[11px] font-mono bg-slate-900/90 border border-slate-800 rounded px-2.5 py-1 text-slate-400 overflow-x-auto">
                    <span className="text-slate-400 font-semibold mr-2">EVIDENCE:</span>
                    {ind.evidence}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
