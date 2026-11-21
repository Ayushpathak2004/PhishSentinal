import React from 'react';
import { ShieldCheck, AlertCircle, AlertTriangle, ShieldAlert } from 'lucide-react';
import { RiskLevel } from '../types';

interface RiskScoreGaugeProps {
  score: number;
  level: RiskLevel;
  confidence: number;
  fraudProbability: number;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score,
  level,
  confidence,
  fraudProbability
}) => {
  const getColor = () => {
    if (score >= 70) return {
      border: 'border-rose-500',
      text: 'text-rose-400',
      bg: 'bg-rose-500/10',
      fill: '#f43f5e',
      icon: ShieldAlert
    };
    if (score >= 40) return {
      border: 'border-amber-500',
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      fill: '#f59e0b',
      icon: AlertTriangle
    };
    if (score >= 20) return {
      border: 'border-yellow-500',
      text: 'text-yellow-400',
      bg: 'bg-yellow-500/10',
      fill: '#eab308',
      icon: AlertCircle
    };
    return {
      border: 'border-emerald-500',
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      fill: '#10b981',
      icon: ShieldCheck
    };
  };

  const style = getColor();
  const Icon = style.icon;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col md:flex-row items-center justify-between gap-6">
      <div className="flex items-center space-x-6">
        {/* Score Dial */}
        <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
          <svg className="w-full h-full transform -rotate-90">
            <circle
              cx="56"
              cy="56"
              r="48"
              stroke="currentColor"
              strokeWidth="8"
              className="text-slate-800"
              fill="transparent"
            />
            <circle
              cx="56"
              cy="56"
              r="48"
              stroke={style.fill}
              strokeWidth="8"
              strokeDasharray={2 * Math.PI * 48}
              strokeDashoffset={2 * Math.PI * 48 * (1 - score / 100)}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className={`text-3xl font-extrabold ${style.text}`}>{Math.round(score)}</span>
            <span className="text-[10px] text-slate-400 uppercase font-semibold">/ 100</span>
          </div>
        </div>

        {/* Level & Classification */}
        <div>
          <div className="flex items-center space-x-2">
            <Icon className={`w-5 h-5 ${style.text}`} />
            <span className="text-xs uppercase font-bold tracking-widest text-slate-400">Risk Assessment</span>
          </div>
          <h2 className={`text-2xl font-bold tracking-tight mt-1 ${style.text}`}>
            {level} THREAT LEVEL
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-sm">
            {score >= 70 && 'Critical threat detected. Containment recommended immediately.'}
            {score >= 40 && score < 70 && 'High probability of malicious intent. Avoid interaction.'}
            {score >= 20 && score < 40 && 'Moderate risk observed. Verify credentials before acting.'}
            {score < 20 && 'Low risk. Baseline security signatures passed without anomalies.'}
          </p>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-2 gap-3 w-full md:w-auto shrink-0">
        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 text-center min-w-[130px]">
          <div className="text-[11px] text-slate-400 uppercase font-medium">Confidence</div>
          <div className="text-lg font-bold text-slate-100 mt-0.5">
            {Math.round(confidence * 100)}%
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">Tri-layer verified</div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 text-center min-w-[130px]">
          <div className="text-[11px] text-slate-400 uppercase font-medium">Fraud Prob.</div>
          <div className="text-lg font-bold text-slate-100 mt-0.5">
            {(fraudProbability * 100).toFixed(1)}%
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">ML calibrated</div>
        </div>
      </div>
    </div>
  );
};
