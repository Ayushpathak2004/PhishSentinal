import React, { useState } from 'react';
import { Globe, Play, AlertCircle, CheckCircle2, RefreshCw } from 'lucide-react';
import { scanApi } from '../services/api';
import { ScanResult } from '../types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { AgentTimeline } from '../components/AgentTimeline';
import { ThreatIndicatorsList } from '../components/ThreatIndicatorsList';

export const WebsiteScannerPage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url.trim()) {
      setError('Please provide a URL to inspect.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      const res = await scanApi.scanWebsite(url.trim());
      setResult(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Website analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
            <Globe className="w-6 h-6 text-cyan-400" />
            <span>Website & Malicious URL Scanner</span>
          </h1>

        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* URL Input Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <label className="block text-xs font-semibold text-slate-300 uppercase">
          Target Website URL
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
            <input
              type="text"
              placeholder="e.g. https://mybank-account-update.com/signin"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <button
            onClick={handleScan}
            disabled={loading}
            className="flex items-center justify-center space-x-2 px-6 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/30 transition-all disabled:opacity-50 shrink-0"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Inspecting...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Analyze Website</span>
              </>
            )}
          </button>
        </div>

      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6 pt-4 border-t border-slate-800/80">
          {/* Risk Gauge */}
          <RiskScoreGauge
            score={result.risk_score}
            level={result.risk_level}
            confidence={result.confidence}
            fraudProbability={result.fraud_probability}
            isMlActive={Boolean(result.agent_outputs?.risk_score_agent?.data?.ml_analysis?.is_ml_active)}
          />

          {/* AI Threat Summary & Action */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">
              Forensic Evaluation & Containment Guidance
            </h3>
            <p className="text-sm text-slate-200 leading-relaxed">
              {result.summary}
            </p>
            <div className="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs flex items-center space-x-2 text-slate-300">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong className="text-slate-100">Enforced Action:</strong> {result.recommended_action}
              </span>
            </div>
          </div>

          {/* Indicators & Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ThreatIndicatorsList indicators={result.indicators} />
            <AgentTimeline events={result.timeline} />
          </div>
        </div>
      )}
    </div>
  );
};
