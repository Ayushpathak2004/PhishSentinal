import React, { useEffect, useState } from 'react';
import { Settings, Shield, Sliders, Key, Save, CheckCircle2, Cpu } from 'lucide-react';
import { settingsApi } from '../services/api';

export const SettingsPage: React.FC = () => {
  const [lowMax, setLowMax] = useState(19);
  const [moderateMax, setModerateMax] = useState(39);
  const [highMax, setHighMax] = useState(69);
  const [criticalMin, setCriticalMin] = useState(70);
  const [groqKey, setGroqKey] = useState('');
  const [groqKeyPreview, setGroqKeyPreview] = useState('Not Set');
  const [groqModel, setGroqModel] = useState('openai/gpt-oss-120b');
  const [isConfigured, setIsConfigured] = useState(false);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const data = await settingsApi.getSettings();
        setLowMax(data.threshold_low_max);
        setModerateMax(data.threshold_moderate_max);
        setHighMax(data.threshold_high_max);
        setCriticalMin(data.threshold_critical_min);
        setIsConfigured(data.groq_api_key_configured);
        setGroqKeyPreview(data.groq_api_key_preview);
        setGroqModel(data.groq_model);
      } catch (err) {
        console.error(err);
      }
    };
    fetchSettings();
  }, []);

  const handleSave = async () => {
    setLoading(true);
    setSavedMessage(null);
    try {
      await settingsApi.updateSettings({
        threshold_low_max: Number(lowMax),
        threshold_moderate_max: Number(moderateMax),
        threshold_high_max: Number(highMax),
        threshold_critical_min: Number(criticalMin),
        groq_api_key: groqKey.trim() || undefined,
        groq_model: groqModel
      });
      setSavedMessage('Security policy thresholds and AI parameters updated successfully.');
      if (groqKey.trim()) {
        setIsConfigured(true);
        setGroqKeyPreview(`${groqKey.trim().slice(0, 4)}...${groqKey.trim().slice(-4)}`);
        setGroqKey('');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
          <Settings className="w-6 h-6 text-cyan-400" />
          <span>System Settings & Security Policy Configuration</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Customize risk scoring bands, Groq LLM integration parameters, and autonomous response behavior.
        </p>
      </div>

      {savedMessage && (
        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{savedMessage}</span>
        </div>
      )}

      {/* Threshold Configuration */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
            Policy Agent Risk Thresholds
          </h3>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          The Policy Agent uses these calibrated score ranges to trigger mandatory containment, warnings, or allowances.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 pt-2">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <label className="text-[11px] font-bold text-emerald-400 uppercase">Safe / Low (Max)</label>
            <input
              type="number"
              value={lowMax}
              onChange={(e) => setLowMax(Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100"
            />
            <span className="text-[10px] text-slate-400">Normal processing allowed</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <label className="text-[11px] font-bold text-yellow-400 uppercase">Moderate (Max)</label>
            <input
              type="number"
              value={moderateMax}
              onChange={(e) => setModerateMax(Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100"
            />
            <span className="text-[10px] text-slate-400">Caution message display</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <label className="text-[11px] font-bold text-amber-400 uppercase">High (Max)</label>
            <input
              type="number"
              value={highMax}
              onChange={(e) => setHighMax(Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100"
            />
            <span className="text-[10px] text-slate-400">Strong warning & review flag</span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <label className="text-[11px] font-bold text-rose-400 uppercase">Critical (Min)</label>
            <input
              type="number"
              value={criticalMin}
              onChange={(e) => setCriticalMin(Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100"
            />
            <span className="text-[10px] text-slate-400">Auto-containment triggered</span>
          </div>
        </div>
      </div>

      {/* Groq API Configuration */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Key className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
            Groq AI Integration Layer
          </h3>
        </div>

        <div className="flex items-center justify-between text-xs bg-slate-950 p-3 rounded-lg border border-slate-800">
          <div>
            <span className="text-slate-400">API Key Status: </span>
            <span className={`font-bold ${isConfigured ? 'text-emerald-400' : 'text-slate-400'}`}>
              {isConfigured ? 'Configured & Active' : 'Not Configured (Operating on Deterministic Engine)'}
            </span>
          </div>
          <span className="font-mono text-[11px] text-slate-400">{groqKeyPreview}</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
              Update Groq API Key
            </label>
            <input
              type="password"
              placeholder="gsk_..."
              value={groqKey}
              onChange={(e) => setGroqKey(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <span className="text-[10px] text-slate-400 mt-1 block">
              Saved strictly in backend environment. Never exposed to frontend clients.
            </span>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
              Groq Model Selection
            </label>
            <select
              value={groqModel}
              onChange={(e) => setGroqModel(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="openai/gpt-oss-120b">openai/gpt-oss-120b (Recommended)</option>
              <option value="openai/gpt-oss-20b">openai/gpt-oss-20b (Ultra Fast)</option>
              <option value="qwen/qwen3.8-27b">qwen/qwen3.8-27b</option>
            </select>
            <span className="text-[10px] text-slate-400 mt-1 block">
              High-throughput inference model for contextual threat explanation.
            </span>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={loading}
          className="flex items-center space-x-2 px-6 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md shadow-cyan-600/30 transition-all disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          <span>{loading ? 'Saving Settings...' : 'Save Configuration'}</span>
        </button>
      </div>
    </div>
  );
};
