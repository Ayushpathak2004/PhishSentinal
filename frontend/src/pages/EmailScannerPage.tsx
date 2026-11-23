import React, { useState } from 'react';
import { Mail, Upload, Play, AlertCircle, FileText, CheckCircle2, RefreshCw } from 'lucide-react';
import { scanApi } from '../services/api';
import { ScanResult } from '../types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { AgentTimeline } from '../components/AgentTimeline';
import { ThreatIndicatorsList } from '../components/ThreatIndicatorsList';

export const EmailScannerPage: React.FC = () => {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [rawEml, setRawEml] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadPhishingSample = () => {
    setSender('security-alert@paypal-update-alert.ru');
    setSubject('URGENT: Your PayPal Account Has Been Suspended - Action Required in 24 Hours');
    setBody(
      'Dear Valued Customer,\n\n' +
      'We detected unauthorized login attempts from an unknown IP address (185.220.101.5).\n' +
      'For your protection, your access has been temporarily limited.\n\n' +
      'You must confirm your PIN, verify credit card, and enter your password immediately:\n' +
      'http://paypa1-security-verification.xyz/login\n\n' +
      'Failure to complete verification within 24 hours will result in permanent account termination.\n\n' +
      'PayPal Security Department'
    );
    setRawEml('');
    setFile(null);
  };

  const loadLegitimateSample = () => {
    setSender('notifications@github.com');
    setSubject('[GitHub] A personal access token has been generated');
    setBody(
      'Hey developer,\n\n' +
      'A new personal access token was generated for your GitHub account.\n' +
      'Token Name: CI-Build-Deploy\n' +
      'Scopes: repo, read:org\n\n' +
      'If you generated this token, you can safely ignore this message.\n' +
      'If you did not generate this token, please visit https://github.com/settings/tokens to revoke it.\n\n' +
      'Thanks,\nThe GitHub Team'
    );
    setRawEml('');
    setFile(null);
  };

  const handleScan = async () => {
    if (!rawEml && !body && !file && !subject) {
      setError('Please provide email content, subject, or upload a .eml file.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      if (file) {
        const formData = new FormData();
        formData.append('file', file);
        if (sender) formData.append('sender', sender);
        if (subject) formData.append('subject', subject);
        const res = await scanApi.scanEmail(formData);
        setResult(res);
      } else {
        const payload = {
          raw_content: rawEml || undefined,
          sender: sender || undefined,
          subject: subject || undefined,
          body: body || undefined
        };
        const res = await scanApi.scanEmail(payload);
        setResult(res);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Scan failed. Check inputs or connection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
            <Mail className="w-6 h-6 text-cyan-400" />
            <span>Email Fraud & Phishing Scanner</span>
          </h1>
        </div>

        {/* Sample Load Buttons */}
        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={loadPhishingSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors font-medium"
          >
            Load Phishing Sample
          </button>
          <button
            onClick={loadLegitimateSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors font-medium"
          >
            Load Benign Sample
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Input Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
                Sender (From)
              </label>
              <input
                type="text"
                placeholder="e.g. security@paypal.com"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
                Subject Line
              </label>
              <input
                type="text"
                placeholder="e.g. Action required on your account"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
              Email Body or Raw MIME Content
            </label>
            <textarea
              rows={7}
              placeholder="Paste email text, headers, or full MIME message here..."
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500 leading-relaxed"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              onClick={handleScan}
              disabled={loading}
              className="flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/30 transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Agents Analyzing...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Execute Multi-Agent Scan</span>
                </>
              )}
            </button>
            <span className="text-[11px] text-slate-400">Strict SSRF & Non-invasive sandbox active</span>
          </div>
        </div>

        {/* .eml File Upload Box */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2 flex items-center space-x-2">
              <Upload className="w-4 h-4 text-cyan-400" />
              <span>Upload .EML / RFC822 File</span>
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Upload raw exported email files from Outlook, Thunderbird, or Gmail. MIME boundaries, signatures, and attachments are safely analyzed without execution.
            </p>

            <div className="mt-4 border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-6 text-center transition-colors">
              <input
                type="file"
                accept=".eml,.txt"
                onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
                className="hidden"
                id="eml-upload-input"
              />
              <label htmlFor="eml-upload-input" className="cursor-pointer space-y-2 block">
                <FileText className="w-8 h-8 text-cyan-400 mx-auto" />
                <div className="text-xs font-medium text-slate-200">
                  {file ? file.name : 'Choose or drop .eml file'}
                </div>
                <div className="text-[10px] text-slate-400">
                  {file ? `${(file.size / 1024).toFixed(1)} KB` : 'RFC-822 Standard Format'}
                </div>
              </label>
            </div>
          </div>

          {file && (
            <button
              onClick={() => setFile(null)}
              className="mt-3 text-[11px] text-rose-400 hover:text-rose-300 block text-center"
            >
              Remove uploaded file
            </button>
          )}
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

          {/* AI Threat Summary & Recommended Action */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">
              AI Threat Synthesis & Security Recommendation
            </h3>
            <p className="text-sm text-slate-200 leading-relaxed">
              {result.summary}
            </p>
            <div className="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs flex items-center space-x-2 text-slate-300">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong className="text-slate-100">Mandated Action:</strong> {result.recommended_action}
              </span>
            </div>
          </div>

          {/* Two-column: Indicators & Agent Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ThreatIndicatorsList indicators={result.indicators} />
            <AgentTimeline events={result.timeline} />
          </div>
        </div>
      )}
    </div>
  );
};
