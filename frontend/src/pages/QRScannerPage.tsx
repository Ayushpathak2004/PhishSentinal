import React, { useState } from 'react';
import { QrCode, Upload, Play, AlertCircle, ShieldAlert, CheckCircle2, RefreshCw, Lock, Image as ImageIcon } from 'lucide-react';
import { scanApi } from '../services/api';
import { ScanResult } from '../types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { AgentTimeline } from '../components/AgentTimeline';
import { ThreatIndicatorsList } from '../components/ThreatIndicatorsList';

export const QRScannerPage: React.FC = () => {
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [manualPayload, setManualPayload] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files ? e.target.files[0] : null;
    if (file) {
      setImageFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const loadPaymentScamSample = () => {
    setImageFile(null);
    setImagePreview(null);
    setManualPayload('upi://pay?pa=power.billing.dept@okaxis&pn=ElectricityRecovery&tn=Overdue+fine+pay+within+2+hours+to+avoid+power+cut&am=3850');
  };

  const loadPhishingUrlSample = () => {
    setImageFile(null);
    setImagePreview(null);
    setManualPayload('https://paypa1-security-verification.xyz/account/login');
  };

  const loadLegitimateSample = () => {
    setImageFile(null);
    setImagePreview(null);
    setManualPayload('https://www.google.com');
  };

  const handleScan = async () => {
    if (!imageFile && !manualPayload.trim()) {
      setError('Please upload a QR image or supply QR content.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      if (imageFile) {
        const formData = new FormData();
        formData.append('file', imageFile);
        const res = await scanApi.scanQR(formData);
        setResult(res);
      } else {
        const res = await scanApi.scanQR({ manual_content: manualPayload.trim() });
        setResult(res);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'QR scan failed.');
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
            <QrCode className="w-6 h-6 text-cyan-400" />
            <span>QR Code Fraud & Quishing Scanner</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Detects QR payment hijacking, malicious redirects, hidden phishing URLs, and exploit payloads.
          </p>
        </div>

        {/* Quick Samples */}
        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={loadPaymentScamSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors font-medium"
          >
            Payment Scam Sample
          </button>
          <button
            onClick={loadPhishingUrlSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 transition-colors font-medium"
          >
            Phishing URL Sample
          </button>
          <button
            onClick={loadLegitimateSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors font-medium"
          >
            Benign Sample
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Safety Notice Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center space-x-3 text-xs text-slate-300">
        <Lock className="w-5 h-5 text-cyan-400 shrink-0" />
        <div>
          <strong className="text-slate-100">Zero-Execution Safety Protocol:</strong> Decoded payment instructions and URLs are analyzed within an isolated sandbox. Payment transactions and external navigation are permanently locked.
        </div>
      </div>

      {/* Input Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload Box */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            <span>Upload QR Matrix Image (PNG/JPG)</span>
          </h3>

          <div className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-6 text-center transition-colors">
            <input
              type="file"
              accept="image/png,image/jpeg,image/webp"
              onChange={handleImageChange}
              className="hidden"
              id="qr-file-input"
            />
            <label htmlFor="qr-file-input" className="cursor-pointer space-y-2 block">
              {imagePreview ? (
                <div className="space-y-2">
                  <img
                    src={imagePreview}
                    alt="QR Preview"
                    className="w-36 h-36 object-contain mx-auto rounded-lg border border-slate-700 bg-white p-1"
                  />
                  <div className="text-xs text-slate-300 font-medium">{imageFile?.name}</div>
                  <div className="text-[10px] text-cyan-400">Click to replace image</div>
                </div>
              ) : (
                <div className="space-y-2">
                  <ImageIcon className="w-10 h-10 text-cyan-400 mx-auto" />
                  <div className="text-xs font-medium text-slate-200">
                    Drop QR image here or click to browse
                  </div>
                  <div className="text-[10px] text-slate-400">
                    Supports high-resolution camera photos and screenshots
                  </div>
                </div>
              )}
            </label>
          </div>
        </div>

        {/* Manual Payload Editor */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Or Inspect Raw Decoded Payload String
            </h3>
            <textarea
              rows={6}
              placeholder="e.g. upi://pay?pa=user@okhdfc... or https://masked-url.com..."
              value={manualPayload}
              onChange={(e) => setManualPayload(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500 leading-relaxed"
            />
            <div className="text-[11px] text-slate-400">
              Useful when decoding via an external handheld scanner or terminal logger.
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800">
            <button
              onClick={handleScan}
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/30 transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Decoding and Assessing QR...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Execute QR Fraud Scan</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6 pt-4 border-t border-slate-800/80">
          <RiskScoreGauge
            score={result.risk_score}
            level={result.risk_level}
            confidence={result.confidence}
            fraudProbability={result.fraud_probability}
          />

          {/* AI Threat Summary & Action */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">
              Quishing Threat Forensics
            </h3>
            <p className="text-sm text-slate-200 leading-relaxed">
              {result.summary}
            </p>
            <div className="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs flex items-center space-x-2 text-slate-300">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong className="text-slate-100">Enforcement Status:</strong> {result.recommended_action}
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
