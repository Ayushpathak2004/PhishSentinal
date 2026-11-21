import React, { useEffect, useState } from 'react';
import { Archive, ShieldCheck, CheckCircle2, AlertTriangle, Key, RefreshCw, X, ShieldAlert } from 'lucide-react';
import { quarantineApi } from '../services/api';
import { QuarantinedItem } from '../types';

export const QuarantineVaultPage: React.FC = () => {
  const [files, setFiles] = useState<QuarantinedItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<QuarantinedItem | null>(null);
  const [authorizedBy, setAuthorizedBy] = useState('Senior SOC Lead');
  const [restoreReason, setRestoreReason] = useState('Approved legitimate business document after manual sandbox inspection.');
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const fetchQuarantined = async () => {
    try {
      const data = await quarantineApi.getFiles();
      setFiles(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQuarantined();
  }, []);

  const handleVerify = async (id: string) => {
    setActionLoading(true);
    setVerificationResult(null);
    try {
      const res = await quarantineApi.verifyIntegrity(id);
      setVerificationResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRestore = async () => {
    if (!selectedFile) return;
    setActionLoading(true);
    setMessage(null);
    try {
      const res = await quarantineApi.restoreFile(selectedFile.id, {
        authorized_by: authorizedBy,
        reason: restoreReason
      });
      setMessage(res.message);
      fetchQuarantined();
      setSelectedFile(null);
    } catch (err: any) {
      setMessage(err?.response?.data?.detail || 'Restoration failed.');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
          <Archive className="w-6 h-6 text-rose-400" />
          <span>Application Quarantine Vault & Recovery</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Cryptographically isolated storage managed by the Enforcer Agent. Files undergo SHA-256 integrity validation prior to restoration.
        </p>
      </div>

      {message && (
        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {/* Verification Result Banner */}
      {verificationResult && (
        <div className={`p-4 rounded-xl border ${verificationResult.verified ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'} space-y-1 text-xs`}>
          <div className="flex items-center space-x-2 font-bold text-sm">
            {verificationResult.verified ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> : <ShieldAlert className="w-5 h-5 text-rose-400" />}
            <span>{verificationResult.status}: {verificationResult.verified ? 'Cryptographic Integrity Confirmed' : 'Tampering Detected'}</span>
          </div>
          <div className="font-mono text-[11px] pt-1">
            Computed Hash: {verificationResult.computed_hash}
          </div>
        </div>
      )}

      {/* Quarantined Files Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg space-y-4 p-5">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
          Isolated Artifacts Directory ({files.length})
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Original Filename</th>
                <th className="py-2.5 px-3">SHA-256 Hash</th>
                <th className="py-2.5 px-3">Size</th>
                <th className="py-2.5 px-3">Quarantine Directive</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Vault Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {files.map((file) => (
                <tr key={file.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 text-slate-100 font-sans font-semibold">
                    {file.original_filename}
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {file.file_hash?.slice(0, 16)}...
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    {(file.file_size / 1024).toFixed(1)} KB
                  </td>
                  <td className="py-3 px-3 text-slate-400 font-sans text-xs">
                    {file.quarantine_reason}
                  </td>
                  <td className="py-3 px-3 font-sans">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      file.status === 'RESTORED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }`}>
                      {file.status}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right space-x-2 font-sans">
                    <button
                      onClick={() => handleVerify(file.id)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
                    >
                      Verify Hash
                    </button>
                    {file.status !== 'RESTORED' && (
                      <button
                        onClick={() => setSelectedFile(file)}
                        className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                      >
                        Restore File
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Restoration Authorization Modal */}
      {selectedFile && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center space-x-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>Authorized File Restoration</span>
              </h3>
              <button onClick={() => setSelectedFile(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Restoring <strong className="text-slate-200">{selectedFile.original_filename}</strong>. The Vault Keeper will verify the physical file against the baseline hash before release.
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Authorizing Lead / Officer</label>
                <input
                  type="text"
                  value={authorizedBy}
                  onChange={(e) => setAuthorizedBy(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Operational Justification</label>
                <textarea
                  rows={3}
                  value={restoreReason}
                  onChange={(e) => setRestoreReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedFile(null)}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                disabled={actionLoading}
                onClick={handleRestore}
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
              >
                {actionLoading ? 'Verifying & Restoring...' : 'Authorize Restoration'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
