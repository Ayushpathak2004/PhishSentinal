import React, { useEffect, useState } from 'react';
import { Archive, RefreshCw } from 'lucide-react';
import { quarantineApi } from '../services/api';
import { QuarantinedItem } from '../types';

export const QuarantineVaultPage: React.FC = () => {
  const [files, setFiles] = useState<QuarantinedItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
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

    fetchQuarantined();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
          <Archive className="w-6 h-6 text-rose-400" />
          <span>Quarantine Vault</span>
        </h1>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg p-5">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-4">
          Stored Files ({files.length})
        </h3>

        {loading ? (
          <div className="flex items-center justify-center py-10 text-slate-400 text-xs">
            <RefreshCw className="w-4 h-4 animate-spin mr-2" />
            Loading stored files...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Original Filename</th>
                  <th className="py-2.5 px-3">SHA-256 Hash</th>
                  <th className="py-2.5 px-3">Size</th>
                  <th className="py-2.5 px-3">Quarantine Reason</th>
                  <th className="py-2.5 px-3">Stored At</th>
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
                    <td className="py-3 px-3 text-slate-400 font-sans text-xs">
                      {new Date(file.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {files.length === 0 && (
              <div className="py-10 text-center text-xs text-slate-400">
                No quarantined files stored.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
