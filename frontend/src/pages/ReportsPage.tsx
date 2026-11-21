import React, { useEffect, useState } from 'react';
import { FileText, Download, FileSpreadsheet, ShieldAlert, CheckCircle2, Clock } from 'lucide-react';
import { reportsApi } from '../services/api';

export const ReportsPage: React.FC = () => {
  const [reportData, setReportData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const data = await reportsApi.getSummary();
        setReportData(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
            <FileText className="w-6 h-6 text-cyan-400" />
            <span>Forensic Reports & Incident Exports</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Generate formal PDF executive security audits and export chronological incident records in CSV format.
          </p>
        </div>

        {/* Global Export Buttons */}
        <div className="flex items-center space-x-2 shrink-0">
          <a
            href={reportsApi.getCsvExportUrl()}
            download
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-semibold"
          >
            <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
            <span>Export CSV Spreadsheets</span>
          </a>
        </div>
      </div>

      {/* Summary Cards */}
      {reportData && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <span className="text-xs font-semibold uppercase text-slate-400">Total Scanned</span>
            <div className="text-2xl font-bold text-slate-100 mt-1">{reportData.summary.total_scans}</div>
            <span className="text-[10px] text-slate-400">Analyzed by Swarm</span>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <span className="text-xs font-semibold uppercase text-slate-400">Critical Incidents</span>
            <div className="text-2xl font-bold text-rose-400 mt-1">{reportData.summary.critical_scans}</div>
            <span className="text-[10px] text-slate-400">Mandated Quarantine</span>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <span className="text-xs font-semibold uppercase text-slate-400">Open Triage</span>
            <div className="text-2xl font-bold text-amber-400 mt-1">{reportData.summary.open_incidents}</div>
            <span className="text-[10px] text-slate-400">Pending Review</span>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
            <span className="text-xs font-semibold uppercase text-slate-400">Remediated</span>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{reportData.summary.resolved_incidents}</div>
            <span className="text-[10px] text-slate-400">Audited by Vault Keeper</span>
          </div>
        </div>
      )}

      {/* Critical Findings & PDF Downloads Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
          Individual Incident Investigation Dossiers (Downloadable PDFs)
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Target Reference</th>
                <th className="py-2.5 px-3">Calculated Risk</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Date</th>
                <th className="py-2.5 px-3 text-right">PDF Dossier</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {reportData?.critical_findings?.map((scan: any) => (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 font-mono font-bold text-cyan-400">
                    {scan.type}
                  </td>
                  <td className="py-3 px-3 text-slate-100 font-semibold max-w-sm truncate">
                    {scan.target}
                  </td>
                  <td className="py-3 px-3 font-mono font-bold text-rose-400">
                    {scan.score} / 100
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                      {scan.level}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <a
                      href={reportsApi.getPdfUrl(scan.id)}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center space-x-1 px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-sm transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download PDF</span>
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
