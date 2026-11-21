import React, { useEffect, useState } from 'react';
import { AlertTriangle, ShieldCheck, CheckCircle2, Search, Filter, Clock, Eye, X } from 'lucide-react';
import { incidentsApi } from '../services/api';
import { IncidentItem } from '../types';

export const IncidentManagementPage: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);

  const fetchIncidents = async () => {
    try {
      const data = await incidentsApi.getIncidents({
        severity: severityFilter || undefined,
        status: statusFilter || undefined
      });
      setIncidents(data.items || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [severityFilter, statusFilter]);

  const openDetail = async (id: string) => {
    try {
      const detail = await incidentsApi.getIncidentById(id);
      setSelectedIncident(detail);
    } catch (err) {
      console.error(err);
    }
  };

  const handleUpdateStatus = async (newStatus: string) => {
    if (!selectedIncident) return;
    setUpdating(true);
    try {
      await incidentsApi.updateIncident(selectedIncident.incident.id, {
        status: newStatus,
        resolution_notes: `Status changed to ${newStatus} by SOC Analyst.`
      });
      await openDetail(selectedIncident.incident.id);
      fetchIncidents();
    } catch (err) {
      console.error(err);
    } finally {
      setUpdating(false);
    }
  };

  const filtered = incidents.filter(i =>
    i.title.toLowerCase().includes(search.toLowerCase()) ||
    i.incident_type.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
            <AlertTriangle className="w-6 h-6 text-amber-400" />
            <span>Incident Triage & Response Management</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated detection incidents flagged by Policy Agent and Enforcer Agent for SOC analyst investigation.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-md">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-400" />
            <input
              type="text"
              placeholder="Search incidents by title..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MODERATE">Moderate</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="UNDER_REVIEW">Under Review</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>

        <div className="text-xs text-slate-400 font-medium">
          Showing {filtered.length} Incident Records
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title / Target</th>
                <th className="py-3 px-4">Fraud Type</th>
                <th className="py-3 px-4">Enforced Action</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Recorded</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((inc) => (
                <tr key={inc.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      inc.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' :
                      inc.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                      'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                    }`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-semibold text-slate-200 max-w-sm">
                    {inc.title}
                  </td>
                  <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                    {inc.incident_type}
                  </td>
                  <td className="py-3 px-4 text-cyan-400 font-mono text-[11px]">
                    {inc.assigned_action}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      inc.status === 'RESOLVED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                      inc.status === 'CONTAINED' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' :
                      'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                    }`}>
                      {inc.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-[11px]">
                    {new Date(inc.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => openDetail(inc.id)}
                      className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors text-xs"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Review</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider">
                  Incident Forensics & Investigation
                </span>
                <h2 className="text-lg font-bold text-slate-100 mt-0.5">
                  {selectedIncident.incident.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Status & Resolution Controls */}
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-[11px] text-slate-400">Current Lifecycle Status</div>
                <div className="text-sm font-bold text-slate-100">{selectedIncident.incident.status}</div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  disabled={updating}
                  onClick={() => handleUpdateStatus('CONTAINED')}
                  className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                >
                  Mark Contained
                </button>
                <button
                  disabled={updating}
                  onClick={() => handleUpdateStatus('RESOLVED')}
                  className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
                >
                  Mark Resolved
                </button>
              </div>
            </div>

            {/* Threat Indicators Summary */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Correlating Threat Indicators ({selectedIncident.threat_indicators?.length || 0})
              </h4>
              <div className="space-y-2">
                {selectedIncident.threat_indicators?.map((ti: any, idx: number) => (
                  <div key={idx} className="bg-slate-950/70 border border-slate-800/80 rounded p-2.5 text-xs">
                    <div className="font-semibold text-slate-200">{ti.title}</div>
                    <div className="text-slate-400 mt-0.5">{ti.description}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Action Log History */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Enforcement Audit History
              </h4>
              <div className="space-y-2 font-mono text-[11px]">
                {selectedIncident.action_logs?.map((log: any, idx: number) => (
                  <div key={idx} className="bg-slate-950/70 border border-slate-800/80 rounded p-2.5 flex justify-between">
                    <div>
                      <span className="text-cyan-400 font-bold">{log.agent_name}: </span>
                      <span className="text-slate-300">{log.action_details}</span>
                    </div>
                    <span className="text-slate-400 shrink-0 ml-2">
                      {new Date(log.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
