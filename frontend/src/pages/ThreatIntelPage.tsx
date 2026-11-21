import React, { useEffect, useState } from 'react';
import { Database, ShieldAlert, Plus, Search, Lock, AlertTriangle, ShieldCheck } from 'lucide-react';
import { settingsApi } from '../services/api';
import { BlocklistEntryItem } from '../types';

export const ThreatIntelPage: React.FC = () => {
  const [blocklist, setBlocklist] = useState<BlocklistEntryItem[]>([]);
  const [attackPatterns, setAttackPatterns] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchIntel = async () => {
      try {
        const data = await settingsApi.getThreatIntel();
        setBlocklist(data.blocklist_entries || []);
        setAttackPatterns(data.attack_patterns || []);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchIntel();
  }, []);

  const filtered = blocklist.filter(b => 
    b.value.toLowerCase().includes(search.toLowerCase()) ||
    b.reason.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
          <Database className="w-6 h-6 text-cyan-400" />
          <span>Internal Threat Intelligence & Indicators</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Active blocklist entries, IoC indicators, and attack pattern signatures managed by the Enforcer Agent.
        </p>
      </div>

      {/* Attack Patterns Showcase */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {attackPatterns.map((pat, idx) => (
          <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-100">{pat.name}</span>
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                {pat.frequency}
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              {pat.description}
            </p>
          </div>
        ))}
      </div>

      {/* Blocklist Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Enforced Blocklist Directory ({blocklist.length})
            </h3>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-400" />
            <input
              type="text"
              placeholder="Filter IoCs or domains..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase font-semibold border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Malicious IoC / Destination</th>
                <th className="py-2.5 px-3">Reason & Context</th>
                <th className="py-2.5 px-3">Enforced By</th>
                <th className="py-2.5 px-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-400 border border-slate-700">
                      {item.type}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-200 font-medium break-all">
                    {item.value}
                  </td>
                  <td className="py-3 px-3 text-slate-400 font-sans">
                    {item.reason}
                  </td>
                  <td className="py-3 px-3 text-slate-300 font-sans">
                    {item.added_by}
                  </td>
                  <td className="py-3 px-3 text-slate-400">
                    {new Date(item.created_at).toLocaleDateString()}
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
