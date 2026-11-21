import React, { useEffect, useState } from 'react';
import { Bot, Clock, CheckCircle2, Shield, Activity, RefreshCw } from 'lucide-react';
import { agentsApi } from '../services/api';
import { AgentStatus } from '../types';

export const AgentActivityPage: React.FC = () => {
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [activity, setActivity] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [statusData, actData] = await Promise.all([
        agentsApi.getStatus(),
        agentsApi.getActivity()
      ]);
      setAgents(statusData);
      setActivity(actData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center space-x-2.5">
            <Bot className="w-6 h-6 text-cyan-400" />
            <span>Multi-Agent Swarm Telemetry</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time status, completed workloads, execution latencies, and forensic decision trails for all five autonomous agents.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs shrink-0 font-medium"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Agents Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {agents.map((agent, idx) => (
          <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-100">{agent.name}</span>
                <span className="flex items-center space-x-1 text-[10px] text-emerald-400 font-bold bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 rounded">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                  <span>ONLINE</span>
                </span>
              </div>
              <div className="text-[11px] text-cyan-400 font-medium mt-1">
                {agent.role}
              </div>
              <p className="text-[11px] text-slate-400 mt-2 leading-relaxed line-clamp-3">
                {agent.description}
              </p>
            </div>

            <div className="border-t border-slate-800/80 pt-3 space-y-1 text-xs">
              <div className="flex justify-between text-slate-400">
                <span>Completed Tasks:</span>
                <span className="font-bold text-slate-200">{agent.completed_tasks}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Avg Latency:</span>
                <span className="font-semibold text-cyan-400">{agent.avg_latency_ms} ms</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Real-time Agent Execution Log */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Chronological Agent Execution Audit Log ({activity.length})
            </h3>
          </div>
          <span className="text-xs text-slate-400">Database-backed trace</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase font-semibold border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Agent</th>
                <th className="py-2.5 px-3">Task ID</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3">Execution Summary & Decision</th>
                <th className="py-2.5 px-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {activity.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 text-cyan-400 font-sans font-bold">
                    {item.agent_name}
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {item.task_id?.slice(0, 8)}...
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    {item.execution_time_ms} ms
                  </td>
                  <td className="py-3 px-3 text-slate-300 font-sans text-xs max-w-md">
                    {item.output_summary}
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {new Date(item.created_at).toLocaleTimeString()}
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
