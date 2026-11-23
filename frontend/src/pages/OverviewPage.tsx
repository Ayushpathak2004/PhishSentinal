import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  Mail, 
  Globe, 
  QrCode, 
  CheckCircle, 
  TrendingUp, 
  AlertTriangle,
  Bot
} from 'lucide-react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip 
} from 'recharts';
import { dashboardApi, agentsApi, mlApi } from '../services/api';
import { DashboardStats, AgentStatus, MlModelMetrics } from '../types';

export const OverviewPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [mlModels, setMlModels] = useState<MlModelMetrics[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchOverview = async () => {
      try {
        const [statsData, agentsData] = await Promise.all([
          dashboardApi.getStats(),
          agentsApi.getStatus()
        ]);
        setStats(statsData);
        setAgents(agentsData);
        try {
          const mlData = await mlApi.getMetrics();
          setMlModels(mlData.models);
        } catch (err) {
          console.error('Failed to load ML model metrics', err);
        }
      } catch (err) {
        console.error('Failed to load overview data', err);
      } finally {
        setLoading(false);
      }
    };
    fetchOverview();
  }, []);

  const pieData = stats ? [
    { name: 'Critical', value: stats.risk_distribution.CRITICAL, color: '#f43f5e' },
    { name: 'High', value: stats.risk_distribution.HIGH, color: '#f59e0b' },
    { name: 'Moderate', value: stats.risk_distribution.MODERATE, color: '#eab308' },
    { name: 'Safe', value: stats.risk_distribution.SAFE, color: '#10b981' },
  ] : [];

  const barData = stats ? [
    { name: 'Emails', count: stats.emails_analyzed },
    { name: 'Websites', count: stats.websites_analyzed },
    { name: 'QR Codes', count: stats.qr_analyzed },
    { name: 'Threats', count: stats.threats_detected }
  ] : [];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">Security Operations Dashboard</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-agent telemetry and automated threat containment statistics.
          </p>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">Total Scans</span>
            <TrendingUp className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-2">
            {stats ? stats.total_scans : '...'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Cross-protocol analyses</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">Threats Detected</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 mt-2">
            {stats ? stats.threats_detected : '...'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {stats ? `${stats.critical_threats} critical risks` : '...'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase">Incidents Resolved</span>
            <CheckCircle className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-2">
            {stats ? stats.incidents_resolved : '...'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Remediated & verified</div>
        </div>
      </div>

      {/* Per-task ML training and test metrics */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider mb-4">
          ML Model Training & Test Performance
        </h3>
        {mlModels ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {mlModels.map((model) => (
              <div key={model.task} className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-slate-100">{model.display_name}</span>
                  <span className={`text-[10px] uppercase font-semibold ${
                    model.status === 'trained' ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    {model.status.replace('_', ' ')}
                  </span>
                </div>
                {model.metrics ? (
                  <>
                    <div className="text-[10px] text-slate-400">
                      {model.model_type} · {model.dataset_source} · {model.dataset_samples?.toLocaleString()} samples
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <div className="text-[10px] uppercase text-slate-500 mb-1">Training</div>
                        <div className="text-xs text-slate-300">
                          Accuracy: {(model.metrics.train.accuracy * 100).toFixed(2)}%
                        </div>
                        <div className="text-xs text-slate-300">
                          Precision: {(model.metrics.train.precision * 100).toFixed(2)}%
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] uppercase text-slate-500 mb-1">Testing</div>
                        <div className="text-xs text-slate-300">
                          Accuracy: {(model.metrics.test.accuracy * 100).toFixed(2)}%
                        </div>
                        <div className="text-xs text-slate-300">
                          Precision: {(model.metrics.test.precision * 100).toFixed(2)}%
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <p className="text-xs text-slate-400">
                    {model.reason || 'No training metrics available.'}
                  </p>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-400">Model metrics are unavailable.</p>
        )}
      </div>

      {/* Visual Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Donut */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider mb-2">
            Risk Classification Distribution
          </h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#e2e8f0', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex items-center justify-around text-xs mt-2 border-t border-slate-800/80 pt-3">
            {pieData.map((d, i) => (
              <div key={i} className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }}></span>
                <span className="text-slate-400">{d.name}:</span>
                <span className="font-semibold text-slate-200">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Volume by Protocol */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider mb-2">
            Protocol Volume & Threat Breakdown
          </h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#e2e8f0', fontSize: '12px' }}
                />
                <Bar dataKey="count" fill="#0284c7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="text-[11px] text-slate-400 text-center mt-2 border-t border-slate-800/80 pt-3">
            Aggregate count of email, web, and QR artifacts analyzed by the 5-agent pipeline.
          </div>
        </div>
      </div>

      {/* Agents Telemetry Snapshot */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Bot className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Specialized Multi-Agent Swarm Status
            </h3>
          </div>
          <span className="text-xs text-slate-400">Autonomous Orchestration</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {agents.map((agent, i) => (
            <div key={i} className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200">{agent.name}</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              </div>
              <div className="text-[11px] text-slate-400 line-clamp-1">{agent.role}</div>
              <div className="text-xs font-semibold text-cyan-400 pt-1">
                {agent.completed_tasks} Tasks Executed
              </div>
              <div className="text-[10px] text-slate-400">
                Avg Latency: {agent.avg_latency_ms}ms
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
