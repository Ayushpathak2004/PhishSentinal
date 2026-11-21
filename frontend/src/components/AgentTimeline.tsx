import React from 'react';
import { CheckCircle2, Clock, Bot, ShieldCheck, Zap, Lock, Database } from 'lucide-react';
import { AgentTimelineEvent } from '../types';

interface AgentTimelineProps {
  events: AgentTimelineEvent[];
}

export const AgentTimeline: React.FC<AgentTimelineProps> = ({ events }) => {
  const getAgentIcon = (name: string) => {
    switch (name) {
      case 'File Agent': return Database;
      case 'Risk Score Agent': return Zap;
      case 'Policy Agent': return ShieldCheck;
      case 'Enforcer Agent': return Lock;
      case 'Vault Keeper': return Bot;
      default: return Bot;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Bot className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
            Multi-Agent Orchestration Timeline
          </h3>
        </div>
        <span className="text-xs text-slate-400">
          5 Specialized Agents Executed
        </span>
      </div>

      <div className="relative pl-6 space-y-6 before:content-[''] before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {events.map((event, idx) => {
          const Icon = getAgentIcon(event.agent_name);
          return (
            <div key={idx} className="relative group">
              {/* Step Marker */}
              <div className="absolute -left-6 top-0 w-6 h-6 rounded-full bg-slate-950 border-2 border-cyan-500/80 flex items-center justify-center shrink-0 shadow-sm shadow-cyan-500/30">
                <Icon className="w-3 h-3 text-cyan-400" />
              </div>

              {/* Event Content */}
              <div className="bg-slate-950/50 border border-slate-800/80 rounded-lg p-3.5 hover:border-slate-700 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold text-slate-200">
                      Step {event.step_number || idx + 1}: {event.agent_name}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      SUCCESS
                    </span>
                  </div>

                  <div className="flex items-center space-x-1 text-slate-400 text-xs">
                    <Clock className="w-3 h-3 text-slate-400" />
                    <span>{event.execution_time_ms.toFixed(1)} ms</span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                  {event.summary}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
