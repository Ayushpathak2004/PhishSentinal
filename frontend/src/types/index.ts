export type RiskLevel = 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface ThreatIndicator {
  indicator_type: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence?: string;
}

export interface AgentTimelineEvent {
  agent_name: string;
  task_id: string;
  step_number: number;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED';
  execution_time_ms: number;
  summary: string;
  details?: any;
}

export interface ScanResult {
  id: string;
  scan_type: 'EMAIL' | 'WEBSITE' | 'QR';
  input_reference: string;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  fraud_probability: number;
  summary: string;
  indicators: ThreatIndicator[];
  recommended_action: string;
  timeline: AgentTimelineEvent[];
  agent_outputs: {
    file_agent?: any;
    risk_score_agent?: any;
    policy_agent?: any;
    enforcer_agent?: any;
    vault_keeper?: any;
  };
  incident_id?: string;
  created_at: string;
}

export interface DashboardStats {
  total_scans: number;
  emails_analyzed: number;
  websites_analyzed: number;
  qr_analyzed: number;
  threats_detected: number;
  critical_threats: number;
  files_quarantined: number;
  incidents_resolved: number;
  risk_distribution: {
    SAFE: number;
    MODERATE: number;
    HIGH: number;
    CRITICAL: number;
  };
  recent_activity: Array<{
    id: string;
    type: string;
    reference: string;
    score: number;
    level: string;
    timestamp: string;
  }>;
}

export interface AgentStatus {
  name: string;
  role: string;
  description: string;
  status: 'ONLINE' | 'STANDBY' | 'BUSY';
  completed_tasks: number;
  avg_latency_ms: number;
  last_active: string | null;
  recent_decision: string;
}

export interface IncidentItem {
  id: string;
  scan_id?: string;
  title: string;
  incident_type: string;
  severity: string;
  status: string;
  assigned_action?: string;
  potential_impact: string;
  resolution_notes?: string;
  created_at: string;
  updated_at?: string;
}

export interface QuarantinedItem {
  id: string;
  scan_id?: string;
  original_filename: string;
  stored_filename: string;
  file_size: number;
  file_hash: string;
  quarantine_reason: string;
  status: string;
  restored_at?: string;
  restored_by?: string;
  created_at: string;
}

export interface BlocklistEntryItem {
  id: string;
  type: string;
  value: string;
  reason: string;
  severity: string;
  added_by: string;
  created_at: string;
}
