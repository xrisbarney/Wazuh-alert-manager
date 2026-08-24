import { ALERT_STATUSES, CASE_SEVERITIES, CASE_STATUSES, AI_PROVIDERS } from './constants';

export type AlertStatus = typeof ALERT_STATUSES[number];
export type CaseSeverity = typeof CASE_SEVERITIES[number];
export type CaseStatus = typeof CASE_STATUSES[number];
export type AiProvider = typeof AI_PROVIDERS[number];

export interface AiAnalysis {
  text: string;
  provider: AiProvider;
  model?: string | null;
  generated_at: string;
}

export interface AiSettings {
  enabled: boolean;
  provider: AiProvider;
  model?: string;
  baseUrl?: string;
  configured: boolean;
  encryptionConfigured: boolean;
}

export interface AuditEntry {
  timestamp: string;
  user: string;
  action: string;
  from?: string | null;
  to?: string | null;
}

export interface Alert {
  _id: string;
  _source: {
    agent?: {
      ip?: string;
      name?: string;
      id?: string;
    };
    manager?: {
      name?: string;
    };
    rule?: {
      id?: string;
      description?: string;
      level?: number;
    };
    '@timestamp': string;
    status: AlertStatus;
    case_id?: string | null;
    assigned_to?: string | null;
    related_alert_ids?: string[];
    ai_analysis?: AiAnalysis;
    updated_at?: string;
    updated_by?: string;
    history?: AuditEntry[];
    [key: string]: any;
  };
}

export interface Comment {
  id?: string;
  alert_id?: string | null;
  case_id?: string | null;
  text: string;
  author: string;
  created_at: string;
}

export interface Case {
  id: string;
  title: string;
  description?: string;
  severity: CaseSeverity;
  status: CaseStatus;
  assigned_to?: string | null;
  alert_ids: string[];
  created_by: string;
  created_at: string;
  updated_by?: string;
  updated_at?: string;
  closed_at?: string | null;
  history?: AuditEntry[];
}

export interface AlertCounts {
  open: number;
  in_progress: number;
  closed: number;
  total: number;
}

export interface SlaBreakdownEntry {
  label: string;
  met: number;
  breached: number;
}

export interface ReportMetrics {
  from: string;
  to: string;
  totalAlerts: number;
  sampledAlerts: number;
  truncated: boolean;
  statusBreakdown: { open: number; in_progress: number; closed: number };
  resolvedCount: number;
  assignedCount: number;
  meanTimeToResolveMinutes: number | null;
  meanTimeToAssignMinutes: number | null;
  slaCompliancePct: number | null;
  slaBreakdown: SlaBreakdownEntry[];
  slaPolicy: Array<{ minLevel: number; label: string; targetMinutes: number }>;
}

export interface FilterOptions {
  ruleIds: Array<{ value: string; count: number }>;
  agents: Array<{ value: string; count: number }>;
  alertTypes: Array<{ value: string; count: number }>;
  assignees: Array<{ value: string; count: number }>;
  levelRange: { min: number; max: number };
}
