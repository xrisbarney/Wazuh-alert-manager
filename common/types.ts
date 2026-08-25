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
  ai_analysis?: AiAnalysis;
}

export interface AlertCounts {
  open: number;
  in_progress: number;
  closed: number;
  total: number;
}

export type AttackGraphNodeType = 'host' | 'user' | 'technique';

export interface AttackGraphNode {
  id: string;
  type: AttackGraphNodeType;
  label: string;
  alertCount: number;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  alertId: string;
  timestamp: string;
  level: number;
}

export interface KillChainPhase {
  tactic: string;
  order: number;
  alertCount: number;
  techniques: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface AttackGraphHop {
  timestamp: string;
  alertId: string;
  host: string | null;
  users: string[];
  techniques: string[];
  tactics: string[];
  ruleDescription: string;
  level: number;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  killChain: KillChainPhase[];
  hops: AttackGraphHop[];
}

export interface SlaBreakdownEntry {
  label: string;
  met: number;
  breached: number;
}

export interface CaseMetrics {
  totalCases: number;
  statusBreakdown: { open: number; in_progress: number; closed: number };
  severityBreakdown: Record<CaseSeverity, number>;
  meanTimeToCloseMinutes: number | null;
  closedCount: number;
}

export interface ReportMetrics {
  from: string;
  to: string;
  totalAlerts: number;
  sampledAlerts: number;
  sampleLimit?: number;
  truncated: boolean;
  statusBreakdown: { open: number; in_progress: number; closed: number };
  alertsPerDay?: Array<{ date: string; count: number }>;
  statusPerDay?: Array<{ date: string; open: number; in_progress: number; closed: number }>;
  resolvedCount: number;
  assignedCount: number;
  meanTimeToResolveMinutes: number | null;
  meanTimeToAssignMinutes: number | null;
  slaCompliancePct: number | null;
  slaBreakdown: SlaBreakdownEntry[];
  slaPolicy: Array<{ minLevel: number; label: string; targetMinutes: number }>;
  analysts?: AnalystMetrics[];
  caseAnalysts?: CaseAnalystMetrics[];
  cases: CaseMetrics;
}

export interface AnalystMetrics {
  assignee: string;
  total: number;
  open: number;
  in_progress: number;
  closed: number;
  resolvedCount: number;
  meanTimeToResolveMinutes: number | null;
}

export interface CaseAnalystMetrics {
  assignee: string;
  open: number;
  in_progress: number;
  closed: number;
  total: number;
  meanTimeToCloseMinutes: number | null;
}

export type CorrelationEntity = 'agent' | 'srcip' | 'dstip' | 'user' | 'dstuser' | 'process';

export type MatchMode = 'any' | 'all';

// When and over what an automation rule fires:
//  - 'per_alert': the actions apply to every matching alert as it is ingested.
//  - 'burst': alerts are grouped by `entity`; the rule fires for an entity once
//    at least `threshold` matching alerts land on it within `windowMinutes`.
//    Actions then apply to that entity's burst (and case creation is possible).
export interface CorrelationRuleTrigger {
  type: 'per_alert' | 'burst';
  entity?: CorrelationEntity;
  windowMinutes?: number;
  threshold?: number;
}

// Actions an automation rule can take when it fires. At least one must be
// selected. Any action works with either trigger: `setStatus`/`assignTo` give
// auto-close and auto-assign (per-alert, or scoped to a burst); `createCase`
// requires the 'burst' trigger.
export interface CorrelationRuleActions {
  createCase: boolean;
  caseSeverity?: CaseSeverity;
  setStatus?: AlertStatus | null;
  assignTo?: string | null;
}

// An automation rule. Alerts are selected by `match`, the rule fires per
// `trigger`, and `actions` decide what happens. `match` sections each carry an
// optional 'any'/'all' mode: 'all' means the entity must, within the window,
// have seen every listed value at least once (co-occurrence, not volume).
export interface CorrelationRule {
  id: string;
  name: string;
  enabled: boolean;
  match: {
    ruleGroups?: string[];
    ruleGroupsMode?: MatchMode;
    ruleIds?: string[];
    ruleIdsMode?: MatchMode;
    agentNames?: string[];
    agentNamesMode?: MatchMode;
    minLevel?: number;
  };
  trigger: CorrelationRuleTrigger;
  actions: CorrelationRuleActions;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
  matchCount?: number;
  lastFired?: string | null;
}

export interface CorrelationRulePreview {
  triggerType: 'per_alert' | 'burst';
  windowMinutes: number;
  lookbackHours: number;
  matchingAlerts: number;
  triggeringEntities: Array<{ entity: string; count: number }>;
  wouldOpenCases: number;
}

export interface FilterOptions {
  ruleIds: Array<{ value: string; count: number }>;
  agents: Array<{ value: string; count: number }>;
  alertTypes: Array<{ value: string; count: number }>;
  assignees: Array<{ value: string; count: number }>;
  levelRange: { min: number; max: number };
}
