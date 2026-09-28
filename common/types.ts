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
  _index?: string;
  _raw_source?: Record<string, any> | null;
  _source_available?: boolean;
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

export interface CommentListResponse {
  comments: Comment[];
  nextCursor: string | null;
  total: number;
  truncated: boolean;
}

export interface EvidenceListResponse {
  evidence: CaseEvidence[];
  alerts?: Alert[];
  nextCursor: string | null;
  total: number;
  truncated: boolean;
}

export interface CaseEvidence {
  id: string;
  case_id: string;
  alert_id: string;
  relationship_state: 'linked' | 'held' | 'archived' | 'purged' | 'legacy';
  snapshot?: Record<string, any> | null;
  archive_index?: string | null;
  archive_id?: string | null;
  hold_reason?: string | null;
  legacy_fallback?: boolean;
  [key: string]: any;
}

export interface CloseCaseResult {
  ok: boolean;
  caseId: string;
  caseClosed: boolean;
  linkedAlerts: number;
  closedAlerts: number;
  alreadyClosedAlerts: number;
  excludedAlertIds: string[];
  evidenceOnlyAlertIds: string[];
  archiveOnlyAlertIds: string[];
  failedAlertIds: string[];
  stages: Array<{ stage: 'resolve' | 'close_alerts' | 'close_case' | 'activity'; attempted: number; succeeded: number; failed: number }>;
  errors: Array<{ stage: 'close_alerts' | 'close_case' | 'activity'; alertId?: string; message: string }>;
}

export interface Case {
  id: string;
  case_uid: string;
  title: string;
  description?: string;
  severity: CaseSeverity;
  status: CaseStatus;
  assigned_to?: string | null;
  alert_ids: string[];
  /** Exact authoritative evidence relationship count; alert_ids is only a bounded compatibility preview. */
  evidence_count?: number;
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
  // Source addresses (data.srcip) - the "who" behind the alert when the decoder
  // records one. Optional so graphs cached/served by older builds still render.
  sources?: string[];
  users: string[];
  // MITRE technique ids aligned index-for-index with `techniques` (labels).
  techniqueIds?: string[];
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
  exact: boolean;
  alertBasis: 'exact_cohort';
  timingBasis: 'exact_cohort';
  caseBasis: 'exact_cohort' | 'unavailable';
  coverage: {
    closedMissingReporting: number;
    assignedMissingReporting: number;
  };
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

export type CorrelationEntity =
  | 'agent'
  | 'srcip'
  | 'dstip'
  | 'srcport'
  | 'dstport'
  | 'user'
  | 'dstuser'
  | 'process';

export type MatchMode = 'any' | 'all';

export type RuleProcessingMode = 'continue' | 'stop';

export interface CorrelationRulePreconditions {
  statuses?: AlertStatus[];
  assignment?: 'any' | 'unassigned';
}

export interface CorrelationRuleRateLimit {
  maxExecutions: number;
  windowMinutes: number;
}

export interface CorrelationRuleSafety {
  acknowledgeMatchAll: boolean;
  maxActionsPerRun?: number;
  maxCasesPerRun?: number;
  rateLimit?: CorrelationRuleRateLimit;
}

export interface CorrelationRuleCounters {
  matchedAlerts: number;
  triggeredEntities: number;
  actionsAttempted: number;
  actionsSucceeded: number;
  actionsSkipped: number;
  actionsConflicted: number;
  actionsFailed: number;
  casesCreated: number;
  casesExtended: number;
  evidenceLinksWritten: number;
}

/** Runtime state stored independently from the editable rule definition. */
export interface CorrelationRuleExecutionState {
  document_type: 'rule_execution';
  rule_id: string;
  counters: CorrelationRuleCounters;
  matchCount: number;
  lastFired: string | null;
  updated_at: string;
}

export const correlationRuleExecutionId = (ruleId: string) => `rule-execution:${ruleId}`;

export interface CorrelationEntityPredicate {
  id: string;
  order: number;
  entity: CorrelationEntity;
  operator: 'exists' | 'equals';
  value?: string;
}

export interface CorrelationEntityGroup {
  id: string;
  order: number;
  predicates: CorrelationEntityPredicate[];
}

/** Predicates are ANDed within a group; groups are ORed. */
export interface CorrelationEntityExpression {
  version: 1;
  groups: CorrelationEntityGroup[];
}

export type CorrelationCaseRouting =
  | 'separate_by_group'
  | 'consolidate_overlapping'
  | 'one_per_rule';

export interface CorrelationRuleCooldown {
  durationMinutes: number;
}

export interface CorrelationRuleRearm {
  type: 'immediate' | 'after_quiet_period';
  quietPeriodMinutes: number;
}

// Canonical trigger schema. Every matching alert fires immediately; a burst
// applies its threshold/window independently to each resolved expression group.
export interface CorrelationRuleTrigger {
  type: 'per_alert' | 'burst';
  entityExpression?: CorrelationEntityExpression;
  routing?: CorrelationCaseRouting;
  cooldown?: CorrelationRuleCooldown;
  rearm?: CorrelationRuleRearm;
  /** Read compatibility only. Canonical writes use entityExpression. */
  entity?: CorrelationEntity;
  windowMinutes?: number;
  threshold?: number;
}

// Actions an automation rule can take when it fires. At least one must be
// selected. Every action, including deduplicated case creation, works with both
// trigger types.
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
  /** Absent only on legacy documents returned during schema migration. */
  schemaVersion?: 2;
  id: string;
  name: string;
  enabled: boolean;
  revision: number;
  if_seq_no: number;
  if_primary_term: number;
  priority?: number;
  sortOrder?: number;
  processingMode?: RuleProcessingMode;
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
  preconditions?: CorrelationRulePreconditions;
  safety?: CorrelationRuleSafety;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
  deleted_at?: string | null;
  deleted_by?: string | null;
}

export interface CanonicalCorrelationRuleTrigger extends CorrelationRuleTrigger {
  entityExpression: CorrelationEntityExpression;
  routing: CorrelationCaseRouting;
  cooldown: CorrelationRuleCooldown;
  rearm: CorrelationRuleRearm;
}

export interface CanonicalCorrelationRule extends Omit<CorrelationRule, 'schemaVersion' | 'trigger'> {
  schemaVersion: 2;
  trigger: CanonicalCorrelationRuleTrigger;
}

export interface CorrelationRuleConcurrency {
  revision: number;
  if_seq_no: number;
  if_primary_term: number;
}

export type CorrelationRuleCreateRequest = Pick<
  CanonicalCorrelationRule,
  'name' | 'match' | 'trigger' | 'actions'
> &
  Partial<
    Pick<
      CanonicalCorrelationRule,
      'enabled' | 'priority' | 'sortOrder' | 'processingMode' | 'preconditions' | 'safety'
    >
  >;

export type CorrelationRuleUpdateRequest = Partial<CorrelationRuleCreateRequest>;

export interface CorrelationRuleListRequest {
  size?: number;
  cursor?: string;
  includeDeleted?: boolean;
}

export interface CorrelationRuleRevision {
  document_type: 'rule_revision';
  rule_id: string;
  revision: number;
  changed_at: string;
  changed_by: string;
  change_type: 'create' | 'update' | 'delete' | 'rollback';
  snapshot: CorrelationRuleCreateRequest;
}

export interface CorrelationRuleListResponse {
  rules: CorrelationRule[];
  nextCursor: string | null;
}

export interface CorrelationRuleRevisionsResponse {
  revisions: CorrelationRuleRevision[];
  page: number;
  size: number;
  total: number;
  nextPage: number | null;
}

export interface CorrelationRuleDeleteResponse extends CorrelationRuleConcurrency {
  deleted: true;
  tombstone: true;
}

export interface CorrelationRulePreview {
  triggerType: 'per_alert' | 'burst';
  windowMinutes: number;
  lookbackHours: number;
  matchingAlerts: number;
  triggeringEntities: Array<{ entity: string; count: number }>;
  wouldOpenCases: number;
  casesCreated?: number;
  casesExtended?: number;
  statusChanges?: number;
  assignments?: number;
  skips?: number;
  conflicts?: Array<Record<string, any>>;
  skippedBySafety?: number;
  rateLimited?: boolean;
  missingEntities?: number;
  missingEntityRate?: number;
  representativeAlerts?: Array<{ id: string; timestamp: string | null }>;
  sampledAlerts?: number;
  totalAlerts?: number;
  queryTimeMs?: number;
  truncated?: boolean;
  token: string;
  fingerprint: string;
}

export type CorrelationRulePreviewRequest = CorrelationRuleCreateRequest & {
  id: string;
  revision: number;
  lookbackHours?: number;
};

export interface FilterOptions {
  ruleIds: Array<{ value: string; count: number }>;
  agents: Array<{ value: string; count: number }>;
  alertTypes: Array<{ value: string; count: number }>;
  assignees: Array<{ value: string; count: number }>;
  levelRange: { min: number; max: number };
}
