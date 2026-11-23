import { ALERT_STATUSES, CASE_SEVERITIES, CASE_STATUSES, DISPOSITIONS, AI_PROVIDERS, ENRICHMENT_SOURCE_KINDS, ENRICHMENT_VERDICTS, ENRICHMENT_LOOKUP_TYPES, ENRICHMENT_VERDICT_FILTERS, ASSET_CRITICALITIES, ASSET_MATCH_KINDS, NOTIFICATION_EVENTS, NOTIFICATION_CHANNEL_KINDS, NOTIFICATION_CHANNEL_WARNINGS, NOTIFICATION_STATUSES, NOTIFICATION_TARGET_TYPES } from './constants';
import type { SeverityBand } from './severity';

export type AlertStatus = typeof ALERT_STATUSES[number];
export type CaseSeverity = typeof CASE_SEVERITIES[number];
export type CaseStatus = typeof CASE_STATUSES[number];
/** Outcome recorded when a case or alert is closed (step 2.4). */
export type Disposition = typeof DISPOSITIONS[number];
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
  /** Set on the close entry when the close carried a disposition (step 2.4). */
  disposition?: string | null;
}

export interface Alert {
  _id: string;
  _index?: string;
  _raw_source?: Record<string, any> | null;
  _source_available?: boolean;
  /** Wazuh 5.0: the underlying event a finding references (guarded second hop). */
  _raw_event?: Record<string, any> | null;
  _event_available?: boolean;
  _source_family?: 'wazuh4_alerts' | 'wazuh5_findings' | null;
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
      /** 4.x numeric level; null for 5.0 findings (see severity_label). */
      level?: number | null;
    };
    /** Which native family produced the record (absent on pre-v3 records). */
    source_family?: 'wazuh4_alerts' | 'wazuh5_findings' | null;
    source_profile_version?: number | null;
    /** Wazuh 5.0 severity label, stored verbatim; null for 4.x alerts. */
    severity_label?: string | null;
    event_index?: string | null;
    event_doc_id?: string | null;
    space?: string | null;
    '@timestamp': string;
    status: AlertStatus;
    case_id?: string | null;
    assigned_to?: string | null;
    /** Close outcome (step 2.4); set on close, kept on reopen for audit, shown only while closed. */
    disposition?: Disposition | null;
    closure_reason?: string | null;
    related_alert_ids?: string[];
    ai_analysis?: AiAnalysis;
    updated_at?: string;
    updated_by?: string;
    history?: AuditEntry[];
    /** Native context ingested for indicator extraction (common/indicators.ts). */
    syscheck?: { path?: string | null; md5_after?: string | null; sha1_after?: string | null; sha256_after?: string | null } | null;
    related?: { ip?: string[]; hosts?: string[]; hash?: string[]; user?: string[] } | null;
    threat?: { matches?: any[]; total?: number; truncated?: boolean; sibling_of?: string | null; integration?: string | null } | null;
    geo?: any[] | null;
    /** Stored enrichment verdicts written by per-alert lookups (step 6.3). */
    enrichment?: AlertEnrichment | null;
    /** Asset context stamped at projection time on every sync (step 6.4a); never plugin-owned. */
    asset?: AlertAsset | null;
    /** Wazuh 5.0 `wazuh.case.*` read-only projection (step 2.6); always null on 4.x records. */
    native_case?: AlertNativeCase | null;
    /** Write-time reporting fields incl. the due timestamps of step 3.2. */
    reporting?: AlertReporting | null;
    /** Breach / escalation markers written by the SLA escalation scanner (step 3.3). */
    sla?: SlaMarkers | null;
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
  /** True when the case was closed before this call (a re-close: the stored outcome is kept, nothing notifies). */
  alreadyClosed: boolean;
  linkedAlerts: number;
  closedAlerts: number;
  alreadyClosedAlerts: number;
  excludedAlertIds: string[];
  evidenceOnlyAlertIds: string[];
  archiveOnlyAlertIds: string[];
  failedAlertIds: string[];
  stages: Array<{ stage: 'resolve' | 'close_alerts' | 'close_case' | 'activity'; attempted: number; succeeded: number; failed: number }>;
  errors: Array<{ stage: 'close_alerts' | 'close_case' | 'activity'; alertId?: string; message: string }>;
  /** Effective outcome (step 2.4): the request's on a first close, the case's stored one on a re-close. */
  disposition: Disposition;
  closureReason: string | null;
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
  /** Close outcome (step 2.4); stored by POST /cases/{id}/close and propagated to the alerts it closes. */
  disposition?: Disposition | null;
  closure_reason?: string | null;
  /** `created_at` + the resolve target of the case severity (step 3.2); recomputed when the severity changes. */
  sla_due_at?: string | null;
  /** Breach / escalation markers written by the SLA escalation scanner (step 3.3). */
  sla?: SlaMarkers | null;
  history?: AuditEntry[];
  ai_analysis?: AiAnalysis;
  /** Checklist (step 2.1), sorted by `order`; capped at CASE_TASKS_MAX. */
  tasks?: CaseTask[];
  /** Always kept consistent with `tasks` by server/lib/case_tasks.ts. */
  task_counts?: CaseTaskCounts;
  /** TaskLists applied to this case (step 2.2); one entry per task list, never repeated. */
  applied_task_lists?: AppliedTaskList[];
}

/** Marker written on the case when a task list's tasks were appended (step 2.2). */
export interface AppliedTaskList {
  task_list_id: string;
  applied_at: string;
  applied_by: string;
}

/** One template task of a task list (step 2.2). */
export interface TaskListTask {
  /** Single line, 1..CASE_TASK_TITLE_MAX_LENGTH characters. */
  title: string;
  owner?: string | null;
  /** Minutes after the apply time the task falls due (1..TASK_LIST_DUE_OFFSET_MAX_MINUTES); null = no due date. */
  dueOffsetMinutes?: number | null;
  /** Position in the template, renumbered 0..n-1 on every write. */
  order: number;
}

export interface TaskList {
  id: string;
  /** 1..TASK_LIST_NAME_MAX_LENGTH characters, unique ignoring case. */
  name: string;
  description?: string;
  /** 1..TASK_LIST_TASKS_MAX tasks, sorted by `order`. */
  tasks: TaskListTask[];
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

export interface TaskListTaskInput {
  title: string;
  owner?: string | null;
  dueOffsetMinutes?: number | null;
}

export interface TaskListInput {
  name: string;
  description?: string;
  tasks: TaskListTaskInput[];
  enabled?: boolean;
}

export interface TaskListListResponse {
  taskLists: TaskList[];
  /** TASK_LISTS_MAX, so the editor can disable "new" when the store is full. */
  limit: number;
}

export interface TaskListMutationResponse {
  taskList: TaskList;
}

/** `POST /cases/{id}/task-lists/{taskListId}/apply` (step 2.2). */
export interface TaskListApplyResponse {
  applied: boolean;
  /** Set when `applied` is false. */
  reason?: 'already_applied';
  task_list_id: string;
  tasks_added: number;
  counts: CaseTaskCounts;
}

/** Outcome of the optional `taskListId` on `POST /cases`; a failure never rolls the case back. */
export interface CreateCaseTaskListOutcome {
  applied: boolean;
  tasks_added?: number;
  error?: string;
}

/** One checklist item on a case (step 2.1). */
export interface CaseTask {
  /** 12-char base36 id, unique within the case. */
  id: string;
  /** Single line, 1..CASE_TASK_TITLE_MAX_LENGTH characters. */
  title: string;
  owner?: string | null;
  /** ISO timestamp or null. */
  due_at?: string | null;
  done: boolean;
  done_by?: string | null;
  done_at?: string | null;
  created_by: string;
  created_at: string;
  /** Position in the list, renumbered 0..n-1 on every write. */
  order: number;
}

/** One row of `GET /cases/{id}/timeline` (step 2.3). */
export type CaseTimelineEntryKind = 'alert' | 'comment' | 'audit' | 'task_due';

export interface CaseTimelineRef {
  alert_id?: string;
  activity_id?: string;
  task_id?: string;
}

export interface CaseTimelineEntry {
  /** Unique within the case: `alert:<id>`, `activity:<id>` or `task_due:<taskId>`; the tiebreak of the ordering. */
  id: string;
  kind: CaseTimelineEntryKind;
  /** ISO timestamp the entry is ordered by. */
  at: string;
  actor?: string | null;
  title: string;
  details?: string | null;
  ref: CaseTimelineRef;
  /** Audit entries: the activity action (`status_change`, `task_added`, `sla_breached`, ...). */
  action?: string | null;
  /** Alert entries: the severity band of the record (`common/severity.ts`), null when unknown. */
  severity_band?: SeverityBand | null;
}

export interface CaseTimelineResponse {
  entries: CaseTimelineEntry[];
  /** Opaque cursor of the next page (scoped to the case), null on the last page. */
  next_cursor: string | null;
  /** True when the case links more alerts than CASE_TIMELINE_ALERTS_MAX; the oldest relationships beyond the cap are not listed. */
  truncated_alerts: boolean;
}

export interface CaseTaskCounts {
  open: number;
  done: number;
}

export interface CaseTaskInput {
  title: string;
  owner?: string | null;
  /** ISO timestamp; null clears. */
  dueAt?: string | null;
}

export interface CaseTaskUpdateInput {
  title?: string;
  owner?: string | null;
  dueAt?: string | null;
  done?: boolean;
  order?: number;
}

export interface CaseTaskListResponse {
  tasks: CaseTask[];
  counts: CaseTaskCounts;
  /** CASE_TASKS_MAX, so the UI can disable "add" when the case is full. */
  limit: number;
}

export interface CaseTaskMutationResponse {
  task: CaseTask;
  counts: CaseTaskCounts;
}

export type AttachmentKind = 'link' | 'file';

/** One case attachment as the list and create routes return it (never the file bytes). */
export interface CaseAttachment {
  id: string;
  case_id: string;
  kind: AttachmentKind;
  name: string;
  /** Links only. */
  url: string | null;
  /** Files only; always one of ATTACHMENT_ALLOWED_CONTENT_TYPES. */
  content_type: string | null;
  /** Decoded size in bytes (0 for links). */
  size: number;
  /** Files only: hex SHA-256 of the decoded bytes. */
  sha256: string | null;
  created_by: string;
  created_at: string;
}

export interface CaseAttachmentListResponse {
  attachments: CaseAttachment[];
  total: number;
  /** ATTACHMENT_MAX_PER_CASE, so the UI can disable "add" when the case is full. */
  limit: number;
}

export interface CaseAttachmentInput {
  kind: AttachmentKind;
  name: string;
  url?: string;
  contentType?: string;
  /** Raw base64 (no data: prefix). */
  dataBase64?: string;
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
  /** Wazuh rule ID (rule.id). Optional so payloads from older builds still render. */
  ruleId?: string;
  ruleDescription: string;
  level: number;
  /** Alert lifecycle status (open / in_progress / closed) when known. */
  status?: string | null;
  /** Case evidence relationship for this alert, so filtered Linked Alerts views can act on it. */
  evidence?: {
    relationship_state: string | null;
    hold_reason: string | null;
    archive_index: string | null;
  };
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
  /** SLA enforcement figures (step 3.4); absent only from a payload older than this step. */
  slaCurrentlyBreached?: SlaCurrentlyBreached;
  slaBreachesInPeriod?: SlaBreachesInPeriod;
  slaEscalationsInPeriod?: SlaEscalationsInPeriod;
  /**
   * Dispositions (step 2.4) of the alerts closed in the period (`status: closed`
   * with `reporting.closed_at` in the range; a closed alert without a stored
   * disposition counts as `undetermined`). Absent only from a payload older than this step.
   */
  dispositions?: Record<Disposition, number>;
  /** False-positive share of the same closed-in-period alerts, by rule (top DISPOSITION_RULE_BUCKETS_MAX rules by closed count). */
  falsePositiveByRule?: FalsePositiveByRuleRow[];
}

export interface FalsePositiveByRuleRow {
  rule_id: string;
  description: string | null;
  /** Alerts of the rule closed in the period. */
  closed: number;
  false_positive: number;
  /** false_positive / closed, 0..1. */
  rate: number;
}

/**
 * Records breached right now (not bound to the report range): open or
 * in-progress alerts and non-closed cases carrying `sla.breached_at` or
 * whose resolve due date (`reporting.sla_due_at` / `sla_due_at`) is in the
 * past. `byBand` is alerts plus cases per SLA band.
 */
export interface SlaCurrentlyBreached {
  /** The instant the counts were taken (ISO). */
  asOf: string;
  alerts: number;
  cases: number;
  byBand: Record<SlaBand, number>;
}

/** `sla_breached` activity events whose timestamp falls in the report range. */
export interface SlaBreachesInPeriod {
  total: number;
  alerts: number;
  cases: number;
}

/** `sla_escalated` activity events in the report range, by escalation rule (id + name as recorded on the event). */
export interface SlaEscalationsInPeriod {
  total: number;
  byEscalation: Array<{ id: string; name: string; count: number }>;
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
  | 'process'
  | 'hash'
  | 'domain'
  | 'url';

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
  /** Disposition written with `setStatus: 'closed'` (step 2.4); dropped by normalisation for any other status. */
  disposition?: Disposition | null;
  assignTo?: string | null;
  /** TaskList applied when the rule creates a NEW case (never when it routes into an existing one). */
  applyTaskListId?: string | null;
  /**
   * Step 1.4: enqueue a `rule.action` notification for every alert the rule
   * fires on, to these channel ids (bound in Settings > Notifications; 1 to
   * RULE_NOTIFY_MAX_CHANNELS, validated against the stored channel list at
   * save time). Combines freely with the other actions; a rule with only
   * `notify` is valid. Absent / null = no notification.
   */
  notify?: CorrelationRuleNotifyAction | null;
}

export interface CorrelationRuleNotifyAction {
  channelIds: string[];
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
    /** Alert `asset.criticality` floor (step 6.4a); unstamped alerts never meet it. */
    /** `null` on a partial update clears a stored floor. */
    minAssetCriticality?: AssetCriticality | null;
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
  /** Step 12.3: joined from the rule's `rule-execution:<id>` companion; absent until the rule first fires. */
  matchCount?: number;
  lastFired?: string | null;
  counters?: Partial<CorrelationRuleCounters>;
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
  /** Step 1.4: outbox entries the candidate's `notify` action would write (alerts it fires on x the channel ids the stored settings resolve to an enabled channel). */
  notifications?: number;
  /** Step 1.4: notify targets execution would skip (unknown or disabled channel id, or notifications disabled globally). */
  notificationsSkipped?: number;
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

// Enrichment sources (step 6.2).
export type EnrichmentSourceKind = typeof ENRICHMENT_SOURCE_KINDS[number];
export type EnrichmentVerdict = typeof ENRICHMENT_VERDICTS[number];
export type EnrichmentLookupType = typeof ENRICHMENT_LOOKUP_TYPES[number];

/** One configured source as the browser sees it: the API key is masked to `apiKeyConfigured`. */
export interface EnrichmentSource {
  id: string;
  name: string;
  kind: EnrichmentSourceKind;
  enabled: boolean;
  /** Indicator types this source is asked about; always inside the kind's capability. */
  supports: EnrichmentLookupType[];
  cacheTtlSeconds: number;
  timeoutMs: number;
  /** misp: server root; generic_http: unused (see urlTemplate); abuseipdb / wazuh_cti_local: none. */
  baseUrl?: string;
  /** generic_http: GET URL with `{value}` and `{type}` placeholders. */
  urlTemplate?: string;
  /** generic_http: extra request headers; a value may contain `{apiKey}`. */
  headers?: Record<string, string>;
  /** generic_http: RFC 6901 JSON pointers into the response body. */
  verdictPath?: string;
  scorePath?: string;
  tagsPath?: string;
  linkPath?: string;
  /** generic_http: raw verdict value (as a string) -> normalised verdict. */
  verdictMap?: Record<string, EnrichmentVerdict>;
  /**
   * misp / generic_http: relax transport security for an allowlisted host.
   * Only honoured for hosts on WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS (the
   * egress policy refuses http everywhere else): plain http for any listed
   * host, and an unverified (self-signed) TLS certificate only for a listed
   * local-suffix name (.internal, .local, .home.arpa), e.g. a lab MISP at
   * https://misp.internal. A public host keeps verified HTTPS regardless.
   */
  allowInsecure?: boolean;
  /** Set by `read()` of the settings doc; never stored. */
  apiKeyConfigured?: boolean;
  /** True for the synthesised `wazuh_cti_local` entry (cannot be deleted, only toggled). */
  builtIn?: boolean;
}

/** PUT payload: a source may carry a new plaintext `apiKey`; '' / absent keeps the stored one, null clears it. */
export interface EnrichmentSourceInput extends Omit<EnrichmentSource, 'apiKeyConfigured' | 'builtIn' | 'supports' | 'cacheTtlSeconds' | 'timeoutMs'> {
  supports?: EnrichmentLookupType[];
  cacheTtlSeconds?: number;
  timeoutMs?: number;
  apiKey?: string | null;
  apiKeyConfigured?: boolean;
  builtIn?: boolean;
}

export interface EnrichmentSettingsResponse {
  sources: EnrichmentSource[];
  encryptionConfigured: boolean;
  /** Hostnames from WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS on the dashboard service (informational). */
  egressAllowedHosts: string[];
  updated_at?: string;
  updated_by?: string;
}

/** Normalised verdict every provider returns. */
export interface EnrichmentResult {
  /** Source id. */
  source: string;
  verdict: EnrichmentVerdict;
  /** 0-100 when the source scores, else null. */
  score: number | null;
  tags: string[];
  link: string | null;
  summary: string;
  checkedAt: string;
}

export interface EnrichmentLookupItem {
  sourceId: string;
  sourceName: string;
  kind: EnrichmentSourceKind;
  status: 'ok' | 'error';
  /** True when the result came from the cache index rather than the source. */
  cached: boolean;
  result?: EnrichmentResult;
  error?: string;
}

export interface EnrichmentLookupRequest {
  type: EnrichmentLookupType;
  value: string;
  sourceIds?: string[];
  refresh?: boolean;
}

export interface EnrichmentLookupResponse {
  type: EnrichmentLookupType;
  /** Canonical form that was looked up (lower-cased hash, normalised IP, ...). */
  value: string;
  results: EnrichmentLookupItem[];
}

export interface EnrichmentTestResponse extends EnrichmentLookupItem {
  type: EnrichmentLookupType;
  value: string;
}

// Stored enrichment on the alert record (step 6.3).
export type EnrichmentVerdictFilter = typeof ENRICHMENT_VERDICT_FILTERS[number];

/** One (source, indicator) verdict as stored under `alert.enrichment.items[]`. */
export interface AlertEnrichmentItem {
  type: EnrichmentLookupType;
  /** Canonical indicator value that was looked up. */
  value: string;
  /** Source id. */
  source: string;
  verdict: EnrichmentVerdict;
  score: number | null;
  /** At most MAX_ALERT_ENRICHMENT_TAGS. */
  tags: string[];
  link: string | null;
  checked_at: string;
}

/** Bounded `enrichment` object on the alert record (plugin-owned field). */
export interface AlertEnrichment {
  updated_at: string;
  /** Worst verdict across items (malicious > suspicious > clean > unknown); null without items. */
  worst_verdict: EnrichmentVerdict | null;
  /** At most MAX_ALERT_ENRICHMENT_ITEMS, one per (source, type, value), newest first. */
  items: AlertEnrichmentItem[];
}

/** Response of `POST /enrichment/alerts/{alertId}/lookup`: the lookup plus the stored object after the write. */
export interface AlertEnrichmentLookupResponse extends EnrichmentLookupResponse {
  alertId: string;
  /** Stored object after the lookup; null when nothing has ever been stored (e.g. no enabled source supports the type). */
  enrichment: AlertEnrichment | null;
}

// Asset criticality (step 6.4a).
export type AssetCriticality = typeof ASSET_CRITICALITIES[number];
export type AssetMatchKind = typeof ASSET_MATCH_KINDS[number];

/**
 * One row of the `asset_settings` document. `match.value` is an exact agent
 * name (`name`), a `*`/`?` glob over the agent name (`glob`), an agent group
 * name (`group`) or a 4.x agent label as `key=value` (`label`).
 */
export interface AssetEntry {
  id: string;
  match: { kind: AssetMatchKind; value: string };
  criticality: AssetCriticality;
  tags: string[];
}

export interface AssetSettingsResponse {
  assets: AssetEntry[];
  updated_at?: string;
  updated_by?: string;
}

/** Result of running the matcher over one agent (GET /assets/resolve). */
export interface AssetResolution {
  criticality: AssetCriticality | null;
  tags: string[];
  matchedId: string | null;
  matchedBy: AssetMatchKind | null;
}

/** The `asset` object stamped on every synced alert record (re-stamped on every resync). */
export interface AlertAsset {
  criticality: AssetCriticality | null;
  tags: string[];
  /** 5.0: `wazuh.agent.groups`; 4.x: cached Wazuh API lookup when available, else []. */
  groups: string[];
  /** 4.x `agent.labels` when present (labels were removed in 5.0). */
  labels: Record<string, string> | null;
  matched_id: string | null;
  matched_by: AssetMatchKind | null;
}

/**
 * Read-only copy of the native Case Management fields on a Wazuh 5.0 finding
 * (`wazuh.case.*`, step 2.6 / decision Q6). Re-derived on every resync and
 * reconciled by the sync tick when the case changes later (an edit in the
 * Wazuh Cases app does not move the finding's @timestamp), so edits flow
 * through; the plugin never writes it back. Every value is a bounded string
 * (see NATIVE_CASE_* in constants.ts). `id` is reserved: rc2 writes none.
 */
export interface AlertNativeCase {
  id: string | null;
  /** Native status, verbatim (rc2: active | acknowledged | completed | error | deleted | audit). */
  status: string | null;
  severity: string | null;
  priority: string | null;
  tlp: string | null;
  title: string | null;
  tags: string[];
  updated_at: string | null;
}

// Asset context chips (step 6.4b): read-only summaries of the native
// `wazuh-states-*` families for one agent (GET /assets/context).
export type AssetContextFamilyStatus = 'ok' | 'no_access' | 'not_available' | 'error';

export interface AssetContextFamilyBase {
  status: AssetContextFamilyStatus;
  /** Set on `error` (e.g. `timeout`) and on a line-level `not_available`. */
  reason?: string;
}

export interface AssetContextTopCve {
  id: string;
  severity: string | null;
  score: number | null;
}

export interface AssetContextResponse {
  agentId: string | null;
  agentName: string | null;
  /** Wazuh line whose field map answered (4 or 5). */
  line: 4 | 5;
  fetchedAt: string;
  cached: boolean;
  families: {
    system: AssetContextFamilyBase & {
      os?: { name: string | null; version: string | null; platform: string | null } | null;
      hostname?: string | null;
    };
    networks: AssetContextFamilyBase & { ips?: string[]; total?: number };
    ports: AssetContextFamilyBase & { open?: number; listening?: number };
    vulnerabilities: AssetContextFamilyBase & {
      total?: number;
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
      topCves?: AssetContextTopCve[];
    };
    /** 5.0 only (`wazuh-states-sca`); `not_available` on 4.x builds. */
    sca: AssetContextFamilyBase & { total?: number; failed?: number; passed?: number };
  };
  /**
   * App-relative dashboard paths; the browser prepends `server.basePath`. `itHygiene` is null on builds before Wazuh 4.13,
   * where the app does not exist; `configurationAssessment` is set on 4.x only, where SCA results live in the manager and
   * the Configuration Assessment app is the way to see them (the chip reads `n/a` there).
   */
  links: { itHygiene: string | null; vulnerabilityDetection: string; configurationAssessment: string | null };
}

// Scheduled summaries (step 5.4).

export type ReportScheduleCadence = 'daily' | 'weekly';

export interface ReportSchedule {
  /** 1-64 lower-case letters, digits, "-" or "_"; also keys the stored last run. */
  id: string;
  name: string;
  cadence: ReportScheduleCadence;
  /** 0 (Sunday) - 6 (Saturday); only used when cadence is `weekly`. */
  dayOfWeek: number;
  /** Hour of the day in UTC (0-23) at which the slot is due. */
  hourUtc: number;
  /** The summary covers the `rangeDays` days ending at the slot. */
  rangeDays: number;
  /**
   * Notification channel ids (Settings > Notifications) the rendered run is
   * delivered to as `report.scheduled` (step 1.3): each must exist and be
   * enabled; unknown or disabled ids are logged and skipped.
   */
  channelIds: string[];
  enabled: boolean;
}

/**
 * One stored run (`report_run:<scheduleId>` in the meta index). `slot`,
 * `generated_at`, `range_*`, `triggered_by` and `markdown` describe the last
 * SUCCESSFUL render and survive a later failed attempt; a failure is
 * recorded next to them in `error` / `failed_slot` / `failed_at` /
 * `attempts` and cleared by the next success.
 */
export interface ReportRun {
  schedule_id: string;
  /** ISO timestamp of the UTC slot the stored Markdown covers (idempotency key); empty before the first success. */
  slot: string;
  generated_at: string;
  range_from: string;
  range_to: string;
  /** Who triggered the stored render: `scheduler` or the user behind "Run now". */
  triggered_by: string;
  markdown: string;
  /** Message of the most recent attempt when it failed; null after a success. */
  error: string | null;
  /** Slot of the failed attempt (the scheduler retries it up to `REPORT_RUN_MAX_ATTEMPTS` times). */
  failed_slot: string | null;
  failed_at: string | null;
  /** Consecutive failed attempts at `failed_slot`; 0 after a success. */
  attempts: number;
}

/** `ReportRun` without the body, as the list and last-run routes return it. */
export interface ReportRunSummary extends Omit<ReportRun, 'markdown'> {
  markdown_bytes: number;
  truncated: boolean;
}

export interface ReportSchedulesResponse {
  schedules: ReportSchedule[];
  /** Last stored run per schedule id, when one exists. */
  lastRuns: Record<string, ReportRunSummary>;
  /** ISO timestamp of each schedule's next due slot (UTC), by id. */
  nextSlots: Record<string, string>;
  updated_at?: string;
  updated_by?: string;
}

export interface ReportScheduleLastRunResponse {
  run: ReportRunSummary | null;
}

/** Extra figures the scheduled summary adds on top of `ReportMetrics`. */
export interface ReportSummaryExtras {
  severityBands: Record<string, number>;
  topRules: Array<{ id: string; description: string | null; count: number }>;
  topAgents: Array<{ id: string | null; name: string; count: number }>;
  /** Cases currently open or in progress, by severity (not bounded by the range). */
  openCasesBySeverity: Record<string, number>;
  /** Alerts closed in the range whose SLA was breached; null when not available. */
  breachedCount: number | null;
}

export interface ReportSummaryData {
  metrics: ReportMetrics;
  extras: ReportSummaryExtras;
}

/**
 * Discover/Reporting bridge (step 5.6) outcome, reported by GET /system/version.
 * Plugin administrators get the full record; other users get the same shape
 * with a generic `message` and an empty `objects` map (the detailed text can
 * embed internal-user permission and index-name details).
 */
export type SavedObjectsBridgeState = 'ok' | 'skipped' | 'error';

export interface SavedObjectsBridgeStatus {
  /** `ok` = all four objects present at the current bridge version; `skipped` = not attempted on this replica; `error` = at least one upsert failed or the version record was unreadable. */
  indexPatterns: SavedObjectsBridgeState;
  message: string;
  /** Bridge version (MAPPING_VERSION * 1000 + bridge revision) the objects were last written for, when known. */
  version: number | null;
  checkedAt: string | null;
  /** Per saved-object outcome keyed by id (empty for non-admin callers). */
  objects: Record<string, 'created' | 'updated' | 'unchanged' | 'error'>;
}

// SLA policy (step 3.1). `targets` keys are the four numeric severity bands;
// `escalations[]` is validated here and consumed by the scanner of step 3.3.
export type SlaBand = 'critical' | 'high' | 'medium' | 'low';

export interface SlaTarget {
  /** Minutes from the alert's `@timestamp` (case: `created_at`) to resolution. */
  resolveMinutes: number;
  /** Minutes to first assignment. */
  assignMinutes: number;
}

export type SlaEscalationTarget = 'alert' | 'case';
export type SlaEscalationCondition = 'unassigned' | 'untouched' | 'any';

export interface SlaEscalation {
  id: string;
  name: string;
  target: SlaEscalationTarget;
  /** Percentage (1..100) of the band's resolve target that must have elapsed. */
  thresholdPercent: number;
  condition: SlaEscalationCondition;
  actions: {
    assignTo?: string;
    /** Cases only. */
    raiseSeverity?: boolean;
    comment?: string;
    /**
     * Notification channel ids the `sla.escalated` notification goes to
     * instead of the event's bound channels (step 1.3); each must exist and
     * be enabled, unknown or disabled ids are logged and skipped.
     */
    notify?: string[];
  };
  enabled: boolean;
}

export interface SlaPolicy {
  targets: Record<SlaBand, SlaTarget>;
  escalations: SlaEscalation[];
}

/** GET/PUT /sla/policy. `defaults` is the built-in policy so the UI can offer "Reset to defaults". */
export interface SlaPolicyResponse {
  policy: SlaPolicy;
  updated_at?: string;
  updated_by?: string;
  defaults: SlaPolicy;
  /** The stored document exists but no longer validates; `policy` is the defaults until an administrator saves. */
  storedInvalid?: boolean;
}

// Due timestamps (step 3.2).
export type SlaState = 'breached' | 'due_soon' | 'on_track';

/** Write-time reporting fields on an alert (`reporting.*`; see server/lib/reporting_fields.ts). */
export interface AlertReporting {
  first_assigned_at?: string | null;
  assign_minutes?: number | null;
  closed_at?: string | null;
  resolve_minutes?: number | null;
  assignee_at_close?: string | null;
  sla_tier?: string | null;
  sla_met?: boolean | null;
  /** `@timestamp` + the resolve target of the severity band at first projection (null without a severity). */
  sla_due_at?: string | null;
  /** `@timestamp` + the first-assignment target of the band. */
  assign_due_at?: string | null;
  reporting_version?: number;
}

// Escalation scanner (step 3.3).

/** Markers the scanner leaves on an alert (`sla.*`) or a case (`sla.*`). */
export interface SlaMarkers {
  /** Set once, when the scanner first saw the resolve due date in the past. */
  breached_at?: string | null;
  /** Ids of the escalations already applied to this record (never applied twice). */
  escalated?: string[] | null;
}

export interface SlaEscalationStatusError {
  at: string;
  message: string;
}

/** META_INDEX doc `sla_escalation_status`: the last tick of the lease holder. */
export interface SlaEscalationStatus {
  last_tick_at: string;
  holder: string;
  breached_alerts: number;
  breached_cases: number;
  escalated: number;
  /** The last ten errors across ticks, oldest first. */
  errors: SlaEscalationStatusError[];
  /** True when a per-tick cap was hit (the remainder is handled next tick). */
  capped: boolean;
}

/**
 * The status as GET /sla/escalation/status answers it: `holder` (hostname +
 * pid of the lease holder) only for plugin administrators; `errors[]` are
 * the sanitised messages the scanner stores (error type + HTTP status, never
 * raw OpenSearch text or index names).
 */
export type SlaEscalationStatusPublic = Omit<SlaEscalationStatus, 'holder'> & { holder?: string };

/** GET /sla/escalation/status. `enabled: null` = the scanner was never started on this replica. */
export interface SlaEscalationStatusResponse {
  enabled: boolean | null;
  tickSeconds: number;
  status: SlaEscalationStatusPublic | null;
}

/** GET /sla/backfill: progress of the due-date backfill a policy change schedules. */
export interface SlaDueBackfillStatus {
  /** `partial`: every pass ended with documents changed concurrently; run it again. */
  status: 'running' | 'completed' | 'partial' | 'failed' | 'skipped';
  started_at: string;
  finished_at: string | null;
  /** Last progress write of a running task (null once finished). */
  heartbeat_at?: string | null;
  updated: number;
  /** Documents the update script could not apply (bulk failures). */
  failures: number;
  /** Documents skipped by the last pass because they changed concurrently. */
  version_conflicts?: number;
  /** `updated_at` of the policy the run applied (null for the defaults). */
  policy_version: string | null;
  /** Short, index-name-free description of the failure (the full message is logged). */
  error?: string | null;
}

// Notifications (phase 1, step 1.1).
export type NotificationEvent = typeof NOTIFICATION_EVENTS[number];
export type NotificationChannelKind = typeof NOTIFICATION_CHANNEL_KINDS[number];
export type IndexerChannelWarning = typeof NOTIFICATION_CHANNEL_WARNINGS[number];

/** Binding to a channel of the indexer Notifications plugin (delivered through an inline Alerting `_execute`). */
export interface NotificationIndexerChannelConfig {
  /** `config_id` of the Notifications channel. */
  configId: string;
}

/** Direct webhook as the browser sees it: the HMAC secret is masked to `secretConfigured`. */
export interface NotificationWebhookConfig {
  url: string;
  /** Extra request headers (<= NOTIFICATION_MAX_WEBHOOK_HEADERS); the signature headers and Content-Type cannot be overridden. */
  headers?: Record<string, string>;
  /** Always 'application/json'; stored so receivers can rely on it. */
  contentType: 'application/json';
  /**
   * Relax transport security for an allowlisted receiver, exactly like
   * enrichment sources: plain http for a host on
   * WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS, and an unverified (self-signed)
   * TLS certificate only for a listed local-suffix name (.internal, .local,
   * .home.arpa). Ignored for every other host (verified HTTPS stays on).
   */
  allowInsecure?: boolean;
  /** Set by `read()` of the settings doc; never stored. */
  secretConfigured?: boolean;
}

export interface NotificationChannel {
  /** ^[a-z0-9][a-z0-9_-]{0,63}$, unique. */
  id: string;
  name: string;
  kind: NotificationChannelKind;
  enabled: boolean;
  /** Events routed to this channel (subset of NOTIFICATION_EVENTS). */
  events: NotificationEvent[];
  indexer_channel?: NotificationIndexerChannelConfig;
  webhook?: NotificationWebhookConfig;
  /**
   * Read-only. Set when the stored channel no longer passes the current
   * server policy (a webhook URL outside WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS
   * after the allowlist changed): the channel is answered `enabled: false`
   * with the reason and must be repaired or removed before the next save.
   */
  invalid?: string;
}

/** PUT payload: a webhook may carry a new plaintext `secret`; '' / absent keeps the stored one, null clears it. */
export interface NotificationWebhookInput extends Omit<NotificationWebhookConfig, 'contentType'> {
  contentType?: 'application/json';
  secret?: string | null;
}

export interface NotificationChannelInput extends Omit<NotificationChannel, 'webhook'> {
  webhook?: NotificationWebhookInput;
}

export interface NotificationSettings {
  /** Global switch: when false nothing is dispatched, bindings are kept. */
  enabled: boolean;
  channels: NotificationChannel[];
}

export interface NotificationSettingsInput {
  enabled: boolean;
  channels: NotificationChannelInput[];
}

/**
 * GET /notifications/settings. Administrators get the full (masked) document;
 * every other signed-in user gets `redacted: true` with each channel reduced to
 * `{id, name, kind, enabled, events}` (no webhook URL, headers or allowlist).
 */
export interface NotificationSettingsResponse extends NotificationSettings {
  encryptionConfigured: boolean;
  /** Hostnames from WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS on the dashboard service (informational; administrators only). */
  egressAllowedHosts?: string[];
  /** True when the caller is not an administrator and the channel configs were stripped. */
  redacted?: boolean;
  /** Build target line (4 or 5); the browser hides the other line's hints. */
  wazuhMajor: number;
  updated_at?: string;
  updated_by?: string;
}

/** One channel of the indexer Notifications plugin as listed for the picker. */
export interface IndexerChannelSummary {
  configId: string;
  name: string;
  type: string;
  isEnabled: boolean;
  warnings: IndexerChannelWarning[];
}

export type IndexerChannelsAccess = 'ok' | 'forbidden' | 'unavailable';

/** GET /notifications/channels. `forbidden` = the signed-in user lacks notifications_read_access; `unavailable` = plugin absent or unreachable. */
export interface IndexerChannelsResponse {
  channels: IndexerChannelSummary[];
  access: IndexerChannelsAccess;
  message?: string;
}

/** POST /notifications/test/{channelId}. */
export interface NotificationTestResponse {
  channelId: string;
  kind: NotificationChannelKind;
  ok: boolean;
  /** HTTP status of the receiver (webhook) or the channel's delivery status (indexer channel); null when the request never completed. */
  statusCode: number | null;
  error: string | null;
  durationMs: number;
}

// Notification outbox (phase 1, step 1.2).
export type NotificationStatus = typeof NOTIFICATION_STATUSES[number];
export type NotificationTargetType = typeof NOTIFICATION_TARGET_TYPES[number];

/** Transport response summary stored on a sent (or last failed) entry; never the receiver's body. */
export interface NotificationDelivery {
  transport: NotificationChannelKind;
  /** `x-wam-delivery` of a webhook send; the inline monitor name suffix of an indexer send. */
  deliveryId: string | null;
  statusCode: number | null;
  durationMs: number | null;
}

/**
 * One outbox entry as `GET /notifications/outbox` lists it. `payload` (the
 * allowlisted projection that was or will be sent) is only present on
 * `GET /notifications/outbox/{id}` for administrators.
 */
export interface NotificationOutboxEntry {
  id: string;
  event: NotificationEvent | 'test';
  channel_id: string;
  channel_kind: NotificationChannelKind;
  status: NotificationStatus;
  subject: string;
  target_type: NotificationTargetType;
  target_id: string;
  /** Delivery attempts made so far (kept across an administrator retry). */
  attempts: number;
  created_at: string;
  /** When the entry is next due (`pending` / `failed`); null once sent or dead. */
  next_attempt_at: string | null;
  sent_at: string | null;
  updated_at: string;
  last_error: string | null;
  last_status_code: number | null;
  delivery: NotificationDelivery | null;
  dedupe_key: string | null;
  /** Dispatcher replica holding a `sending` claim. */
  claimed_by?: string | null;
  claimed_at?: string | null;
  payload?: Record<string, any>;
}

export interface NotificationOutboxListResponse {
  items: NotificationOutboxEntry[];
  /** Opaque cursor for the next page; null on the last page. */
  next_cursor: string | null;
  /** Matching entries. */
  total: number;
}

export interface NotificationOutboxFilter {
  status?: NotificationStatus;
  channelId?: string;
  event?: NotificationEvent;
  cursor?: string;
  limit?: number;
}

export interface NotificationDispatcherStatusError {
  at: string;
  message: string;
}

/** Meta doc `notification_dispatcher_status`: the last tick of the lease holder. */
export interface NotificationDispatcherStatus {
  last_tick_at: string;
  /** Lease holder (hostname + pid); answered only to plugin administrators. */
  holder?: string;
  claimed: number;
  sent: number;
  failed: number;
  dead: number;
  /** The last ten errors across ticks, oldest first. */
  errors: NotificationDispatcherStatusError[];
}

/** GET /notifications/status. `enabled: null` = the dispatcher was never started on this replica. */
export interface NotificationStatusResponse {
  enabled: boolean | null;
  tickSeconds: number;
  status: NotificationDispatcherStatus | null;
  counts: Record<NotificationStatus, number>;
}

/** POST /notifications/outbox/{id}/retry. */
export interface NotificationRetryResponse {
  id: string;
  status: NotificationStatus;
  next_attempt_at: string | null;
  attempts: number;
}
