import { CoreStart } from '../../../../src/core/public';
import { API_ROOT, Disposition, ReportExportFormat } from '../../common';
import { AlertStatus, Case, CaseSeverity, CaseStatus, AiProvider, ReportMetrics, AttackGraph, CommentListResponse, EvidenceListResponse, CloseCaseResult, CaseIndicatorsResponse, AlertSiblingVerdictsResponse, EnrichmentSettingsResponse, EnrichmentSourceInput, EnrichmentLookupRequest, EnrichmentLookupResponse, EnrichmentTestResponse, EnrichmentVerdictFilter, AlertEnrichmentLookupResponse, AssetCriticality, AssetEntry, AssetResolution, AssetSettingsResponse, AssetContextResponse, SlaPolicy, SlaPolicyResponse, SlaState, SlaDueBackfillStatus, SlaEscalationStatusResponse, CaseAttachment, CaseAttachmentInput, CaseAttachmentListResponse, CaseTaskCounts, CaseTaskInput, CaseTaskListResponse, CaseTaskMutationResponse, CaseTaskUpdateInput, CaseTimelineResponse, TaskListApplyResponse, TaskListInput, TaskListListResponse, TaskListMutationResponse, CreateCaseTaskListOutcome, ReportSchedule, ReportSchedulesResponse, ReportScheduleLastRunResponse, ReportRunSummary, SavedObjectsBridgeStatus, IndexerChannelsResponse, NotificationSettingsInput, NotificationSettingsResponse, NotificationTestResponse, NotificationOutboxFilter, NotificationOutboxListResponse, NotificationOutboxEntry, NotificationRetryResponse, NotificationStatusResponse } from '../../common';
import {
  CorrelationRule,
  CorrelationRuleConcurrency,
  CorrelationRuleCreateRequest,
  CorrelationRuleDeleteResponse,
  CorrelationRuleListResponse,
  CorrelationRulePreview,
  CorrelationRulePreviewRequest,
  CorrelationRuleRevisionsResponse,
  CorrelationRuleUpdateRequest,
} from '../../common';

export interface BuildInfo {
  pluginVersion: string;
  buildId: string;
  builtAt: string;
  targetOsdVersion: string;
  /** Wazuh release this build targets (4.x reads alerts, 5.0 reads findings). */
  targetWazuhVersion?: string;
  targetWazuhMajor?: number;
  /** Discover/Reporting bridge outcome on the answering replica (step 5.6). */
  savedObjectsBridge?: SavedObjectsBridgeStatus;
}

export interface AutomationDlqItem {
  id: string;
  event_id: string;
  execution_id?: string;
  ruleset_snapshot?: string;
  rules_snapshot?: unknown[];
  rule_revisions?: Array<{ id: string; revision: number }>;
  alert_uid?: string;
  stage?: string;
  failed_at?: string;
  attempts?: number;
  error?: string | { message?: string; name?: string; statusCode?: number };
  payload?: { alert_uid?: string; [key: string]: unknown };
}

export interface AutomationSettings {
  paused: boolean;
  maxBacklog: number;
  maxDeferred: number;
}

export interface AutomationHealth {
  lag: number;
  oldestEvent: string | null;
  oldestAgeSeconds: number | null;
  retries: number;
  dlq: number;
  states: Record<string, number>;
  paused: boolean;
  admissionOpen: boolean;
  deferred: number;
  maxBacklog: number;
  maxDeferred: number;
  fencing: {
    generation: number | null;
    holderId: string | null;
    leaseExpiresAt: string | null;
    maxQueueGeneration: number | null;
  };
}

export interface AutomationDlqPage {
  items: AutomationDlqItem[];
  nextCursor: string | null;
}

export type SourceFamily = 'wazuh4_alerts' | 'wazuh5_findings';

/** Which native Wazuh storage this build reads and whether it is reachable. */
export interface SourceHealth {
  status: 'ready' | 'waiting' | 'blocked' | 'unknown';
  family: SourceFamily | null;
  pattern: string | null;
  mode: 'auto' | SourceFamily | null;
  eligible: SourceFamily[];
  reason: string;
  probe?: { indices: number; dataStreams: number; aliases: number; timestampMapped: boolean | null } | null;
  checkedAt?: string | null;
  build?: { targetWazuhVersion: string; targetOsdVersion: string };
  nativeReadOnly: boolean;
}

export interface SystemHealth {
  /** false when the server could not create its own stores on start. */
  provisioned?: boolean;
  counts?: Record<string, number | null>;
  sourcePattern?: string;
  source?: SourceHealth | null;
  sync?: {
    completed_at?: string;
    updated_at?: string;
    window_from?: string | null;
    window_to?: string | null;
    search_after?: unknown[] | null;
    pit_id?: string | null;
  } | null;
  automation?: AutomationHealth | null;
  [key: string]: any;
}

export interface AlertFilterParams {
  statuses?: AlertStatus[];
  levelMin?: number;
  levelMax?: number;
  ruleIds?: string[];
  agentNames?: string[];
  alertTypes?: string[];
  assignedTo?: string[];
  caseId?: string;
  /** Stored enrichment worst verdict (step 6.3); undefined = any. */
  enrichmentVerdict?: EnrichmentVerdictFilter;
  /** Stamped asset criticality (step 6.4a); empty = any. */
  assetCriticality?: AssetCriticality[];
  /** Due-date state (step 3.2): breached | due_soon | on_track; undefined = any. */
  slaState?: SlaState;
  /** Close outcome (step 2.4); empty = any. */
  disposition?: Disposition[];
  q?: string;
  from?: string;
  to?: string;
}

/** Body of `POST /cases/{id}/close` as the client sends it (step 2.4). */
export interface CloseCaseOptions {
  excludeAlertIds?: string[];
  disposition?: Disposition;
  closureReason?: string | null;
}

export interface BulkCaseUpdateResponse {
  requested: number;
  updated: number;
  failed: number;
  results: Array<{ id: string; ok: boolean; mutationApplied?: boolean; error?: string }>;
}

export type CaseListSortField = 'title' | 'severity' | 'status' | 'assigned_to' | 'created_by' | 'created_at' | 'updated_at' | 'sla_due_at';

export interface CaseListResponse {
  cases: Case[];
  total: number;
  summary?: { open: number; in_progress: number; closed: number; total: number };
}

export interface BulkAlertUpdateResponse {
  message?: string;
  requested: number;
  updated: number;
  failed?: Array<{ alertId?: string; operation?: unknown }>;
  linkage?: Array<{
    ok: boolean;
    unknownAlertIds?: string[];
    linkedAlertIds?: string[];
    unlinkedAlertIds?: string[];
    retryAlertIds?: string[];
    conflictedAlertIds?: string[];
    errors?: Array<{ alertId?: string; message?: string }>;
  }>;
}

function toFilterQuery(filters: AlertFilterParams) {
  const query: Record<string, any> = {};
  if (filters.statuses?.length) query.statuses = filters.statuses.join(',');
  if (filters.levelMin != null) query.levelMin = filters.levelMin;
  if (filters.levelMax != null) query.levelMax = filters.levelMax;
  if (filters.ruleIds?.length) query.ruleIds = filters.ruleIds.join(',');
  if (filters.agentNames?.length) query.agentNames = filters.agentNames.join(',');
  if (filters.alertTypes?.length) query.alertTypes = filters.alertTypes.join(',');
  if (filters.assignedTo?.length) query.assignedTo = filters.assignedTo.join(',');
  if (filters.caseId) query.caseId = filters.caseId;
  if (filters.enrichmentVerdict) query.enrichmentVerdict = filters.enrichmentVerdict;
  if (filters.assetCriticality?.length) query.assetCriticality = filters.assetCriticality.join(',');
  if (filters.slaState) query.slaState = filters.slaState;
  if (filters.disposition?.length) query.disposition = filters.disposition.join(',');
  if (filters.q) query.q = filters.q;
  if (filters.from) query.from = filters.from;
  if (filters.to) query.to = filters.to;
  return query;
}

/** Formats of `GET /cases/{id}/report` (step 5.2). */
export type CaseReportFormat = 'markdown' | 'html';

/** A CSV export as the browser receives it (step 5.1). */
export interface CsvExportResult {
  blob: Blob;
  /** Server-suggested attachment name (`wam-alerts-<date>.csv`). */
  filename: string;
  /** True when the server hit its row cap and dropped the remainder. */
  truncated: boolean;
}

/** Parameters of the case list that the case CSV export also accepts. */
export interface CaseFilterParams {
  status?: CaseStatus[];
  severity?: CaseSeverity[];
  assignedTo?: string[];
  /** Due-date state (step 3.2); undefined = any. */
  slaState?: SlaState;
  /** Close outcome (step 2.4); empty = any. */
  disposition?: Disposition[];
  q?: string;
  from?: string;
  to?: string;
}

function toCaseFilterQuery(params: CaseFilterParams) {
  return {
    status: params.status?.length ? params.status.join(',') : undefined,
    severity: params.severity?.length ? params.severity.join(',') : undefined,
    assignedTo: params.assignedTo?.length ? params.assignedTo.join(',') : undefined,
    slaState: params.slaState,
    disposition: params.disposition?.length ? params.disposition.join(',') : undefined,
    q: params.q,
    from: params.from,
    to: params.to,
  };
}

const CSV_MEDIA_TYPE = 'text/csv; charset=utf-8';

const REPORT_EXPORT_MEDIA_TYPE: Record<ReportExportFormat, string> = {
  html: 'text/html; charset=utf-8',
  markdown: 'text/markdown; charset=utf-8',
  csv: CSV_MEDIA_TYPE,
  json: 'application/json; charset=utf-8',
};
const REPORT_EXPORT_EXTENSION: Record<ReportExportFormat, string> = { html: 'html', markdown: 'md', csv: 'csv', json: 'json' };

function filenameFromDisposition(header: string | null, fallback: string): string {
  const match = /filename="([^"]+)"/.exec(header || '');
  return match ? match[1] : fallback;
}

/** Hand the browser a file: an object URL on a temporary anchor, revoked afterwards. */
export function downloadBlob(filename: string, blob: Blob): void {
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Revoke after the click has been dispatched; some browsers read the URL asynchronously.
  window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
}

export class AlertsApiService {
  constructor(private http: CoreStart['http']) {}

  /**
   * Core `http.fetch` (basePath + `osd-xsrf` applied) returning the raw
   * response: the CSV body is text (core only parses JSON), wrapped in a Blob.
   */
  private async fetchCsv(path: string, query: Record<string, any>, fallbackName: string): Promise<CsvExportResult> {
    const res: any = await this.http.fetch(path, { method: 'GET', query, asResponse: true });
    const body = typeof res?.body === 'string' ? res.body : res?.body instanceof Blob ? res.body : String(res?.body ?? '');
    const headers: Headers | undefined = res?.response?.headers;
    return {
      blob: body instanceof Blob ? body : new Blob([body], { type: CSV_MEDIA_TYPE }),
      filename: filenameFromDisposition(headers?.get('content-disposition') ?? null, fallbackName),
      truncated: (headers?.get('x-wam-truncated') || '').toLowerCase() === 'true',
    };
  }

  /** `GET /alerts/export.csv` with the same filters as `fetchAlerts`. */
  async exportAlertsCsv(filters: AlertFilterParams): Promise<CsvExportResult> {
    return this.fetchCsv(`${API_ROOT}/alerts/export.csv`, toFilterQuery(filters), 'wam-alerts.csv');
  }

  /** `GET /cases/export.csv` with the same filters as `fetchCases`. */
  async exportCasesCsv(params: CaseFilterParams): Promise<CsvExportResult> {
    return this.fetchCsv(`${API_ROOT}/cases/export.csv`, toCaseFilterQuery(params), 'wam-cases.csv');
  }

  /**
   * `GET /cases/{id}/report?format=` (step 5.2) as a downloadable file: the
   * server's attachment name is kept so the browser saves `wam-case-<id>-<date>.(md|html)`.
   */
  async downloadCaseReport(caseId: string, format: CaseReportFormat): Promise<CsvExportResult> {
    const path = `${API_ROOT}/cases/${encodeURIComponent(caseId)}/report`;
    const res: any = await this.http.fetch(path, { method: 'GET', query: { format }, asResponse: true });
    const type = format === 'markdown' ? 'text/markdown; charset=utf-8' : 'text/html; charset=utf-8';
    const body = typeof res?.body === 'string' ? res.body : res?.body instanceof Blob ? res.body : String(res?.body ?? '');
    const headers: Headers | undefined = res?.response?.headers;
    return {
      blob: body instanceof Blob ? body : new Blob([body], { type }),
      filename: filenameFromDisposition(headers?.get('content-disposition') ?? null, `wam-case-${caseId}.${format === 'markdown' ? 'md' : 'html'}`),
      truncated: false,
    };
  }

  /**
   * Absolute (basePath-aware) URL of the inline HTML report, for a new tab.
   * `print` makes the page call `window.print()` once it has loaded.
   */
  caseReportUrl(caseId: string, options: { print?: boolean } = {}): string {
    const query = `format=html&inline=1${options.print ? '&print=1' : ''}`;
    return this.appUrl(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/report?${query}`);
  }

  async fetchAlerts(
    filters: AlertFilterParams,
    opts: { from?: number; size?: number; sortField?: string; sortDirection?: 'asc' | 'desc' } = {}
  ) {
    return this.http.get(`${API_ROOT}/alerts`, {
      query: {
        ...toFilterQuery(filters),
        from_offset: opts.from ?? 0,
        size: opts.size ?? 20,
        sortField: opts.sortField,
        sortDirection: opts.sortDirection,
      },
    });
  }

  async fetchAlertCounts(filters: AlertFilterParams) {
    return this.http.get(`${API_ROOT}/alerts/counts`, { query: toFilterQuery(filters) });
  }

  async bulkUpdateAlerts(
    ids: string[],
    changes: { status?: AlertStatus; caseId?: string | null; assignedTo?: string | null; disposition?: Disposition; closureReason?: string | null }
  ): Promise<BulkAlertUpdateResponse> {
    return this.http.post(`${API_ROOT}/alerts/bulk-update`, {
      body: JSON.stringify({ ids, ...changes }),
    });
  }

  async fetchFilterOptions() {
    return this.http.get(`${API_ROOT}/filters/options`);
  }

  async fetchComments(target: { alertId?: string; caseId?: string }, cursor?: string): Promise<CommentListResponse> {
    return this.http.get(`${API_ROOT}/comments`, { query: { ...target, cursor } });
  }

  async addComment(target: { alertId?: string; caseId?: string }, text: string) {
    return this.http.post(`${API_ROOT}/comments`, { body: JSON.stringify({ ...target, text }) });
  }

  async deleteComment(id: string) {
    return this.http.delete(`${API_ROOT}/comments/${id}`);
  }

  async fetchCases(
    params: CaseFilterParams & {
      fromOffset?: number;
      size?: number;
      sortField?: CaseListSortField;
      sortDirection?: 'asc' | 'desc';
    } = {}
  ): Promise<CaseListResponse> {
    return this.http.get(`${API_ROOT}/cases`, {
      query: {
        ...toCaseFilterQuery(params),
        from_offset: params.fromOffset,
        size: params.size,
        sortField: params.sortField,
        sortDirection: params.sortDirection,
      },
    });
  }

  async fetchCase(id: string) {
    return this.http.get(`${API_ROOT}/cases/${id}`);
  }

  async createCase(payload: {
    title: string;
    description?: string;
    severity: CaseSeverity;
    alertIds: string[];
    assignedTo?: string | null;
    /** TaskList applied right after creation (step 2.2); the response carries `taskList: { applied, tasks_added?, error? }`. */
    taskListId?: string | null;
  }): Promise<Case & { id: string; taskList?: CreateCaseTaskListOutcome }> {
    return this.http.post(`${API_ROOT}/cases`, { body: JSON.stringify(payload) });
  }

  async updateCase(
    id: string,
    payload: {
      title?: string;
      description?: string;
      severity?: CaseSeverity;
      status?: Exclude<CaseStatus, 'closed'>;
      assignedTo?: string | null;
      addAlertIds?: string[];
      removeAlertIds?: string[];
    }
  ) {
    return this.http.put(`${API_ROOT}/cases/${id}`, { body: JSON.stringify(payload) });
  }

  async bulkUpdateCases(
    ids: string[],
    changes: { status?: Exclude<CaseStatus, 'closed'>; assignedTo?: string | null }
  ): Promise<BulkCaseUpdateResponse> {
    return this.http.post(`${API_ROOT}/cases/bulk-update`, {
      body: JSON.stringify({ ids, ...changes }),
    });
  }

  async closeCase(id: string, options: CloseCaseOptions = {}): Promise<CloseCaseResult> {
    const { excludeAlertIds = [], disposition, closureReason } = options;
    return this.http.post(`${API_ROOT}/cases/${id}/close`, {
      body: JSON.stringify({
        excludeAlertIds,
        ...(disposition ? { disposition } : {}),
        ...(closureReason !== undefined ? { closureReason } : {}),
      }),
    });
  }

  async fetchUsers(): Promise<string[]> {
    const res: any = await this.http.get(`${API_ROOT}/users`);
    return res?.users || [];
  }

  async fetchReportMetrics(from: string, to: string): Promise<ReportMetrics> {
    return this.http.get(`${API_ROOT}/reports/metrics`, { query: { from, to } });
  }

  /**
   * `GET /reports/export?format=` (step 10.3) as a downloadable file over the
   * same window the page shows; the server's attachment name is kept so the
   * browser saves `wam-report-<date>-<window>.<ext>`.
   */
  async downloadReportExport(from: string, to: string, format: ReportExportFormat): Promise<CsvExportResult> {
    const res: any = await this.http.fetch(`${API_ROOT}/reports/export`, { method: 'GET', query: { from, to, format }, asResponse: true });
    const type = REPORT_EXPORT_MEDIA_TYPE[format];
    const raw = res?.body;
    // Core parses a JSON body; every other format arrives as text.
    const body = typeof raw === 'string' ? raw : raw instanceof Blob ? raw : format === 'json' ? JSON.stringify(raw ?? null, null, 2) : String(raw ?? '');
    const headers: Headers | undefined = res?.response?.headers;
    return {
      blob: body instanceof Blob ? body : new Blob([body], { type }),
      filename: filenameFromDisposition(headers?.get('content-disposition') ?? null, `wam-report.${REPORT_EXPORT_EXTENSION[format]}`),
      truncated: false,
    };
  }

  /**
   * Absolute (basePath-aware) URL of the inline HTML export, for a new tab.
   * `print` makes the page call `window.print()` once it has loaded (the
   * browser's Save as PDF is the PDF path; no PDF library is bundled).
   */
  reportExportUrl(from: string, to: string, options: { print?: boolean } = {}): string {
    const query = new URLSearchParams({ format: 'html', inline: '1', from, to });
    if (options.print) query.set('print', '1');
    return this.appUrl(`${API_ROOT}/reports/export?${query.toString()}`);
  }

  async fetchAttackPath(caseId: string): Promise<AttackGraph> {
    return this.http.get(`${API_ROOT}/cases/${caseId}/attack-path`);
  }

  async fetchCaseIndicators(caseId: string): Promise<CaseIndicatorsResponse> {
    return this.http.get(`${API_ROOT}/cases/${caseId}/indicators`);
  }

  /** `GET /cases/{id}/attachments` (step 5.3): links and file metadata, never file bytes. */
  async fetchCaseAttachments(caseId: string): Promise<CaseAttachmentListResponse> {
    return this.http.get(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/attachments`);
  }

  /** `POST /cases/{id}/attachments`: a link, or a file as raw base64 with its allowlisted content type. */
  async addCaseAttachment(caseId: string, input: CaseAttachmentInput): Promise<{ attachment: CaseAttachment }> {
    return this.http.post(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/attachments`, { body: JSON.stringify(input) });
  }

  /** `DELETE /cases/{id}/attachments/{attachmentId}` (author or administrator). */
  async deleteCaseAttachment(caseId: string, attachmentId: string): Promise<{ deleted: boolean }> {
    return this.http.delete(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/attachments/${encodeURIComponent(attachmentId)}`);
  }

  /** Absolute (basePath-aware) download URL; the server answers with `content-disposition: attachment`. */
  caseAttachmentDownloadUrl(caseId: string, attachmentId: string): string {
    return this.appUrl(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/attachments/${encodeURIComponent(attachmentId)}/download`);
  }

  /** `GET /cases/{id}/timeline` (step 2.3): one page of the merged case timeline; pass `next_cursor` back for the next one. */
  async fetchCaseTimeline(caseId: string, options: { cursor?: string | null; limit?: number } = {}): Promise<CaseTimelineResponse> {
    const query: Record<string, string | number> = {};
    if (options.cursor) query.cursor = options.cursor;
    if (options.limit) query.limit = options.limit;
    return this.http.get(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/timeline`, { query });
  }

  /** `GET /cases/{id}/tasks` (step 2.1): the checklist sorted by order, with counts and the cap. */
  async fetchCaseTasks(caseId: string): Promise<CaseTaskListResponse> {
    return this.http.get(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/tasks`);
  }

  /** `POST /cases/{id}/tasks`: 200 with the new task and the fresh counts; 409 at the cap or on a closed case. */
  async addCaseTask(caseId: string, input: CaseTaskInput): Promise<CaseTaskMutationResponse> {
    return this.http.post(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/tasks`, { body: JSON.stringify(input) });
  }

  /** `PUT /cases/{id}/tasks/{taskId}`: partial update; `done` transitions stamp done_by / done_at server-side. */
  async updateCaseTask(caseId: string, taskId: string, input: CaseTaskUpdateInput): Promise<CaseTaskMutationResponse> {
    return this.http.put(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/tasks/${encodeURIComponent(taskId)}`, { body: JSON.stringify(input) });
  }

  /** `DELETE /cases/{id}/tasks/{taskId}` (task author, case assignee or administrator). */
  async deleteCaseTask(caseId: string, taskId: string): Promise<{ deleted: boolean; counts: CaseTaskCounts }> {
    return this.http.delete(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/tasks/${encodeURIComponent(taskId)}`);
  }

  // TaskLists (step 2.2).
  /** `GET /task-lists[?enabled=true]`: every user; `enabledOnly` keeps only task lists a case may apply. */
  async fetchTaskLists(enabledOnly = false): Promise<TaskListListResponse> {
    return this.http.get(`${API_ROOT}/task-lists`, { query: enabledOnly ? { enabled: true } : {} });
  }

  async fetchTaskList(id: string): Promise<TaskListMutationResponse> {
    return this.http.get(`${API_ROOT}/task-lists/${encodeURIComponent(id)}`);
  }

  /** `POST /task-lists` (administrator): 200 `{ task list }`; 409 on a duplicate name or the TASK_LISTS_MAX cap. */
  async createTaskList(input: TaskListInput): Promise<TaskListMutationResponse> {
    return this.http.post(`${API_ROOT}/task-lists`, { body: JSON.stringify(input) });
  }

  /** `PUT /task-lists/{id}` (administrator): whole-document replace. */
  async updateTaskList(id: string, input: TaskListInput): Promise<TaskListMutationResponse> {
    return this.http.put(`${API_ROOT}/task-lists/${encodeURIComponent(id)}`, { body: JSON.stringify(input) });
  }

  async deleteTaskList(id: string): Promise<{ deleted: boolean }> {
    return this.http.delete(`${API_ROOT}/task-lists/${encodeURIComponent(id)}`);
  }

  /** `POST /cases/{id}/task-lists/{taskListId}/apply`: idempotent per task list per case; 409 on a disabled task list, closed case or task cap. */
  async applyTaskListToCase(caseId: string, taskListId: string): Promise<TaskListApplyResponse> {
    return this.http.post(`${API_ROOT}/cases/${encodeURIComponent(caseId)}/task-lists/${encodeURIComponent(taskListId)}/apply`);
  }

  async fetchAlert(id: string) {
    return this.http.get(`${API_ROOT}/alerts/${id}`);
  }

  /** Native verdicts carried by 4.x sibling alerts (`threat.sibling_of` = this alert). */
  async fetchAlertSiblingVerdicts(alertId: string): Promise<AlertSiblingVerdictsResponse> {
    return this.http.get(`${API_ROOT}/alerts/${alertId}/sibling-verdicts`);
  }

  // Scheduled summaries (step 5.4). The list and "run now" are administrator
  // routes; the last run of a schedule is readable by any user.
  async fetchReportSchedules(): Promise<ReportSchedulesResponse> {
    return this.http.get(`${API_ROOT}/reports/schedules`);
  }

  async saveReportSchedules(payload: { schedules: ReportSchedule[] }): Promise<ReportSchedulesResponse> {
    return this.http.put(`${API_ROOT}/reports/schedules`, { body: JSON.stringify(payload) });
  }

  async fetchReportScheduleLastRun(scheduleId: string): Promise<ReportScheduleLastRunResponse> {
    return this.http.get(`${API_ROOT}/reports/schedules/${encodeURIComponent(scheduleId)}/last-run`);
  }

  async runReportScheduleNow(scheduleId: string): Promise<{ run: ReportRunSummary }> {
    return this.http.post(`${API_ROOT}/reports/schedules/${encodeURIComponent(scheduleId)}/run-now`);
  }

  /** `GET /reports/schedules/{id}/last-run.md` as a downloadable file (server attachment name kept). */
  async downloadReportScheduleLastRun(scheduleId: string): Promise<CsvExportResult> {
    const path = `${API_ROOT}/reports/schedules/${encodeURIComponent(scheduleId)}/last-run.md`;
    const res: any = await this.http.fetch(path, { method: 'GET', asResponse: true });
    const body = typeof res?.body === 'string' ? res.body : res?.body instanceof Blob ? res.body : String(res?.body ?? '');
    const headers: Headers | undefined = res?.response?.headers;
    return {
      blob: body instanceof Blob ? body : new Blob([body], { type: 'text/markdown; charset=utf-8' }),
      filename: filenameFromDisposition(headers?.get('content-disposition') ?? null, `wam-report-${scheduleId}.md`),
      truncated: false,
    };
  }

  async fetchEnrichmentSettings(): Promise<EnrichmentSettingsResponse> {
    return this.http.get(`${API_ROOT}/enrichment/settings`);
  }

  async saveEnrichmentSettings(payload: { sources: EnrichmentSourceInput[] }): Promise<EnrichmentSettingsResponse> {
    return this.http.put(`${API_ROOT}/enrichment/settings`, { body: JSON.stringify(payload) });
  }

  async lookupEnrichment(request: EnrichmentLookupRequest): Promise<EnrichmentLookupResponse> {
    const { refresh, ...body } = request;
    return this.http.post(`${API_ROOT}/enrichment/lookup`, {
      body: JSON.stringify(body),
      query: refresh ? { refresh: true } : undefined,
    });
  }

  /**
   * Look up one indicator of an alert and persist the bounded verdicts on the
   * alert record (`_source.enrichment`); the response carries the stored object.
   */
  async lookupAlertEnrichment(alertId: string, request: EnrichmentLookupRequest): Promise<AlertEnrichmentLookupResponse> {
    const { refresh, ...body } = request;
    return this.http.post(`${API_ROOT}/enrichment/alerts/${encodeURIComponent(alertId)}/lookup`, {
      body: JSON.stringify(body),
      query: refresh ? { refresh: true } : undefined,
    });
  }

  async testEnrichmentSource(sourceId: string): Promise<EnrichmentTestResponse> {
    return this.http.post(`${API_ROOT}/enrichment/test/${encodeURIComponent(sourceId)}`);
  }

  // SLA policy (step 3.1): targets per severity band; read by every signed-in user, written by administrators.
  /** GET /notifications/settings (step 1.1): masked bindings (webhook secrets are never returned). */
  async fetchNotificationSettings(): Promise<NotificationSettingsResponse> {
    return this.http.get(`${API_ROOT}/notifications/settings`);
  }

  /** PUT /notifications/settings (administrators): full replace of the channel list; `webhook.secret` ''/absent keeps, string replaces, null clears. */
  async saveNotificationSettings(payload: NotificationSettingsInput): Promise<NotificationSettingsResponse> {
    return this.http.put(`${API_ROOT}/notifications/settings`, { body: JSON.stringify(payload) });
  }

  /** GET /notifications/channels: Notifications plugin channels visible to the signed-in user (a 403 is `access: forbidden`, not an error). */
  async fetchIndexerChannels(): Promise<IndexerChannelsResponse> {
    return this.http.get(`${API_ROOT}/notifications/channels`);
  }

  /** POST /notifications/test/{channelId} (administrators): sends the fixed test payload through the saved channel as the signed-in user. */
  async testNotificationChannel(channelId: string): Promise<NotificationTestResponse> {
    return this.http.post(`${API_ROOT}/notifications/test/${encodeURIComponent(channelId)}`);
  }

  /** GET /notifications/outbox (step 1.2): newest first, cursor paging; the payload is not listed. */
  async fetchNotificationOutbox(filter: NotificationOutboxFilter = {}): Promise<NotificationOutboxListResponse> {
    const query: Record<string, string | number> = {};
    if (filter.status) query.status = filter.status;
    if (filter.channelId) query.channelId = filter.channelId;
    if (filter.event) query.event = filter.event;
    if (filter.cursor) query.cursor = filter.cursor;
    if (typeof filter.limit === 'number') query.limit = filter.limit;
    return this.http.get(`${API_ROOT}/notifications/outbox`, { query });
  }

  /** GET /notifications/outbox/{id} (administrators): one entry with its payload. */
  async fetchNotificationOutboxEntry(id: string): Promise<NotificationOutboxEntry> {
    return this.http.get(`${API_ROOT}/notifications/outbox/${encodeURIComponent(id)}`);
  }

  /** POST /notifications/outbox/{id}/retry (administrators): a failed or dead entry becomes pending, due now. */
  async retryNotification(id: string): Promise<NotificationRetryResponse> {
    return this.http.post(`${API_ROOT}/notifications/outbox/${encodeURIComponent(id)}/retry`);
  }

  /** GET /notifications/status: dispatcher status (last tick) and the outbox counts by status. */
  async fetchNotificationStatus(): Promise<NotificationStatusResponse> {
    return this.http.get(`${API_ROOT}/notifications/status`);
  }

  async fetchSlaPolicy(): Promise<SlaPolicyResponse> {
    return this.http.get(`${API_ROOT}/sla/policy`);
  }

  async saveSlaPolicy(policy: SlaPolicy): Promise<SlaPolicyResponse> {
    return this.http.put(`${API_ROOT}/sla/policy`, { body: JSON.stringify(policy) });
  }

  // Due-date backfill (step 3.2): status of the last run; administrators can run it now.
  async fetchSlaBackfillStatus(): Promise<{ status: SlaDueBackfillStatus | null }> {
    return this.http.get(`${API_ROOT}/sla/backfill`);
  }

  async runSlaBackfill(): Promise<{ status: SlaDueBackfillStatus }> {
    return this.http.post(`${API_ROOT}/sla/backfill`);
  }

  /** Escalation scanner (step 3.3): last tick of the lease holder plus this replica's config. */
  async fetchSlaEscalationStatus(): Promise<SlaEscalationStatusResponse> {
    return this.http.get(`${API_ROOT}/sla/escalation/status`);
  }

  // Asset criticality (step 6.4a): administrator-only settings + matcher check.
  async fetchAssetSettings(): Promise<AssetSettingsResponse> {
    return this.http.get(`${API_ROOT}/assets/settings`);
  }

  async saveAssetSettings(payload: { assets: AssetEntry[] }): Promise<AssetSettingsResponse> {
    return this.http.put(`${API_ROOT}/assets/settings`, { body: JSON.stringify(payload) });
  }

  /** Run the stored matcher over one agent (settings tab "Test match"); groups/labels are csv (`key=value` for labels). */
  async resolveAsset(input: { agentName?: string; groups?: string[]; labels?: string[] }): Promise<AssetResolution> {
    const query: Record<string, string> = {};
    if (input.agentName) query.agentName = input.agentName;
    if (input.groups?.length) query.groups = input.groups.join(',');
    if (input.labels?.length) query.labels = input.labels.join(',');
    return this.http.get(`${API_ROOT}/assets/resolve`, { query });
  }

  /**
   * Asset context chips (step 6.4b): read-only `wazuh-states-*` summaries for
   * one agent. Every family answers with its own status, so a missing role
   * grant is a `no_access` chip and never a failed request.
   */
  async fetchAssetContext(input: { agentId?: string | null; agentName?: string | null }): Promise<AssetContextResponse> {
    const query: Record<string, string> = {};
    if (input.agentId) query.agentId = input.agentId;
    if (input.agentName) query.agentName = input.agentName;
    return this.http.get(`${API_ROOT}/assets/context`, { query });
  }

  /** Browser URL of an app-relative dashboard path (e.g. the 5.0 CTI Explorer), honouring server.basePath. */
  appUrl(path: string): string {
    const basePath: any = (this.http as any)?.basePath;
    return typeof basePath?.prepend === 'function' ? basePath.prepend(path) : path;
  }

  async searchAlertsQuick(q: string, excludeId?: string) {
    const res: any = await this.fetchAlerts({ q }, { size: 10 });
    let hits = res?.hits?.hits || [];
    if (hits.length === 0) {
      // Might be a pasted alert ID rather than a search term.
      try {
        const exact: any = await this.fetchAlert(q.trim());
        if (exact?._id) hits = [exact];
      } catch (e) {
        // not a valid id either - leave hits empty
      }
    }
    return excludeId ? hits.filter((h: any) => h._id !== excludeId) : hits;
  }

  async fetchRelatedAlerts(alertId: string) {
    return this.http.get(`${API_ROOT}/alerts/${alertId}/related`);
  }

  async fetchSuggestedAlerts(alertId: string): Promise<{ alerts: Array<{ _id: string; _source: any; reasons: string[]; score: number }> }> {
    return this.http.get(`${API_ROOT}/alerts/${alertId}/suggested`);
  }

  async fetchPrecedent(alertId: string): Promise<{
    ruleId: string | null;
    agentName: string | null;
    ruleDescription: string | null;
    total: number;
    byStatus: { open?: number; in_progress?: number; closed?: number };
    escalatedToCase: number;
  }> {
    return this.http.get(`${API_ROOT}/alerts/${alertId}/precedent`);
  }

  async updateRelatedAlerts(alertId: string, relatedIds: string[], mode: 'add' | 'remove') {
    return this.http.post(`${API_ROOT}/alerts/${alertId}/related`, { body: JSON.stringify({ relatedIds, mode }) });
  }

  async fetchAiSettings() {
    return this.http.get(`${API_ROOT}/ai/settings`);
  }

  async saveAiSettings(payload: { enabled: boolean; provider: AiProvider; apiKey?: string; model?: string; baseUrl?: string }) {
    return this.http.post(`${API_ROOT}/ai/settings`, { body: JSON.stringify(payload) });
  }

  async analyzeAlert(alertId: string) {
    return this.http.post(`${API_ROOT}/ai/analyze`, { body: JSON.stringify({ alertId }) });
  }

  async analyzeCase(caseId: string) {
    return this.http.post(`${API_ROOT}/ai/analyze`, { body: JSON.stringify({ caseId }) });
  }

  async searchCasesQuick(q: string, excludeId?: string) {
    const res: any = await this.fetchCases({ q });
    const cases = res?.cases || [];
    return excludeId ? cases.filter((c: any) => c.id !== excludeId) : cases;
  }

  async fetchRules(): Promise<{ rules: CorrelationRule[] }> {
    const rules: CorrelationRule[] = [];
    let cursor: string | undefined;
    do {
      const page: CorrelationRuleListResponse = await this.http.get(`${API_ROOT}/rules`, {
        query: { size: 100, cursor },
      });
      rules.push(...(page.rules || []));
      cursor = page.nextCursor || undefined;
    } while (cursor);
    return { rules };
  }

  async fetchRule(id: string): Promise<CorrelationRule> {
    return this.http.get(`${API_ROOT}/rules/${id}`);
  }

  async createRule(payload: CorrelationRuleCreateRequest): Promise<CorrelationRule> {
    return this.http.post(`${API_ROOT}/rules`, { body: JSON.stringify(payload) });
  }

  async updateRule(
    id: string,
    payload: CorrelationRuleUpdateRequest,
    concurrency: CorrelationRuleConcurrency
  ): Promise<CorrelationRule> {
    return this.http.put(`${API_ROOT}/rules/${id}`, {
      body: JSON.stringify({ ...payload, ...concurrency }),
    });
  }

  async deleteRule(id: string, concurrency: CorrelationRuleConcurrency): Promise<CorrelationRuleDeleteResponse> {
    return this.http.delete(`${API_ROOT}/rules/${id}`, { query: concurrency });
  }

  async fetchRuleRevisions(
    id: string,
    page = 1,
    size = 20
  ): Promise<CorrelationRuleRevisionsResponse> {
    return this.http.get(`${API_ROOT}/rules/${id}/revisions`, { query: { page, size } });
  }

  async rollbackRule(
    id: string,
    targetRevision: number,
    concurrency: CorrelationRuleConcurrency
  ): Promise<CorrelationRule> {
    return this.http.post(`${API_ROOT}/rules/${id}/rollback/${targetRevision}`, {
      body: JSON.stringify(concurrency),
    });
  }

  async previewRule(payload: CorrelationRulePreviewRequest): Promise<CorrelationRulePreview> {
    return this.http.post(`${API_ROOT}/rules/preview`, { body: JSON.stringify(payload) });
  }

  async fetchCaseEvidence(caseId: string, cursor?: string, size = 25): Promise<EvidenceListResponse> {
    return this.http.get(`${API_ROOT}/cases/${caseId}/evidence`, { query: { cursor, size } });
  }

  async fetchCaseEvidenceAlert(caseId: string, alertId: string): Promise<any> {
    return this.http.get(`${API_ROOT}/cases/${caseId}/evidence/${alertId}`);
  }

  async setEvidenceHold(caseId: string, alertId: string, reason: string): Promise<any> {
    return this.http.put(`${API_ROOT}/cases/${caseId}/evidence/${alertId}/hold`, {
      body: JSON.stringify({ reason }),
    });
  }

  async releaseEvidenceHold(caseId: string, alertId: string): Promise<any> {
    return this.http.delete(`${API_ROOT}/cases/${caseId}/evidence/${alertId}/hold`);
  }

  async fetchSystemHealth(): Promise<SystemHealth> {
    return this.http.get(`${API_ROOT}/system/health`);
  }

  async fetchAutomationQueue(): Promise<AutomationHealth> {
    return this.http.get(`${API_ROOT}/system/automation/queue`);
  }

  async fetchAutomationSettings(): Promise<AutomationSettings> {
    return this.http.get(`${API_ROOT}/system/automation/queue/settings`);
  }

  async saveAutomationSettings(settings: AutomationSettings): Promise<AutomationSettings> {
    return this.http.put(`${API_ROOT}/system/automation/queue/settings`, {
      body: JSON.stringify(settings),
    });
  }

  async fetchAutomationDlq(limit = 25, cursor?: string): Promise<AutomationDlqPage> {
    return this.http.get(`${API_ROOT}/system/automation/dlq`, { query: { limit, cursor } });
  }

  async retryAutomationDlqEvent(eventId: string): Promise<{
    eventId: string;
    state: 'pending' | 'retry' | 'claimed' | 'completed';
    attempts?: number;
    idempotent?: boolean;
  }> {
    return this.http.post(`${API_ROOT}/system/automation/dlq/retry`, {
      body: JSON.stringify({ eventId }),
    });
  }

  async resolveAutomationDlqEvent(id: string): Promise<{ id: string; resolved: true; idempotent?: boolean }> {
    return this.http.post(`${API_ROOT}/system/automation/dlq/resolve`, {
      body: JSON.stringify({ id }),
    });
  }

  async fetchBuildInfo(): Promise<BuildInfo> {
    return this.http.get(`${API_ROOT}/system/version`, {
      query: { _: Date.now() },
    });
  }

  /** Discover/Reporting bridge outcome (step 5.6), from the version route. */
  async fetchSavedObjectsBridgeStatus(): Promise<SavedObjectsBridgeStatus | null> {
    const info = await this.fetchBuildInfo();
    return info?.savedObjectsBridge || null;
  }

  async fetchSystemCapabilities(): Promise<any> {
    return this.http.get(`${API_ROOT}/system/capabilities`);
  }

  async fetchLifecycleSettings(): Promise<any> {
    return this.http.get(`${API_ROOT}/system/lifecycle/settings`);
  }

  async fetchSyncSettings(): Promise<any> {
    return this.http.get(`${API_ROOT}/system/sync/settings`);
  }

  async saveSyncSettings(settings: { enabled: boolean; intervalSeconds: number }): Promise<any> {
    return this.http.put(`${API_ROOT}/system/sync/settings`, { body: JSON.stringify(settings) });
  }

  async saveLifecycleSettings(settings: any): Promise<any> {
    return this.http.put(`${API_ROOT}/system/lifecycle/settings`, { body: JSON.stringify(settings) });
  }

  async rolloverStorage(family: 'alerts' | 'activity' | 'cases' | 'evidence'): Promise<any> {
    return this.http.post(`${API_ROOT}/system/rollover`, { body: JSON.stringify({ family }) });
  }

  async planAlertRetirement(retiringIndex: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/retirement/plan`, {
      body: JSON.stringify({ retiringIndex }),
    });
  }

  async retireAlertGeneration(retiringIndex: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/retirement/execute`, {
      body: JSON.stringify({ retiringIndex, confirmation: retiringIndex }),
    });
  }

  async purgeRetiredAlertGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/retirement/purge`, {
      body: JSON.stringify({ index, confirmation: `PURGE ${index}` }),
    });
  }

  async restoreRetiredAlertGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/retirement/restore`, {
      body: JSON.stringify({ index, confirmation: `RESTORE ${index}` }),
    });
  }

  async retireActivityGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/activity-retirement/execute`, {
      body: JSON.stringify({ index, confirmation: index }),
    });
  }

  async purgeRetiredActivityGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/activity-retirement/purge`, {
      body: JSON.stringify({ index, confirmation: `PURGE ${index}` }),
    });
  }

  async retireEvidenceGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/evidence-retirement/execute`, {
      body: JSON.stringify({ index, confirmation: index }),
    });
  }

  async purgeRetiredEvidenceGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/evidence-retirement/purge`, {
      body: JSON.stringify({ index, confirmation: `PURGE ${index}` }),
    });
  }

  async planCaseRetirement(retiringIndex: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/cases/retirement/plan`, {
      body: JSON.stringify({ retiringIndex }),
    });
  }

  async retireCaseGeneration(retiringIndex: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/cases/retirement/execute`, {
      body: JSON.stringify({ retiringIndex, confirmation: retiringIndex }),
    });
  }

  async fetchArchivedCaseGenerations(): Promise<any[]> {
    return this.http.get(`${API_ROOT}/system/cases/archived`);
  }

  async reopenArchivedCase(caseId: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/cases/archived/${caseId}/reopen`);
  }

  async purgeArchivedCaseGeneration(index: string): Promise<any> {
    return this.http.post(`${API_ROOT}/system/cases/archived/purge`, {
      body: JSON.stringify({ index, confirmation: `PURGE ${index}` }),
    });
  }
}
