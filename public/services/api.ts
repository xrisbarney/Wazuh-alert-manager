import { CoreStart } from '../../../../src/core/public';
import { API_ROOT } from '../../common';
import { AlertStatus, Case, CaseSeverity, CaseStatus, AiProvider, ReportMetrics, AttackGraph, CommentListResponse, EvidenceListResponse, CloseCaseResult } from '../../common';
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

export interface SystemHealth {
  counts?: Record<string, number | null>;
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
  q?: string;
  from?: string;
  to?: string;
}

export interface BulkCaseUpdateResponse {
  requested: number;
  updated: number;
  failed: number;
  results: Array<{ id: string; ok: boolean; mutationApplied?: boolean; error?: string }>;
}

export type CaseListSortField = 'title' | 'severity' | 'status' | 'assigned_to' | 'created_by' | 'created_at' | 'updated_at';

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
  if (filters.q) query.q = filters.q;
  if (filters.from) query.from = filters.from;
  if (filters.to) query.to = filters.to;
  return query;
}

export class AlertsApiService {
  constructor(private http: CoreStart['http']) {}

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
    changes: { status?: AlertStatus; caseId?: string | null; assignedTo?: string | null }
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
    params: {
      status?: CaseStatus[];
      severity?: CaseSeverity[];
      assignedTo?: string[];
      q?: string;
      from?: string;
      to?: string;
      fromOffset?: number;
      size?: number;
      sortField?: CaseListSortField;
      sortDirection?: 'asc' | 'desc';
    } = {}
  ): Promise<CaseListResponse> {
    return this.http.get(`${API_ROOT}/cases`, {
      query: {
        status: params.status?.length ? params.status.join(',') : undefined,
        severity: params.severity?.length ? params.severity.join(',') : undefined,
        assignedTo: params.assignedTo?.length ? params.assignedTo.join(',') : undefined,
        q: params.q,
        from: params.from,
        to: params.to,
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
  }) {
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

  async closeCase(id: string, excludeAlertIds: string[] = []): Promise<CloseCaseResult> {
    return this.http.post(`${API_ROOT}/cases/${id}/close`, {
      body: JSON.stringify({ excludeAlertIds }),
    });
  }

  async fetchUsers(): Promise<string[]> {
    const res: any = await this.http.get(`${API_ROOT}/users`);
    return res?.users || [];
  }

  async fetchReportMetrics(from: string, to: string): Promise<ReportMetrics> {
    return this.http.get(`${API_ROOT}/reports/metrics`, { query: { from, to } });
  }

  async fetchAttackPath(caseId: string): Promise<AttackGraph> {
    return this.http.get(`${API_ROOT}/cases/${caseId}/attack-path`);
  }

  async fetchAlert(id: string) {
    return this.http.get(`${API_ROOT}/alerts/${id}`);
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

  async fetchCaseEvidence(caseId: string, cursor?: string): Promise<EvidenceListResponse> {
    return this.http.get(`${API_ROOT}/cases/${caseId}/evidence`, { query: { cursor } });
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
