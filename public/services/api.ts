import { CoreStart } from '../../../../src/core/public';
import { API_ROOT } from '../../common';
import { AlertStatus, CaseSeverity, CaseStatus, AiProvider, ReportMetrics, AttackGraph } from '../../common';

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

  async bulkUpdateAlerts(ids: string[], changes: { status?: AlertStatus; caseId?: string | null; assignedTo?: string | null }) {
    return this.http.post(`${API_ROOT}/alerts/bulk-update`, {
      body: JSON.stringify({ ids, ...changes }),
    });
  }

  async fetchFilterOptions() {
    return this.http.get(`${API_ROOT}/filters/options`);
  }

  async fetchComments(target: { alertId?: string; caseId?: string }) {
    return this.http.get(`${API_ROOT}/comments`, { query: target });
  }

  async addComment(target: { alertId?: string; caseId?: string }, text: string) {
    return this.http.post(`${API_ROOT}/comments`, { body: JSON.stringify({ ...target, text }) });
  }

  async deleteComment(id: string) {
    return this.http.delete(`${API_ROOT}/comments/${id}`);
  }

  async fetchCases(params: { status?: CaseStatus[]; assignedTo?: string[]; q?: string; from?: string; to?: string } = {}) {
    return this.http.get(`${API_ROOT}/cases`, {
      query: {
        status: params.status?.length ? params.status.join(',') : undefined,
        assignedTo: params.assignedTo?.length ? params.assignedTo.join(',') : undefined,
        q: params.q,
        from: params.from,
        to: params.to,
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
      status?: CaseStatus;
      assignedTo?: string | null;
      addAlertIds?: string[];
      removeAlertIds?: string[];
    }
  ) {
    return this.http.put(`${API_ROOT}/cases/${id}`, { body: JSON.stringify(payload) });
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
}
