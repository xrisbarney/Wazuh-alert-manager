import { REPORTING_FIELD_VERSION, slaForLevel } from './reporting_fields';
import {
  ACTIVITY_READ_ALIAS,
  ALERT_STATUS_INDEX,
  CASES_INDEX,
  DEFAULT_DISPOSITION,
  DISPOSITIONS,
  DISPOSITION_RULE_BUCKETS_MAX,
  SLA_BANDS,
  SLA_BREACHED_ACTION,
  SLA_ESCALATED_ACTION,
} from '../../common/constants';
import type {
  Disposition,
  FalsePositiveByRuleRow,
  SlaBand,
  SlaBreachesInPeriod,
  SlaCurrentlyBreached,
  SlaEscalationTarget,
  SlaEscalationsInPeriod,
  SlaPolicy,
} from '../../common/types';
import { effectiveLevel } from '../../common/severity';
import { bandClause, thresholdInstant } from './sla/escalation';

export interface ReportHistoryEntry {
  timestamp: string;
  user?: string | null;
  action: string;
  from?: string | null;
  to?: string | null;
}

const REPORT_SCROLL_KEEP_ALIVE = '2m';
export const REPORT_ALERT_SAMPLE_SORT = [
  { '@timestamp': { order: 'asc' } },
  { alert_uid: { order: 'asc' } },
];

/** Collect every hit from a report query and always release its scroll context. */
export async function collectReportHits(client: any, request: any): Promise<any[]> {
  const hits: any[] = [];
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({ ...request, scroll: REPORT_SCROLL_KEEP_ALIVE });
    while (true) {
      scrollId = page?.body?._scroll_id || scrollId;
      const pageHits = page?.body?.hits?.hits || [];
      if (!pageHits.length) break;
      hits.push(...pageHits);
      page = await client.scroll({ scrollId, scroll: REPORT_SCROLL_KEEP_ALIVE });
    }
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // Expired scroll contexts do not affect the completed report.
      }
    }
  }
  return hits;
}

export async function loadReportActivity(
  client: any,
  index: string,
  alertIds: string[]
): Promise<Record<string, ReportHistoryEntry[]>> {
  if (!alertIds.length) return {};
  const hits = await collectReportHits(client, {
    index,
    size: 1000,
    body: {
      query: {
        bool: {
          filter: [
            { term: { event_type: 'audit' } },
            { term: { target_type: 'alert' } },
            { terms: { target_id: alertIds } },
          ],
        },
      },
      sort: ['_doc'],
    },
  });
  const byAlert: Record<string, ReportHistoryEntry[]> = {};
  for (const hit of hits) {
    const event = hit._source;
    if (!event?.target_id) continue;
    (byAlert[event.target_id] || (byAlert[event.target_id] = [])).push(event);
  }
  return byAlert;
}

export async function loadReportActivityCoverage(
  client: any,
  index: string,
  alertIds: string[]
): Promise<{ byAlert: Record<string, ReportHistoryEntry[]>; truncated: boolean }> {
  try {
    return { byAlert: await loadReportActivity(client, index, alertIds), truncated: false };
  } catch (e) {
    return { byAlert: {}, truncated: true };
  }
}

function eventKey(event: ReportHistoryEntry): string {
  return [event.timestamp, event.user || '', event.action, event.from || '', event.to || ''].join('\u0000');
}

/** Merge compatibility history with v2 activity without dropping either source. */
export function mergeReportHistory(
  embedded: ReportHistoryEntry[] = [],
  activity: ReportHistoryEntry[] = [],
  throughMs: number = Number.POSITIVE_INFINITY
): ReportHistoryEntry[] {
  const merged = new Map<string, ReportHistoryEntry>();
  for (const event of [...embedded, ...activity]) {
    const timestamp = Date.parse(event?.timestamp || '');
    if (!event?.action || !Number.isFinite(timestamp) || timestamp > throughMs) continue;
    merged.set(eventKey(event), event);
  }
  return Array.from(merged.values()).sort((a, b) => {
    const timestampOrder = Date.parse(a.timestamp) - Date.parse(b.timestamp);
    return timestampOrder || eventKey(a).localeCompare(eventKey(b));
  });
}

export interface AlertTimingMetrics {
  resolveMinutes: number | null;
  assignMinutes: number | null;
  assigneeAtClose: string | null;
  firstAssignedAt: string | null;
  closedAt: string | null;
}

export function deriveAlertTiming(
  source: any,
  activity: ReportHistoryEntry[] = [],
  throughMs: number = Number.POSITIVE_INFINITY
): AlertTimingMetrics {
  const occurredAt = Date.parse(source?.['@timestamp'] || '');
  const history = mergeReportHistory(source?.history || [], activity, throughMs);
  const assignments = history.filter((event) => event.action === 'assignment_change' && event.to);
  const firstAssignment = assignments[0];
  const assignMinutes = firstAssignment && Number.isFinite(occurredAt)
    ? Math.max(0, (Date.parse(firstAssignment.timestamp) - occurredAt) / 60000)
    : null;

  // Current state must still be closed. A close followed by reopen is not a
  // resolved alert and must not remain in MTTR/SLA merely because close history exists.
  if (source?.status !== 'closed') {
    return {
      resolveMinutes: null,
      assignMinutes,
      assigneeAtClose: null,
      firstAssignedAt: firstAssignment?.timestamp || null,
      closedAt: null,
    };
  }
  const closes = history.filter(
    (event) => (event.action === 'status_change' || event.action === 'case_closed') && event.to === 'closed'
  );
  const close = closes[closes.length - 1];
  if (!close || !Number.isFinite(occurredAt)) {
    return {
      resolveMinutes: null,
      assignMinutes,
      assigneeAtClose: null,
      firstAssignedAt: firstAssignment?.timestamp || null,
      closedAt: null,
    };
  }
  const closedAt = Date.parse(close.timestamp);
  const resolveMinutes = closedAt >= occurredAt ? (closedAt - occurredAt) / 60000 : null;
  const assignmentAtClose = assignments.filter((event) => Date.parse(event.timestamp) <= closedAt).pop();
  const reassignedAfterClose = assignments.some((event) => Date.parse(event.timestamp) > closedAt);
  return {
    resolveMinutes,
    assignMinutes,
    assigneeAtClose: assignmentAtClose?.to || (reassignedAfterClose ? null : source?.assigned_to) || null,
    firstAssignedAt: firstAssignment?.timestamp || null,
    closedAt: close.timestamp,
  };
}

/**
 * Derive the complete write-time `reporting` object for an alert that predates
 * the reporting-field schema, so the resumable backfill can materialize exact
 * timing/SLA fields from embedded history and the append-only activity store.
 */
export function deriveAlertReporting(
  source: any,
  activity: ReportHistoryEntry[] = [],
  throughMs: number = Number.POSITIVE_INFINITY,
  policy?: SlaPolicy | null
): Record<string, any> {
  const timing = deriveAlertTiming(source, activity, throughMs);
  // 4.x: the numeric level. 5.0: the lowest level of the label's band, so a
  // label never claims a stricter SLA tier than the equivalent 4.x alert.
  const level = effectiveLevel(source) ?? 0;
  const tier = slaForLevel(level, policy);
  const reporting: Record<string, any> = {
    first_assigned_at: timing.firstAssignedAt,
    assign_minutes: timing.assignMinutes,
    closed_at: timing.closedAt,
    resolve_minutes: timing.resolveMinutes,
    assignee_at_close: timing.assigneeAtClose,
    sla_tier: timing.resolveMinutes != null ? tier.label : null,
    sla_met:
      timing.resolveMinutes != null ? timing.resolveMinutes <= tier.targetMinutes : null,
    reporting_version: REPORTING_FIELD_VERSION,
  };
  return reporting;
}

export interface CompositeBucketRequest {
  index: string;
  query: any;
  /** { composite: { size, sources }, aggs: { ... } } — sub-aggregations ride along. */
  bucket: any;
}

/**
 * Paginate a composite aggregation to completion so per-analyst (or other
 * high-cardinality) buckets are never truncated to a top-N. Composite
 * aggregation is deterministic and returns a bounded page plus an after_key.
 */
export async function collectCompositeBuckets(
  client: any,
  request: CompositeBucketRequest
): Promise<any[]> {
  const buckets: any[] = [];
  let afterKey: any = undefined;
  while (true) {
    const bucketSpec: any = { ...request.bucket };
    if (afterKey) {
      bucketSpec.composite = { ...bucketSpec.composite, after: afterKey };
    }
    const res: any = await client.search({
      index: request.index,
      body: { size: 0, query: request.query, aggs: { bucket: bucketSpec } },
    });
    const agg = res?.body?.aggregations?.bucket;
    const pageBuckets = agg?.buckets || [];
    buckets.push(...pageBuckets);
    if (!pageBuckets.length || !agg?.after_key) break;
    afterKey = agg.after_key;
  }
  return buckets;
}

// ---------------------------------------------------------------------------
// SLA enforcement figures (step 3.4). Pure request builders and parsers; the
// collector in report_schedules/metrics.ts runs them. Every count is an exact
// aggregation (`track_total_hits`, filter buckets, bounded terms buckets).
// ---------------------------------------------------------------------------

export const SLA_ESCALATION_BUCKETS_MAX = 50;

/** Alerts: the two active statuses. Cases: anything not closed (the breach pass uses the same clauses). */
function activeStatusClause(target: SlaEscalationTarget): any {
  return target === 'alert'
    ? { terms: { status: ['open', 'in_progress'] } }
    : { bool: { must_not: [{ term: { status: 'closed' } }] } };
}

const DUE_FIELD: Record<SlaEscalationTarget, string> = { alert: 'reporting.sla_due_at', case: 'sla_due_at' };
const READ_INDEX: Record<SlaEscalationTarget, string> = { alert: ALERT_STATUS_INDEX, case: CASES_INDEX };

/**
 * "Currently breached" is bound to `now`, never to the report range: active
 * records that carry the scanner's `sla.breached_at` stamp OR whose resolve
 * due date has passed (the scanner may not have ticked yet). The per-band
 * filters reuse the scanner's band clause so a 5.0 label and a 4.x level land
 * in the same band here as in the escalation pass.
 *
 * Cases written before step 3.2 carry no `sla_due_at` (the due backfill covers
 * alerts only). With a policy the case query therefore also accepts, exactly
 * like the scanner's `breachQuery`, a record without `sla_due_at` whose
 * `created_at` plus its band's resolve target has passed, so the figure does
 * not depend on the scanner being enabled or having ticked.
 */
export function slaCurrentlyBreachedRequest(
  target: SlaEscalationTarget,
  now: string,
  policy?: SlaPolicy | null
): any {
  const byBand: Record<string, any> = {};
  for (const band of SLA_BANDS) byBand[band] = bandClause(target, band);
  const should: any[] = [{ exists: { field: 'sla.breached_at' } }, { range: { [DUE_FIELD[target]]: { lt: now } } }];
  if (target === 'case' && policy) {
    for (const band of SLA_BANDS) {
      should.push({
        bool: {
          filter: [bandClause('case', band), { range: { created_at: { lte: thresholdInstant(policy, band, 100, now) } } }],
          must_not: [{ exists: { field: 'sla_due_at' } }],
        },
      });
    }
  }
  return {
    index: READ_INDEX[target],
    ignore_unavailable: true,
    allow_no_indices: true,
    body: {
      size: 0,
      track_total_hits: true,
      query: {
        bool: {
          filter: [activeStatusClause(target), { bool: { should, minimum_should_match: 1 } }],
        },
      },
      aggs: { by_band: { filters: { filters: byBand } } },
    },
  };
}

export function parseSlaCurrentlyBreached(alertResult: any, caseResult: any, now: string): SlaCurrentlyBreached {
  const byBand = Object.fromEntries(SLA_BANDS.map((band) => [band, 0])) as Record<SlaBand, number>;
  for (const result of [alertResult, caseResult]) {
    const buckets = result?.body?.aggregations?.by_band?.buckets || {};
    for (const band of SLA_BANDS) byBand[band] += buckets[band]?.doc_count ?? 0;
  }
  return {
    asOf: now,
    alerts: alertResult?.body?.hits?.total?.value ?? 0,
    cases: caseResult?.body?.hits?.total?.value ?? 0,
    byBand,
  };
}

/**
 * The scanner's `sla_breached` / `sla_escalated` audit events whose
 * `timestamp` is in the report range. The activity mapping keeps `details`
 * unindexed (`enabled: false`), so the escalation is read from the indexed
 * keywords the event carries: `from` = escalation id, `to` = escalation
 * name (`applyEscalation`); breaches are split by `target_type`. Bounded:
 * at most `SLA_ESCALATION_BUCKETS_MAX` rules (the policy holds 20).
 */
export function slaEventsInPeriodRequest(range: { from: string; to: string }): any {
  return {
    index: ACTIVITY_READ_ALIAS,
    // A missing or retired activity alias answers zero events instead of
    // failing the whole metrics response (the Overview never depended on it).
    ignore_unavailable: true,
    allow_no_indices: true,
    body: {
      size: 0,
      query: {
        bool: {
          filter: [
            { term: { event_type: 'audit' } },
            { terms: { action: [SLA_BREACHED_ACTION, SLA_ESCALATED_ACTION] } },
            { range: { timestamp: { gte: range.from, lte: range.to } } },
          ],
        },
      },
      aggs: {
        breaches: {
          filter: { term: { action: SLA_BREACHED_ACTION } },
          aggs: { by_target: { terms: { field: 'target_type', size: 2 } } },
        },
        escalations: {
          filter: { term: { action: SLA_ESCALATED_ACTION } },
          aggs: {
            by_escalation: {
              terms: { field: 'from', size: SLA_ESCALATION_BUCKETS_MAX, missing: '' },
              aggs: { name: { terms: { field: 'to', size: 1 } } },
            },
          },
        },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Dispositions (step 2.4). One exact, bounded aggregation over the alerts
// closed in the report range: `status: closed` AND `reporting.closed_at` in
// the range (the write-time close stamp every close path merges; a reopen
// clears it, so a reopened alert is not "closed in period"). A closed alert
// without a stored disposition (closed before this step, or through a client
// that sent none) counts as `undetermined` through the `missing` bucket.
// ---------------------------------------------------------------------------

export function dispositionsRequest(range: { from: string; to: string }): any {
  const byDisposition = {
    terms: { field: 'disposition', size: DISPOSITIONS.length, missing: DEFAULT_DISPOSITION },
  };
  return {
    index: ALERT_STATUS_INDEX,
    ignore_unavailable: true,
    allow_no_indices: true,
    body: {
      size: 0,
      track_total_hits: true,
      query: {
        bool: {
          filter: [
            { term: { status: 'closed' } },
            { range: { 'reporting.closed_at': { gte: range.from, lte: range.to } } },
          ],
        },
      },
      aggs: {
        by_disposition: byDisposition,
        by_rule: {
          terms: { field: 'rule.id', size: DISPOSITION_RULE_BUCKETS_MAX },
          aggs: {
            description: { terms: { field: 'rule.description.keyword', size: 1 } },
            by_disposition: byDisposition,
          },
        },
      },
    },
  };
}

function dispositionCounts(buckets: any[] = []): Record<Disposition, number> {
  const counts = Object.fromEntries(DISPOSITIONS.map((value) => [value, 0])) as Record<Disposition, number>;
  for (const bucket of buckets) {
    const key = String(bucket?.key ?? '');
    if ((DISPOSITIONS as readonly string[]).includes(key)) counts[key as Disposition] += bucket.doc_count ?? 0;
    else counts[DEFAULT_DISPOSITION] += bucket.doc_count ?? 0;
  }
  return counts;
}

export function parseDispositions(result: any): { dispositions: Record<Disposition, number>; falsePositiveByRule: FalsePositiveByRuleRow[] } {
  const aggs = result?.body?.aggregations || {};
  const dispositions = dispositionCounts(aggs.by_disposition?.buckets || []);
  const falsePositiveByRule: FalsePositiveByRuleRow[] = (aggs.by_rule?.buckets || []).map((bucket: any) => {
    const closed = bucket.doc_count ?? 0;
    const counts = dispositionCounts(bucket.by_disposition?.buckets || []);
    const description = bucket.description?.buckets?.[0]?.key;
    return {
      rule_id: String(bucket.key ?? ''),
      description: description != null && description !== '' ? String(description) : null,
      closed,
      false_positive: counts.false_positive,
      rate: closed > 0 ? counts.false_positive / closed : 0,
    };
  });
  return { dispositions, falsePositiveByRule };
}

export function parseSlaEventsInPeriod(result: any): { breaches: SlaBreachesInPeriod; escalations: SlaEscalationsInPeriod } {
  const aggs = result?.body?.aggregations || {};
  const breaches: SlaBreachesInPeriod = { total: aggs.breaches?.doc_count ?? 0, alerts: 0, cases: 0 };
  for (const bucket of aggs.breaches?.by_target?.buckets || []) {
    if (bucket.key === 'alert') breaches.alerts = bucket.doc_count ?? 0;
    else if (bucket.key === 'case') breaches.cases = bucket.doc_count ?? 0;
  }
  const byEscalation = (aggs.escalations?.by_escalation?.buckets || []).map((bucket: any) => {
    const id = String(bucket.key ?? '');
    const name = bucket.name?.buckets?.[0]?.key;
    return { id, name: name != null && name !== '' ? String(name) : id, count: bucket.doc_count ?? 0 };
  });
  return {
    breaches,
    escalations: { total: aggs.escalations?.doc_count ?? 0, byEscalation },
  };
}
