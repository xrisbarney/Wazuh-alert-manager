import { REPORTING_FIELD_VERSION, slaForLevel } from './reporting_fields';

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
  throughMs: number = Number.POSITIVE_INFINITY
): Record<string, any> {
  const timing = deriveAlertTiming(source, activity, throughMs);
  const level = source?.rule?.level != null ? Number(source.rule.level) : 0;
  const tier = slaForLevel(level);
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
