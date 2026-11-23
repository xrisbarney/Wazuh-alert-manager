import { CASE_TIMELINE_ALERTS_MAX, CASE_TIMELINE_PAGE } from '../../common';
import { CaseTimelineEntry, CaseTimelineResponse } from '../../common/types';
import { severityBandOf } from '../../common/severity';
import { ActivitySortValue, queryCaseActivity } from './activity';
import { ResolvedCaseDocument, resolveCase } from './case_index_resolution';
import { collectCaseEvidence } from './evidence';
import { ResolvedCaseAlert, resolveAlerts } from './index_resolution';

/**
 * Case timeline (PLAN.md step 2.3): one chronological list per case merging
 *
 *  - the `@timestamp` of every linked alert (evidence, cap
 *    `CASE_TIMELINE_ALERTS_MAX`; the cut is reported as `truncated_alerts`),
 *    read from the bounded evidence `snapshot` (the fields an entry needs);
 *    only legacy relationships without a snapshot are looked up live, and
 *    only when their timestamp is unknown or past the cursor boundary,
 *  - comments and audit events of the case from the activity alias (every
 *    action, no filter: status / assignment changes, `task_*`,
 *    `task_list_applied`, `sla_breached` / `sla_escalated`, `attachment_*`, ...),
 *  - the due date of every open task of the case (`task_due`).
 *
 * Entries are ordered by `at`, then `id`. Paging uses an opaque cursor scoped
 * to the case: activity is read with `search_after` from the last activity
 * hit the previous pages consumed, alerts and task dues (bounded, loaded per
 * page) are filtered by the `(at, id)` boundary of the last entry served. A
 * page therefore never loads more activity than it needs, and the ordering
 * stays stable while new events arrive (they only ever land after the
 * boundary or are skipped, never duplicated). Alerts and task dues are
 * re-read on every page (one evidence walk of at most
 * `CASE_TIMELINE_ALERTS_MAX` rows, no per-alert lookups), the bounded cost
 * of a cursor that stays independent of the alert source. Nothing here writes.
 */

/** Hard ceiling of one page; the report reads two pages of 250 for its cap of 500. */
export const CASE_TIMELINE_LIMIT_MAX = 500;

const CURSOR_VERSION = 1;
const TEXT_LIMIT = 2000;

export interface CaseTimelineCursor {
  v: number;
  case: string;
  /** Boundary: the last entry served, exclusive. */
  at: string;
  id: string;
  sources: {
    /** `search_after` of the activity source: sort values (`[created_at millis, event_uid | null]`) of the last activity hit consumed. */
    activity_after?: ActivitySortValue[];
    /** `[at, alert_id]` of the last alert entry served (informational; the boundary above governs). */
    alert_after?: [string, string];
  };
}

export interface CollectCaseTimelineOptions {
  cursor?: string | null;
  /** Page size, 1..CASE_TIMELINE_LIMIT_MAX; default CASE_TIMELINE_PAGE. */
  limit?: number;
  /** Already-resolved case document (the report resolves it once); resolved here when omitted. */
  caseDoc?: ResolvedCaseDocument;
  /** Already-resolved alerts of the case plus whether their evidence walk was cut; paged and resolved here when omitted. */
  alerts?: { items: ResolvedCaseAlert[]; truncated: boolean };
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

function base64UrlEncode(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value: string): string {
  const normalised = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

function cursorError(): Error {
  const error: any = new Error('Invalid or mismatched timeline cursor.');
  error.statusCode = 400;
  return error;
}

export function encodeTimelineCursor(cursor: Omit<CaseTimelineCursor, 'v'>): string {
  return base64UrlEncode(JSON.stringify({ v: CURSOR_VERSION, ...cursor }));
}

/** Decode a cursor; a malformed cursor or one issued for another case is a 400. */
export function decodeTimelineCursor(cursor: string | null | undefined, caseId: string): CaseTimelineCursor | null {
  if (cursor == null || cursor === '') return null;
  let parsed: any;
  try {
    parsed = JSON.parse(base64UrlDecode(String(cursor)));
  } catch (e) {
    throw cursorError();
  }
  const sortValue = (value: unknown) => typeof value === 'string' || typeof value === 'number' || value === null;
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    parsed.v !== CURSOR_VERSION ||
    typeof parsed.case !== 'string' ||
    typeof parsed.at !== 'string' ||
    typeof parsed.id !== 'string' ||
    !parsed.sources ||
    typeof parsed.sources !== 'object' ||
    (parsed.sources.activity_after !== undefined &&
      (!Array.isArray(parsed.sources.activity_after) || !parsed.sources.activity_after.every(sortValue))) ||
    (parsed.sources.alert_after !== undefined &&
      (!Array.isArray(parsed.sources.alert_after) ||
        parsed.sources.alert_after.length !== 2 ||
        !parsed.sources.alert_after.every((value: unknown) => typeof value === 'string')))
  ) {
    throw cursorError();
  }
  if (parsed.case !== caseId) throw cursorError();
  return {
    v: CURSOR_VERSION,
    case: parsed.case,
    at: parsed.at,
    id: parsed.id,
    sources: {
      ...(parsed.sources.activity_after ? { activity_after: parsed.sources.activity_after } : {}),
      ...(parsed.sources.alert_after ? { alert_after: parsed.sources.alert_after } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Entry builders
// ---------------------------------------------------------------------------

function text(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null;
}

function clampText(value: string | null): string | null {
  if (value == null) return null;
  return value.length > TEXT_LIMIT ? `${value.slice(0, TEXT_LIMIT)}… [truncated]` : value;
}

/** ISO form of a stored timestamp (string or epoch millis); null when unparseable. */
function isoOf(value: unknown): string | null {
  if (value == null || value === '') return null;
  const ms = typeof value === 'number' ? value : Date.parse(String(value));
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

/** Ordering of the timeline: `at` then `id` (both plain string comparisons on ISO / stable ids). */
export function compareTimelineEntries(a: { at: string; id: string }, b: { at: string; id: string }): number {
  if (a.at !== b.at) return a.at < b.at ? -1 : 1;
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

function isAfterBoundary(entry: { at: string; id: string }, boundary: { at: string; id: string } | null): boolean {
  return !boundary || compareTimelineEntries(entry, boundary) > 0;
}

/** The wording of an audit event, shared with the case report (`action: from → to`). */
export function describeAuditEvent(source: any): string {
  const action = text(source?.action) || 'event';
  const from = text(source?.from);
  const to = text(source?.to);
  const label = action.replace(/_/g, ' ');
  if (from != null && to != null) return `${label}: ${from} → ${to}`;
  if (to != null) return `${label}: ${to}`;
  if (from != null) return `${label} (was ${from})`;
  return label;
}

/** Secondary line of an audit event from its unindexed `details`, when they say something the title does not. */
function auditDetails(source: any): string | null {
  const details = source?.details;
  if (!details || typeof details !== 'object') return null;
  const parts: string[] = [];
  const action = text(source?.action) || '';
  if (action === 'task_list_applied') {
    const added = details.tasks_added;
    if (typeof added === 'number') parts.push(`${added} task${added === 1 ? '' : 's'} added`);
  } else if (action.startsWith('task_')) {
    const owner = text(details.owner);
    if (owner) parts.push(`owner ${owner}`);
    const due = isoOf(details.due_at);
    if (due) parts.push(`due ${due}`);
  } else if (action === 'sla_escalated') {
    const name = text(details.escalation?.name) || text(details.escalation_id) || text(details.escalation?.id);
    if (name) parts.push(`escalation ${name}`);
  } else if (action === 'enrichment_lookup') {
    const verdict = text(details.worst_verdict) || text(details.verdict);
    if (verdict) parts.push(`verdict ${verdict}`);
  }
  return parts.length ? clampText(parts.join(' · ')) : null;
}

export function activityEntry(hit: any): CaseTimelineEntry | null {
  const source = hit?._source || {};
  const id = text(hit?._id);
  // `created_at` first: it is the field every activity document carries and
  // the one `queryCaseActivity` sorts on, so the merge order is the page order.
  const at = isoOf(source.created_at) || isoOf(source.timestamp);
  if (!id || !at) return null;
  if (source.event_type === 'comment') {
    return {
      id: `activity:${id}`,
      kind: 'comment',
      at,
      actor: text(source.author) || text(source.user),
      title: 'Comment',
      details: clampText(text(source.text)) || '',
      ref: { activity_id: id },
    };
  }
  return {
    id: `activity:${id}`,
    kind: 'audit',
    at,
    actor: text(source.user) || text(source.author),
    title: describeAuditEvent(source),
    details: auditDetails(source),
    ref: { activity_id: id },
    action: text(source.action),
  };
}

export function alertEntry(alert: { id: string; source: any }): CaseTimelineEntry | null {
  const s = alert?.source || {};
  const at = isoOf(s['@timestamp']);
  if (!at) return null;
  const band = severityBandOf(s);
  const ruleId = text(s.rule?.id);
  const level = typeof s.rule?.level === 'number' ? s.rule.level : null;
  const parts = [
    ruleId ? `rule ${ruleId}` : null,
    text(s.agent?.name) ? `on ${text(s.agent?.name)}` : null,
    band ? `${band}${level != null ? ` (${level})` : ''}` : null,
  ].filter(Boolean) as string[];
  return {
    id: `alert:${alert.id}`,
    kind: 'alert',
    at,
    actor: null,
    title: clampText(text(s.rule?.description)) || `Alert ${alert.id}`,
    details: parts.length ? parts.join(' · ') : null,
    ref: { alert_id: alert.id },
    severity_band: band,
  };
}

/** `task_due` entries of every open task that carries a due date. */
export function taskDueEntries(tasks: unknown): CaseTimelineEntry[] {
  if (!Array.isArray(tasks)) return [];
  const out: CaseTimelineEntry[] = [];
  for (const task of tasks) {
    if (!task || typeof task !== 'object') continue;
    const t: any = task;
    if (t.done === true) continue;
    const id = text(t.id);
    const at = isoOf(t.due_at);
    if (!id || !at) continue;
    out.push({
      id: `task_due:${id}`,
      kind: 'task_due',
      at,
      actor: text(t.owner),
      title: `Task due: ${clampText(text(t.title)) || '(untitled task)'}`,
      details: text(t.owner) ? `owner ${text(t.owner)}` : null,
      ref: { task_id: id },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/**
 * Alert sources for the entries of a page from the evidence rows: the stored
 * `snapshot` carries exactly what `alertEntry` reads (`@timestamp`, `rule`,
 * `agent`, `severity_label`), so no alert is fetched for it. A legacy
 * relationship (`alert_ids` fallback, `snapshot: null`) is looked up live in
 * one `ids` query; its archive is never walked here (the report's
 * `resolveCaseAlerts` still does that for its own listing). Rows whose
 * snapshot timestamp is at or before the boundary are dropped before any
 * lookup: they can never appear on this page.
 */
async function alertsFromEvidence(
  client: any,
  evidence: any[],
  boundary: { at: string; id: string } | null
): Promise<Array<{ id: string; source: any }>> {
  const out: Array<{ id: string; source: any }> = [];
  const seen = new Set<string>();
  const missing: string[] = [];
  for (const row of evidence) {
    const id = text(row?.alert_id);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const snapshot = row?.snapshot;
    if (snapshot && typeof snapshot === 'object') {
      const at = isoOf(snapshot['@timestamp']);
      if (at && !isAfterBoundary({ at, id: `alert:${id}` }, boundary)) continue;
      out.push({ id, source: snapshot });
    } else {
      missing.push(id);
    }
  }
  if (missing.length) {
    const live: Map<string, any> = await resolveAlerts(client, missing, true);
    for (const id of missing) {
      const hit = live.get(id);
      if (hit?.source) out.push({ id, source: hit.source });
    }
  }
  return out;
}

/**
 * One page of the case timeline. Throws `{ statusCode: 404 }` for an unknown
 * case and `{ statusCode: 400 }` for a malformed or foreign cursor.
 */
export async function collectCaseTimeline(
  client: any,
  caseId: string,
  options: CollectCaseTimelineOptions = {}
): Promise<CaseTimelineResponse> {
  const limit = Math.max(1, Math.min(Math.floor(options.limit ?? CASE_TIMELINE_PAGE), CASE_TIMELINE_LIMIT_MAX));
  const cursor = decodeTimelineCursor(options.cursor, caseId);
  const boundary = cursor ? { at: cursor.at, id: cursor.id } : null;

  const caseDoc = options.caseDoc ?? (await resolveCase(client, caseId));
  const caseSource = caseDoc.source || {};

  // Alerts: bounded, loaded per page, filtered by the boundary.
  let resolvedAlerts: Array<{ id: string; source: any }>;
  let truncatedAlerts: boolean;
  if (options.alerts) {
    resolvedAlerts = options.alerts.items;
    truncatedAlerts = options.alerts.truncated;
  } else {
    const { evidence, truncated } = await collectCaseEvidence(client, caseId, caseSource.alert_ids, { limit: CASE_TIMELINE_ALERTS_MAX });
    resolvedAlerts = await alertsFromEvidence(client, evidence, boundary);
    truncatedAlerts = truncated;
  }
  const candidates: CaseTimelineEntry[] = [];
  for (const alert of resolvedAlerts) {
    const entry = alertEntry(alert);
    if (entry && isAfterBoundary(entry, boundary)) candidates.push(entry);
  }
  for (const entry of taskDueEntries(caseSource.tasks)) {
    if (isAfterBoundary(entry, boundary)) candidates.push(entry);
  }

  // Activity: search_after from the last hit consumed by the previous pages.
  const activity = await queryCaseActivity(client, caseId, { after: cursor?.sources.activity_after ?? null, limit });
  const activitySorts = new Map<string, Array<string | number>>();
  for (const hit of activity.hits) {
    const entry = activityEntry(hit);
    if (!entry) continue;
    // Defensive: an event re-read at the boundary (equal sort values) is never repeated.
    if (!isAfterBoundary(entry, boundary)) continue;
    candidates.push(entry);
    if (Array.isArray(hit.sort)) activitySorts.set(entry.id, hit.sort);
  }

  candidates.sort(compareTimelineEntries);
  const entries = candidates.slice(0, limit);
  const hasMore = candidates.length > limit || activity.hasMore;

  let nextCursor: string | null = null;
  if (hasMore && !entries.length) {
    // Every activity hit of this page was unusable (no timestamp) yet more
    // exist: keep the boundary and skip past the hits read.
    nextCursor = encodeTimelineCursor({
      case: caseId,
      at: boundary?.at ?? '',
      id: boundary?.id ?? '',
      sources: {
        ...(activity.lastSort ? { activity_after: activity.lastSort } : {}),
        ...(cursor?.sources.alert_after ? { alert_after: cursor.sources.alert_after } : {}),
      },
    });
  } else if (hasMore) {
    const last = entries[entries.length - 1];
    // The activity source continues after the last activity hit served; an
    // activity hit read this page but not served (it sorts after an alert or
    // task that filled the page) is read again next page and passes the boundary.
    let activityAfter = cursor?.sources.activity_after;
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const sort = activitySorts.get(entries[i].id);
      if (sort) {
        activityAfter = sort;
        break;
      }
    }
    let alertAfter = cursor?.sources.alert_after;
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      if (entries[i].kind === 'alert' && entries[i].ref.alert_id) {
        alertAfter = [entries[i].at, entries[i].ref.alert_id as string];
        break;
      }
    }
    nextCursor = encodeTimelineCursor({
      case: caseId,
      at: last.at,
      id: last.id,
      sources: {
        ...(activityAfter ? { activity_after: activityAfter } : {}),
        ...(alertAfter ? { alert_after: alertAfter } : {}),
      },
    });
  }

  return { entries, next_cursor: nextCursor, truncated_alerts: truncatedAlerts };
}
