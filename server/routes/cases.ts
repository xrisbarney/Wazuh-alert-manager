import { schema } from '@osd/config-schema';
import { randomBytes } from 'crypto';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  CASES_INDEX,
  CASES_WRITE_ALIAS,
  CASE_SEVERITIES,
  CASE_TIMELINE_PAGE,
  CLOSURE_REASON_MAX_LENGTH,
  DEFAULT_DISPOSITION,
  DISPOSITIONS,
  SLA_STATES,
} from '../../common';
import type { Disposition } from '../../common';
import { dispositionFilterValues, normaliseClosureReason } from '../lib/disposition';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';
import { resolveCaseAlerts } from '../lib/index_resolution';
import { appendActivity, appendActivityOnce } from '../lib/activity';
import { getNotificationEmitter } from '../lib/notifications/emitters';
import {
  backfillCaseEvidence,
  listCaseEvidenceWithLegacy,
} from '../lib/evidence';
import { reconcileCaseEvidence } from '../lib/case_evidence_service';
import { resolveCase, resolveCases } from '../lib/case_index_resolution';
import { listComments } from './comments';
import { requirePluginAdmin } from '../lib/authorization';
import { CloseCaseResult, CreateCaseTaskListOutcome } from '../../common';
import { applyTaskListToCase, getTaskList } from '../lib/task_lists';
import { buildReportingUpdate, computeCaseDueAt, REPORTING_MERGE_SCRIPT, slaStateClause } from '../lib/reporting_fields';
import { getSlaPolicy, SlaPolicyLogger } from '../lib/sla/policy';
import {
  CSV_EXPORT_MAX_ROWS,
  CSV_EXPORT_PAGE_SIZE,
  CsvColumn,
  csvExportFilename,
  csvExportStream,
  downloadResponse,
  searchAfterOf,
} from '../lib/http_download';
import {
  CaseReportFormat,
  caseReportContentType,
  caseReportFilename,
  collectCaseReportData,
  renderCaseReport,
} from '../lib/case_report';
import { CASE_TIMELINE_LIMIT_MAX, collectCaseTimeline } from '../lib/case_timeline';

async function allCaseEvidence(client: any, caseId: string, legacyAlertIds: any): Promise<any[]> {
  const evidence: any[] = [];
  let cursor: string | undefined;
  do {
    const page = await listCaseEvidenceWithLegacy(client, caseId, legacyAlertIds, { cursor });
    evidence.push(...page.evidence);
    cursor = page.nextCursor || undefined;
  } while (cursor);
  const byAlert = new Map<string, any>();
  for (const item of evidence) {
    if (item?.alert_id && (!byAlert.has(item.alert_id) || !item.legacy_fallback)) byAlert.set(item.alert_id, item);
  }
  return Array.from(byAlert.values());
}

function message(error: any): string {
  return error?.reason || error?.caused_by?.reason || error?.message || String(error || 'Operation failed');
}

export interface BulkCaseUpdateResult {
  requested: number;
  updated: number;
  failed: number;
  results: Array<{ id: string; ok: boolean; mutationApplied?: boolean; error?: string }>;
}

const CASE_SORT_FIELDS: Record<string, string> = {
  title: 'title.keyword',
  severity: 'severity',
  status: 'status',
  assigned_to: 'assigned_to',
  created_by: 'created_by',
  created_at: 'created_at',
  updated_at: 'updated_at',
  // Due date (step 3.2).
  sla_due_at: 'sla_due_at',
};
const CASE_RESULT_WINDOW = 10000;
/** Due timestamp of a case (step 3.2). */
export const CASE_DUE_FIELD = 'sla_due_at';

/** Severity order of a case, lowest first; `severity` itself is a keyword. */
const CASE_SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * The `sort` clause of the case list. Severity is a keyword field, so sorting
 * on it directly would order the queue alphabetically (critical, high, low,
 * medium) instead of by how bad the case is; it goes through the rank above,
 * so `desc` really does put critical first. Every other field sorts on itself,
 * with `case_uid` as the stable tiebreak.
 */
export function buildCaseListSort(sortField: string | undefined, sortDirection: string | undefined): any[] {
  const order = sortDirection === 'asc' ? 'asc' : 'desc';
  let primary: any;
  if (sortField === 'severity') {
    primary = {
      _script: {
        type: 'number',
        order,
        script: {
          lang: 'painless',
          source:
            "def f = doc['severity']; if (f.size() == 0) return -1; def r = params.ranks.get(f.value); return r == null ? -1 : r;",
          params: { ranks: CASE_SEVERITY_RANK },
        },
      },
    };
  } else if (sortField === 'sla_due_at') {
    primary = { sla_due_at: { order, missing: '_last' } };
  } else {
    primary = { [CASE_SORT_FIELDS[sortField as string] || 'updated_at']: { order } };
  }
  return [primary, { case_uid: { order: 'asc' } }];
}

/** Query filters shared by the case list and the CSV export. */
export const caseFilterQuerySchema = schema.object({
  status: schema.maybe(schema.string()), // csv
  severity: schema.maybe(schema.string()), // csv
  assignedTo: schema.maybe(schema.string()), // csv; `__unassigned__` selects cases without an assignee
  // Due-date state (step 3.2) over sla_due_at: breached | due_soon | on_track.
  slaState: schema.maybe(schema.oneOf(SLA_STATES.map((v) => schema.literal(v)) as any)),
  // Close outcome (step 2.4): csv of DISPOSITIONS values, unknown values ignored.
  disposition: schema.maybe(schema.string()),
  q: schema.maybe(schema.string()),
  from: schema.maybe(schema.string()),
  to: schema.maybe(schema.string()),
});

/**
 * Queries for the case read alias from the validated list filters. `listQuery`
 * applies every filter; `summaryQuery` leaves the status filter out so the
 * status summary counts every status within the other filters.
 */
/** Plain-text search clause of the Cases queue box (`q`): title or description, typed as a prefix of a phrase. */
export const caseTextQuery = (q: string) => ({
  multi_match: { query: String(q).trim(), type: 'phrase_prefix', fields: ['title^2', 'description'], max_expansions: 50 },
});

export function buildCaseListQueries(query: Record<string, any>, now: string = new Date().toISOString()): { listQuery: any; summaryQuery: any } {
  const { status, severity, assignedTo, slaState, disposition, q, from, to } = query || {};
  const filter: any[] = [];
  const must: any[] = [];
  if (severity) filter.push({ terms: { severity: String(severity).split(',').filter(Boolean) } });
  if (slaState) filter.push(slaStateClause(slaState, CASE_DUE_FIELD, now));
  if (disposition) {
    const values = dispositionFilterValues(disposition);
    if (values.length) filter.push({ terms: { disposition: values } });
  }
  if (assignedTo) {
    const assignees = String(assignedTo).split(',').filter(Boolean);
    const includeUnassigned = assignees.includes('__unassigned__');
    const namedAssignees = assignees.filter((value) => value !== '__unassigned__');
    if (includeUnassigned && namedAssignees.length) {
      filter.push({ bool: { should: [
        { terms: { assigned_to: namedAssignees } },
        { bool: { must_not: [{ exists: { field: 'assigned_to' } }] } },
      ], minimum_should_match: 1 } });
    } else if (includeUnassigned) {
      filter.push({ bool: { must_not: [{ exists: { field: 'assigned_to' } }] } });
    } else if (namedAssignees.length) {
      filter.push({ terms: { assigned_to: namedAssignees } });
    }
  }
  if (from || to) {
    const range: any = {};
    if (from) range.gte = from;
    if (to) range.lte = to;
    filter.push({ range: { created_at: range } });
  }
  // Step 12.3: the search box is plain text ("title/description search" in the
  // User Guide), not a Lucene expression: a phrase-prefix match on the two text
  // fields lets a title with `:` (every rule-created case, `<rule>: automated
  // incident`) or any other Lucene special character be found as typed.
  if (q) must.push(caseTextQuery(q));
  const summaryQuery = must.length || filter.length ? { bool: { must, filter } } : { match_all: {} };
  const listFilter = [...filter];
  if (status) listFilter.push({ terms: { status: String(status).split(',').filter(Boolean) } });
  const listQuery = must.length || listFilter.length ? { bool: { must, filter: listFilter } } : { match_all: {} };
  return { listQuery, summaryQuery };
}

/** A case hit as the export reads it from the read alias. */
export interface CaseExportRecord {
  _id: string;
  _source: Record<string, any>;
  sort?: unknown[];
}

/**
 * CSV columns of `GET /cases/export.csv`, in output order; the one place the
 * list lives. `disposition` and `sla_due_at` are reserved for phases 2 and 3
 * and stay empty until those fields exist on the record.
 */
export const CASE_EXPORT_COLUMNS: ReadonlyArray<CsvColumn<CaseExportRecord>> = [
  { header: 'id', value: (hit) => hit._id },
  { header: 'title', value: (hit) => hit._source?.title ?? '' },
  { header: 'status', value: (hit) => hit._source?.status ?? '' },
  { header: 'severity', value: (hit) => hit._source?.severity ?? '' },
  { header: 'assignee', value: (hit) => hit._source?.assigned_to ?? '' },
  // The queue hides Created by by default (step 13.2); the export is where an
  // analyst scans the creator in bulk, so the column must be here.
  { header: 'created_by', value: (hit) => hit._source?.created_by ?? '' },
  { header: 'created_at', value: (hit) => hit._source?.created_at ?? '' },
  { header: 'updated_at', value: (hit) => hit._source?.updated_at ?? '' },
  { header: 'closed_at', value: (hit) => hit._source?.closed_at ?? '' },
  {
    header: 'alert_count',
    value: (hit) => {
      const count = hit._source?.evidence_count;
      if (typeof count === 'number') return count;
      return Array.isArray(hit._source?.alert_ids) ? hit._source.alert_ids.length : 0;
    },
  },
  { header: 'disposition', value: (hit) => hit._source?.disposition ?? '' },
  { header: 'sla_due_at', value: (hit) => hit._source?.sla_due_at ?? '' },
];

const CASE_EXPORT_SOURCE_FIELDS = [
  'title', 'status', 'severity', 'assigned_to', 'created_by', 'created_at', 'updated_at', 'closed_at',
  'evidence_count', 'alert_ids', 'disposition', 'sla_due_at',
];

/** One `search_after` page of the case export: newest first, `case_uid` as the tiebreak (same as the list route; no `_id` fielddata). */
export function buildCaseExportSearchBody(q: any, searchAfter?: unknown[] | null): Record<string, any> {
  return {
    size: CSV_EXPORT_PAGE_SIZE,
    track_total_hits: CSV_EXPORT_MAX_ROWS + 1,
    _source: CASE_EXPORT_SOURCE_FIELDS,
    sort: [{ created_at: { order: 'desc' } }, { case_uid: { order: 'asc' } }],
    query: buildCaseListQueries(q).listQuery,
    ...(searchAfter && searchAfter.length ? { search_after: searchAfter } : {}),
  };
}

/** Query of `GET /cases/{id}/report` (step 5.2). `inline` / `print` accept `1` or `true`. */
export const caseReportQuerySchema = schema.object({
  format: schema.oneOf([schema.literal('markdown'), schema.literal('html')], { defaultValue: 'html' }),
  inline: schema.maybe(schema.string({ maxLength: 8 })),
  print: schema.maybe(schema.string({ maxLength: 8 })),
});

function isTruthyFlag(value: unknown): boolean {
  return value === '1' || value === 'true' || value === true;
}

/** Query of `GET /cases/{id}/timeline` (step 2.3): opaque case-scoped cursor and page size. */
export const caseTimelineQuerySchema = schema.object({
  cursor: schema.maybe(schema.string({ minLength: 1, maxLength: 4096 })),
  limit: schema.number({ min: 1, max: CASE_TIMELINE_LIMIT_MAX, defaultValue: CASE_TIMELINE_PAGE }),
});

/**
 * Body of `POST /cases/{id}/close` (step 2.4). `disposition` is optional on
 * the route so a client predating this step keeps working (`undetermined` is
 * stored); the UI dialog always sends one.
 */
export const closeCaseBodySchema = schema.object({
  excludeAlertIds: schema.arrayOf(schema.string(), { defaultValue: [], maxSize: 1000 }),
  disposition: schema.maybe(schema.oneOf(DISPOSITIONS.map((value) => schema.literal(value)) as any)),
  closureReason: schema.maybe(schema.nullable(schema.string({ maxLength: CLOSURE_REASON_MAX_LENGTH }))),
});

/** CSP of the case report document: inline styles and data images only, scripts solely by nonce. */
export function caseReportCsp(nonce: string): string {
  return `default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'`;
}

export async function bulkUpdateCases(
  client: any,
  input: {
    ids: string[];
    actor: string;
    status?: 'open' | 'in_progress';
    assignedTo?: string | null;
    timestamp?: string;
  }
): Promise<BulkCaseUpdateResult> {
  const now = input.timestamp || new Date().toISOString();
  const action = input.status !== undefined ? 'status_change' : 'assignment_change';
  const locations = await resolveCases(client, input.ids);
  const sources = new Map<string, any>();
  for (const [id, location] of locations) sources.set(id, location.source || {});
  const fields: Record<string, any> = { updated_at: now, updated_by: input.actor };
  if (input.status !== undefined) {
    fields.status = input.status;
    fields.closed_at = null;
  }
  if (input.assignedTo !== undefined) fields.assigned_to = input.assignedTo;
  const entry = buildHistoryEntry({ user: input.actor, action, to: input.status ?? input.assignedTo ?? null });
  entry.timestamp = now;

  const body = input.ids.flatMap((id) => [
    { update: { _index: locations.get(id)?.index || CASES_WRITE_ALIAS, _id: id } },
    { script: { lang: 'painless', source: APPEND_HISTORY_SCRIPT_SOURCE, params: { entry, fields } } },
  ]);
  const bulk: any = await client.bulk({ refresh: 'wait_for', body });
  const items = bulk?.body?.items;
  if (!Array.isArray(items) || items.length !== input.ids.length) {
    return {
      requested: input.ids.length,
      updated: 0,
      failed: input.ids.length,
      results: input.ids.map((id) => ({ id, ok: false, error: 'Invalid bulk response item count.' })),
    };
  }

  const mutationResults = items.map((item: any, index: number) => {
    const detail = item?.update;
    const status = Number(detail?.status || 0);
    if (detail && !detail.error && status >= 200 && status < 300) return { id: input.ids[index], ok: true };
    return { id: input.ids[index], ok: false, error: message(detail?.error || `Bulk item returned ${status || 'unknown'}`) };
  });
  const results = await Promise.all(mutationResults.map(async (result) => {
    if (!result.ok) return result;
    try {
      const source = sources.get(result.id) || {};
      const activity = await appendActivity(client, {
        targetType: 'case',
        targetId: result.id,
        user: input.actor,
        action,
        from: input.status !== undefined ? source.status : source.assigned_to,
        to: input.status ?? input.assignedTo ?? null,
        timestamp: now,
      });
      // Notifications (step 1.3): a request that changes status and assignee
      // together has one `status_change` audit row, which the activity hook
      // maps to nothing, so `case.assigned` is emitted here (same key as the
      // hook would use). The emitter never throws.
      if (action === 'status_change' && input.assignedTo && input.assignedTo !== source.assigned_to) {
        await getNotificationEmitter()?.emitCaseEvent('case.assigned', { ...source, ...fields, id: result.id }, {
          actor: input.actor,
          changes: { from: source.assigned_to ?? null, to: input.assignedTo },
          activityId: activity.event_uid,
          now: new Date(now),
        });
      }
      return result;
    } catch (error: any) {
      return {
        id: result.id,
        ok: false,
        mutationApplied: true,
        error: `Case updated, but activity audit failed: ${message(error)}`,
      };
    }
  }));
  const updated = results.filter((item: any) => item.ok).length;
  return { requested: input.ids.length, updated, failed: input.ids.length - updated, results };
}

export async function closeCaseAndLinkedAlerts(
  client: any,
  input: {
    caseId: string;
    actor: string;
    excludeAlertIds?: string[];
    timestamp?: string;
    /** Close outcome (step 2.4); stored on the case and on every alert this call closes. Defaults to `undetermined`. */
    disposition?: Disposition | null;
    closureReason?: string | null;
    /** Receives the warning when the SLA policy document cannot be read and the defaults are stamped. */
    logger?: SlaPolicyLogger;
  }
): Promise<CloseCaseResult> {
  const current = await resolveCase(client, input.caseId);
  const caseSource = current.source || {};
  // A re-close of an already-closed case (API clients only; the UI hides the
  // control) must not stamp a second outcome: the case keeps its stored
  // disposition, so any still-open linked alert and the audit carry that one.
  const reClose = caseSource.status === 'closed';
  const requestedDisposition = reClose ? caseSource.disposition : input.disposition;
  const disposition: Disposition = requestedDisposition && (DISPOSITIONS as readonly string[]).includes(requestedDisposition)
    ? requestedDisposition
    : DEFAULT_DISPOSITION;
  const closureReason = normaliseClosureReason(reClose ? caseSource.closure_reason : input.closureReason);
  const relationships = await allCaseEvidence(client, input.caseId, caseSource.alert_ids);
  const locations = await resolveCaseAlerts(client, relationships);
  const excluded = new Set((input.excludeAlertIds || []).filter((id) => locations.has(id)));
  const evidenceOnlyAlertIds = relationships
    .map((item) => item.alert_id)
    .filter((id) => !locations.get(id) || locations.get(id)?.availability !== 'live');
  const archiveOnlyAlertIds = relationships
    .filter((item) => item.archive_index && locations.get(item.alert_id)?.availability !== 'live')
    .map((item) => item.alert_id);
  const liveToClose = Array.from(locations.values()).filter(
    (item) => item.availability === 'live' && !excluded.has(item.id) && item.source?.status !== 'closed'
  );
  const alreadyClosedAlerts = Array.from(locations.values()).filter(
    (item) => item.availability === 'live' && !excluded.has(item.id) && item.source?.status === 'closed'
  ).length;
  const errors: CloseCaseResult['errors'] = [];
  const failedAlertIds: string[] = [];
  let closedAlerts = 0;
  const now = input.timestamp || new Date().toISOString();
  const slaPolicy = await getSlaPolicy(client, input.logger);

  for (let offset = 0; offset < liveToClose.length; offset += 500) {
    const chunk = liveToClose.slice(offset, offset + 500);
    let bulk: any;
    try {
      bulk = await client.bulk({
        refresh: 'wait_for',
        body: chunk.flatMap((item) => [
          { update: { _index: item.index, _id: item.id } },
          {
            script: {
              lang: 'painless',
              source:
                "if (ctx._source.status != 'closed') { ctx._source.status = 'closed'; ctx._source.updated_at = params.now; " +
                'ctx._source.updated_by = params.actor; ctx._source.disposition = params.disposition; ctx._source.closure_reason = params.closure_reason; ' +
                'if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); while (ctx._source.history.size() > 1000) { ctx._source.history.remove(0); } ' +
                REPORTING_MERGE_SCRIPT + ' }',
              params: {
                now,
                actor: input.actor,
                disposition,
                closure_reason: closureReason,
                entry: { timestamp: now, user: input.actor, action: 'status_change', from: item.source?.status, to: 'closed', disposition },
                reporting: buildReportingUpdate(item.source, { status: 'closed' }, now, slaPolicy),
              },
            },
          },
        ]),
      });
    } catch (error: any) {
      for (const item of chunk) {
        failedAlertIds.push(item.id);
        errors.push({ stage: 'close_alerts', alertId: item.id, message: message(error) });
      }
      continue;
    }
    const items = bulk?.body?.items;
    if (!Array.isArray(items) || items.length !== chunk.length) {
      for (const item of chunk) {
        failedAlertIds.push(item.id);
        errors.push({ stage: 'close_alerts', alertId: item.id, message: 'Invalid bulk response item count.' });
      }
      continue;
    }
    items.forEach((item: any, index: number) => {
      const detail = item?.update;
      const status = Number(detail?.status || 0);
      if (detail && !detail.error && status >= 200 && status < 300) closedAlerts += 1;
      else {
        const alertId = chunk[index].id;
        failedAlertIds.push(alertId);
        errors.push({ stage: 'close_alerts', alertId, message: message(detail?.error || `Bulk item returned ${status || 'unknown'}`) });
      }
    });
  }

  const stamped = new Set(liveToClose.filter((item) => !failedAlertIds.includes(item.id)).map((item) => item.id));
  const auditTargets = [
    ...liveToClose.filter((item) => stamped.has(item.id)),
    ...Array.from(locations.values()).filter(
      (item) => item.availability === 'live' && !excluded.has(item.id) && item.source?.status === 'closed'
    ),
  ];
  for (const item of auditTargets) {
    try {
      // The audit names the outcome actually stored on the alert: this close's
      // for the alerts the bulk script stamped, the retained one for alerts
      // that were already closed and keep their own disposition.
      const details = stamped.has(item.id)
        ? { disposition, closure_reason: closureReason }
        : { disposition: item.source?.disposition ?? null, closure_reason: item.source?.closure_reason ?? null, retained: true };
      await appendActivityOnce(client, `case-close:${input.caseId}:${item.id}`, {
        targetType: 'alert', targetId: item.id, user: input.actor,
        action: 'status_change', from: item.source?.status, to: 'closed', timestamp: now,
        source: `case:${input.caseId}`,
        details,
      });
    } catch (error: any) {
      errors.push({ stage: 'activity', alertId: item.id, message: message(error) });
    }
  }

  let caseClosed = caseSource.status === 'closed';
  try {
    if (!caseClosed && failedAlertIds.length === 0 && !errors.some((error) => error.stage === 'activity')) {
      const entry: Record<string, any> = buildHistoryEntry({ user: input.actor, action: 'status_change', from: caseSource.status, to: 'closed' });
      entry.timestamp = now;
      entry.disposition = disposition;
      await client.update({
        index: current.index,
        id: input.caseId,
        refresh: 'wait_for',
        body: {
          script: {
            lang: 'painless',
            source:
              "if (ctx._source.status != 'closed') { ctx._source.status = 'closed'; ctx._source.closed_at = params.now; " +
              'ctx._source.disposition = params.disposition; ctx._source.closure_reason = params.closure_reason; ' +
              'ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor; if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); while (ctx._source.history.size() > 1000) { ctx._source.history.remove(0); } }',
            params: { now, actor: input.actor, disposition, closure_reason: closureReason, entry },
          },
        },
      });
      caseClosed = true;
    }
  } catch (error: any) {
    errors.push({ stage: 'close_case', message: message(error) });
  }

  const activityFailures = errors.filter((error) => error.stage === 'activity').length;
  const stages: CloseCaseResult['stages'] = [
    { stage: 'resolve', attempted: relationships.length, succeeded: locations.size, failed: relationships.length - locations.size },
    { stage: 'close_alerts', attempted: liveToClose.length, succeeded: closedAlerts, failed: failedAlertIds.length },
    { stage: 'activity', attempted: auditTargets.length, succeeded: auditTargets.length - activityFailures, failed: activityFailures },
    { stage: 'close_case', attempted: 1, succeeded: caseClosed ? 1 : 0, failed: caseClosed ? 0 : 1 },
  ];
  return {
    ok: caseClosed && failedAlertIds.length === 0,
    caseId: input.caseId,
    caseClosed,
    alreadyClosed: reClose,
    linkedAlerts: relationships.length,
    closedAlerts,
    alreadyClosedAlerts,
    excludedAlertIds: Array.from(excluded),
    evidenceOnlyAlertIds,
    archiveOnlyAlertIds,
    failedAlertIds,
    stages,
    errors,
    disposition,
    closureReason,
  };
}

export function defineCaseRoutes(router: IRouter) {
  router.post(
    {
      path: `${API_ROOT}/cases/evidence-backfill`,
      validate: { body: schema.object({ batchSize: schema.maybe(schema.number({ min: 1, max: 200 })) }) },
    },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const result = await backfillCaseEvidence(context.core.opensearch.client.asCurrentUser, {
          actor: identity.name,
          batchSize: (request.body as any).batchSize,
        });
        return response.ok({ body: result });
      } catch (e: any) {
        return response.customError({ statusCode: e?.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/cases`,
      validate: {
        query: caseFilterQuerySchema.extends({
          from_offset: schema.maybe(schema.number({ min: 0 })),
          size: schema.maybe(schema.number({ min: 1, max: 200 })),
          sortField: schema.maybe(schema.oneOf(Object.keys(CASE_SORT_FIELDS).map((field) => schema.literal(field)) as any)),
          sortDirection: schema.maybe(schema.oneOf([schema.literal('asc'), schema.literal('desc')])),
        }),
      },
    },
    async (context, request, response) => {
      const { from_offset, size, sortField, sortDirection } = request.query as any;
      const offset = from_offset || 0;
      const pageSize = size || 50;
      if (offset + pageSize > CASE_RESULT_WINDOW) {
        return response.badRequest({
          body: { message: `Case pagination is limited to the first ${CASE_RESULT_WINDOW} results. Refine the filters to continue.` },
        });
      }
      const { listQuery, summaryQuery } = buildCaseListQueries(request.query as any);

      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: CASES_INDEX,
          body: {
            from: offset,
            size: pageSize,
            track_total_hits: true,
            sort: buildCaseListSort(sortField, sortDirection),
            query: listQuery,
            aggs: {
              summary_scope: {
                global: {},
                aggs: {
                  filtered: {
                    filter: summaryQuery,
                    aggs: { by_status: { terms: { field: 'status', size: 10 } } },
                  },
                },
              },
            },
          },
        });
        const cases = result.body.hits.hits.map((h: any) => ({ id: h._id, ...h._source }));
        const rawTotal = result.body.hits.total;
        const total = typeof rawTotal === 'number' ? rawTotal : rawTotal?.value ?? 0;
        const summary: Record<string, number> = { open: 0, in_progress: 0, closed: 0, total: 0 };
        const filteredSummary = result.body.aggregations?.summary_scope?.filtered;
        summary.total = filteredSummary?.doc_count ?? 0;
        for (const bucket of filteredSummary?.by_status?.buckets || []) {
          if (bucket.key in summary) summary[bucket.key] = bucket.doc_count;
        }
        return response.ok({ body: { cases, total, summary } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  // Same filters as the list, streamed as CSV from the case read alias as the
  // current user, capped at CSV_EXPORT_MAX_ROWS (`x-wam-truncated: true` when
  // rows were dropped).
  router.get(
    {
      path: `${API_ROOT}/cases/export.csv`,
      validate: { query: caseFilterQuerySchema },
    },
    async (context, request, response) => {
      const q = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const logger: any = (context as any).wazuhAlertManager?.logger || console;
        const page = async (searchAfter?: unknown[] | null) => {
          const result: any = await client.search({ index: CASES_INDEX, body: buildCaseExportSearchBody(q, searchAfter) });
          const hits: CaseExportRecord[] = result.body?.hits?.hits || [];
          return { records: hits, searchAfter: searchAfterOf(hits), total: result.body?.hits?.total };
        };
        const first = await page(null);
        const rawTotal = first.total;
        const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal?.value ?? 0);
        const truncated = total > CSV_EXPORT_MAX_ROWS || rawTotal?.relation === 'gte';
        const body = csvExportStream<CaseExportRecord>({
          columns: CASE_EXPORT_COLUMNS,
          firstPage: first,
          fetchPage: page,
          onTruncated: (written) => logger.warn(`cases CSV export truncated at ${written} rows (cap ${CSV_EXPORT_MAX_ROWS})`),
          onError: (error: any) => logger.error(`cases CSV export failed mid-stream: ${error?.message || error}`),
        });
        return downloadResponse(response, {
          filename: csvExportFilename('cases'),
          contentType: 'text/csv; charset=utf-8',
          headers: truncated ? { 'x-wam-truncated': 'true' } : undefined,
          body,
        });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/cases/{id}/report`,
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }),
        query: caseReportQuerySchema,
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const q = request.query as any;
      const format: CaseReportFormat = q.format;
      const inline = format === 'html' && isTruthyFlag(q.inline);
      // The print trigger only makes sense for the document shown in a tab; a
      // saved attachment must never print itself when opened later.
      const print = inline && isTruthyFlag(q.print);
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const now = new Date();
        const data = await collectCaseReportData(client, id, now);
        // OSD core adds no CSP to API responses, and the HTML report is a
        // top-level document on the dashboard origin: a per-response nonce
        // lets only our own print script run, whatever the escaping missed.
        const nonce = randomBytes(16).toString('base64');
        const body = renderCaseReport(data, format, { print, nonce });
        const contentType = caseReportContentType(format);
        const filename = caseReportFilename(id, format, now);
        const csp = caseReportCsp(nonce);
        if (inline) {
          // Viewed in a tab (Print / PDF): same document, shown instead of saved.
          return response.ok({
            headers: {
              'content-type': contentType,
              'content-disposition': `inline; filename="${filename}"`,
              'cache-control': 'no-store',
              'x-content-type-options': 'nosniff',
              'referrer-policy': 'no-referrer',
              'content-security-policy': csp,
            },
            body,
          });
        }
        return downloadResponse(response, {
          filename,
          contentType,
          headers: { 'x-content-type-options': 'nosniff', 'content-security-policy': csp },
          body,
        });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 500;
        if (statusCode === 404) return response.notFound({ body: { message: e.message } });
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/cases/bulk-update`,
      validate: {
        body: schema.object({
          ids: schema.arrayOf(schema.string({ minLength: 1, maxLength: 512 }), { minSize: 1, maxSize: 1000 }),
          status: schema.maybe(schema.oneOf([schema.literal('open'), schema.literal('in_progress')])),
          assignedTo: schema.maybe(schema.nullable(schema.string({ minLength: 1, maxLength: 256 }))),
        }),
      },
    },
    async (context, request, response) => {
      const { ids, status, assignedTo } = request.body as any;
      if (status === undefined && assignedTo === undefined) {
        return response.badRequest({ body: { message: 'Provide status or assignedTo.' } });
      }
      const uniqueIds = Array.from(new Set(ids));
      if (uniqueIds.length !== ids.length) {
        return response.badRequest({ body: { message: 'Case IDs must be unique.' } });
      }
      try {
        const actor = await getCurrentUsername(context, request);
        const result = await bulkUpdateCases(context.core.opensearch.client.asCurrentUser, {
          ids: uniqueIds as string[], actor, status, assignedTo,
        });
        return response.ok({ body: result });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/cases/{id}`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const caseRes = await resolveCase(client, id);
        const caseDoc = { id: caseRes.id, ...caseRes.source };

        // Case details render one bounded evidence page. Further pages are
        // resolved by the dedicated evidence endpoint, keeping large cases
        // responsive without loading every relationship into the browser.
        const evidencePage = await listCaseEvidenceWithLegacy(client, id, caseDoc.alert_ids, { size: 25 });
        const locations = await resolveCaseAlerts(client, evidencePage.evidence);
        const alerts = evidencePage.evidence.map((item: any) => {
          const resolved = locations.get(item.alert_id);
          return {
            _id: item.alert_id,
            _source: resolved?.source || item.snapshot || {},
            evidence_only: resolved?.availability !== 'live',
            evidence_availability: resolved?.availability || 'unavailable',
          };
        });

        const comments = await listComments(client, { caseId: id });

        return response.ok({ body: { case: caseDoc, alerts, evidence: evidencePage, comments } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 404, body: { message: e.message } });
      }
    }
  );

  // Step 2.3: one page of the case timeline (alerts, comments, every audit
  // event, open task due dates) merged by time. Read-only, as the current
  // user; the cursor is scoped to the case (400 when it belongs to another).
  router.get(
    {
      path: `${API_ROOT}/cases/{id}/timeline`,
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }),
        query: caseTimelineQuerySchema,
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const { cursor, limit } = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const body = await collectCaseTimeline(client, id, { cursor, limit });
        return response.ok({ body });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || 500;
        if (statusCode === 404) return response.notFound({ body: { message: e.message } });
        if (statusCode === 400) return response.badRequest({ body: { message: e.message } });
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/cases/{id}/close`,
      validate: {
        params: schema.object({ id: schema.string() }),
        body: closeCaseBodySchema,
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const user = await getCurrentUsername(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { excludeAlertIds, disposition, closureReason } = request.body as any;
        const result = await closeCaseAndLinkedAlerts(client, {
          caseId: id,
          actor: user,
          excludeAlertIds,
          disposition,
          closureReason,
          logger: (context as any).wazuhAlertManager?.logger || console,
        });
        try {
          await appendActivity(client, {
            targetType: 'case', targetId: id, user,
            action: result.caseClosed ? 'case_closed' : 'case_close_partial',
            to: result.caseClosed ? 'complete' : 'partial',
            // The effective outcome: the body's on a first close, the stored one
            // on a re-close (flagged, so the notification hook stays quiet).
            details: {
              disposition: result.disposition,
              closure_reason: result.closureReason,
              ...(result.alreadyClosed ? { already_closed: true } : {}),
            },
          });
          const activityStage = result.stages.find((stage) => stage.stage === 'activity')!;
          activityStage.attempted += 1;
          activityStage.succeeded += 1;
        } catch (activityError: any) {
          result.ok = false;
          const activityStage = result.stages.find((stage) => stage.stage === 'activity')!;
          activityStage.attempted += 1;
          activityStage.failed += 1;
          result.errors.push({ stage: 'activity', message: message(activityError) });
        }
        return response.ok({ body: result });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/cases`,
      validate: {
        body: schema.object({
          title: schema.string({ minLength: 1, maxLength: 256 }),
          description: schema.maybe(schema.string({ maxLength: 5000 })),
          severity: schema.oneOf(CASE_SEVERITIES.map((s) => schema.literal(s)) as any),
          alertIds: schema.arrayOf(schema.string(), { defaultValue: [], maxSize: 1000 }),
          assignedTo: schema.maybe(schema.nullable(schema.string())),
          // TaskList applied right after creation (step 2.2); a failure never rolls the case back.
          taskListId: schema.maybe(schema.nullable(schema.string({ minLength: 1, maxLength: 64 }))),
        }),
      },
    },
    async (context, request, response) => {
      const { title, description, severity, alertIds, assignedTo, taskListId } = request.body as any;
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const client = context.core.opensearch.client.asCurrentUser;
      const caseId = `case-${randomBytes(16).toString('hex')}`;
      // Due date (step 3.2): created_at + the resolve target of the severity.
      const slaPolicy = await getSlaPolicy(client, (context as any).wazuhAlertManager?.logger || console);

      const doc = {
        case_uid: caseId,
        title,
        description: description ?? '',
        severity,
        status: 'open',
        assigned_to: assignedTo ?? null,
        alert_ids: [],
        evidence_count: 0,
        created_by: user,
        created_at: now,
        updated_by: user,
        updated_at: now,
        closed_at: null,
        sla_due_at: computeCaseDueAt(severity, now, slaPolicy),
        history: [buildHistoryEntry({ user, action: 'case_created' })],
      };

      try {
        await client.create({ index: CASES_WRITE_ALIAS, id: caseId, body: doc, refresh: 'wait_for' });
        const linkage = await reconcileCaseEvidence(client, {
          caseId,
          linkAlertIds: alertIds,
          actor: user,
          action: 'case_link',
          timestamp: now,
        });
        if (!linkage.ok) {
          return response.customError({
            statusCode: 500,
            body: { message: 'Case was created, but evidence linkage was incomplete.', caseId, linkage },
          });
        }
        await appendActivity(client, { targetType: 'case', targetId: caseId, user, action: 'case_created' });
        // Optional task list (step 2.2): applied in the same request, after the
        // case exists. A failure is reported in `task list`, never rolled back.
        let taskList: CreateCaseTaskListOutcome | undefined;
        if (taskListId) {
          try {
            const template = await getTaskList(client, taskListId);
            const outcome = await applyTaskListToCase(client, caseId, template, user, new Date().toISOString());
            taskList = { applied: outcome.applied, tasks_added: outcome.tasks_added };
          } catch (error: any) {
            taskList = { applied: false, error: error?.message || 'Task list could not be applied.' };
          }
        }
        const created = await resolveCase(client, caseId);
        return response.ok({ body: { id: caseId, ...created.source, ...(taskList ? { taskList } : {}) } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/cases/{id}`,
      validate: {
        params: schema.object({ id: schema.string() }),
        body: schema.object({
          title: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
          description: schema.maybe(schema.string({ maxLength: 5000 })),
          severity: schema.maybe(schema.oneOf(CASE_SEVERITIES.map((s) => schema.literal(s)) as any)),
          status: schema.maybe(schema.oneOf([schema.literal('open'), schema.literal('in_progress')])),
          assignedTo: schema.maybe(schema.nullable(schema.string())),
          addAlertIds: schema.arrayOf(schema.string(), { defaultValue: [], maxSize: 1000 }),
          removeAlertIds: schema.arrayOf(schema.string(), { defaultValue: [], maxSize: 1000 }),
        }),
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const { title, description, severity, status, assignedTo, addAlertIds, removeAlertIds } = request.body as any;
      if (status === 'closed') {
        return response.badRequest({
          body: { message: `Use POST ${API_ROOT}/cases/${id}/close to close a case and coordinate its linked alerts.` },
        });
      }
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const client = context.core.opensearch.client.asCurrentUser;

      try {
        const current = await resolveCase(client, id);
        const fields: Record<string, any> = { updated_by: user, updated_at: now };
        if (title != null) fields.title = title;
        if (description != null) fields.description = description;
        if (severity != null) {
          fields.severity = severity;
          // A severity change moves the due date (created_at + the new band's
          // resolve target); the same severity leaves it untouched.
          if (severity !== current.source.severity) {
            const slaPolicy = await getSlaPolicy(client, (context as any).wazuhAlertManager?.logger || console);
            fields.sla_due_at = computeCaseDueAt(severity, current.source.created_at, slaPolicy);
          }
        }
        if (assignedTo !== undefined) fields.assigned_to = assignedTo;
        if (status != null) {
          fields.status = status;
          fields.closed_at = null;
        }

        const action = status != null ? 'status_change' : assignedTo !== undefined ? 'assignment_change' : 'case_updated';
        const entry = buildHistoryEntry({
          user,
          action,
          from: action === 'status_change' ? current.source.status : current.source.assigned_to,
          to: status ?? assignedTo ?? current.source.status,
        });

        await client.update({
          index: current.index,
          id,
          refresh: 'wait_for',
          body: {
            script: { lang: 'painless', source: APPEND_HISTORY_SCRIPT_SOURCE, params: { entry, fields } },
          },
        });
        const activity = await appendActivity(client, {
          targetType: 'case',
          targetId: id,
          user,
          action,
          from: entry.from,
          to: entry.to,
        });
        // Notifications (step 1.3): `case.assigned` / `case.closed` /
        // `case.created` come from the activity hook, but the audit row of a
        // severity change (`case_updated`, or the assignment / status row of
        // the same request) carries the status, not the severity, so
        // `case.severity_raised` is emitted here with both values. The
        // emitter only fires when the new band is higher and never throws.
        const emitter = getNotificationEmitter();
        if (emitter && severity != null && severity !== current.source.severity) {
          await emitter.emitCaseEvent('case.severity_raised', { ...current.source, ...fields, id }, {
            actor: user,
            changes: { from: current.source.severity ?? null, to: severity },
          });
        }
        // Likewise an assignment sent together with a status change: its only
        // audit row is the `status_change`, so the hook never sees it.
        if (emitter && action === 'status_change' && assignedTo && assignedTo !== current.source.assigned_to) {
          await emitter.emitCaseEvent('case.assigned', { ...current.source, ...fields, id }, {
            actor: user,
            changes: { from: current.source.assigned_to ?? null, to: assignedTo },
            activityId: activity.event_uid,
            now: new Date(now),
          });
        }

        if (addAlertIds.length || removeAlertIds.length) {
          const linkage = await reconcileCaseEvidence(client, {
            caseId: id,
            linkAlertIds: addAlertIds,
            unlinkAlertIds: removeAlertIds,
            actor: user,
            action: 'case_link',
            timestamp: now,
          });
          if (!linkage.ok) {
            return response.customError({
              statusCode: 500,
              body: { message: 'Case was updated, but evidence linkage was incomplete.', caseId: id, linkage },
            });
          }
        }

        const updated = await resolveCase(client, id);
        return response.ok({ body: { id, ...updated.source } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
