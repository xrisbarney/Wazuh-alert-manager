import { schema } from '@osd/config-schema';
import { randomBytes } from 'crypto';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  CASES_INDEX,
  CASES_WRITE_ALIAS,
  CASE_SEVERITIES,
} from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';
import { resolveCaseAlerts } from '../lib/index_resolution';
import { appendActivity, appendActivityOnce } from '../lib/activity';
import {
  backfillCaseEvidence,
  listCaseEvidenceWithLegacy,
} from '../lib/evidence';
import { reconcileCaseEvidence } from '../lib/case_evidence_service';
import { resolveCase, resolveCases } from '../lib/case_index_resolution';
import { listComments } from './comments';
import { requirePluginAdmin } from '../lib/authorization';
import { CloseCaseResult } from '../../common';
import { buildReportingUpdate, REPORTING_MERGE_SCRIPT } from '../lib/reporting_fields';

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
};
const CASE_RESULT_WINDOW = 10000;

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
      await appendActivity(client, {
        targetType: 'case',
        targetId: result.id,
        user: input.actor,
        action,
        from: input.status !== undefined ? sources.get(result.id)?.status : sources.get(result.id)?.assigned_to,
        to: input.status ?? input.assignedTo ?? null,
        timestamp: now,
      });
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
  input: { caseId: string; actor: string; excludeAlertIds?: string[]; timestamp?: string }
): Promise<CloseCaseResult> {
  const current = await resolveCase(client, input.caseId);
  const caseSource = current.source || {};
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
                'ctx._source.updated_by = params.actor; if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); ' +
                REPORTING_MERGE_SCRIPT + ' }',
              params: {
                now,
                actor: input.actor,
                entry: { timestamp: now, user: input.actor, action: 'status_change', from: item.source?.status, to: 'closed' },
                reporting: buildReportingUpdate(item.source, { status: 'closed' }, now),
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

  const auditTargets = [
    ...liveToClose.filter((item) => !failedAlertIds.includes(item.id)),
    ...Array.from(locations.values()).filter(
      (item) => item.availability === 'live' && !excluded.has(item.id) && item.source?.status === 'closed'
    ),
  ];
  for (const item of auditTargets) {
    try {
      await appendActivityOnce(client, `case-close:${input.caseId}:${item.id}`, {
        targetType: 'alert', targetId: item.id, user: input.actor,
        action: 'status_change', from: item.source?.status, to: 'closed', timestamp: now,
        source: `case:${input.caseId}`,
      });
    } catch (error: any) {
      errors.push({ stage: 'activity', alertId: item.id, message: message(error) });
    }
  }

  let caseClosed = caseSource.status === 'closed';
  try {
    if (!caseClosed && failedAlertIds.length === 0 && !errors.some((error) => error.stage === 'activity')) {
      const entry = buildHistoryEntry({ user: input.actor, action: 'status_change', from: caseSource.status, to: 'closed' });
      entry.timestamp = now;
      await client.update({
        index: current.index,
        id: input.caseId,
        refresh: 'wait_for',
        body: {
          script: {
            lang: 'painless',
            source:
              "if (ctx._source.status != 'closed') { ctx._source.status = 'closed'; ctx._source.closed_at = params.now; " +
              'ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor; if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); }',
            params: { now, actor: input.actor, entry },
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
    linkedAlerts: relationships.length,
    closedAlerts,
    alreadyClosedAlerts,
    excludedAlertIds: Array.from(excluded),
    evidenceOnlyAlertIds,
    archiveOnlyAlertIds,
    failedAlertIds,
    stages,
    errors,
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
        query: schema.object({
          status: schema.maybe(schema.string()),
          severity: schema.maybe(schema.string()),
          assignedTo: schema.maybe(schema.string()),
          q: schema.maybe(schema.string()),
          from: schema.maybe(schema.string()),
          to: schema.maybe(schema.string()),
          from_offset: schema.maybe(schema.number({ min: 0 })),
          size: schema.maybe(schema.number({ min: 1, max: 200 })),
          sortField: schema.maybe(schema.oneOf(Object.keys(CASE_SORT_FIELDS).map((field) => schema.literal(field)) as any)),
          sortDirection: schema.maybe(schema.oneOf([schema.literal('asc'), schema.literal('desc')])),
        }),
      },
    },
    async (context, request, response) => {
      const { status, severity, assignedTo, q, from, to, from_offset, size, sortField, sortDirection } = request.query as any;
      const offset = from_offset || 0;
      const pageSize = size || 50;
      if (offset + pageSize > CASE_RESULT_WINDOW) {
        return response.badRequest({
          body: { message: `Case pagination is limited to the first ${CASE_RESULT_WINDOW} results. Refine the filters to continue.` },
        });
      }
      const filter: any[] = [];
      const must: any[] = [];
      if (severity) filter.push({ terms: { severity: String(severity).split(',').filter(Boolean) } });
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
      if (q) must.push({ query_string: { query: q, default_operator: 'AND', lenient: true } });
      const summaryQuery = must.length || filter.length ? { bool: { must, filter } } : { match_all: {} };
      const listFilter = [...filter];
      if (status) listFilter.push({ terms: { status: String(status).split(',').filter(Boolean) } });
      const listQuery = must.length || listFilter.length ? { bool: { must, filter: listFilter } } : { match_all: {} };

      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: CASES_INDEX,
          body: {
            from: offset,
            size: pageSize,
            track_total_hits: true,
            sort: [
              { [CASE_SORT_FIELDS[sortField] || 'updated_at']: { order: sortDirection || 'desc' } },
              { case_uid: { order: 'asc' } },
            ],
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

        const evidencePage = await listCaseEvidenceWithLegacy(client, id, caseDoc.alert_ids);
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

  router.post(
    {
      path: `${API_ROOT}/cases/{id}/close`,
      validate: {
        params: schema.object({ id: schema.string() }),
        body: schema.object({
          excludeAlertIds: schema.arrayOf(schema.string(), { defaultValue: [], maxSize: 1000 }),
        }),
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const user = await getCurrentUsername(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const result = await closeCaseAndLinkedAlerts(client, {
          caseId: id,
          actor: user,
          excludeAlertIds: (request.body as any).excludeAlertIds,
        });
        try {
          await appendActivity(client, {
            targetType: 'case', targetId: id, user,
            action: result.caseClosed ? 'case_closed' : 'case_close_partial',
            to: result.caseClosed ? 'complete' : 'partial',
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
        }),
      },
    },
    async (context, request, response) => {
      const { title, description, severity, alertIds, assignedTo } = request.body as any;
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const client = context.core.opensearch.client.asCurrentUser;
      const caseId = `case-${randomBytes(16).toString('hex')}`;

      const doc = {
        case_uid: caseId,
        title,
        description: description ?? '',
        severity,
        status: 'open',
        assigned_to: assignedTo ?? null,
        alert_ids: [],
        created_by: user,
        created_at: now,
        updated_by: user,
        updated_at: now,
        closed_at: null,
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
        const created = await resolveCase(client, caseId);
        return response.ok({ body: { id: caseId, ...created.source } });
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
        if (severity != null) fields.severity = severity;
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
        await appendActivity(client, {
          targetType: 'case',
          targetId: id,
          user,
          action,
          from: entry.from,
          to: entry.to,
        });

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
