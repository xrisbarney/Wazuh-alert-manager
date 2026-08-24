import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, ALERT_STATUS_INDEX, CASES_INDEX, ALERT_STATUSES } from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';

/**
 * Keeps a case's own `alert_ids` array in sync when alerts are linked to
 * (or unlinked from) a case from the *alert* side (bulk-update caseId) -
 * the case side (cases.ts addAlertIds/removeAlertIds) already updates the
 * case doc directly, but linking from an alert only ever touched the
 * alert's own case_id field until this, which meant the case's linked-
 * alerts list silently didn't include alerts linked that way.
 */
async function syncCaseAlertIds(client: any, alertIds: string[], newCaseId: string | null) {
  const mgetRes: any = await client.mget({ index: ALERT_STATUS_INDEX, body: { ids: alertIds } });
  const oldCaseIdByAlert = new Map<string, string | null>();
  for (const doc of mgetRes.body.docs) {
    if (doc.found) oldCaseIdByAlert.set(doc._id, doc._source.case_id ?? null);
  }

  const idsByOldCase = new Map<string, string[]>();
  for (const [alertId, oldCaseId] of oldCaseIdByAlert) {
    if (oldCaseId && oldCaseId !== newCaseId) {
      const list = idsByOldCase.get(oldCaseId) || [];
      list.push(alertId);
      idsByOldCase.set(oldCaseId, list);
    }
  }

  const body: any[] = [];
  for (const [oldCaseId, idsToRemove] of idsByOldCase) {
    body.push({ update: { _index: CASES_INDEX, _id: oldCaseId } });
    body.push({
      script: {
        lang: 'painless',
        source: 'if (ctx._source.alert_ids != null) { ctx._source.alert_ids.removeIf(v -> params.ids.contains(v)); }',
        params: { ids: idsToRemove },
      },
    });
  }

  if (newCaseId) {
    body.push({ update: { _index: CASES_INDEX, _id: newCaseId } });
    body.push({
      script: {
        lang: 'painless',
        source:
          'if (ctx._source.alert_ids == null) { ctx._source.alert_ids = []; } ' +
          'for (id in params.ids) { if (!ctx._source.alert_ids.contains(id)) { ctx._source.alert_ids.add(id); } }',
        params: { ids: alertIds },
      },
    });
  }

  if (body.length) await client.bulk({ body });
}

const filterQuerySchema = schema.object({
  statuses: schema.maybe(schema.string()), // csv
  levelMin: schema.maybe(schema.number()),
  levelMax: schema.maybe(schema.number()),
  ruleIds: schema.maybe(schema.string()), // csv
  agentNames: schema.maybe(schema.string()), // csv
  alertTypes: schema.maybe(schema.string()), // csv, maps to rule.groups
  assignedTo: schema.maybe(schema.string()), // csv
  caseId: schema.maybe(schema.string()),
  q: schema.maybe(schema.string()),
  from: schema.maybe(schema.string()),
  to: schema.maybe(schema.string()),
});

function buildBoolQuery(query: Record<string, any>, includeStatusFilter: boolean) {
  const filter: any[] = [];
  const must: any[] = [];

  if (includeStatusFilter && query.statuses) {
    filter.push({ terms: { status: String(query.statuses).split(',').filter(Boolean) } });
  }
  if (query.levelMin != null || query.levelMax != null) {
    const range: any = {};
    if (query.levelMin != null) range.gte = query.levelMin;
    if (query.levelMax != null) range.lte = query.levelMax;
    filter.push({ range: { 'rule.level': range } });
  }
  if (query.ruleIds) {
    filter.push({ terms: { 'rule.id': String(query.ruleIds).split(',').filter(Boolean) } });
  }
  if (query.agentNames) {
    filter.push({ terms: { 'agent.name': String(query.agentNames).split(',').filter(Boolean) } });
  }
  if (query.alertTypes) {
    filter.push({ terms: { 'rule.groups': String(query.alertTypes).split(',').filter(Boolean) } });
  }
  if (query.assignedTo) {
    filter.push({ terms: { assigned_to: String(query.assignedTo).split(',').filter(Boolean) } });
  }
  if (query.caseId) {
    filter.push({ term: { case_id: query.caseId } });
  }
  if (query.from || query.to) {
    const range: any = {};
    if (query.from) range.gte = query.from;
    if (query.to) range.lte = query.to;
    filter.push({ range: { '@timestamp': range } });
  }
  if (query.q) {
    must.push({
      query_string: {
        query: query.q,
        default_operator: 'AND',
        analyze_wildcard: true,
        lenient: true,
      },
    });
  }

  if (must.length === 0 && filter.length === 0) {
    return { match_all: {} };
  }
  return { bool: { must, filter } };
}

export function defineAlertRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/alerts`,
      validate: {
        query: filterQuerySchema.extends({
          from_offset: schema.maybe(schema.number({ min: 0 })),
          size: schema.maybe(schema.number({ min: 1, max: 500 })),
          sortField: schema.maybe(schema.string()),
          sortDirection: schema.maybe(schema.oneOf([schema.literal('asc'), schema.literal('desc')])),
        }),
      },
    },
    async (context, request, response) => {
      const q = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: {
            from: q.from_offset || 0,
            size: q.size || 20,
            sort: [{ [q.sortField || '@timestamp']: { order: q.sortDirection || 'desc' } }],
            query: buildBoolQuery(q, true),
          },
        });
        return response.ok({ body: result.body });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/alerts/counts`,
      validate: { query: filterQuerySchema },
    },
    async (context, request, response) => {
      const q = request.query as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: ALERT_STATUS_INDEX,
          body: {
            size: 0,
            query: buildBoolQuery(q, false),
            aggs: { status_counts: { terms: { field: 'status', size: 10 } } },
          },
        });
        const counts: Record<string, number> = { open: 0, in_progress: 0, closed: 0 };
        for (const bucket of result.body.aggregations?.status_counts?.buckets || []) {
          counts[bucket.key] = bucket.doc_count;
        }
        return response.ok({
          body: {
            ...counts,
            total: result.body.hits.total?.value ?? 0,
          },
        });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/alerts/bulk-update`,
      validate: {
        body: schema.object({
          ids: schema.arrayOf(schema.string(), { minSize: 1, maxSize: 1000 }),
          status: schema.maybe(schema.oneOf(ALERT_STATUSES.map((s) => schema.literal(s)) as any)),
          caseId: schema.maybe(schema.nullable(schema.string())),
          assignedTo: schema.maybe(schema.nullable(schema.string())),
        }),
      },
    },
    async (context, request, response) => {
      const { ids, status, caseId, assignedTo } = request.body as any;
      if (status == null && caseId === undefined && assignedTo === undefined) {
        return response.badRequest({ body: { message: 'Provide at least one of status, caseId, or assignedTo' } });
      }

      const user = await getCurrentUsername(context, request);
      const client = context.core.opensearch.client.asCurrentUser;

      const fields: Record<string, any> = { updated_at: new Date().toISOString(), updated_by: user };
      if (status != null) fields.status = status;
      if (caseId !== undefined) fields.case_id = caseId;
      if (assignedTo !== undefined) fields.assigned_to = assignedTo;

      const changedFields = [
        status != null && 'status_change',
        caseId !== undefined && 'case_link',
        assignedTo !== undefined && 'assignment_change',
      ].filter(Boolean);
      const action = changedFields.length > 1 ? 'bulk_update' : (changedFields[0] as string);
      const entry = buildHistoryEntry({ user, action, to: status ?? assignedTo ?? caseId ?? null });

      const body: any[] = [];
      for (const id of ids) {
        body.push({ update: { _index: ALERT_STATUS_INDEX, _id: id } });
        body.push({
          script: {
            lang: 'painless',
            source: APPEND_HISTORY_SCRIPT_SOURCE,
            params: { entry, fields },
          },
        });
      }

      try {
        if (caseId !== undefined) {
          await syncCaseAlertIds(client, ids, caseId);
        }

        const result: any = await client.bulk({ body });
        const failed = (result.body.items || []).filter((i: any) => i.update?.error);
        if (failed.length) {
          return response.customError({
            statusCode: 207,
            body: { message: `${failed.length}/${ids.length} updates failed`, failed },
          });
        }
        return response.ok({ body: { updated: ids.length } });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/alerts/{id}`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.get({ index: ALERT_STATUS_INDEX, id });
        return response.ok({ body: result.body });
      } catch (e: any) {
        return response.customError({
          statusCode: e?.meta?.statusCode || 500,
          body: { message: e.message },
        });
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/alerts/{id}/related`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const alertRes: any = await client.get({ index: ALERT_STATUS_INDEX, id });
        const relatedIds: string[] = alertRes.body._source.related_alert_ids || [];
        if (relatedIds.length === 0) {
          return response.ok({ body: { alerts: [] } });
        }
        const mgetRes: any = await client.mget({ index: ALERT_STATUS_INDEX, body: { ids: relatedIds } });
        const alerts = mgetRes.body.docs.filter((d: any) => d.found).map((d: any) => ({ _id: d._id, _source: d._source }));
        return response.ok({ body: { alerts } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/alerts/{id}/related`,
      validate: {
        params: schema.object({ id: schema.string() }),
        body: schema.object({
          relatedIds: schema.arrayOf(schema.string(), { minSize: 1, maxSize: 50 }),
          mode: schema.oneOf([schema.literal('add'), schema.literal('remove')]),
        }),
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const { relatedIds, mode } = request.body as any;
      const user = await getCurrentUsername(context, request);
      const client = context.core.opensearch.client.asCurrentUser;

      const scriptSource =
        mode === 'add'
          ? `
            if (ctx._source.related_alert_ids == null) { ctx._source.related_alert_ids = []; }
            for (id in params.ids) { if (!ctx._source.related_alert_ids.contains(id)) { ctx._source.related_alert_ids.add(id); } }
          `
          : `
            if (ctx._source.related_alert_ids != null) { ctx._source.related_alert_ids.removeIf(v -> params.ids.contains(v)); }
          `;

      const entry = buildHistoryEntry({
        user,
        action: mode === 'add' ? 'related_alert_linked' : 'related_alert_unlinked',
        to: relatedIds.join(', '),
      });

      const body: any[] = [
        { update: { _index: ALERT_STATUS_INDEX, _id: id } },
        { script: { lang: 'painless', source: scriptSource, params: { ids: relatedIds } } },
        { update: { _index: ALERT_STATUS_INDEX, _id: id } },
        { script: { lang: 'painless', source: APPEND_HISTORY_SCRIPT_SOURCE, params: { entry, fields: null } } },
      ];
      for (const relatedId of relatedIds) {
        body.push({ update: { _index: ALERT_STATUS_INDEX, _id: relatedId } });
        body.push({ script: { lang: 'painless', source: scriptSource, params: { ids: [id] } } });
      }

      try {
        await client.bulk({ body });
        return response.ok({ body: { updated: true } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
