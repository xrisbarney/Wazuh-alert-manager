import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  CASES_INDEX,
  ALERT_STATUS_INDEX,
  COMMENTS_INDEX,
  CASE_SEVERITIES,
  CASE_STATUSES,
} from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';

async function linkAlertsToCase(client: any, alertIds: string[], caseId: string | null, user: string, action: string) {
  if (alertIds.length === 0) return;
  const entry = buildHistoryEntry({ user, action, to: caseId });
  const body: any[] = [];
  for (const id of alertIds) {
    body.push({ update: { _index: ALERT_STATUS_INDEX, _id: id } });
    body.push({
      script: {
        lang: 'painless',
        source: APPEND_HISTORY_SCRIPT_SOURCE,
        params: { entry, fields: { case_id: caseId, updated_at: entry.timestamp, updated_by: user } },
      },
    });
  }
  await client.bulk({ body });
}

export function defineCaseRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/cases`,
      validate: {
        query: schema.object({
          status: schema.maybe(schema.string()),
          assignedTo: schema.maybe(schema.string()),
          q: schema.maybe(schema.string()),
          from: schema.maybe(schema.string()),
          to: schema.maybe(schema.string()),
          from_offset: schema.maybe(schema.number({ min: 0 })),
          size: schema.maybe(schema.number({ min: 1, max: 200 })),
        }),
      },
    },
    async (context, request, response) => {
      const { status, assignedTo, q, from, to, from_offset, size } = request.query as any;
      const filter: any[] = [];
      const must: any[] = [];
      if (status) filter.push({ terms: { status: String(status).split(',').filter(Boolean) } });
      if (assignedTo) filter.push({ terms: { assigned_to: String(assignedTo).split(',').filter(Boolean) } });
      if (from || to) {
        const range: any = {};
        if (from) range.gte = from;
        if (to) range.lte = to;
        filter.push({ range: { created_at: range } });
      }
      if (q) must.push({ query_string: { query: q, default_operator: 'AND', lenient: true } });

      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: CASES_INDEX,
          body: {
            from: from_offset || 0,
            size: size || 50,
            sort: [{ updated_at: { order: 'desc' } }],
            query: must.length || filter.length ? { bool: { must, filter } } : { match_all: {} },
          },
        });
        const cases = result.body.hits.hits.map((h: any) => ({ id: h._id, ...h._source }));
        return response.ok({ body: { cases, total: result.body.hits.total?.value ?? 0 } });
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
        const caseRes: any = await client.get({ index: CASES_INDEX, id });
        const caseDoc = { id: caseRes.body._id, ...caseRes.body._source };

        let alerts: any[] = [];
        if (caseDoc.alert_ids?.length) {
          const mgetRes: any = await client.mget({
            index: ALERT_STATUS_INDEX,
            body: { ids: caseDoc.alert_ids },
          });
          alerts = mgetRes.body.docs.filter((d: any) => d.found).map((d: any) => ({ _id: d._id, _source: d._source }));
        }

        const commentsRes: any = await client.search({
          index: COMMENTS_INDEX,
          body: {
            size: 200,
            sort: [{ created_at: { order: 'asc' } }],
            query: { term: { case_id: id } },
          },
        });
        const comments = commentsRes.body.hits.hits.map((h: any) => ({ id: h._id, ...h._source }));

        return response.ok({ body: { case: caseDoc, alerts, comments } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 404, body: { message: e.message } });
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
          alertIds: schema.arrayOf(schema.string(), { defaultValue: [] }),
          assignedTo: schema.maybe(schema.nullable(schema.string())),
        }),
      },
    },
    async (context, request, response) => {
      const { title, description, severity, alertIds, assignedTo } = request.body as any;
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const client = context.core.opensearch.client.asCurrentUser;

      const doc = {
        title,
        description: description ?? '',
        severity,
        status: 'open',
        assigned_to: assignedTo ?? null,
        alert_ids: alertIds,
        created_by: user,
        created_at: now,
        updated_by: user,
        updated_at: now,
        closed_at: null,
        history: [buildHistoryEntry({ user, action: 'case_created' })],
      };

      try {
        const result: any = await client.index({ index: CASES_INDEX, body: doc, refresh: 'wait_for' });
        const caseId = result.body._id;
        await linkAlertsToCase(client, alertIds, caseId, user, 'case_link');
        return response.ok({ body: { id: caseId, ...doc } });
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
          status: schema.maybe(schema.oneOf(CASE_STATUSES.map((s) => schema.literal(s)) as any)),
          assignedTo: schema.maybe(schema.nullable(schema.string())),
          addAlertIds: schema.arrayOf(schema.string(), { defaultValue: [] }),
          removeAlertIds: schema.arrayOf(schema.string(), { defaultValue: [] }),
        }),
      },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const { title, description, severity, status, assignedTo, addAlertIds, removeAlertIds } = request.body as any;
      const user = await getCurrentUsername(context, request);
      const now = new Date().toISOString();
      const client = context.core.opensearch.client.asCurrentUser;

      try {
        const current: any = await client.get({ index: CASES_INDEX, id });
        const currentAlertIds: string[] = current.body._source.alert_ids || [];
        const newAlertIds = Array.from(
          new Set([...currentAlertIds, ...addAlertIds].filter((aid) => !removeAlertIds.includes(aid)))
        );

        const fields: Record<string, any> = { updated_by: user, updated_at: now, alert_ids: newAlertIds };
        if (title != null) fields.title = title;
        if (description != null) fields.description = description;
        if (severity != null) fields.severity = severity;
        if (assignedTo !== undefined) fields.assigned_to = assignedTo;
        if (status != null) {
          fields.status = status;
          fields.closed_at = status === 'closed' ? now : null;
        }

        const action = status != null ? 'status_change' : assignedTo !== undefined ? 'assignment_change' : 'case_updated';
        const entry = buildHistoryEntry({
          user,
          action,
          from: action === 'status_change' ? current.body._source.status : current.body._source.assigned_to,
          to: status ?? assignedTo ?? current.body._source.status,
        });

        await client.update({
          index: CASES_INDEX,
          id,
          body: {
            script: { lang: 'painless', source: APPEND_HISTORY_SCRIPT_SOURCE, params: { entry, fields } },
          },
        });

        if (addAlertIds.length) await linkAlertsToCase(client, addAlertIds, id, user, 'case_link');
        if (removeAlertIds.length) await linkAlertsToCase(client, removeAlertIds, null, user, 'case_unlink');

        const updated: any = await client.get({ index: CASES_INDEX, id });
        return response.ok({ body: { id, ...updated.body._source } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
