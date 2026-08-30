import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT } from '../../common';
import { appendActivity } from '../lib/activity';
import { requireLifecycleManager } from '../lib/authorization';
import {
  getEvidence,
  listCaseEvidence,
  resolveArchivedEvidence,
  setEvidenceHold,
} from '../lib/evidence';
import { resolveCaseAlerts } from '../lib/index_resolution';
import { resolveAlerts } from '../lib/index_resolution';

const paramsSchema = schema.object({ caseId: schema.string(), alertId: schema.string() });

export function defineEvidenceRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/cases/{caseId}/evidence`,
      validate: {
        params: schema.object({ caseId: schema.string() }),
        query: schema.object({
          size: schema.maybe(schema.number({ min: 1, max: 1000 })),
          cursor: schema.maybe(schema.string({ maxLength: 4096 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const { size, cursor } = request.query as any;
        const page = await listCaseEvidence(client, (request.params as any).caseId, { size, cursor });
        const locations = await resolveCaseAlerts(client, page.evidence);
        const alerts = page.evidence.map((item: any) => {
          const resolved = locations.get(item.alert_id);
          return {
            _id: item.alert_id,
            _source: resolved?.source || item.snapshot || {},
            evidence_only: resolved?.availability !== 'live',
            evidence_availability: resolved?.availability || 'unavailable',
          };
        });
        return response.ok({ body: { ...page, alerts } });
      } catch (e: any) {
        return response.customError({ statusCode: e.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/cases/{caseId}/evidence/{alertId}`, validate: { params: paramsSchema } },
    async (context, request, response) => {
      const { caseId, alertId } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const evidence = await getEvidence(client, caseId, alertId);
        if (!evidence) return response.notFound({ body: { message: 'Evidence relationship was not found.' } });

        const live = await resolveAlerts(client, [alertId], true);
        const liveAlert = live.get(alertId);
        if (liveAlert) {
          return response.ok({
            body: { availability: 'live', evidence, alert: { _id: alertId, _source: liveAlert.source } },
          });
        }
        if (evidence.relationship_state === 'purged') {
          return response.ok({ body: { availability: 'purged', evidence, alert: null } });
        }
        try {
          const archived = await resolveArchivedEvidence(client, evidence);
          return response.ok({
            body: { availability: 'archived', evidence, alert: { _id: alertId, _source: archived } },
          });
        } catch (e: any) {
          return response.ok({
            body: {
              availability: evidence.archive_index ? 'archive_offline' : 'snapshot_only',
              evidence,
              alert: null,
              message: e.message,
            },
          });
        }
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/cases/{caseId}/evidence/{alertId}/hold`,
      validate: {
        params: paramsSchema,
        body: schema.object({ reason: schema.string({ minLength: 1, maxLength: 1000 }) }),
      },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const { caseId, alertId } = request.params as any;
        const reason = String((request.body as any).reason).trim();
        if (!reason) return response.badRequest({ body: { message: 'A hold reason is required.' } });
        const client = context.core.opensearch.client.asCurrentUser;
        const evidence = await setEvidenceHold(client, caseId, alertId, {
          reason,
          by: identity.name,
          since: new Date().toISOString(),
        });
        await appendActivity(client, {
          targetType: 'case', targetId: caseId, user: identity.name,
          action: 'evidence hold set', to: alertId, source: 'lifecycle',
        });
        return response.ok({ body: evidence });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || (e.message.includes('not found') ? 404 : 500);
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );

  router.delete(
    {
      path: `${API_ROOT}/cases/{caseId}/evidence/{alertId}/hold`,
      validate: { params: paramsSchema },
    },
    async (context, request, response) => {
      try {
        const identity = await requireLifecycleManager(context, request);
        const { caseId, alertId } = request.params as any;
        const client = context.core.opensearch.client.asCurrentUser;
        const evidence = await setEvidenceHold(client, caseId, alertId, null);
        await appendActivity(client, {
          targetType: 'case', targetId: caseId, user: identity.name,
          action: 'evidence hold released', from: alertId, source: 'lifecycle',
        });
        return response.ok({ body: evidence });
      } catch (e: any) {
        const statusCode = e?.statusCode || e?.meta?.statusCode || (e.message.includes('not found') ? 404 : 500);
        return response.customError({ statusCode, body: { message: e.message } });
      }
    }
  );
}
