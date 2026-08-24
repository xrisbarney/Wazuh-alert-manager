import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, COMMENTS_INDEX, ALERT_STATUS_INDEX } from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';

export function defineCommentRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/comments`,
      validate: {
        query: schema.object({
          alertId: schema.maybe(schema.string()),
          caseId: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      const { alertId, caseId } = request.query as any;
      if (!alertId && !caseId) {
        return response.badRequest({ body: { message: 'alertId or caseId is required' } });
      }
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const result: any = await client.search({
          index: COMMENTS_INDEX,
          body: {
            size: 200,
            sort: [{ created_at: { order: 'asc' } }],
            query: { term: alertId ? { alert_id: alertId } : { case_id: caseId } },
          },
        });
        const comments = result.body.hits.hits.map((h: any) => ({ id: h._id, ...h._source }));
        return response.ok({ body: { comments } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/comments`,
      validate: {
        body: schema.object({
          alertId: schema.maybe(schema.string()),
          caseId: schema.maybe(schema.string()),
          text: schema.string({ minLength: 1, maxLength: 5000 }),
        }),
      },
    },
    async (context, request, response) => {
      const { alertId, caseId, text } = request.body as any;
      if (!alertId && !caseId) {
        return response.badRequest({ body: { message: 'alertId or caseId is required' } });
      }
      const user = await getCurrentUsername(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const doc = {
        alert_id: alertId ?? null,
        case_id: caseId ?? null,
        text,
        author: user,
        created_at: new Date().toISOString(),
      };

      try {
        const result: any = await client.index({ index: COMMENTS_INDEX, body: doc, refresh: 'wait_for' });

        if (alertId) {
          // Best-effort visibility into the alert's audit trail; comment
          // creation should still succeed even if this fails.
          try {
            await client.update({
              index: ALERT_STATUS_INDEX,
              id: alertId,
              body: {
                script: {
                  lang: 'painless',
                  source: APPEND_HISTORY_SCRIPT_SOURCE,
                  params: { entry: buildHistoryEntry({ user, action: 'comment_added' }), fields: null },
                },
              },
            });
          } catch (e) {
            // ignore
          }
        }

        return response.ok({ body: { id: result.body._id, ...doc } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );

  router.delete(
    {
      path: `${API_ROOT}/comments/{id}`,
      validate: { params: schema.object({ id: schema.string() }) },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        await client.delete({ index: COMMENTS_INDEX, id });
        return response.ok({ body: { deleted: true } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
