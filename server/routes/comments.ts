import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import { API_ROOT, COMMENTS_INDEX, ACTIVITY_WRITE_ALIAS, CommentListResponse } from '../../common';
import { getCurrentUsername } from '../lib/opensearch';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from '../lib/history';
import { alertIndexOrThrow, resolveManagedDocuments } from '../lib/index_resolution';
import { isPluginAdmin } from '../lib/authorization';
import { trustedIdentity } from '../lib/identity';
import { appendActivity } from '../lib/activity';
import { resolveCase } from '../lib/case_index_resolution';
import { decodePageCursor, encodePageCursor, exactHitTotal } from '../lib/evidence';

function hasExactlyOneTarget(alertId?: string, caseId?: string): boolean {
  return Number(Boolean(alertId)) + Number(Boolean(caseId)) === 1;
}

export async function listComments(
  client: any,
  target: { alertId?: string; caseId?: string },
  options: { size?: number; cursor?: string } = {}
): Promise<CommentListResponse> {
  const size = Math.min(Math.max(options.size ?? 200, 1), 200);
  const targetType = target.alertId ? 'alert' : 'case';
  const targetId = target.alertId || target.caseId || '';
  const scope = `comments:${targetType}:${targetId}`;
  const searchAfter = decodePageCursor(options.cursor, scope);
  const result: any = await client.search({
    index: COMMENTS_INDEX,
    body: {
      size: size + 1,
      track_total_hits: true,
      sort: [{ created_at: { order: 'asc' } }, { _doc: { order: 'asc' } }],
      query: {
        bool: {
          filter: [
            { term: { event_type: 'comment' } },
            { term: target.alertId ? { alert_id: target.alertId } : { case_id: target.caseId } },
          ],
        },
      },
      ...(searchAfter ? { search_after: searchAfter } : {}),
    },
  });
  const hits = result?.body?.hits;
  const visible = (hits?.hits || []).slice(0, size);
  const truncated = (hits?.hits || []).length > size;
  return {
    comments: visible.map((hit: any) => ({ id: hit._id, ...hit._source })),
    nextCursor: truncated && visible.length ? encodePageCursor(scope, visible[visible.length - 1].sort) : null,
    total: exactHitTotal(hits),
    truncated,
  };
}

export function defineCommentRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/comments`,
      validate: {
        query: schema.object({
          alertId: schema.maybe(schema.string()),
          caseId: schema.maybe(schema.string()),
          size: schema.maybe(schema.number({ min: 1, max: 200 })),
          cursor: schema.maybe(schema.string({ maxLength: 4096 })),
        }),
      },
    },
    async (context, request, response) => {
      const { alertId, caseId, size, cursor } = request.query as any;
      if (!hasExactlyOneTarget(alertId, caseId)) {
        return response.badRequest({ body: { message: 'Exactly one of alertId or caseId is required' } });
      }
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        return response.ok({ body: await listComments(client, { alertId, caseId }, { size, cursor }) });
      } catch (e: any) {
        return response.customError({ statusCode: e.statusCode || e?.meta?.statusCode || 500, body: { message: e.message } });
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
      if (!hasExactlyOneTarget(alertId, caseId)) {
        return response.badRequest({ body: { message: 'Exactly one of alertId or caseId is required' } });
      }
      const user = await getCurrentUsername(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const doc = {
        event_type: 'comment',
        target_type: alertId ? 'alert' : 'case',
        target_id: alertId || caseId,
        alert_id: alertId ?? null,
        case_id: caseId ?? null,
        text,
        author: user,
        created_at: new Date().toISOString(),
      };

      try {
        const alertIndex = alertId ? await alertIndexOrThrow(client, alertId) : null;
        if (caseId) await resolveCase(client, caseId);
        const result: any = await client.index({ index: ACTIVITY_WRITE_ALIAS, body: doc, refresh: 'wait_for' });

        if (alertId) {
          // Best-effort visibility into the alert's audit trail; comment
          // creation should still succeed even if this fails.
          try {
            await client.update({
              index: alertIndex!,
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
        const statusCode = e?.meta?.statusCode || (e.message.includes('not found') ? 404 : 500);
        return response.customError({ statusCode, body: { message: e.message } });
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
        const found = await resolveManagedDocuments(
          client,
          COMMENTS_INDEX,
          [id],
          'wazuh-alert-manager-v2-activity-',
          true
        );
        const location = found.get(id);
        if (!location) return response.notFound({ body: { message: 'Comment not found' } });
        if (location.source?.event_type !== 'comment') {
          return response.notFound({ body: { message: 'Comment not found' } });
        }
        const identity = await trustedIdentity(context, request);
        if (identity.source === 'anonymous') {
          return response.forbidden({ body: { message: 'A trusted identity is required to delete a comment.' } });
        }
        if (location.source?.author !== identity.name && !isPluginAdmin(identity)) {
          return response.forbidden({ body: { message: 'Only the comment author or a plugin administrator can delete it.' } });
        }
        await client.delete({ index: location.index, id });
        await appendActivity(client, {
          targetType: location.source?.alert_id ? 'alert' : 'case',
          targetId: location.source?.alert_id || location.source?.case_id,
          user: identity.name,
          action: 'comment_deleted',
        });
        return response.ok({ body: { deleted: true } });
      } catch (e: any) {
        return response.customError({ statusCode: e?.meta?.statusCode || 500, body: { message: e.message } });
      }
    }
  );
}
