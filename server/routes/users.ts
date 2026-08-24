import { IRouter } from '../../../../src/core/server';
import { API_ROOT } from '../../common';

/**
 * Best-effort list of real dashboard users, for the assignee picker.
 * Requires the OpenSearch Security plugin and permission to read its
 * internal users API - on clusters without either, this quietly returns
 * an empty list and the frontend falls back to free text / previously
 * used assignee values (see routes/filters.ts).
 */
export function defineUserRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/users`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const res: any = await client.transport.request({
        method: 'GET',
        path: '/_plugins/_security/api/internalusers',
      });
      const users = Object.keys(res?.body || {}).sort();
      return response.ok({ body: { users } });
    } catch (e) {
      return response.ok({ body: { users: [] } });
    }
  });
}
