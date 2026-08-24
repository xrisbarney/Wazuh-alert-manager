import { RequestHandlerContext, OpenSearchDashboardsRequest } from '../../../../src/core/server';

/**
 * Best-effort lookup of the logged-in dashboard user, using the OpenSearch
 * Security plugin's account API when present. Falls back to a generic
 * identity so the plugin keeps working on clusters without the security
 * plugin installed (e.g. local dev clusters with security disabled).
 */
export async function getCurrentUsername(
  context: RequestHandlerContext,
  request: OpenSearchDashboardsRequest
): Promise<string> {
  try {
    const client = context.core.opensearch.client.asCurrentUser;
    const res: any = await client.transport.request({
      method: 'GET',
      path: '/_plugins/_security/api/account',
    });
    return res?.body?.user_name || res?.body?.username || 'dashboard_user';
  } catch (e) {
    const headerUser = request.headers['x-forwarded-user'];
    if (typeof headerUser === 'string' && headerUser) {
      return headerUser;
    }
    return 'dashboard_user';
  }
}
