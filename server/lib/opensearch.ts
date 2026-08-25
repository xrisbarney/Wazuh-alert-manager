import { RequestHandlerContext, OpenSearchDashboardsRequest } from '../../../../src/core/server';
import { trustedIdentity } from './identity';

/**
 * The display name of the acting user, for audit-history attribution.
 *
 * Delegates to trustedIdentity(), which resolves identity from the OpenSearch
 * Security plugin and NEVER from a client-controlled request header. On a
 * cluster without the security plugin this returns a generic 'dashboard_user'
 * label. For anything that must AUTHORISE on identity (destructive actions),
 * call trustedIdentity() directly and check `source === 'security_plugin'`
 * rather than trusting this string.
 */
export async function getCurrentUsername(
  context: RequestHandlerContext,
  request: OpenSearchDashboardsRequest
): Promise<string> {
  return (await trustedIdentity(context, request)).name;
}
