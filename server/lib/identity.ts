import { RequestHandlerContext, OpenSearchDashboardsRequest } from '../../../../src/core/server';

export interface TrustedIdentity {
  name: string;
  roles: string[];
  // 'security_plugin' means the OpenSearch Security plugin named this user and
  // the identity is trustworthy for attribution AND authorisation. 'anonymous'
  // means we could not establish who this is - safe to display, NEVER safe to
  // authorise a privileged or destructive action on.
  source: 'security_plugin' | 'anonymous';
}

/**
 * Resolves the acting user's identity from the OpenSearch Security plugin only.
 *
 * It deliberately NEVER reads a request header (x-forwarded-user and the like):
 * a request header is client-controlled, so honouring it would let any
 * authenticated dashboard user attribute an action to another person - and an
 * audit record that can be forged is worse than none, because it will be
 * believed. When the security plugin cannot name the user, `source` is
 * 'anonymous' and any caller making an authorisation decision must refuse.
 */
export async function trustedIdentity(
  context: RequestHandlerContext,
  _request: OpenSearchDashboardsRequest
): Promise<TrustedIdentity> {
  try {
    const client = context.core.opensearch.client.asCurrentUser;
    const res: any = await client.transport.request({
      method: 'GET',
      path: '/_plugins/_security/api/account',
    });
    const name = res?.body?.user_name || res?.body?.username;
    if (name) {
      return {
        name,
        roles: Array.isArray(res?.body?.roles) ? res.body.roles : [],
        source: 'security_plugin',
      };
    }
  } catch (e) {
    // Security plugin absent (e.g. a dev cluster with security disabled) or the
    // account call failed - fall through to anonymous.
  }
  return { name: 'dashboard_user', roles: [], source: 'anonymous' };
}
