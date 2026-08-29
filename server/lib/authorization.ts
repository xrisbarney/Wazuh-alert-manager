import { RequestHandlerContext, OpenSearchDashboardsRequest } from '../../../../src/core/server';
import { trustedIdentity, TrustedIdentity } from './identity';

// These are OpenSearch Security roles, not usernames or IdP/LDAP group names.
// Wazuh maps internal users, SAML groups and LDAP/AD groups (backend roles) to
// these effective roles. We intentionally evaluate the mapped result returned
// by the Security plugin so deployments do not need plugin-specific mappings.
const ADMIN_SECURITY_ROLES = new Set(['all_access']);
const LIFECYCLE_SECURITY_ROLES = new Set(['all_access', 'index_management_full_access']);

export function isPluginAdmin(identity: TrustedIdentity): boolean {
  return (
    identity.source === 'security_plugin' &&
    identity.securityRoles.some((role) => ADMIN_SECURITY_ROLES.has(role))
  );
}

export function canManageLifecycle(identity: TrustedIdentity): boolean {
  return (
    identity.source === 'security_plugin' &&
    identity.securityRoles.some((role) => LIFECYCLE_SECURITY_ROLES.has(role))
  );
}

export async function requirePluginAdmin(
  context: RequestHandlerContext,
  request: OpenSearchDashboardsRequest
): Promise<TrustedIdentity> {
  const identity = await trustedIdentity(context, request);
  if (!isPluginAdmin(identity)) {
    const error: any = new Error('Administrator permission is required for this operation.');
    error.statusCode = 403;
    throw error;
  }
  return identity;
}

export async function requireLifecycleManager(
  context: RequestHandlerContext,
  request: OpenSearchDashboardsRequest
): Promise<TrustedIdentity> {
  const identity = await trustedIdentity(context, request);
  if (!canManageLifecycle(identity)) {
    const error: any = new Error(
      'Lifecycle management requires the Wazuh/OpenSearch all_access or index_management_full_access role.'
    );
    error.statusCode = 403;
    throw error;
  }
  return identity;
}
