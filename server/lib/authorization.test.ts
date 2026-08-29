import { canManageLifecycle, isPluginAdmin } from './authorization';
import { TrustedIdentity } from './identity';

const identity = (securityRoles: string[], backendRoles: string[] = []): TrustedIdentity => ({
  name: 'test',
  securityRoles,
  backendRoles,
  roles: [...securityRoles, ...backendRoles],
  source: 'security_plugin',
});

describe('Wazuh/OpenSearch role gating', () => {
  test('allows mapped cluster administrators', () => {
    expect(isPluginAdmin(identity(['all_access'], ['wazuh-admins']))).toBe(true);
    expect(canManageLifecycle(identity(['all_access'], ['wazuh-admins']))).toBe(true);
  });

  test('allows the existing delegated index-management role for lifecycle only', () => {
    expect(canManageLifecycle(identity(['index_management_full_access'], ['security-operations']))).toBe(true);
    expect(isPluginAdmin(identity(['index_management_full_access'], ['security-operations']))).toBe(false);
  });

  test('does not trust arbitrary IdP or LDAP group names without an effective role mapping', () => {
    expect(canManageLifecycle(identity(['readall'], ['admin', 'wazuh-admins']))).toBe(false);
    expect(isPluginAdmin(identity(['readall'], ['admin', 'wazuh-admins']))).toBe(false);
  });
});
