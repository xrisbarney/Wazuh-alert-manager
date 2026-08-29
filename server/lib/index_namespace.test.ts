import { assertManagedWriteTarget, assertSafeSourcePattern, isManagedPhysicalIndex } from './index_namespace';

describe('plugin index namespace', () => {
  test('accepts only plugin-owned v2 write targets', () => {
    expect(assertManagedWriteTarget('wazuh-alert-status-v2-write')).toBe('wazuh-alert-status-v2-write');
    expect(assertManagedWriteTarget('wazuh-alert-manager-v2-meta')).toBe('wazuh-alert-manager-v2-meta');
    expect(() => assertManagedWriteTarget('wazuh-alerts-*')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('wazuh-alert-status')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('*')).toThrow(/Refusing write/);
  });

  test('accepts only native Wazuh alert source patterns', () => {
    expect(assertSafeSourcePattern('wazuh-alerts-*')).toBe('wazuh-alerts-*');
    expect(() => assertSafeSourcePattern('*')).toThrow(/explicit/);
    expect(() => assertSafeSourcePattern('wazuh-alert-status-v2-*')).toThrow(/Unsafe source/);
    expect(() => assertSafeSourcePattern('wazuh-alert-status')).toThrow(/Unsafe source/);
  });

  test('validates resolved backing index families', () => {
    expect(isManagedPhysicalIndex('wazuh-alert-status-v2-000002', 'wazuh-alert-status-v2-')).toBe(true);
    expect(
      isManagedPhysicalIndex('wazuh-alert-manager-v2-activity-000001', 'wazuh-alert-status-v2-')
    ).toBe(false);
  });
});
