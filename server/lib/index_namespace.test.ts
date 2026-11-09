import {
  assertManagedWriteTarget,
  assertSafeSourcePattern,
  isApprovedEvidenceIndex,
  isApprovedSourceIndex,
  isManagedPhysicalIndex,
} from './index_namespace';
import { WAZUH4_ALERTS_PROFILE, WAZUH5_FINDINGS_PROFILE } from './source_profile';

describe('plugin index namespace', () => {
  test('accepts only plugin-owned v2 write targets', () => {
    expect(assertManagedWriteTarget('wazuh-alert-status-v2-write')).toBe('wazuh-alert-status-v2-write');
    expect(assertManagedWriteTarget('wazuh-alert-manager-v2-meta')).toBe('wazuh-alert-manager-v2-meta');
    expect(() => assertManagedWriteTarget('wazuh-alerts-*')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('wazuh-alert-status')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('*')).toThrow(/Refusing write/);
  });

  test('refuses every native 4.x and 5.0 store by name, even if an allowlist mistake named it', () => {
    for (const native of [
      'wazuh-alerts-4.x-2026.10.31',
      'wazuh-archives-4.x-2026.10.31',
      'wazuh-events-v5-security',
      'wazuh-events-raw-v5',
      'wazuh-findings-v5-security',
      '.ds-wazuh-findings-v5-security-000001',
      '.ds-wazuh-events-v5-security-000001',
      'wazuh-states-inventory-system',
      'wazuh-case-management-cases',
      'wazuh-monitoring-2026.10w',
      'wazuh-statistics-2026.10w',
    ]) {
      expect(() => assertManagedWriteTarget(native)).toThrow(/Refusing write/);
    }
  });

  test('refuses multi-target and wildcard write strings', () => {
    expect(() => assertManagedWriteTarget('wazuh-alert-status-v2-write,wazuh-alerts-4.x-x')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('wazuh-alert-status-v2-*')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('wazuh-alert-status-v2-write ')).toThrow(/Refusing write/);
    expect(() => assertManagedWriteTarget('')).toThrow(/<empty>/);
  });

  test('accepts only native Wazuh alert source patterns', () => {
    expect(assertSafeSourcePattern('wazuh-alerts-*')).toBe('wazuh-alerts-*');
    expect(() => assertSafeSourcePattern('*')).toThrow(/explicit/);
    expect(() => assertSafeSourcePattern('wazuh-alert-status-v2-*')).toThrow(/Unsafe source/);
    expect(() => assertSafeSourcePattern('wazuh-alert-status')).toThrow(/Unsafe source/);
  });

  test('4.x profile rejects 5.0 streams and hostile pattern parts', () => {
    for (const bad of [
      'wazuh-findings-v5-*',
      'wazuh-alerts-*,wazuh-findings-v5-*',
      'wazuh-alerts-*,*',
      '_all',
      '-wazuh-alerts-*',
      'wazuh-alerts-**',
      'WAZUH-ALERTS-*',
      'wazuh-alerts-4.x-*/_doc',
      'wazuh-alerts-<x>',
    ]) {
      expect(() => assertSafeSourcePattern(bad, WAZUH4_ALERTS_PROFILE)).toThrow(/explicit|Unsafe source/);
    }
    expect(assertSafeSourcePattern('wazuh-alerts-4.x-*,wazuh-alerts-4.x-wam-e2e')).toBe(
      'wazuh-alerts-4.x-*,wazuh-alerts-4.x-wam-e2e'
    );
  });

  test('5.0 profile accepts only findings data-stream patterns', () => {
    expect(assertSafeSourcePattern('wazuh-findings-v5-*', WAZUH5_FINDINGS_PROFILE)).toBe('wazuh-findings-v5-*');
    expect(assertSafeSourcePattern('wazuh-findings-v5-security,wazuh-findings-v5-wam-e2e', WAZUH5_FINDINGS_PROFILE)).toBe(
      'wazuh-findings-v5-security,wazuh-findings-v5-wam-e2e'
    );
    for (const bad of [
      'wazuh-alerts-*',
      'wazuh-events-v5-*',
      'wazuh-events-raw-v5',
      '.ds-wazuh-findings-v5-security-000001',
      'wazuh-findings-v5-*,wazuh-events-v5-*',
      'wazuh-alert-status-v2-*',
      '*',
      'wazuh-findings-v5-**',
    ]) {
      expect(() => assertSafeSourcePattern(bad, WAZUH5_FINDINGS_PROFILE)).toThrow(/explicit|Unsafe source/);
    }
  });

  test('approved hydration indices are exact physical names inside the family', () => {
    expect(isApprovedSourceIndex('wazuh-alerts-4.x-2026.10.31', WAZUH4_ALERTS_PROFILE)).toBe(true);
    expect(isApprovedSourceIndex('wazuh-alerts-', WAZUH4_ALERTS_PROFILE)).toBe(false);
    expect(isApprovedSourceIndex('wazuh-alerts-*', WAZUH4_ALERTS_PROFILE)).toBe(false);
    expect(isApprovedSourceIndex('.ds-wazuh-findings-v5-security-000001', WAZUH4_ALERTS_PROFILE)).toBe(false);
    expect(isApprovedEvidenceIndex('wazuh-alerts-4.x-2026.10.31', WAZUH4_ALERTS_PROFILE)).toBe(false);

    expect(isApprovedSourceIndex('.ds-wazuh-findings-v5-security-000001', WAZUH5_FINDINGS_PROFILE)).toBe(true);
    expect(isApprovedSourceIndex('.ds-wazuh-findings-v5-system-activity-000042', WAZUH5_FINDINGS_PROFILE)).toBe(true);
    expect(isApprovedSourceIndex('wazuh-findings-v5-security', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedSourceIndex('.ds-wazuh-findings-v5-security-000001,.ds-x', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedSourceIndex('.ds-wazuh-findings-v5-security-*', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedSourceIndex('.ds-wazuh-events-v5-security-000001', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedSourceIndex('wazuh-alerts-4.x-2026.10.31', WAZUH5_FINDINGS_PROFILE)).toBe(false);

    expect(isApprovedEvidenceIndex('.ds-wazuh-events-v5-security-000001', WAZUH5_FINDINGS_PROFILE)).toBe(true);
    expect(isApprovedEvidenceIndex('.ds-wazuh-events-raw-v5-000003', WAZUH5_FINDINGS_PROFILE)).toBe(true);
    expect(isApprovedEvidenceIndex('.ds-wazuh-findings-v5-security-000001', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedEvidenceIndex('wazuh-events-v5-security', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedEvidenceIndex('.ds-wazuh-events-v5-security-000001/../x', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedEvidenceIndex('.kibana_1', WAZUH5_FINDINGS_PROFILE)).toBe(false);
    expect(isApprovedEvidenceIndex('.opendistro_security', WAZUH5_FINDINGS_PROFILE)).toBe(false);
  });

  test('validates resolved backing index families', () => {
    expect(isManagedPhysicalIndex('wazuh-alert-status-v2-000002', 'wazuh-alert-status-v2-')).toBe(true);
    expect(
      isManagedPhysicalIndex('wazuh-alert-manager-v2-activity-000001', 'wazuh-alert-status-v2-')
    ).toBe(false);
  });
});
