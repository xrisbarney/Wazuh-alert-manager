import {
  SOURCE_PROFILES,
  WAZUH4_ALERTS_PROFILE,
  WAZUH5_FINDINGS_PROFILE,
  sourceFamilyOfIndex,
  sourceProfile,
} from './source_profile';

describe('Wazuh source profiles', () => {
  test('profiles are frozen and resolvable by family', () => {
    expect(sourceProfile('wazuh4_alerts')).toBe(WAZUH4_ALERTS_PROFILE);
    expect(sourceProfile('wazuh5_findings')).toBe(WAZUH5_FINDINGS_PROFILE);
    expect(Object.isFrozen(SOURCE_PROFILES)).toBe(true);
    expect(() => sourceProfile('wazuh6' as any)).toThrow(/Unknown Wazuh source family/);
  });

  test('4.x profile describes numeric rule.level and plain alert indices', () => {
    expect(WAZUH4_ALERTS_PROFILE.severityModel).toBe('numeric_level');
    expect(WAZUH4_ALERTS_PROFILE.defaultPattern).toBe('wazuh-alerts-*');
    expect(WAZUH4_ALERTS_PROFILE.isSourceIndex('wazuh-alerts-4.x-2026.10.31')).toBe(true);
    expect(WAZUH4_ALERTS_PROFILE.isSourceIndex('wazuh-alerts-4.x-wam-benchmark')).toBe(true);
    expect(WAZUH4_ALERTS_PROFILE.isEvidenceIndex('wazuh-alerts-4.x-2026.10.31')).toBe(false);
  });

  test('5.0 profile describes labelled severity, findings backing indices and event evidence', () => {
    expect(WAZUH5_FINDINGS_PROFILE.severityModel).toBe('label');
    expect(WAZUH5_FINDINGS_PROFILE.defaultPattern).toBe('wazuh-findings-v5-*');
    expect(WAZUH5_FINDINGS_PROFILE.isAllowedPatternPart('wazuh-findings-v5-*')).toBe(true);
    expect(WAZUH5_FINDINGS_PROFILE.isAllowedPatternPart('wazuh-findings-v5*')).toBe(true);
    expect(WAZUH5_FINDINGS_PROFILE.isAllowedPatternPart('wazuh-findings-v5-access-management')).toBe(true);
    expect(WAZUH5_FINDINGS_PROFILE.isAllowedPatternPart('.ds-wazuh-findings-v5-security-000001')).toBe(false);
    expect(WAZUH5_FINDINGS_PROFILE.isAllowedPatternPart('wazuh-findings-v4-*')).toBe(false);
    expect(WAZUH5_FINDINGS_PROFILE.isSourceIndex('.ds-wazuh-findings-v5-access-management-000007')).toBe(true);
    expect(WAZUH5_FINDINGS_PROFILE.isSourceIndex('.ds-wazuh-findings-v5-security-00001')).toBe(false);
    expect(WAZUH5_FINDINGS_PROFILE.isSourceIndex('.ds-wazuh-findings-v5--000001')).toBe(false);
    expect(WAZUH5_FINDINGS_PROFILE.isEvidenceIndex('.ds-wazuh-events-v5-access-management-000001')).toBe(true);
    expect(WAZUH5_FINDINGS_PROFILE.isEvidenceIndex('.ds-wazuh-events-raw-v5-000001')).toBe(true);
    expect(WAZUH5_FINDINGS_PROFILE.isEvidenceIndex('.ds-wazuh-events-v4-security-000001')).toBe(false);
  });

  test('a stored source_index resolves to exactly one family or none', () => {
    expect(sourceFamilyOfIndex('wazuh-alerts-4.x-2026.10.31')).toBe('wazuh4_alerts');
    expect(sourceFamilyOfIndex('.ds-wazuh-findings-v5-security-000001')).toBe('wazuh5_findings');
    expect(sourceFamilyOfIndex('.ds-wazuh-events-v5-security-000001')).toBeNull();
    expect(sourceFamilyOfIndex('wazuh-alert-status-v2-000001')).toBeNull();
    expect(sourceFamilyOfIndex('')).toBeNull();
  });
});
