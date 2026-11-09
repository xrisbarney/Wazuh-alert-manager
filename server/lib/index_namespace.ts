import { MANAGED_INDEX_PREFIXES, CASES_WRITE_ALIAS } from '../../common';
import { WAZUH4_ALERTS_PROFILE, WazuhSourceProfile } from './source_profile';

/**
 * Native Wazuh storage the plugin must never write to, named explicitly so a
 * refusal does not depend on the managed-prefix allowlist alone. Covers 4.x
 * alert indices, 5.0 event/finding data streams and their hidden `.ds-`
 * backing indices, state/inventory indices, and native case management.
 */
export const NATIVE_WAZUH_PREFIXES = [
  'wazuh-alerts-',
  'wazuh-archives-',
  'wazuh-events-',
  'wazuh-findings-',
  '.ds-wazuh-',
  'wazuh-states-',
  'wazuh-monitoring-',
  'wazuh-statistics-',
  'wazuh-case-management-',
] as const;

function namesNativeStorage(index: string): boolean {
  return NATIVE_WAZUH_PREFIXES.some((prefix) => index.startsWith(prefix));
}

/**
 * Fail closed before any plugin write reaches OpenSearch. This is intentionally
 * independent of role configuration: even an over-privileged dashboard
 * internal user must not be able to turn a programming mistake into a write to
 * Wazuh's native indices.
 */
export function assertManagedWriteTarget(index: string): string {
  const owned = Boolean(index) && MANAGED_INDEX_PREFIXES.some((prefix) => index.startsWith(prefix));
  if (!owned || namesNativeStorage(index) || /[\s,*]/.test(index)) {
    throw new Error(`Refusing write to non-plugin index target: ${index || '<empty>'}`);
  }
  return index;
}

/**
 * Reject a source pattern that leaves the selected source family or could
 * include the plugin's own v2 indices. Defaults to the 4.x profile so existing
 * callers keep their exact behaviour.
 */
export function assertSafeSourcePattern(
  pattern: string,
  profile: WazuhSourceProfile = WAZUH4_ALERTS_PROFILE
): string {
  const normalized = String(pattern || '').trim();
  if (!normalized || normalized === '*' || normalized === '_all') {
    throw new Error('The Wazuh source index pattern must be explicit; * and _all are not allowed.');
  }
  for (const part of normalized.split(',').map((p) => p.trim())) {
    if (!profile.isAllowedPatternPart(part)) {
      throw new Error(`Unsafe source index pattern: ${part}. Expected ${profile.defaultPattern}.`);
    }
    if (MANAGED_INDEX_PREFIXES.some((prefix) => part.startsWith(prefix))) {
      throw new Error(`Source index pattern overlaps plugin storage: ${part}`);
    }
  }
  return normalized;
}

/**
 * Is `index` an exact physical index the given family may hydrate a stored
 * alert from? Used before any read of a stored `source_index`, so a tampered
 * or stale projection can never direct the server at an arbitrary index.
 */
export function isApprovedSourceIndex(index: string, profile: WazuhSourceProfile): boolean {
  return typeof index === 'string' && !namesPluginStorage(index) && profile.isSourceIndex(index);
}

/** Is `index` an exact underlying-evidence index the family allows a second hop to? */
export function isApprovedEvidenceIndex(index: string, profile: WazuhSourceProfile): boolean {
  return typeof index === 'string' && !namesPluginStorage(index) && profile.isEvidenceIndex(index);
}

function namesPluginStorage(index: string): boolean {
  return MANAGED_INDEX_PREFIXES.some((prefix) => index.startsWith(prefix));
}

export function isManagedPhysicalIndex(index: string, familyPrefix?: string): boolean {
  if (!MANAGED_INDEX_PREFIXES.some((prefix) => index.startsWith(prefix))) return false;
  return familyPrefix ? index.startsWith(familyPrefix) : true;
}

/** Fail-closed case write target: the single cases write alias. */
export function casesWriteTarget(): string {
  return assertManagedWriteTarget(CASES_WRITE_ALIAS);
}
