import { MANAGED_INDEX_PREFIXES, CASES_WRITE_ALIAS } from '../../common';

const NATIVE_WAZUH_PREFIX = 'wazuh-';

/**
 * Fail closed before any plugin write reaches OpenSearch. This is intentionally
 * independent of role configuration: even an over-privileged dashboard
 * internal user must not be able to turn a programming mistake into a write to
 * Wazuh's native indices.
 */
export function assertManagedWriteTarget(index: string): string {
  const owned = Boolean(index) && MANAGED_INDEX_PREFIXES.some((prefix) => index.startsWith(prefix));
  if (!owned || index.startsWith(`${NATIVE_WAZUH_PREFIX}alerts-`)) {
    throw new Error(`Refusing write to non-plugin index target: ${index || '<empty>'}`);
  }
  return index;
}

/** Reject a source pattern that could include the plugin's own v2 indices. */
export function assertSafeSourcePattern(pattern: string): string {
  const normalized = String(pattern || '').trim();
  if (!normalized || normalized === '*' || normalized === '_all') {
    throw new Error('The Wazuh source index pattern must be explicit; * and _all are not allowed.');
  }
  for (const part of normalized.split(',').map((p) => p.trim())) {
    if (!part.startsWith('wazuh-alerts-')) {
      throw new Error(`Unsafe source index pattern: ${part}. Expected wazuh-alerts-*.`);
    }
    if (MANAGED_INDEX_PREFIXES.some((prefix) => part.startsWith(prefix))) {
      throw new Error(`Source index pattern overlaps plugin storage: ${part}`);
    }
  }
  return normalized;
}

export function isManagedPhysicalIndex(index: string, familyPrefix?: string): boolean {
  if (!MANAGED_INDEX_PREFIXES.some((prefix) => index.startsWith(prefix))) return false;
  return familyPrefix ? index.startsWith(familyPrefix) : true;
}

/** Fail-closed case write target: the single cases write alias. */
export function casesWriteTarget(): string {
  return assertManagedWriteTarget(CASES_WRITE_ALIAS);
}
