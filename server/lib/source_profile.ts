/**
 * Wazuh source profiles.
 *
 * A profile describes one native, READ-ONLY family of Wazuh storage that the
 * plugin may project alerts from. Everything downstream of sync (cases,
 * evidence, automation, reports, lifecycle) consumes the canonical plugin
 * record and never needs to know which profile produced it.
 *
 * - `wazuh4_alerts`: Wazuh 4.x `wazuh-alerts-*` plain indices.
 * - `wazuh5_findings`: Wazuh 5.0 `wazuh-findings-v5*` data streams. A search
 *   over a data stream reports the physical backing index
 *   (`.ds-wazuh-findings-v5-<category>-00000N`) as `_index`; that physical
 *   name plus `_id` is the finding's stable provenance. A finding points at
 *   its underlying event via `event.index` / `event.doc_id`, which must name
 *   a `.ds-wazuh-events-*` backing index before the plugin will follow it.
 *
 * Matchers are deliberately strict: lowercase, no wildcards in physical
 * names, no commas, no whitespace, and nothing that could name plugin
 * storage, hidden security-analytics state, or an arbitrary index.
 */

export type SourceFamily = 'wazuh4_alerts' | 'wazuh5_findings';

export type SeverityModel = 'numeric_level' | 'label';

export interface WazuhSourceProfile {
  readonly family: SourceFamily;
  /** Bumped when normalization semantics for this family change. */
  readonly profileVersion: number;
  readonly label: string;
  /** Pattern used when the operator has not configured an override. */
  readonly defaultPattern: string;
  readonly severityModel: SeverityModel;
  readonly timestampField: '@timestamp';
  /** Does one comma-free pattern part stay inside this family? */
  isAllowedPatternPart(part: string): boolean;
  /** Is this an exact physical index the family may have produced a hit from? */
  isSourceIndex(index: string): boolean;
  /** Is this an exact physical index the family allows as lazy underlying evidence? */
  isEvidenceIndex(index: string): boolean;
}

// Index names OpenSearch accepts are lowercase and never contain whitespace,
// commas, `*` (except in patterns), `#`, `:`, `"`, `<`, `>`, `|`, `?`, `\` or `/`.
const PATTERN_PART = /^[a-z0-9][a-z0-9._*-]*$/;
const PHYSICAL_NAME = /^[a-z0-9.][a-z0-9._-]*$/;

function isCleanPatternPart(part: string): boolean {
  return PATTERN_PART.test(part) && !part.includes('**');
}

function isCleanPhysicalName(index: string): boolean {
  return PHYSICAL_NAME.test(index) && !index.includes('*');
}

export const WAZUH4_ALERTS_PROFILE: WazuhSourceProfile = Object.freeze({
  family: 'wazuh4_alerts' as const,
  profileVersion: 1,
  label: 'Wazuh 4.x alerts (wazuh-alerts-*)',
  defaultPattern: 'wazuh-alerts-*',
  severityModel: 'numeric_level' as const,
  timestampField: '@timestamp' as const,
  isAllowedPatternPart(part: string): boolean {
    return isCleanPatternPart(part) && part.startsWith('wazuh-alerts-');
  },
  isSourceIndex(index: string): boolean {
    return isCleanPhysicalName(index) && index.startsWith('wazuh-alerts-') && index.length > 'wazuh-alerts-'.length;
  },
  isEvidenceIndex(_index: string): boolean {
    // 4.x alerts carry their own full_log; there is no second hop.
    return false;
  },
});

// Backing indices of a data stream: `.ds-<stream>-<6 digit generation>`.
const FINDINGS_BACKING = /^\.ds-wazuh-findings-v5-[a-z0-9][a-z0-9-]*-\d{6}$/;
const EVENTS_BACKING = /^\.ds-wazuh-events-(?:v5-[a-z0-9][a-z0-9-]*|raw-v5)-\d{6}$/;

export const WAZUH5_FINDINGS_PROFILE: WazuhSourceProfile = Object.freeze({
  family: 'wazuh5_findings' as const,
  profileVersion: 1,
  label: 'Wazuh 5.0 findings (wazuh-findings-v5-*)',
  defaultPattern: 'wazuh-findings-v5-*',
  severityModel: 'label' as const,
  timestampField: '@timestamp' as const,
  isAllowedPatternPart(part: string): boolean {
    // The logical data-stream name (optionally per category or a plugin test
    // stream). Never the hidden `.ds-` backing indices and never events.
    return isCleanPatternPart(part) && part.startsWith('wazuh-findings-v5');
  },
  isSourceIndex(index: string): boolean {
    return isCleanPhysicalName(index) && FINDINGS_BACKING.test(index);
  },
  isEvidenceIndex(index: string): boolean {
    return isCleanPhysicalName(index) && EVENTS_BACKING.test(index);
  },
});

export const SOURCE_PROFILES: Readonly<Record<SourceFamily, WazuhSourceProfile>> = Object.freeze({
  wazuh4_alerts: WAZUH4_ALERTS_PROFILE,
  wazuh5_findings: WAZUH5_FINDINGS_PROFILE,
});

export function sourceProfile(family: SourceFamily): WazuhSourceProfile {
  const profile = SOURCE_PROFILES[family];
  if (!profile) throw new Error(`Unknown Wazuh source family: ${String(family)}`);
  return profile;
}

/**
 * Which family a resolved physical index belongs to, or null when it belongs
 * to neither. Used when a stored `source_index` must be re-validated before
 * hydration regardless of which profile is active today.
 */
export function sourceFamilyOfIndex(index: string): SourceFamily | null {
  if (WAZUH4_ALERTS_PROFILE.isSourceIndex(index)) return 'wazuh4_alerts';
  if (WAZUH5_FINDINGS_PROFILE.isSourceIndex(index)) return 'wazuh5_findings';
  return null;
}
