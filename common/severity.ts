/**
 * One severity model for both native sources.
 *
 * Wazuh 4.x alerts carry a numeric `rule.level` (0-16). Wazuh 5.0 findings
 * carry a label in `wazuh.rule.level` (`informational`, `low`, `medium`,
 * `high`, `critical`), which the 5.0 adapter stores verbatim in
 * `severity_label` while leaving `rule.level` null. Nothing in the plugin
 * converts a label into a fake number; instead every consumer compares on a
 * *band*, and a numeric threshold is translated into the bands it covers.
 *
 * Numeric bands are the ones this plugin has always shown in its severity
 * badges (Low 0-3, Medium 4-6, High 7-11, Critical 12+), so v3 changes no
 * visible classification of a 4.x alert. `informational` has no numeric
 * counterpart on 4.x and only ever comes from a 5.0 label.
 */

export const SEVERITY_BANDS = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export type SeverityBand = typeof SEVERITY_BANDS[number];

const BAND_RANK: Record<SeverityBand, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Band of a 4.x numeric level; null when the level is absent or not a number. */
export function bandFromLevel(level: unknown): SeverityBand | null {
  const n = typeof level === 'number' ? level : typeof level === 'string' && /^\d+$/.test(level.trim()) ? Number(level) : NaN;
  if (!Number.isFinite(n)) return null;
  if (n >= 12) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  return 'low';
}

const LABEL_ALIASES: Record<string, SeverityBand> = {
  informational: 'informational',
  info: 'informational',
  informative: 'informational',
  low: 'low',
  minor: 'low',
  medium: 'medium',
  moderate: 'medium',
  high: 'high',
  major: 'high',
  critical: 'critical',
  severe: 'critical',
};

/** Band of a 5.0 severity label; null when absent or unrecognized (never guessed). */
export function bandFromLabel(label: unknown): SeverityBand | null {
  if (typeof label !== 'string') return null;
  const key = label.trim().toLowerCase();
  return LABEL_ALIASES[key] ?? null;
}

/** Band of a canonical record: numeric level first (4.x), then the stored label (5.0). */
export function severityBandOf(source: any): SeverityBand | null {
  return bandFromLevel(source?.rule?.level) ?? bandFromLabel(source?.severity_label);
}

/** Human label for a record: the stored 5.0 label verbatim, else the numeric band. */
export function severityDisplay(source: any): { band: SeverityBand | null; level: number | null; label: string | null } {
  const level = typeof source?.rule?.level === 'number' ? source.rule.level : null;
  const label = typeof source?.severity_label === 'string' ? source.severity_label : null;
  return { band: severityBandOf(source), level, label };
}

/** Bands whose severity is at least that of a numeric level (inclusive). */
export function bandsAtOrAboveLevel(minLevel: number): SeverityBand[] {
  const floor = bandFromLevel(minLevel);
  if (!floor) return [];
  return SEVERITY_BANDS.filter((band) => BAND_RANK[band] >= BAND_RANK[floor]);
}

/** Bands that fall inside an inclusive numeric level range (either bound optional). */
export function bandsBetweenLevels(min?: number | null, max?: number | null): SeverityBand[] {
  const lo = min != null ? bandFromLevel(min) : null;
  const hi = max != null ? bandFromLevel(max) : null;
  return SEVERITY_BANDS.filter((band) => {
    if (band === 'informational') return min == null || min <= 0;
    if (lo && BAND_RANK[band] < BAND_RANK[lo]) return false;
    if (hi && BAND_RANK[band] > BAND_RANK[hi]) return false;
    return true;
  });
}

/**
 * A representative numeric level for a band, used only where an existing
 * numeric policy (SLA tiers keyed by minLevel) must classify a label-only 5.0
 * record. It is the lowest level of the band, so a label never claims a
 * stricter tier than the equivalent 4.x alert would.
 */
export function representativeLevel(band: SeverityBand | null): number | null {
  switch (band) {
    case 'informational': return 0;
    case 'low': return 0;
    case 'medium': return 4;
    case 'high': return 7;
    case 'critical': return 12;
    default: return null;
  }
}

/** Effective numeric level for numeric policies: the real level, else the band's representative. */
export function effectiveLevel(source: any): number | null {
  if (typeof source?.rule?.level === 'number' && Number.isFinite(source.rule.level)) return source.rule.level;
  return representativeLevel(bandFromLabel(source?.severity_label));
}

/**
 * OpenSearch filter matching records whose severity lies in a numeric range,
 * for either family: 4.x by `rule.level`, 5.0 by `severity_label`.
 */
export function severityRangeClause(min?: number | null, max?: number | null): any | null {
  if (min == null && max == null) return null;
  const range: any = {};
  if (min != null) range.gte = min;
  if (max != null) range.lte = max;
  const bands = bandsBetweenLevels(min, max);
  const should: any[] = [{ range: { 'rule.level': range } }];
  if (bands.length) should.push({ terms: { severity_label: bands } });
  return { bool: { should, minimum_should_match: 1 } };
}

/** True when a record's severity is at least `minLevel`, for either family. */
export function meetsMinLevel(source: any, minLevel: number): boolean {
  const level = source?.rule?.level;
  if (typeof level === 'number' && Number.isFinite(level)) return level >= minLevel;
  const band = bandFromLabel(source?.severity_label);
  if (!band) return false;
  return bandsAtOrAboveLevel(minLevel).includes(band);
}
