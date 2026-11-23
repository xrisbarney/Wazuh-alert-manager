import { ASSET_CRITICALITIES, ASSET_MAX_GROUPS, ASSET_MAX_LABELS, ASSET_MAX_TAGS } from '../../../common/constants';
import type { AssetCriticality, AssetEntry, AssetMatchKind, AssetResolution } from '../../../common/types';

/**
 * Asset criticality matcher (step 6.4a).
 *
 * Resolves one agent (name, groups, 4.x labels) to the first `asset_settings`
 * entry that matches it. Precedence is fixed and documented in the settings
 * tab: an exact `name` beats a `glob`, which beats a `group`, which beats a
 * `label`. Inside one kind the first matching entry in list order wins.
 *
 * Names and globs compare case-insensitively (hostnames are). Groups and
 * labels compare exactly, the way Wazuh reports them.
 *
 * The glob matcher is a plain two-pointer wildcard walk (`*` any run, `?` one
 * character): no regular expression is ever built from user input, so a
 * hostile pattern cannot cause catastrophic backtracking.
 */

const RANK: Record<AssetCriticality, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function isAssetCriticality(value: unknown): value is AssetCriticality {
  return typeof value === 'string' && (ASSET_CRITICALITIES as readonly string[]).includes(value);
}

export function criticalityRank(value: unknown): number | null {
  return isAssetCriticality(value) ? RANK[value] : null;
}

/** Every criticality at or above `floor`, in ascending order (for a `terms` filter). */
export function criticalitiesAtOrAbove(floor: AssetCriticality): AssetCriticality[] {
  const min = RANK[floor];
  return ASSET_CRITICALITIES.filter((c) => RANK[c] >= min);
}

/**
 * Same semantics as `meetsMinLevel` in common/severity.ts: a record whose
 * `asset.criticality` is absent or unknown never meets a floor.
 */
export function meetsMinAssetCriticality(source: any, floor: AssetCriticality): boolean {
  const rank = criticalityRank(source?.asset?.criticality);
  return rank != null && rank >= RANK[floor];
}

/** Linear-time wildcard match: `*` = any run (including empty), `?` = exactly one character. */
export function globMatch(pattern: string, input: string): boolean {
  let p = 0;
  let s = 0;
  let starP = -1;
  let starS = -1;
  while (s < input.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === input[s])) {
      p += 1;
      s += 1;
    } else if (p < pattern.length && pattern[p] === '*') {
      starP = p;
      starS = s;
      p += 1;
    } else if (starP >= 0) {
      p = starP + 1;
      starS += 1;
      s = starS;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p += 1;
  return p === pattern.length;
}

export interface AssetMatchInput {
  agentName?: string | null;
  groups?: string[] | null;
  labels?: Record<string, string> | null;
}

export interface AssetMatcher {
  /** Number of configured entries; 0 means every resolution is empty. */
  readonly size: number;
  resolve(input: AssetMatchInput): AssetResolution;
}

export const EMPTY_RESOLUTION: AssetResolution = Object.freeze({
  criticality: null,
  tags: [],
  matchedId: null,
  matchedBy: null,
}) as AssetResolution;

function fold(value: string): string {
  return value.trim().toLowerCase();
}

/** Split a `key=value` label matcher; `null` when it has no key. */
export function parseLabelMatch(value: string): { key: string; value: string } | null {
  const index = value.indexOf('=');
  if (index <= 0) return null;
  const key = value.slice(0, index).trim();
  if (!key) return null;
  return { key, value: value.slice(index + 1).trim() };
}

function resolution(entry: AssetEntry, kind: AssetMatchKind): AssetResolution {
  return {
    criticality: entry.criticality,
    tags: (entry.tags || []).slice(0, ASSET_MAX_TAGS),
    matchedId: entry.id,
    matchedBy: kind,
  };
}

/**
 * Build a matcher from already-validated entries. Entries with an unknown
 * kind, empty value or unknown criticality are ignored rather than thrown on,
 * so a hand-edited document can never stop the sync job.
 */
export function buildAssetMatcher(entries: ReadonlyArray<AssetEntry> | null | undefined): AssetMatcher {
  const byName = new Map<string, AssetEntry>();
  const globs: Array<{ pattern: string; entry: AssetEntry }> = [];
  const byGroup = new Map<string, AssetEntry>();
  const labels: Array<{ key: string; value: string; entry: AssetEntry }> = [];
  let size = 0;
  for (const entry of entries || []) {
    if (!entry || typeof entry !== 'object' || !entry.match || typeof entry.match !== 'object') continue;
    if (!isAssetCriticality(entry.criticality)) continue;
    const value = typeof entry.match.value === 'string' ? entry.match.value.trim() : '';
    if (!value) continue;
    switch (entry.match.kind) {
      case 'name': {
        const key = fold(value);
        if (!byName.has(key)) byName.set(key, entry);
        break;
      }
      case 'glob':
        globs.push({ pattern: fold(value), entry });
        break;
      case 'group':
        if (!byGroup.has(value)) byGroup.set(value, entry);
        break;
      case 'label': {
        const parsed = parseLabelMatch(value);
        if (!parsed) continue;
        labels.push({ ...parsed, entry });
        break;
      }
      default:
        continue;
    }
    size += 1;
  }

  const resolve = (input: AssetMatchInput): AssetResolution => {
    if (!size) return EMPTY_RESOLUTION;
    const name = typeof input.agentName === 'string' ? fold(input.agentName) : '';
    if (name) {
      const exact = byName.get(name);
      if (exact) return resolution(exact, 'name');
      for (const { pattern, entry } of globs) {
        if (globMatch(pattern, name)) return resolution(entry, 'glob');
      }
    }
    const groups = Array.isArray(input.groups) ? input.groups : [];
    if (groups.length && byGroup.size) {
      // Entry order wins, not group order: the first configured group entry
      // that the agent belongs to.
      const groupSet = new Set(groups.map((g) => String(g)));
      for (const [group, entry] of byGroup) {
        if (groupSet.has(group)) return resolution(entry, 'group');
      }
    }
    const agentLabels = input.labels && typeof input.labels === 'object' ? input.labels : null;
    if (agentLabels && labels.length) {
      for (const { key, value, entry } of labels) {
        const actual = agentLabels[key];
        if (actual != null && String(actual) === value) return resolution(entry, 'label');
      }
    }
    return EMPTY_RESOLUTION;
  };

  return { size, resolve };
}

export const EMPTY_ASSET_MATCHER: AssetMatcher = buildAssetMatcher([]);

/** Bounded string list for `asset.groups` (never more than ASSET_MAX_GROUPS, each at most 256 chars). */
export function boundedGroups(value: unknown): string[] {
  if (value == null) return [];
  const list = Array.isArray(value) ? value : [value];
  const out: string[] = [];
  for (const item of list) {
    if (item == null) continue;
    const s = String(item).trim().slice(0, 256);
    if (s && !out.includes(s)) out.push(s);
    if (out.length >= ASSET_MAX_GROUPS) break;
  }
  return out;
}

/**
 * Bounded copy of a 4.x `agent.labels` object (`{ key: value }`, values may be
 * nested one level by Wazuh's label syntax `a.b=c` -> `{ a: { b: 'c' } }`,
 * which is flattened to `a.b`). Null when nothing usable is present.
 */
export function boundedLabels(value: unknown): Record<string, string> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const out: Record<string, string> = {};
  let count = 0;
  const visit = (node: Record<string, any>, prefix: string) => {
    for (const [rawKey, raw] of Object.entries(node)) {
      if (count >= ASSET_MAX_LABELS) return;
      const key = `${prefix}${String(rawKey).trim()}`.slice(0, 128);
      if (!key) continue;
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
        visit(raw, `${key}.`);
        continue;
      }
      if (raw == null) continue;
      out[key] = (Array.isArray(raw) ? raw.map(String).join(',') : String(raw)).slice(0, 256);
      count += 1;
    }
  };
  visit(value as Record<string, any>, '');
  return count ? out : null;
}
