import {
  ASSET_CRITICALITIES,
  ASSET_MATCH_KINDS,
  ASSET_MAX_ENTRIES,
  ASSET_MAX_TAGS,
  ASSET_SETTINGS_DOC_ID,
} from '../../../common/constants';
import type { AssetCriticality, AssetEntry, AssetMatchKind } from '../../../common/types';
import { defineSettingsDoc, typedError } from '../plugin_settings';
import { AssetMatcher, buildAssetMatcher, EMPTY_ASSET_MATCHER, parseLabelMatch } from './matcher';

/**
 * Asset settings document (`asset_settings` in META_INDEX, step 6.4a).
 *
 * `assets[]` is the ordered list the matcher runs over (see matcher.ts for
 * the precedence rules). There are no secrets in this document. The sync job
 * reads it once per batch through `loadAssetMatcher`, which never throws: a
 * missing document means "no assets", and a read failure degrades to the
 * same empty matcher so ingestion continues.
 */

export interface AssetSettingsDoc {
  assets: AssetEntry[];
}

const ENTRY_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const KINDS = new Set<string>(ASSET_MATCH_KINDS);
const CRITICALITIES = new Set<string>(ASSET_CRITICALITIES);
const MAX_MATCH_VALUE = 256;
const MAX_TAG = 64;

function bad(message: string): never {
  throw typedError(message, 400);
}

function cleanTags(raw: unknown, label: string): string[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) bad(`${label}: tags must be a list of strings.`);
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== 'string') bad(`${label}: tags must be a list of strings.`);
    const tag = item.trim().slice(0, MAX_TAG);
    if (tag && !out.includes(tag)) out.push(tag);
  }
  if (out.length > ASSET_MAX_TAGS) bad(`${label}: at most ${ASSET_MAX_TAGS} tags per asset.`);
  return out;
}

function normaliseEntry(raw: any, index: number): AssetEntry {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad(`assets[${index}] must be an object.`);
  const id = typeof raw.id === 'string' ? raw.id : '';
  if (!ENTRY_ID.test(id)) bad(`assets[${index}]: id must be 1-64 lower-case letters, digits, "-" or "_".`);
  const label = `Asset "${id}"`;
  const match = raw.match && typeof raw.match === 'object' && !Array.isArray(raw.match) ? raw.match : null;
  if (!match) bad(`${label}: match must be an object with kind and value.`);
  const kind = typeof match.kind === 'string' ? match.kind : '';
  if (!KINDS.has(kind)) bad(`${label}: match.kind must be one of ${ASSET_MATCH_KINDS.join(', ')}.`);
  const value = typeof match.value === 'string' ? match.value.trim() : '';
  if (!value) bad(`${label}: match.value is required.`);
  if (value.length > MAX_MATCH_VALUE) bad(`${label}: match.value must be at most ${MAX_MATCH_VALUE} characters.`);
  if (/[\r\n\0]/.test(value)) bad(`${label}: match.value must be a single line.`);
  if (kind === 'label' && !parseLabelMatch(value)) bad(`${label}: a label match is written as key=value.`);
  if (kind === 'glob' && !/[*?]/.test(value)) bad(`${label}: a glob match needs at least one * or ? wildcard (use kind "name" for an exact name).`);
  const criticality = typeof raw.criticality === 'string' ? raw.criticality : '';
  if (!CRITICALITIES.has(criticality)) bad(`${label}: criticality must be one of ${ASSET_CRITICALITIES.join(', ')}.`);
  return {
    id,
    match: { kind: kind as AssetMatchKind, value },
    criticality: criticality as AssetCriticality,
    tags: cleanTags(raw.tags, label),
  };
}

/** Validate and normalise the merged document. */
export function normaliseAssetSettings(doc: AssetSettingsDoc): AssetSettingsDoc {
  const list = Array.isArray(doc?.assets) ? doc.assets : [];
  if (list.length > ASSET_MAX_ENTRIES) bad(`At most ${ASSET_MAX_ENTRIES} assets can be configured.`);
  const seen = new Set<string>();
  const assets = list.map((raw, index) => {
    const entry = normaliseEntry(raw, index);
    if (seen.has(entry.id)) bad(`Asset id "${entry.id}" is used more than once.`);
    seen.add(entry.id);
    return entry;
  });
  return { assets };
}

export const assetSettings = defineSettingsDoc<AssetSettingsDoc>({
  docId: ASSET_SETTINGS_DOC_ID,
  defaults: { assets: [] },
  validate: normaliseAssetSettings,
});

/**
 * The matcher for the stored document. Never throws: an absent document is
 * the empty matcher, and any other read failure is logged (when a logger is
 * given) and also yields the empty matcher so a sync tick still completes.
 */
export async function loadAssetMatcher(
  client: any,
  logger?: { debug(message: string): void; warn?(message: string): void }
): Promise<AssetMatcher> {
  try {
    const doc = await assetSettings.read(client);
    return buildAssetMatcher(doc.assets);
  } catch (e: any) {
    const message = `wazuh-alert-manager assets: could not read ${ASSET_SETTINGS_DOC_ID}, syncing without asset criticality: ${e?.message || String(e)}`;
    if (logger?.warn) logger.warn(message);
    else logger?.debug(message);
    return EMPTY_ASSET_MATCHER;
  }
}
