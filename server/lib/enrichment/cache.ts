import { createHash } from 'crypto';

import { ENRICHMENT_CACHE_INDEX } from '../../../common';
import type { EnrichmentLookupType, EnrichmentResult, EnrichmentSourceKind } from '../../../common';
import { assertManagedWriteTarget } from '../index_namespace';

/**
 * Lookup cache in the fixed index `wazuh-alert-manager-v2-enrichment-cache`.
 * One document per (source, type, canonical value); the id is the sha256 of
 * `source:type:value` so a repeat lookup is a single GET and a refresh is an
 * overwrite. `expires_at` is derived from the source's `cacheTtlSeconds` at
 * write time, so changing the TTL affects new entries only.
 */

export interface EnrichmentCacheDoc {
  source_id: string;
  kind: EnrichmentSourceKind;
  type: EnrichmentLookupType;
  value: string;
  checked_at: string;
  expires_at: string;
  result: EnrichmentResult;
}

export interface CacheWriteInput {
  sourceId: string;
  kind: EnrichmentSourceKind;
  type: EnrichmentLookupType;
  value: string;
  result: EnrichmentResult;
  ttlSeconds: number;
  now?: Date;
  /** See `sourceConfigFingerprint`; omitted for sources with no lookup-relevant config. */
  configFingerprint?: string;
}

/**
 * Short hash of the lookup-relevant configuration of a source (kind, URLs,
 * header names, pointers, verdict map). Folded into the cache id so an entry
 * produced under an older configuration of the same id is never served
 * again once the administrator changes what the source actually asks.
 */
export function sourceConfigFingerprint(source: {
  kind: string;
  baseUrl?: string;
  urlTemplate?: string;
  headers?: Record<string, string>;
  verdictPath?: string;
  scorePath?: string;
  tagsPath?: string;
  linkPath?: string;
  verdictMap?: Record<string, string>;
}): string {
  const relevant = {
    kind: source.kind,
    baseUrl: source.baseUrl || '',
    urlTemplate: source.urlTemplate || '',
    headerNames: Object.keys(source.headers || {}).sort(),
    verdictPath: source.verdictPath || '',
    scorePath: source.scorePath || '',
    tagsPath: source.tagsPath || '',
    linkPath: source.linkPath || '',
    verdictMap: Object.entries(source.verdictMap || {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  };
  return createHash('sha256').update(JSON.stringify(relevant), 'utf8').digest('hex').slice(0, 16);
}

export function cacheDocId(sourceId: string, type: string, value: string, configFingerprint = ''): string {
  const key = configFingerprint ? `${sourceId}:${configFingerprint}:${type}:${value}` : `${sourceId}:${type}:${value}`;
  return createHash('sha256').update(key, 'utf8').digest('hex');
}

function statusCodeOf(error: any): number | undefined {
  const code = error?.meta?.statusCode ?? error?.statusCode;
  return typeof code === 'number' ? code : undefined;
}

/**
 * The cached result for this source/type/value, or null when nothing is
 * stored, the entry has expired, or the cache index does not exist yet.
 */
export async function readCachedResult(
  client: any,
  sourceId: string,
  type: EnrichmentLookupType,
  value: string,
  now: Date = new Date(),
  configFingerprint = ''
): Promise<EnrichmentCacheDoc | null> {
  let source: any;
  try {
    const res: any = await client.get({ index: ENRICHMENT_CACHE_INDEX, id: cacheDocId(sourceId, type, value, configFingerprint) });
    source = res?.body?._source;
  } catch (e: any) {
    if (statusCodeOf(e) === 404) return null;
    throw e;
  }
  if (!source || typeof source !== 'object' || !source.result) return null;
  const expires = Date.parse(String(source.expires_at));
  if (!Number.isFinite(expires) || expires <= now.getTime()) return null;
  return source as EnrichmentCacheDoc;
}

/** Store (or overwrite) a result. Always a plugin-owned write target. */
export async function writeCachedResult(client: any, input: CacheWriteInput): Promise<EnrichmentCacheDoc> {
  const now = input.now || new Date();
  const ttl = Math.max(0, Math.floor(input.ttlSeconds));
  const doc: EnrichmentCacheDoc = {
    source_id: input.sourceId,
    kind: input.kind,
    type: input.type,
    value: input.value,
    checked_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl * 1000).toISOString(),
    result: input.result,
  };
  await client.index({
    index: assertManagedWriteTarget(ENRICHMENT_CACHE_INDEX),
    id: cacheDocId(input.sourceId, input.type, input.value, input.configFingerprint || ''),
    body: doc,
  });
  return doc;
}
