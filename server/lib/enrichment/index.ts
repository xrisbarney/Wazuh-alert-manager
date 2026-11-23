import type {
  EnrichmentLookupItem,
  EnrichmentLookupRequest,
  EnrichmentLookupResponse,
  EnrichmentLookupType,
  EnrichmentResult,
  EnrichmentSourceKind,
  EnrichmentTestResponse,
} from '../../../common';
import { canonicalDomain, canonicalHash, canonicalIp, canonicalUrl } from '../../../common/indicators';
import { isEgressError } from '../egress/http';
import { typedError } from '../plugin_settings';
import { readCachedResult, sourceConfigFingerprint, writeCachedResult } from './cache';
import { abuseIpDbProvider } from './abuseipdb';
import { genericHttpProvider } from './generic_http';
import { mispProvider } from './misp';
import { wazuhCtiLocalProvider } from './wazuh_cti_local';
import { EnrichmentProvider, EnrichmentSourceError, ResolvedEnrichmentSource } from './provider';
import { enrichmentSettings, withBuiltInSources } from './settings';

export { enrichmentSettings, withBuiltInSources, builtInCtiLocalSource, normaliseEnrichmentSettings, KIND_CAPABILITIES } from './settings';
export { cacheDocId, readCachedResult, sourceConfigFingerprint, writeCachedResult } from './cache';
export { EnrichmentSourceError } from './provider';

export const PROVIDERS: Record<EnrichmentSourceKind, EnrichmentProvider> = {
  abuseipdb: abuseIpDbProvider,
  misp: mispProvider,
  generic_http: genericHttpProvider,
  wazuh_cti_local: wazuhCtiLocalProvider,
};

/** Benign, well-known values the "Test" action looks up per type. */
export const TEST_VALUES: Record<EnrichmentLookupType, string> = {
  ip: '8.8.8.8',
  domain: 'example.com',
  url: 'https://example.com/',
  hash: 'd41d8cd98f00b204e9800998ecf8427e',
};

/** Canonical form of a lookup value, or a 400 when it is not a valid value of that type. */
export function canonicalLookupValue(type: EnrichmentLookupType, raw: string): string {
  const text = String(raw || '').trim();
  let canonical: string | null = null;
  if (type === 'ip') canonical = canonicalIp(text);
  else if (type === 'domain') canonical = canonicalDomain(text);
  else if (type === 'url') canonical = canonicalUrl(text)?.url ?? null;
  else if (type === 'hash') canonical = canonicalHash(text);
  if (!canonical) throw typedError(`"${text.slice(0, 128)}" is not a valid ${type} indicator.`, 400);
  return canonical;
}

export interface LookupOptions {
  /** Skip and overwrite cached results. */
  refresh?: boolean;
  /** Never read or write the cache (used by the test route). */
  bypassCache?: boolean;
  now?: Date;
  /** Receives cache write failures (they never fail the lookup). */
  logger?: { warn(message: string): void };
}

function errorMessage(error: unknown): string {
  if (isEgressError(error)) return error.message;
  if (error instanceof EnrichmentSourceError) return error.message;
  const message = (error as any)?.message;
  return typeof message === 'string' && message ? message : 'Lookup failed.';
}

/**
 * Load every effective source (stored + built-in) with secrets decrypted.
 * When the stored secrets cannot be decrypted (key missing or rotated) the
 * masked list is used and `secretError` explains it, so sources that need a
 * key fail individually while key-less sources still run.
 */
async function loadResolvedSources(client: any): Promise<{ sources: ResolvedEnrichmentSource[]; secretError: string | null }> {
  try {
    const doc = await enrichmentSettings.readWithSecrets(client);
    return { sources: withBuiltInSources(doc.sources || []) as ResolvedEnrichmentSource[], secretError: null };
  } catch (e: any) {
    if (typeof e?.statusCode !== 'number') throw e;
    const masked = await enrichmentSettings.read(client);
    const sources = withBuiltInSources(masked.sources || []).map((source: any) => {
      const { apiKeyConfigured, ...rest } = source;
      return { ...rest, apiKey: apiKeyConfigured ? '\u0000undecryptable' : '' } as ResolvedEnrichmentSource;
    });
    return { sources, secretError: e.message || 'Stored API keys cannot be decrypted.' };
  }
}

async function lookupOne(
  client: any,
  source: ResolvedEnrichmentSource,
  type: EnrichmentLookupType,
  value: string,
  options: LookupOptions,
  secretError: string | null
): Promise<EnrichmentLookupItem> {
  const base = { sourceId: source.id, sourceName: source.name, kind: source.kind };
  const now = options.now || new Date();
  if (secretError && source.apiKey === '\u0000undecryptable') {
    return { ...base, status: 'error', cached: false, error: secretError };
  }
  const fingerprint = sourceConfigFingerprint(source);
  let result: EnrichmentResult;
  try {
    if (!options.bypassCache && !options.refresh) {
      const cached = await readCachedResult(client, source.id, type, value, now, fingerprint);
      if (cached) return { ...base, status: 'ok', cached: true, result: cached.result };
    }
    result = await PROVIDERS[source.kind].lookup({ source, type, value, client, now });
  } catch (e) {
    return { ...base, status: 'error', cached: false, error: errorMessage(e) };
  }
  // The verdict is already paid for: a cache write failure (index not yet
  // provisioned, write denied, transient 5xx) must not turn it into an error.
  if (!options.bypassCache) {
    try {
      await writeCachedResult(client, {
        sourceId: source.id,
        kind: source.kind,
        type,
        value,
        result,
        ttlSeconds: source.cacheTtlSeconds,
        now,
        configFingerprint: fingerprint,
      });
    } catch (e) {
      options.logger?.warn(`Enrichment cache write failed for source "${source.id}": ${errorMessage(e)}`);
    }
  }
  return { ...base, status: 'ok', cached: false, result };
}

/**
 * Run every enabled source that supports `type` (optionally narrowed to
 * `sourceIds`) in parallel. One source failing never fails the lookup: each
 * entry carries its own status. Results are cached per source unless the
 * entry is expired or `refresh` is set.
 */
export async function runEnrichmentLookup(
  client: any,
  request: EnrichmentLookupRequest,
  options: LookupOptions = {}
): Promise<EnrichmentLookupResponse> {
  const value = canonicalLookupValue(request.type, request.value);
  const { sources, secretError } = await loadResolvedSources(client);
  const wanted = Array.isArray(request.sourceIds) && request.sourceIds.length > 0 ? new Set(request.sourceIds) : null;
  const selected = sources.filter(
    (source) => source.enabled && source.supports.includes(request.type) && (!wanted || wanted.has(source.id))
  );
  const settled = await Promise.allSettled(
    selected.map((source) => lookupOne(client, source, request.type, value, { ...options, refresh: request.refresh || options.refresh }, secretError))
  );
  const results: EnrichmentLookupItem[] = settled.map((outcome, index) =>
    outcome.status === 'fulfilled'
      ? outcome.value
      : {
          sourceId: selected[index].id,
          sourceName: selected[index].name,
          kind: selected[index].kind,
          status: 'error',
          cached: false,
          error: errorMessage(outcome.reason),
        }
  );
  return { type: request.type, value, results };
}

/**
 * Look up a fixed benign value through one source regardless of its enabled
 * flag, bypassing the cache, so an administrator can verify credentials and
 * egress policy from the settings tab.
 */
export async function testEnrichmentSource(client: any, sourceId: string, options: LookupOptions = {}): Promise<EnrichmentTestResponse> {
  const { sources, secretError } = await loadResolvedSources(client);
  const source = sources.find((candidate) => candidate.id === sourceId);
  if (!source) throw typedError(`Enrichment source "${sourceId}" does not exist.`, 404);
  const type = source.supports[0];
  if (!type) throw typedError(`Enrichment source "${sourceId}" supports no indicator type.`, 400);
  const value = TEST_VALUES[type];
  const item = await lookupOne(client, source, type, value, { ...options, bypassCache: true }, secretError);
  return { ...item, type, value };
}
