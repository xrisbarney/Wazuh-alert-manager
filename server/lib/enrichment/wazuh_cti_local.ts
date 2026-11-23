import type { EnrichmentResult } from '../../../common';
import { countNative, searchNative } from '../native_read';
import { EnrichmentProvider, EnrichmentSourceError, LookupContext, buildResult, clampScore } from './provider';
import { WAZUH_CTI_LOCAL_INDEX_PATTERN } from './settings';

/**
 * Built-in source for Wazuh 5.0: a read of the local CTI IoC catalog that
 * Content Manager syncs into `wazuh-threatintel-enrichments*`, using the CTI
 * Explorer's own query shape (case-insensitive `term document.name`, plus a
 * `prefix "<ip>:"` over `connection` records for bare IPs; the checksum doc
 * `__ioc_type_hashes__` has no `document.type` and is excluded). A hit is a
 * malicious verdict with the catalog's confidence; a miss is `unknown`
 * ("absent from the catalog"), never `clean`. Nothing here calls the CTI API.
 *
 * Results carry `link: null`: the CTI Explorer is an app-relative path
 * (`CTI_EXPLORER_APP_PATH` in common/constants.ts) the browser builds with
 * the dashboard basePath on 5.0 builds, not an external URL.
 *
 * Catalog absence is detected explicitly. The wildcard pattern matches no
 * index on 4.x (or on 5.0 before Content Manager has synced) and OpenSearch
 * answers that with 200 and zero hits, so a miss is only a miss when the
 * catalog actually holds records; otherwise the source errors instead of
 * caching an "unknown" for the TTL.
 */
export const CTI_LOCAL_MAX_HITS = 20;
export const CTI_CATALOG_NOT_AVAILABLE = `The local CTI catalog (${WAZUH_CTI_LOCAL_INDEX_PATTERN}) is not available on this install (Wazuh 5.0 with a synced CTI catalog is required).`;
const NO_ACCESS_MESSAGE = `No read access to ${WAZUH_CTI_LOCAL_INDEX_PATTERN}; map the wazuh_alert_manager_native_read role (install.sh) to this user.`;

/** True when at least one catalog record exists; throws the per-source error when the catalog is absent or empty. */
export async function assertCtiCatalogPresent(client: any): Promise<void> {
  const count = await countNative(client, {
    indexPattern: WAZUH_CTI_LOCAL_INDEX_PATTERN,
    body: { query: { exists: { field: 'document.type' } } },
    purpose: 'Enrichment source wazuh_cti_local (catalog presence)',
  });
  if (count.status === 'no_access') throw new EnrichmentSourceError(NO_ACCESS_MESSAGE);
  if (count.status === 'not_available' || count.total === 0) throw new EnrichmentSourceError(CTI_CATALOG_NOT_AVAILABLE);
}

export function buildCtiLocalQuery(type: string, value: string): Record<string, unknown> {
  const exact = { term: { 'document.name': { value, case_insensitive: true } } };
  const should: unknown[] = [exact];
  if (type === 'ip') {
    should.push({
      bool: {
        filter: [
          { term: { 'document.type': 'connection' } },
          { prefix: { 'document.name': { value: `${value}:`, case_insensitive: true } } },
        ],
      },
    });
  }
  return {
    size: CTI_LOCAL_MAX_HITS,
    _source: ['document'],
    query: {
      bool: {
        filter: [{ exists: { field: 'document.type' } }],
        should,
        minimum_should_match: 1,
      },
    },
  };
}

/** CTI confidence arrives as a stringified number or a word; map both to 0-100. */
export function confidenceScore(raw: unknown): number | null {
  if (typeof raw === 'string') {
    const word = raw.trim().toLowerCase();
    if (word === 'high') return 90;
    if (word === 'medium') return 60;
    if (word === 'low') return 30;
  }
  return clampScore(raw);
}

export const wazuhCtiLocalProvider: EnrichmentProvider = {
  kind: 'wazuh_cti_local',
  async lookup({ source, type, value, client, now }: LookupContext): Promise<EnrichmentResult> {
    const result = await searchNative<{ document?: Record<string, any> }>(client, {
      indexPattern: WAZUH_CTI_LOCAL_INDEX_PATTERN,
      body: buildCtiLocalQuery(type, value),
      purpose: 'Enrichment source wazuh_cti_local',
    });
    if (result.status === 'no_access') throw new EnrichmentSourceError(NO_ACCESS_MESSAGE);
    if (result.status === 'not_available') throw new EnrichmentSourceError(CTI_CATALOG_NOT_AVAILABLE);
    const docs = result.hits.map((hit) => hit._source?.document).filter((doc): doc is Record<string, any> => Boolean(doc));
    if (docs.length === 0) {
      await assertCtiCatalogPresent(client);
      return buildResult(source, { verdict: 'unknown', score: null, tags: [], link: null, summary: 'Not in the local Wazuh CTI catalog' }, now);
    }
    let score: number | null = null;
    const tags: string[] = [];
    const providers = new Set<string>();
    const types = new Set<string>();
    for (const doc of docs) {
      const confidence = confidenceScore(doc.confidence);
      if (confidence !== null && (score === null || confidence > score)) score = confidence;
      if (typeof doc.provider === 'string' && doc.provider) providers.add(doc.provider);
      if (typeof doc.type === 'string' && doc.type) types.add(doc.type);
      const feed = doc.feed && typeof doc.feed === 'object' ? doc.feed.name : undefined;
      if (typeof feed === 'string' && feed) tags.push(`feed:${feed}`);
      for (const tag of Array.isArray(doc.tags) ? doc.tags : []) if (typeof tag === 'string') tags.push(tag);
      const software = doc.software && typeof doc.software === 'object' ? doc.software.name : undefined;
      if (typeof software === 'string' && software) tags.push(`software:${software}`);
    }
    const summary = `${docs.length} CTI catalog record${docs.length === 1 ? '' : 's'} (${Array.from(types).join(', ') || 'ioc'})${
      providers.size > 0 ? ` from ${Array.from(providers).join(', ')}` : ''
    }${score !== null ? `, confidence ${score}` : ''}`;
    return buildResult(source, { verdict: 'malicious', score, tags, link: null, summary }, now);
  },
};
