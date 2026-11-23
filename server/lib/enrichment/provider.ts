import { ENRICHMENT_MAX_TAGS, ENRICHMENT_MAX_TIMEOUT_MS } from '../../../common';
import type { EnrichmentLookupType, EnrichmentResult, EnrichmentVerdict } from '../../../common';
import { boundedFetch, BoundedFetchOptions, BoundedFetchResult } from '../egress/http';
import type { StoredEnrichmentSource } from './settings';

/** A source as a provider sees it: the stored shape with the decrypted key. */
export interface ResolvedEnrichmentSource extends StoredEnrichmentSource {
  apiKey?: string;
}

export interface LookupContext {
  source: ResolvedEnrichmentSource;
  type: EnrichmentLookupType;
  /** Canonical indicator value (see `canonicalLookupValue`). */
  value: string;
  /** OpenSearch client as the current user (only the local CTI source reads). */
  client: any;
  now: Date;
}

export interface EnrichmentProvider {
  kind: StoredEnrichmentSource['kind'];
  lookup(context: LookupContext): Promise<EnrichmentResult>;
}

/** Raised by a provider for a condition the analyst can act on (bad key, HTTP 4xx, ...). */
export class EnrichmentSourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnrichmentSourceError';
  }
}

/** Response body cap for every remote source: a verdict never needs more. */
export const MAX_SOURCE_RESPONSE_BYTES = 512 * 1024;

export function sourceTimeoutMs(source: { timeoutMs?: number }): number {
  const value = Number(source.timeoutMs);
  if (!Number.isFinite(value) || value <= 0) return 8000;
  return Math.min(Math.floor(value), ENRICHMENT_MAX_TIMEOUT_MS);
}

/** `boundedFetch` with the per-source timeout, size cap and purpose label applied. */
export async function fetchSource(
  source: ResolvedEnrichmentSource,
  url: string,
  options: Omit<BoundedFetchOptions, 'timeoutMs' | 'maxResponseBytes' | 'purpose'> = {}
): Promise<BoundedFetchResult> {
  return boundedFetch(url, {
    ...options,
    timeoutMs: sourceTimeoutMs(source),
    maxResponseBytes: MAX_SOURCE_RESPONSE_BYTES,
    purpose: `Enrichment source ${source.name}`,
  });
}

/** Parse a JSON body or raise a source error naming the HTTP status. */
export function parseJsonBody(response: BoundedFetchResult, sourceName: string): any {
  if (response.status < 200 || response.status >= 300) {
    const detail = response.bodyText ? `: ${response.bodyText.slice(0, 200)}` : '';
    throw new EnrichmentSourceError(`${sourceName} answered HTTP ${response.status}${detail}`);
  }
  if (!response.bodyText.trim()) return null;
  try {
    return JSON.parse(response.bodyText);
  } catch (e) {
    throw new EnrichmentSourceError(`${sourceName} did not return JSON.`);
  }
}

export function clampScore(value: unknown): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Number(value) : NaN;
  if (!Number.isFinite(n)) return null;
  return Math.min(100, Math.max(0, Math.round(n)));
}

/** Verdict from a 0-100 score when a source does not state one. */
export function verdictFromScore(score: number | null): EnrichmentVerdict {
  if (score === null) return 'unknown';
  if (score >= 75) return 'malicious';
  if (score >= 25) return 'suspicious';
  return 'clean';
}

/** Unique, trimmed, bounded tag list from whatever the source sent. */
export function cleanTags(values: unknown): string[] {
  const list = Array.isArray(values) ? values : values === undefined || values === null ? [] : [values];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of list) {
    const tag = typeof raw === 'string' ? raw.trim().slice(0, 128) : typeof raw === 'number' ? String(raw) : '';
    if (!tag || seen.has(tag)) continue;
    seen.add(tag);
    out.push(tag);
    if (out.length >= ENRICHMENT_MAX_TAGS) break;
  }
  return out;
}

/** Only http(s) links are ever handed to the browser. */
export function cleanLink(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!/^https?:\/\//i.test(text) || text.length > 2048) return null;
  try {
    return new URL(text).toString();
  } catch (e) {
    return null;
  }
}

export function buildResult(
  source: { id: string },
  partial: Omit<EnrichmentResult, 'source' | 'checkedAt'> & { checkedAt?: string },
  now: Date
): EnrichmentResult {
  return {
    source: source.id,
    verdict: partial.verdict,
    score: partial.score,
    tags: cleanTags(partial.tags),
    link: partial.link,
    summary: String(partial.summary || '').slice(0, 2048),
    checkedAt: partial.checkedAt || now.toISOString(),
  };
}
