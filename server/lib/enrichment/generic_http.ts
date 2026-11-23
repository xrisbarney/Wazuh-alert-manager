import { ENRICHMENT_VERDICTS } from '../../../common';
import type { EnrichmentResult, EnrichmentVerdict } from '../../../common';
import {
  EnrichmentProvider,
  EnrichmentSourceError,
  LookupContext,
  buildResult,
  clampScore,
  cleanLink,
  cleanTags,
  fetchSource,
  parseJsonBody,
  verdictFromScore,
} from './provider';

/**
 * Generic JSON-over-HTTPS source: GET `urlTemplate` with `{value}` / `{type}`
 * substituted (URL-encoded), optional headers (a header value may carry
 * `{apiKey}`), then RFC 6901 JSON pointers pick the verdict, score, tags and
 * link out of the response. `verdictMap` translates the raw verdict value;
 * without a usable verdict the score decides (75 / 25 thresholds).
 */

/** RFC 6901 pointer evaluation; `undefined` when any step is missing. */
export function jsonPointer(document: unknown, pointer: string): unknown {
  if (pointer === '' || pointer === undefined || pointer === null) return document;
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) return undefined;
  let node: any = document;
  for (const rawToken of pointer.slice(1).split('/')) {
    const token = rawToken.replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === null || node === undefined) return undefined;
    if (Array.isArray(node)) {
      if (!/^(0|[1-9][0-9]*)$/.test(token)) return undefined;
      node = node[Number(token)];
    } else if (typeof node === 'object') {
      if (!Object.prototype.hasOwnProperty.call(node, token)) return undefined;
      node = node[token];
    } else {
      return undefined;
    }
  }
  return node;
}

export function renderUrlTemplate(template: string, value: string, type: string): string {
  return template.replace(/\{value\}/g, encodeURIComponent(value)).replace(/\{type\}/g, encodeURIComponent(type));
}

const VERDICTS = new Set<string>(ENRICHMENT_VERDICTS);

export function mapVerdict(raw: unknown, verdictMap: Record<string, EnrichmentVerdict> | undefined): EnrichmentVerdict | null {
  if (raw === undefined || raw === null) return null;
  const key = typeof raw === 'string' ? raw : typeof raw === 'number' || typeof raw === 'boolean' ? String(raw) : null;
  if (key === null) return null;
  if (verdictMap && Object.prototype.hasOwnProperty.call(verdictMap, key)) return verdictMap[key];
  const lower = key.trim().toLowerCase();
  if (verdictMap && Object.prototype.hasOwnProperty.call(verdictMap, lower)) return verdictMap[lower];
  return VERDICTS.has(lower) ? (lower as EnrichmentVerdict) : null;
}

export const genericHttpProvider: EnrichmentProvider = {
  kind: 'generic_http',
  async lookup({ source, type, value, now }: LookupContext): Promise<EnrichmentResult> {
    if (!source.urlTemplate) throw new EnrichmentSourceError(`${source.name}: no urlTemplate is configured.`);
    const url = renderUrlTemplate(source.urlTemplate, value, type);
    const headers: Record<string, string> = { Accept: 'application/json' };
    for (const [name, raw] of Object.entries(source.headers || {})) {
      if (raw.includes('{apiKey}') && !source.apiKey) {
        throw new EnrichmentSourceError(`${source.name}: header "${name}" needs the API key, which is not configured.`);
      }
      headers[name] = raw.replace(/\{apiKey\}/g, source.apiKey || '');
    }
    const response = await fetchSource(source, url, { method: 'GET', headers, allowInsecure: source.allowInsecure === true });
    const body = parseJsonBody(response, source.name);

    const rawVerdict = source.verdictPath ? jsonPointer(body, source.verdictPath) : undefined;
    const score = source.scorePath ? clampScore(jsonPointer(body, source.scorePath)) : null;
    const mapped = mapVerdict(rawVerdict, source.verdictMap);
    const verdict: EnrichmentVerdict = mapped ?? (source.scorePath ? verdictFromScore(score) : 'unknown');
    const tags = source.tagsPath ? cleanTags(jsonPointer(body, source.tagsPath)) : [];
    const link = source.linkPath ? cleanLink(jsonPointer(body, source.linkPath)) : null;
    let host = '';
    try {
      host = new URL(url).hostname;
    } catch (e) {
      host = source.name;
    }
    const parts: string[] = [];
    if (rawVerdict !== undefined && rawVerdict !== null && typeof rawVerdict !== 'object') parts.push(`verdict "${String(rawVerdict).slice(0, 64)}"`);
    if (score !== null) parts.push(`score ${score}`);
    const summary = parts.length > 0 ? `${host}: ${parts.join(', ')}` : `${host}: no verdict field in the response`;
    return buildResult(source, { verdict, score, tags, link, summary }, now);
  },
};
