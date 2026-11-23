import type { EnrichmentResult, EnrichmentVerdict } from '../../../common';
import { EnrichmentProvider, EnrichmentSourceError, LookupContext, buildResult, cleanLink, fetchSource, parseJsonBody } from './provider';

/**
 * MISP `POST /attributes/restSearch` (ip / domain / url / hash). Any
 * attribute flagged `to_ids` is a malicious verdict; attributes that exist
 * without the IDS flag are suspicious; an empty answer is `unknown` (absence
 * from one MISP instance is not evidence of a clean indicator).
 */
export const MISP_SEARCH_LIMIT = 20;

export const mispProvider: EnrichmentProvider = {
  kind: 'misp',
  async lookup({ source, value, now }: LookupContext): Promise<EnrichmentResult> {
    if (!source.baseUrl) throw new EnrichmentSourceError(`${source.name}: no base URL is configured.`);
    if (!source.apiKey) throw new EnrichmentSourceError(`${source.name}: no API key is configured.`);
    const base = source.baseUrl.replace(/\/+$/, '');
    const response = await fetchSource(source, `${base}/attributes/restSearch`, {
      method: 'POST',
      allowInsecure: source.allowInsecure === true,
      headers: {
        Authorization: source.apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ value, returnFormat: 'json', limit: MISP_SEARCH_LIMIT }),
    });
    const body = parseJsonBody(response, source.name);
    const attributes: any[] = Array.isArray(body?.response?.Attribute) ? body.response.Attribute : [];
    const ids = attributes.filter((attribute) => attribute?.to_ids === true || attribute?.to_ids === 1 || attribute?.to_ids === '1');
    const events = new Set<string>();
    const tags: string[] = [];
    for (const attribute of attributes) {
      if (attribute?.event_id !== undefined && attribute?.event_id !== null) events.add(String(attribute.event_id));
      for (const tag of Array.isArray(attribute?.Tag) ? attribute.Tag : []) {
        if (typeof tag?.name === 'string') tags.push(tag.name);
      }
    }
    const first = attributes[0];
    const link = first?.event_id !== undefined && first?.event_id !== null ? cleanLink(`${base}/events/view/${encodeURIComponent(String(first.event_id))}`) : null;
    const verdict: EnrichmentVerdict = ids.length > 0 ? 'malicious' : attributes.length > 0 ? 'suspicious' : 'unknown';
    const info = typeof first?.Event?.info === 'string' && first.Event.info ? ` - "${first.Event.info.slice(0, 120)}"` : '';
    const summary =
      attributes.length === 0
        ? 'No matching attribute in MISP'
        : `${attributes.length} attribute${attributes.length === 1 ? '' : 's'} in ${events.size} event${events.size === 1 ? '' : 's'}, ${ids.length} flagged for IDS${info}`;
    return buildResult(source, { verdict, score: null, tags, link, summary }, now);
  },
};
