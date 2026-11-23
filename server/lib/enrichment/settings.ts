import {
  ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS,
  ENRICHMENT_DEFAULT_TIMEOUT_MS,
  ENRICHMENT_KIND_CAPABILITIES,
  ENRICHMENT_LOOKUP_TYPES,
  ENRICHMENT_MAX_CACHE_TTL_SECONDS,
  ENRICHMENT_MAX_SOURCES,
  ENRICHMENT_MAX_TIMEOUT_MS,
  ENRICHMENT_SETTINGS_DOC_ID,
  ENRICHMENT_SOURCE_KINDS,
  ENRICHMENT_VERDICTS,
  TARGET_WAZUH_MAJOR,
  WAZUH_CTI_LOCAL_SOURCE_ID,
} from '../../../common';
import type { EnrichmentLookupType, EnrichmentSource, EnrichmentSourceKind, EnrichmentVerdict } from '../../../common';
import { validateEgressUrl } from '../egress/url_policy';
import { defineSettingsDoc, typedError } from '../plugin_settings';

/**
 * Enrichment settings document (`enrichment_settings` in META_INDEX).
 *
 * `sources[]` holds every configured source; `sources[].apiKey` is the only
 * secret (encrypted at rest, masked to `apiKeyConfigured` on read). The
 * built-in `wazuh_cti_local` source is not stored unless an administrator
 * toggles it: `withBuiltInSources` synthesises it on every read so a 5.0
 * build has it enabled out of the box and a 4.x build can switch it on when
 * the catalog index happens to exist.
 */

/** Stored shape: `EnrichmentSource` plus the encrypted secret. */
export interface StoredEnrichmentSource extends Omit<EnrichmentSource, 'apiKeyConfigured' | 'builtIn'> {
  apiKey?: string;
}

export interface EnrichmentSettingsDoc {
  sources: StoredEnrichmentSource[];
}

/** Indicator types each kind can answer (single table in common/constants.ts, shared with the settings tab). */
export const KIND_CAPABILITIES: Record<EnrichmentSourceKind, EnrichmentLookupType[]> = ENRICHMENT_KIND_CAPABILITIES;

export const WAZUH_CTI_LOCAL_INDEX_PATTERN = 'wazuh-threatintel-enrichments*';

const SOURCE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const KINDS = new Set<string>(ENRICHMENT_SOURCE_KINDS);
const TYPES = new Set<string>(ENRICHMENT_LOOKUP_TYPES);
const VERDICTS = new Set<string>(ENRICHMENT_VERDICTS);

function bad(message: string): never {
  throw typedError(message, 400);
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function cleanString(value: unknown, max: number): string {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function cleanHeaders(value: unknown, label: string): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) bad(`${label}: headers must be an object of header name to value.`);
  const out: Record<string, string> = {};
  for (const [name, raw] of Object.entries(value as Record<string, unknown>)) {
    const key = name.trim();
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(key)) bad(`${label}: invalid header name "${name}".`);
    if (typeof raw !== 'string' || /[\r\n\0]/.test(raw)) bad(`${label}: header "${key}" must be a single-line string.`);
    out[key] = raw.slice(0, 2048);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function cleanPointer(value: unknown, label: string, field: string): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string' || !(value === '' || value.startsWith('/')) || value.length > 512) {
    bad(`${label}: ${field} must be an RFC 6901 JSON pointer starting with "/".`);
  }
  return value;
}

/** The host part of a template must be literal; placeholders only in path/query. */
export function assertUrlTemplate(template: string, label: string, options: { allowInsecure?: boolean } = {}): void {
  const placeholderFree = template.replace(/\{value\}/g, 'v').replace(/\{type\}/g, 't');
  if (/\{[a-zA-Z]+\}/.test(placeholderFree)) bad(`${label}: urlTemplate may only use the {value} and {type} placeholders.`);
  if (!/\{value\}/.test(template)) bad(`${label}: urlTemplate must contain the {value} placeholder.`);
  try {
    new URL(placeholderFree); // eslint-disable-line no-new
  } catch (e) {
    bad(`${label}: urlTemplate must be a valid HTTPS URL.`);
  }
  // Scheme and authority (everything before the first "/", "?" or "#" after
  // "://") must be literal so a placeholder can never choose the host.
  const schemeEnd = template.indexOf('://');
  const authorityStart = schemeEnd >= 0 ? schemeEnd + 3 : 0;
  const ends = ['/', '?', '#'].map((c) => template.indexOf(c, authorityStart)).filter((i) => i >= 0);
  const authorityEnd = ends.length > 0 ? Math.min(...ends) : template.length;
  if (template.slice(0, authorityEnd).includes('{')) {
    bad(`${label}: urlTemplate placeholders are only allowed in the path or query, not the host.`);
  }
  try {
    validateEgressUrl(placeholderFree, { purpose: `${label} URL`, allowInsecure: options.allowInsecure === true });
  } catch (e: any) {
    bad(e?.message || `${label}: urlTemplate is not an allowed egress target.`);
  }
}

function normaliseSource(raw: any, index: number): StoredEnrichmentSource {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad(`sources[${index}] must be an object.`);
  // The id is validated exactly as submitted, never rewritten: plugin_settings
  // re-attaches `sources[].apiKey` to the validated element by id, so a
  // normalised id (lower-cased, trimmed) would silently drop the secret.
  const id = typeof raw.id === 'string' ? raw.id : '';
  if (!SOURCE_ID.test(id)) bad(`sources[${index}]: id must be 1-64 lower-case letters, digits, "-" or "_" (no spaces or upper-case).`);
  const kind = cleanString(raw.kind, 32) as EnrichmentSourceKind;
  if (!KINDS.has(kind)) bad(`Source "${id}": kind must be one of ${ENRICHMENT_SOURCE_KINDS.join(', ')}.`);
  if (kind === 'wazuh_cti_local' && id !== WAZUH_CTI_LOCAL_SOURCE_ID) {
    bad(`Source "${id}": the wazuh_cti_local kind is reserved for the built-in source "${WAZUH_CTI_LOCAL_SOURCE_ID}".`);
  }
  const name = cleanString(raw.name, 120) || id;
  const label = `Source "${name}"`;
  const capability = KIND_CAPABILITIES[kind];
  const requested: unknown[] = Array.isArray(raw.supports) ? raw.supports : capability;
  const supports = capability.filter((type) => requested.includes(type)) as EnrichmentLookupType[];
  for (const type of requested) {
    if (!TYPES.has(String(type))) bad(`${label}: unsupported indicator type "${String(type)}".`);
    if (!capability.includes(type as EnrichmentLookupType)) bad(`${label}: a ${kind} source cannot look up "${String(type)}" indicators.`);
  }
  if (supports.length === 0) bad(`${label}: select at least one indicator type.`);

  const source: StoredEnrichmentSource = {
    id,
    name,
    kind,
    enabled: raw.enabled === true,
    supports,
    cacheTtlSeconds: clampInt(raw.cacheTtlSeconds, ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS, 60, ENRICHMENT_MAX_CACHE_TTL_SECONDS),
    timeoutMs: clampInt(raw.timeoutMs, ENRICHMENT_DEFAULT_TIMEOUT_MS, 1000, ENRICHMENT_MAX_TIMEOUT_MS),
  };

  // Plain http is only ever honoured for allowlisted hosts (validateEgressUrl
  // enforces that); the flag is stored only when set so older docs are unchanged.
  const allowInsecure = raw.allowInsecure === true && (kind === 'misp' || kind === 'generic_http');
  if (allowInsecure) source.allowInsecure = true;

  if (kind === 'misp') {
    const baseUrl = cleanString(raw.baseUrl, 2048).replace(/\/+$/, '');
    if (!baseUrl) bad(`${label}: a MISP source needs its server base URL.`);
    try {
      validateEgressUrl(baseUrl, { purpose: `${label} base URL`, allowInsecure });
    } catch (e: any) {
      bad(e?.message || `${label}: base URL is not an allowed egress target.`);
    }
    source.baseUrl = baseUrl;
  } else if (kind === 'generic_http') {
    const urlTemplate = cleanString(raw.urlTemplate, 2048);
    if (!urlTemplate) bad(`${label}: a generic HTTP source needs a urlTemplate with a {value} placeholder.`);
    assertUrlTemplate(urlTemplate, label, { allowInsecure });
    source.urlTemplate = urlTemplate;
    const headers = cleanHeaders(raw.headers, label);
    if (headers) source.headers = headers;
    const verdictPath = cleanPointer(raw.verdictPath, label, 'verdictPath');
    const scorePath = cleanPointer(raw.scorePath, label, 'scorePath');
    const tagsPath = cleanPointer(raw.tagsPath, label, 'tagsPath');
    const linkPath = cleanPointer(raw.linkPath, label, 'linkPath');
    if (!verdictPath && !scorePath) bad(`${label}: set verdictPath or scorePath so the response can be interpreted.`);
    if (verdictPath) source.verdictPath = verdictPath;
    if (scorePath) source.scorePath = scorePath;
    if (tagsPath) source.tagsPath = tagsPath;
    if (linkPath) source.linkPath = linkPath;
    if (raw.verdictMap !== undefined && raw.verdictMap !== null) {
      if (typeof raw.verdictMap !== 'object' || Array.isArray(raw.verdictMap)) bad(`${label}: verdictMap must be an object.`);
      const map: Record<string, EnrichmentVerdict> = {};
      for (const [key, verdict] of Object.entries(raw.verdictMap as Record<string, unknown>)) {
        if (!VERDICTS.has(String(verdict))) bad(`${label}: verdictMap["${key}"] must be one of ${ENRICHMENT_VERDICTS.join(', ')}.`);
        map[key.slice(0, 256)] = verdict as EnrichmentVerdict;
      }
      if (Object.keys(map).length > 0) source.verdictMap = map;
    }
  }
  return source;
}

/** Validate and normalise the merged document (secrets are not present here). */
export function normaliseEnrichmentSettings(doc: EnrichmentSettingsDoc): EnrichmentSettingsDoc {
  const list = Array.isArray(doc?.sources) ? doc.sources : [];
  if (list.length > ENRICHMENT_MAX_SOURCES) bad(`At most ${ENRICHMENT_MAX_SOURCES} enrichment sources can be configured.`);
  const seen = new Set<string>();
  const sources = list.map((raw, index) => {
    const source = normaliseSource(raw, index);
    if (seen.has(source.id)) bad(`Source id "${source.id}" is used more than once.`);
    seen.add(source.id);
    return source;
  });
  return { sources };
}

export const enrichmentSettings = defineSettingsDoc<EnrichmentSettingsDoc>({
  docId: ENRICHMENT_SETTINGS_DOC_ID,
  defaults: { sources: [] },
  secretFields: ['sources[].apiKey'],
  validate: normaliseEnrichmentSettings,
});

/** The built-in local CTI source as it looks before an administrator ever saved it. */
export function builtInCtiLocalSource(): EnrichmentSource {
  return {
    id: WAZUH_CTI_LOCAL_SOURCE_ID,
    name: 'Wazuh CTI catalog (local)',
    kind: 'wazuh_cti_local',
    enabled: true,
    supports: [...KIND_CAPABILITIES.wazuh_cti_local],
    cacheTtlSeconds: ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS,
    timeoutMs: ENRICHMENT_DEFAULT_TIMEOUT_MS,
    builtIn: true,
  };
}

/**
 * Add the built-in source to a source list that does not carry it yet and
 * mark it `builtIn` when it does. Pure; works on masked and unmasked lists.
 */
export function withBuiltInSources<T extends { id: string; kind: string }>(
  sources: T[],
  wazuhMajor: number = Number(TARGET_WAZUH_MAJOR)
): Array<T | EnrichmentSource> {
  // The local CTI catalog exists only on Wazuh 5.0. A 4.x build neither
  // offers nor runs it: the source is dropped from the effective list (even a
  // stored toggle) so the UI never shows a feature the install cannot have.
  if (wazuhMajor !== 5) return (sources || []).filter((source) => source.kind !== 'wazuh_cti_local');
  const list = (sources || []).map((source) =>
    source.kind === 'wazuh_cti_local' ? { ...source, builtIn: true } : source
  );
  if (!list.some((source) => source.kind === 'wazuh_cti_local')) list.unshift(builtInCtiLocalSource() as any);
  return list;
}
