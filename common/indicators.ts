/**
 * Indicator extraction over the canonical alert record (shared by server and
 * browser). Pure and deterministic: the same record always yields the same
 * list, in the same order, with no network or clock access.
 *
 * Inputs are the projected `_source` written by the sync job (both the 4.x
 * alert adapter and the 5.0 finding adapter), including the native data the
 * projection ingests for this purpose: `syscheck.*_after` hashes, `data.url`,
 * `data.hostname`, `data.win.eventdata.ipAddress`, `data.audit.exe` (auditd
 * SYSCALL records, step 9.4), `related.*`, the bounded `threat.matches[]` copy
 * of native verdicts (VirusTotal / Maltiverse sibling alerts, CDB IOC rule ids,
 * 5.0 engine enrichments) and the `geo[]` hints.
 *
 * Only structured decoder fields are read; `full_log` is never scraped. A
 * field whose value is not already a clean indicator (the auditd hex-encoded
 * `saddr`, sudo's `data.command` line with its arguments) is left out.
 */

export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'user' | 'process' | 'host';

export const INDICATOR_TYPES: IndicatorType[] = ['ip', 'domain', 'url', 'hash', 'user', 'process', 'host'];

export type VerdictHintVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'info';

export interface VerdictHint {
  /** Who produced the hint: virustotal, maltiverse, cdb_ioc, wazuh5_engine, geoip, ... */
  source: string;
  verdict: VerdictHintVerdict;
  /** Short human-readable summary (positives/total, feed name, country). */
  detail?: string | null;
  confidence?: string | number | null;
  link?: string | null;
  /** Native field the native matcher reported (5.0 `matched.field`). */
  matchedField?: string | null;
}

export interface Indicator {
  type: IndicatorType;
  /** Normalised value (lower-cased domains/hashes, canonical IPs, ports stripped). */
  value: string;
  /** First canonical field the value was read from. */
  field: string;
  /** Every canonical field the value was read from (deduplicated, ordered). */
  fields: string[];
  verdictHints: VerdictHint[];
  /** `private` for RFC1918 / loopback / link-local / ULA addresses. */
  tags: string[];
}

/** One `threat.matches[]` entry as the projection stores it. */
export interface ThreatMatch {
  source: string;
  verdict?: VerdictHintVerdict | null;
  indicator?: {
    id?: string | null;
    name?: string | null;
    type?: string | null;
    provider?: string | null;
    feed?: string | null;
    confidence?: string | number | null;
    tags?: string[] | null;
    software?: string | null;
  } | null;
  matched_field?: string | null;
  detail?: string | null;
  link?: string | null;
}

/** Entities a `geo[]` hint can describe (ECS entity on 5.0; 4.x is unattributed). */
export type GeoEntity = 'source' | 'destination' | 'client' | 'server' | 'host' | 'unattributed';

/** One `geo[]` hint as the projection stores it. */
export interface GeoHint {
  entity: GeoEntity;
  ip?: string | null;
  country_name?: string | null;
  region_name?: string | null;
  city_name?: string | null;
  provider: string;
  as?: { number?: number | null; organization?: string | null } | null;
}

import type { AlertEnrichmentItem } from './types';

const MAX_VALUE_LENGTH = 2048;
const TYPE_ORDER: Record<IndicatorType, number> = { ip: 0, domain: 1, url: 2, hash: 3, user: 4, process: 5, host: 6 };

function str(value: any): string | null {
  if (value == null) return null;
  if (Array.isArray(value)) return str(value[0]);
  if (typeof value === 'object') return null;
  const s = String(value).trim();
  return s ? s.slice(0, MAX_VALUE_LENGTH) : null;
}

function list(value: any): string[] {
  if (value == null) return [];
  return (Array.isArray(value) ? value : [value]).map(str).filter((v): v is string => Boolean(v));
}

function obj(value: any): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

// ---------------------------------------------------------------------------
// IP handling
// ---------------------------------------------------------------------------

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseIpv4(value: string): number[] | null {
  const m = IPV4_RE.exec(value);
  if (!m) return null;
  const octets = m.slice(1, 5).map((o) => Number(o));
  return octets.every((o) => o >= 0 && o <= 255) ? octets : null;
}

/** Expand an IPv6 literal into eight 16-bit groups, or null when malformed. */
function parseIpv6(value: string): number[] | null {
  let text = value;
  // Embedded IPv4 tail (::ffff:192.0.2.1).
  const v4Tail = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(text);
  if (v4Tail) {
    const octets = parseIpv4(v4Tail[2]);
    if (!octets) return null;
    text = `${v4Tail[1]}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  if (!/^[0-9a-f:]+$/i.test(text) || (text.match(/::/g) || []).length > 1) return null;
  const [head, tail] = text.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = text.includes('::') && tail ? tail.split(':') : [];
  if (!text.includes('::') && headGroups.length !== 8) return null;
  const missing = 8 - headGroups.length - tailGroups.length;
  if (missing < 0 || (text.includes('::') && missing < 1)) return null;
  const groups = [...headGroups, ...Array(missing).fill('0'), ...tailGroups];
  const parsed = groups.map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN));
  return parsed.some((g) => Number.isNaN(g)) ? null : parsed;
}

function formatIpv6(groups: number[]): string {
  // Compress the longest run of zero groups (length >= 2), RFC 5952 style.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i += 1) {
    if (groups[i] !== 0) continue;
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

/**
 * Canonical IP form, or null when the value is not an IP literal. Accepts a
 * trailing `:port` on IPv4 and bracketed IPv6 (`[::1]:443`), leading zeros in
 * IPv4 octets, upper-case hex and IPv4-mapped IPv6.
 */
export function canonicalIp(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let text = raw.trim();
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
  if (bracketed) text = bracketed[1];
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(text)) text = text.slice(0, text.lastIndexOf(':'));
  const zone = text.indexOf('%');
  if (zone > 0) text = text.slice(0, zone);
  const v4 = parseIpv4(text);
  if (v4) return v4.join('.');
  const v6 = parseIpv6(text);
  if (!v6) return null;
  // IPv4-mapped (::ffff:a.b.c.d) collapses to the plain IPv4 address.
  if (v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff) {
    return [v6[6] >> 8, v6[6] & 0xff, v6[7] >> 8, v6[7] & 0xff].join('.');
  }
  return formatIpv6(v6);
}

/** RFC1918, loopback, link-local, CGNAT, unspecified, ULA, multicast. */
export function isPrivateIp(canonical: string): boolean {
  const v4 = parseIpv4(canonical);
  if (v4) {
    const [a, b] = v4;
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  const v6 = parseIpv6(canonical);
  if (!v6) return false;
  if (v6.every((g) => g === 0)) return true; // ::
  if (v6.slice(0, 7).every((g) => g === 0) && v6[7] === 1) return true; // ::1
  const top = v6[0];
  return (top & 0xfe00) === 0xfc00 || (top & 0xffc0) === 0xfe80 || (top & 0xff00) === 0xff00;
}

// ---------------------------------------------------------------------------
// Domain / URL / hash handling
// ---------------------------------------------------------------------------

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$/;

/** Lower-cased domain without port/trailing dot, or null when not a hostname. */
export function canonicalDomain(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let text = raw.trim().toLowerCase();
  if (!text) return null;
  if (text.startsWith('[')) return null; // IPv6 literal
  const colon = text.indexOf(':');
  if (colon > 0 && /^\d{1,5}$/.test(text.slice(colon + 1))) text = text.slice(0, colon);
  if (text.endsWith('.')) text = text.slice(0, -1);
  if (!text || canonicalIp(text) || !DOMAIN_RE.test(text)) return null;
  return text;
}

const URL_RE = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)([^#]*)(#.*)?$/i;

/** Lower-cased scheme and authority; path, query and fragment kept verbatim. */
export function canonicalUrl(raw: string | null | undefined): { url: string; host: string | null } | null {
  if (!raw) return null;
  const text = raw.trim();
  const m = URL_RE.exec(text);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  let authority = m[2].toLowerCase();
  const at = authority.lastIndexOf('@');
  const hostPort = at >= 0 ? authority.slice(at + 1) : authority;
  const bracket = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(hostPort);
  const hostOnly = bracket ? bracket[1] : hostPort.replace(/:\d{1,5}$/, '');
  authority = at >= 0 ? `${authority.slice(0, at + 1)}${hostPort}` : hostPort;
  const host = canonicalIp(hostOnly) || canonicalDomain(hostOnly);
  return { url: `${scheme}://${authority}${m[3] || ''}${m[4] || ''}`, host };
}

/**
 * Program path of an auditd SYSCALL record (`data.audit.exe`), or null. The
 * 4.x auditd decoder keeps the quotes of an AVC record's `exe="..."` value
 * (`"/usr/sbin/apparmor_parser"`) while a plain SYSCALL record is unquoted
 * (`/usr/bin/curl`): one surrounding pair of double quotes is dropped, the
 * value is otherwise kept verbatim and must be an absolute path.
 */
export function canonicalExecutable(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let text = raw.trim();
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) text = text.slice(1, -1).trim();
  return text.startsWith('/') && !/\s/.test(text) ? text : null;
}

const HASH_RE = /^[a-f0-9]+$/;
const HASH_LENGTHS = new Set([32, 40, 64, 128]);

/** Lower-cased MD5/SHA-1/SHA-256/SHA-512 hex digest, or null. */
export function canonicalHash(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const text = raw.trim().toLowerCase();
  return HASH_LENGTHS.has(text.length) && HASH_RE.test(text) ? text : null;
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/** Rule ids the 4.x CDB IOC lists fire (verified on a 4.14 stack). */
export const CDB_IOC_RULE_RANGE: [number, number] = [99901, 99920];

export function isCdbIocRuleId(ruleId: string | number | null | undefined): boolean {
  const n = Number(ruleId);
  return Number.isInteger(n) && n >= CDB_IOC_RULE_RANGE[0] && n <= CDB_IOC_RULE_RANGE[1];
}

class Collector {
  private readonly byKey = new Map<string, Indicator>();

  add(type: IndicatorType, value: string | null, field: string): Indicator | null {
    if (!value) return null;
    const key = `${type}\u0000${value}`;
    let item = this.byKey.get(key);
    if (!item) {
      item = { type, value, field, fields: [field], verdictHints: [], tags: [] };
      if (type === 'ip' && isPrivateIp(value)) item.tags.push('private');
      this.byKey.set(key, item);
    } else if (!item.fields.includes(field)) {
      item.fields.push(field);
    }
    return item;
  }

  find(type: IndicatorType, value: string): Indicator | undefined {
    return this.byKey.get(`${type}\u0000${value}`);
  }

  all(): Indicator[] {
    return Array.from(this.byKey.values());
  }
}

function addHint(item: { verdictHints: VerdictHint[] } | null | undefined, hint: VerdictHint): void {
  if (!item) return;
  const key = `${hint.source}|${hint.verdict}|${hint.detail || ''}|${hint.matchedField || ''}`;
  if (item.verdictHints.some((h) => `${h.source}|${h.verdict}|${h.detail || ''}|${h.matchedField || ''}` === key)) return;
  item.verdictHints.push(hint);
}

/** Classify a native threat-match indicator by its declared type, then by shape. */
function classifyMatch(match: ThreatMatch): Array<{ type: IndicatorType; value: string }> {
  const indicator = obj(match.indicator);
  const name = str(indicator.name);
  if (!name) return [];
  const declared = String(indicator.type || '').toLowerCase();
  const out: Array<{ type: IndicatorType; value: string }> = [];
  const push = (type: IndicatorType, value: string | null) => {
    if (value) out.push({ type, value });
  };
  if (['md5', 'sha1', 'sha256', 'sha512', 'hash', 'file', 'file_hash'].includes(declared)) {
    push('hash', canonicalHash(name));
  } else if (['ip', 'ipv4', 'ipv6', 'ip-src', 'ip-dst', 'connection', 'ip_port'].includes(declared)) {
    push('ip', canonicalIp(name));
  } else if (['domain', 'hostname', 'fqdn', 'dns'].includes(declared)) {
    push('domain', canonicalDomain(name));
  } else if (['url', 'uri'].includes(declared)) {
    const url = canonicalUrl(name);
    push('url', url?.url || null);
  } else {
    push('hash', canonicalHash(name));
    push('ip', canonicalIp(name));
    push('domain', canonicalDomain(name));
    const url = canonicalUrl(name);
    push('url', url?.url || null);
  }
  return out;
}

function hintFromMatch(match: ThreatMatch): VerdictHint {
  const indicator = obj(match.indicator);
  const parts: string[] = [];
  if (indicator.provider) parts.push(String(indicator.provider));
  if (indicator.feed) parts.push(String(indicator.feed));
  if (indicator.software) parts.push(String(indicator.software));
  if (Array.isArray(indicator.tags) && indicator.tags.length) parts.push(indicator.tags.slice(0, 5).join(', '));
  const detail = str(match.detail) || (parts.length ? parts.join(' / ') : null);
  return {
    source: str(match.source) || 'native',
    verdict: match.verdict || 'malicious',
    detail,
    confidence: indicator.confidence ?? null,
    link: str(match.link),
    matchedField: str(match.matched_field),
  };
}

export interface ExtractIndicatorsOptions {
  /**
   * `threat.matches[]` of 4.x sibling alerts (VirusTotal / Maltiverse records
   * whose `threat.sibling_of` names this alert). Their verdicts are attached
   * to the matching indicators of this record and, when the sibling names a
   * value this record does not carry, added as `threat.sibling.indicator.name`.
   */
  siblingMatches?: ThreatMatch[] | null;
}

/** Response of `GET /alerts/{id}/sibling-verdicts`. */
export interface AlertSiblingVerdictsResponse {
  /** Merged `threat.matches[]` of every sibling record (bounded). */
  matches: ThreatMatch[];
  /** Sibling records found. */
  siblings: number;
}

/**
 * Extract indicators from one canonical alert record (`_source`). Never throws
 * on malformed input; unknown shapes are skipped.
 */
export function extractIndicators(record: any, options: ExtractIndicatorsOptions = {}): Indicator[] {
  const source = obj(record);
  const data = obj(source.data);
  const agent = obj(source.agent);
  const rule = obj(source.rule);
  const syscheck = obj(source.syscheck);
  const related = obj(source.related);
  const win = obj(obj(data.win).eventdata);
  const c = new Collector();

  // IPs
  c.add('ip', canonicalIp(str(data.srcip)), 'data.srcip');
  c.add('ip', canonicalIp(str(data.dstip)), 'data.dstip');
  c.add('ip', canonicalIp(str(win.ipAddress)), 'data.win.eventdata.ipAddress');
  c.add('ip', canonicalIp(str(agent.ip)), 'agent.ip');
  for (const ip of list(related.ip)) c.add('ip', canonicalIp(ip), 'related.ip');

  // Domains and URLs
  const hostname = str(data.hostname);
  if (hostname) {
    const asIp = canonicalIp(hostname);
    if (asIp) c.add('ip', asIp, 'data.hostname');
    else c.add('domain', canonicalDomain(hostname), 'data.hostname');
  }
  const rawUrl = str(data.url);
  const url = canonicalUrl(rawUrl);
  if (url) {
    c.add('url', url.url, 'data.url');
    if (url.host) c.add(canonicalIp(url.host) ? 'ip' : 'domain', url.host, 'data.url');
  } else if (rawUrl && rawUrl.startsWith('/')) {
    // 4.x web-access decoders keep only the request path in data.url
    // (`/wp-login.php`); it is still an indicator, kept verbatim.
    c.add('url', rawUrl, 'data.url');
  }

  // Hashes
  c.add('hash', canonicalHash(str(syscheck.md5_after)), 'syscheck.md5_after');
  c.add('hash', canonicalHash(str(syscheck.sha1_after)), 'syscheck.sha1_after');
  c.add('hash', canonicalHash(str(syscheck.sha256_after)), 'syscheck.sha256_after');
  for (const hash of list(related.hash)) c.add('hash', canonicalHash(hash), 'related.hash');

  // Users, processes, hosts
  c.add('user', str(data.srcuser), 'data.srcuser');
  c.add('user', str(data.dstuser), 'data.dstuser');
  for (const user of list(related.user)) c.add('user', user, 'related.user');
  c.add('process', str(obj(data.process).name), 'data.process.name');
  // auditd SYSCALL records (4.x rules 80700-80799): the decoder exposes the
  // resolved binary as data.audit.exe; data.audit.command is the kernel's
  // 15-character `comm` and adds nothing over it.
  c.add('process', canonicalExecutable(str(obj(data.audit).exe)), 'data.audit.exe');
  c.add('host', str(agent.name), 'agent.name');
  for (const host of list(related.hosts)) c.add('host', host, 'related.hosts');

  // Native verdicts (bounded threat.matches[] copy), then the verdicts of 4.x
  // sibling alerts that enriched this record.
  const matches: ThreatMatch[] = Array.isArray(obj(source.threat).matches) ? obj(source.threat).matches : [];
  for (const match of matches) {
    if (!match || typeof match !== 'object') continue;
    const hint = hintFromMatch(match);
    for (const { type, value } of classifyMatch(match)) {
      addHint(c.add(type, value, `threat.matches.indicator.name`), hint);
    }
  }
  const siblingMatches = Array.isArray(options.siblingMatches) ? options.siblingMatches : [];
  for (const match of siblingMatches) {
    if (!match || typeof match !== 'object') continue;
    const hint = hintFromMatch(match);
    for (const { type, value } of classifyMatch(match)) {
      addHint(c.find(type, value) || c.add(type, value, 'threat.sibling.indicator.name'), hint);
    }
  }

  // CDB IOC lists: the rule id says "an IOC list matched" but not which
  // field. The lists only hold public addresses, domains, URLs and hashes, so
  // the monitored host's own address (agent.ip) and private addresses are
  // never the matched value and get no hint.
  if (isCdbIocRuleId(rule.id)) {
    const hint: VerdictHint = {
      source: 'cdb_ioc',
      verdict: 'malicious',
      detail: `${str(rule.description) ? `CDB IOC list rule ${rule.id}: ${str(rule.description)}` : `CDB IOC list rule ${rule.id}`} (matched field not reported; public values only)`,
      confidence: null,
      link: null,
      matchedField: null,
    };
    for (const item of c.all()) {
      if (item.type !== 'ip' && item.type !== 'domain' && item.type !== 'url' && item.type !== 'hash') continue;
      if (item.tags.includes('private')) continue;
      if (item.fields.every((field) => field === 'agent.ip')) continue;
      addHint(item, hint);
    }
  }

  // GeoIP hints attach to the address they describe.
  const geo: GeoHint[] = Array.isArray(source.geo) ? source.geo : [];
  for (const g of geo) {
    if (!g || typeof g !== 'object') continue;
    const targets: string[] = [];
    const explicit = canonicalIp(str(g.ip));
    if (explicit) targets.push(explicit);
    else if (g.entity === 'source' || g.entity === 'client') targets.push(canonicalIp(str(data.srcip)) || '');
    else if (g.entity === 'destination' || g.entity === 'server') targets.push(canonicalIp(str(data.dstip)) || '');
    else if (g.entity === 'host') targets.push(canonicalIp(str(agent.ip)) || '');
    else targets.push(canonicalIp(str(data.srcip)) || '', canonicalIp(str(data.dstip)) || '');
    const place = [g.city_name, g.region_name, g.country_name].map(str).filter(Boolean).join(', ');
    const asn = obj(g.as);
    const asText = asn.number != null || asn.organization ? ` (AS${asn.number ?? '?'}${asn.organization ? ` ${asn.organization}` : ''})` : '';
    if (!place && !asText) continue;
    for (const target of targets) {
      if (!target) continue;
      addHint(c.find('ip', target), {
        source: `geoip:${g.provider || 'unknown'}`,
        verdict: 'info',
        detail: `${place || 'unknown location'}${asText}`,
        confidence: null,
        link: null,
        matchedField: null,
      });
    }
  }

  return c.all().sort((a, b) => TYPE_ORDER[a.type] - TYPE_ORDER[b.type] || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
}

/** Group indicators by type in canonical type order (for display). */
export function groupIndicators(indicators: Indicator[]): Array<{ type: IndicatorType; items: Indicator[] }> {
  const groups = new Map<IndicatorType, Indicator[]>();
  for (const item of indicators) {
    const bucket = groups.get(item.type) || [];
    bucket.push(item);
    groups.set(item.type, bucket);
  }
  return INDICATOR_TYPES.filter((type) => groups.has(type)).map((type) => ({ type, items: groups.get(type)! }));
}

/** Strongest verdict across a set of hints (malicious > suspicious > clean > unknown > info). */
export function strongestVerdict(hints: VerdictHint[]): VerdictHintVerdict | null {
  const order: VerdictHintVerdict[] = ['malicious', 'suspicious', 'clean', 'unknown', 'info'];
  let best: number = order.length;
  for (const hint of hints) {
    const idx = order.indexOf(hint.verdict);
    if (idx >= 0 && idx < best) best = idx;
  }
  return best < order.length ? order[best] : null;
}

// ---------------------------------------------------------------------------
// Case-level aggregation (shared with the route so it is unit-testable)
// ---------------------------------------------------------------------------

export interface CaseIndicator {
  type: IndicatorType;
  value: string;
  /** Number of distinct alerts in the case carrying the indicator. */
  count: number;
  first_seen: string | null;
  last_seen: string | null;
  /** First `MAX_ALERT_IDS_PER_INDICATOR` alert ids, in first-seen order. */
  alert_ids: string[];
  fields: string[];
  tags: string[];
  verdictHints: VerdictHint[];
  /** Stored lookup verdicts (`enrichment.items`) of member alerts for this indicator: one per source, newest wins. */
  enrichment: AlertEnrichmentItem[];
}

export interface CaseIndicatorsResponse {
  indicators: CaseIndicator[];
  /** Alerts whose record (live, archived or snapshot) was available for extraction. */
  includedAlerts: number;
  /** Evidence relationships the route paged (before the cap). */
  totalRelationships: number;
  truncated: boolean;
  limit: number;
}

export const MAX_ALERT_IDS_PER_INDICATOR = 20;

/** Stored `enrichment.items` of one record that name this indicator (shape-checked, never throws). */
function storedEnrichmentFor(source: any, type: IndicatorType, value: string): AlertEnrichmentItem[] {
  const items = obj(obj(source).enrichment).items;
  if (!Array.isArray(items)) return [];
  return items.filter(
    (item: any) =>
      item && typeof item === 'object' && item.type === type && item.value === value &&
      typeof item.source === 'string' && item.source && typeof item.verdict === 'string' && typeof item.checked_at === 'string'
  );
}

/** One stored item per source across the case; the most recently checked wins. */
function addStoredEnrichment(row: { enrichment: AlertEnrichmentItem[] }, item: AlertEnrichmentItem): void {
  const index = row.enrichment.findIndex((existing) => existing.source === item.source);
  if (index < 0) {
    row.enrichment.push(item);
  } else if (item.checked_at > row.enrichment[index].checked_at) {
    row.enrichment[index] = item;
  }
}

function timestampOf(source: any): string | null {
  const value = obj(source)['@timestamp'];
  return typeof value === 'string' && value ? value : null;
}

/**
 * Aggregate indicators across a case's alerts: one row per (type, value) with
 * the alert count, first/last seen (by alert `@timestamp`) and merged hints.
 * Input order does not matter; the output is sorted by type then value.
 */
export function aggregateIndicators(alerts: Array<{ _id: string; _source: any }>): CaseIndicator[] {
  const rows = new Map<string, CaseIndicator & { seen: Set<string> }>();
  const ordered = alerts
    .filter((a) => a && typeof a._id === 'string')
    .slice()
    .sort((a, b) => {
      const ta = timestampOf(a._source) || '';
      const tb = timestampOf(b._source) || '';
      return ta < tb ? -1 : ta > tb ? 1 : a._id < b._id ? -1 : a._id > b._id ? 1 : 0;
    });
  for (const alert of ordered) {
    const stamp = timestampOf(alert._source);
    for (const item of extractIndicators(alert._source)) {
      const key = `${item.type}\u0000${item.value}`;
      let row = rows.get(key);
      if (!row) {
        row = {
          type: item.type,
          value: item.value,
          count: 0,
          first_seen: null,
          last_seen: null,
          alert_ids: [],
          fields: [],
          tags: [],
          verdictHints: [],
          enrichment: [],
          seen: new Set<string>(),
        };
        rows.set(key, row);
      }
      if (row.seen.has(alert._id)) continue;
      row.seen.add(alert._id);
      row.count += 1;
      if (row.alert_ids.length < MAX_ALERT_IDS_PER_INDICATOR) row.alert_ids.push(alert._id);
      if (stamp) {
        if (!row.first_seen || stamp < row.first_seen) row.first_seen = stamp;
        if (!row.last_seen || stamp > row.last_seen) row.last_seen = stamp;
      }
      for (const field of item.fields) if (!row.fields.includes(field)) row.fields.push(field);
      for (const tag of item.tags) if (!row.tags.includes(tag)) row.tags.push(tag);
      for (const hint of item.verdictHints) addHint(row, hint);
      for (const stored of storedEnrichmentFor(alert._source, item.type, item.value)) addStoredEnrichment(row, stored);
    }
  }
  return Array.from(rows.values())
    .map(({ seen, ...row }) => row)
    .sort((a, b) => TYPE_ORDER[a.type] - TYPE_ORDER[b.type] || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
}
