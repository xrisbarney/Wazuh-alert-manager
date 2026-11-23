// Outbound URL policy for everything the dashboard server fetches from a third
// party (AI providers, enrichment sources, direct webhooks). The checks here are
// string-level (no DNS resolution): https only, no embedded credentials, no
// loopback / link-local / private hostnames or IP literals, and an optional
// operator allowlist from WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS.
// `boundedFetch` (http.ts) adds the resolved-address check (`isPrivateAddress`)
// right before it connects.
//
// `ai_url_policy.ts` keeps its provider-keyed API and delegates here.

import * as net from 'net';

export const EGRESS_ALLOWED_HOSTS_ENV_VAR = 'WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS';

export type EgressErrorCode = 'timeout' | 'too_large' | 'redirect' | 'network' | 'policy';

/** Why a `policy` error was raised; lets callers keep their own wording. */
export type EgressPolicyReason = 'invalid_url' | 'scheme' | 'credentials' | 'host' | 'allowlist';

export interface EgressErrorExtra {
  status?: number;
  reason?: EgressPolicyReason;
  /** The refused hostname, set for `host` and `allowlist` policy errors. */
  host?: string;
}

export class EgressError extends Error {
  readonly code: EgressErrorCode;
  readonly status?: number;
  readonly reason?: EgressPolicyReason;
  readonly host?: string;

  constructor(code: EgressErrorCode, message: string, extra: EgressErrorExtra = {}) {
    super(message);
    this.name = 'EgressError';
    this.code = code;
    if (extra.status !== undefined) this.status = extra.status;
    if (extra.reason !== undefined) this.reason = extra.reason;
    if (extra.host !== undefined) this.host = extra.host;
  }
}

export function isEgressError(value: unknown): value is EgressError {
  return value instanceof EgressError;
}

export interface EgressUrlOptions {
  /** Short label used in error messages, e.g. "AI base URL" or "Webhook URL". */
  purpose: string;
  /**
   * Hostnames allowed for this call (case-insensitive, exact match; entries
   * are normalised like URL hostnames, so IDN and trailing dots match). A
   * non-empty list replaces the operator allowlist from
   * WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS. An omitted, empty or blank list
   * means "not provided" and the operator allowlist applies; when that is
   * empty too, every public https host is allowed. A caller can therefore
   * never switch the operator allowlist off by forwarding an empty list.
   */
  allowedHosts?: string[];
  /**
   * Permit plain http, but only for hosts that are explicitly allowlisted.
   * `boundedFetch` additionally reads it as "accept an unverified TLS
   * certificate" for an allowlisted local-suffix name (lab receivers).
   */
  allowInsecure?: boolean;
  /**
   * Refuse local-suffix names (`.internal`, `.local`, `.home.arpa`) even when
   * they are allowlisted. The AI base URL policy sets this so the Q9 private
   * receiver escape hatch (enrichment sources, webhooks) never widens AI egress.
   */
  refuseLocalHostnames?: boolean;
}

export interface EgressUrlResult {
  ok: true;
  url: URL;
  /** True when the host is on the explicit or operator allowlist (an operator decision that may name a private receiver, see Q9). */
  allowlisted: boolean;
}

/** Hostnames from WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS, read at call time. */
export function readEgressAllowedHosts(): string[] {
  return normaliseHosts(String(process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR] || '').split(','));
}

/** Strip one trailing dot so `example.com.` and `example.com` compare equal. */
function stripTrailingDot(host: string): string {
  return host.replace(/\.$/, '');
}

/**
 * Normalise allowlist entries exactly like the WHATWG parser normalises a URL
 * hostname (lower-case, IDN -> punycode), so an operator can write
 * `bücher.example` and match `https://xn--bcher-kva.example/`. Entries that
 * do not parse as a hostname are dropped (they could never match anyway).
 */
export function normaliseHosts(hosts: Array<string | undefined | null>): string[] {
  const seen = new Set<string>();
  for (const host of hosts) {
    const raw = String(host || '').trim();
    if (!raw) continue;
    let value: string;
    try {
      value = new URL(`https://${raw}`).hostname;
    } catch (e) {
      continue;
    }
    value = stripTrailingDot(value.toLowerCase());
    if (value) seen.add(value);
  }
  return Array.from(seen);
}

const IPV4_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * True for any IPv4 or IPv6 literal. The WHATWG URL parser has already
 * normalised shorthand IPv4 forms (`0x7f.1`, `2130706433`) to dotted decimal
 * and wraps IPv6 in brackets, so a dotted-quad test plus a ':' check is exact.
 */
export function isIpLiteral(hostname: string): boolean {
  const host = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return IPV4_LITERAL.test(host) || host.includes(':');
}

/** Hostnames that resolve inside the deployment rather than on the internet. */
/** `localhost` and `*.localhost` always mean the loopback interface. */
export function isLoopbackHostname(hostname: string): boolean {
  const host = stripTrailingDot(hostname.toLowerCase());
  return host === 'localhost' || host.endsWith('.localhost');
}

export function isLocalHostname(hostname: string): boolean {
  const host = stripTrailingDot(hostname.toLowerCase());
  return (
    isLoopbackHostname(host) ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.home.arpa')
  );
}

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0) >>> 0;
}

/** `ip` is inside `base/bits` (IPv4). */
function inV4Block(ip: number, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
}

function isPrivateIpv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  return (
    inV4Block(n, '0.0.0.0', 8) || // "this" network / unspecified
    inV4Block(n, '10.0.0.0', 8) ||
    inV4Block(n, '100.64.0.0', 10) || // carrier-grade NAT
    inV4Block(n, '127.0.0.0', 8) ||
    inV4Block(n, '169.254.0.0', 16) || // link-local incl. cloud metadata
    inV4Block(n, '172.16.0.0', 12) ||
    inV4Block(n, '192.0.0.0', 24) ||
    inV4Block(n, '192.168.0.0', 16) ||
    inV4Block(n, '198.18.0.0', 15) || // benchmarking
    inV4Block(n, '224.0.0.0', 4) || // multicast
    inV4Block(n, '240.0.0.0', 4) // reserved + broadcast
  );
}

function wordsToV4(high: number, low: number): string {
  return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
}

/** Expand an IPv6 address to eight 16-bit words; null when it does not parse. */
function ipv6Words(ip: string): number[] | null {
  let text = ip;
  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);
  // Embedded dotted quad (`::ffff:10.0.0.1`) becomes two words.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!IPV4_LITERAL.test(tail)) return null;
    const v4 = ipv4ToInt(tail);
    text = `${text.slice(0, lastColon)}:${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string) => (part ? part.split(':').map((w) => parseInt(w, 16)) : []);
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const words = [...head, ...new Array(fill).fill(0), ...rest];
  if (words.length !== 8 || words.some((w) => !Number.isFinite(w) || w < 0 || w > 0xffff)) return null;
  return words;
}

function isPrivateIpv6(ip: string): boolean {
  const words = ipv6Words(ip);
  if (!words) return true; // unparsable: fail closed
  const zeroPrefix = words.slice(0, 5).every((w) => w === 0);
  if (zeroPrefix && words[5] === 0 && words[6] === 0 && (words[7] === 0 || words[7] === 1)) {
    return true; // :: (unspecified) and ::1 (loopback)
  }
  if (zeroPrefix && (words[5] === 0xffff || words[5] === 0)) {
    // ::ffff:a.b.c.d (IPv4-mapped) and ::a.b.c.d (deprecated IPv4-compatible)
    return isPrivateIpv4(wordsToV4(words[6], words[7]));
  }
  if (words[0] === 0x64 && words[1] === 0xff9b && words.slice(2, 6).every((w) => w === 0)) {
    return isPrivateIpv4(wordsToV4(words[6], words[7])); // 64:ff9b::/96 NAT64
  }
  if ((words[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((words[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((words[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
  if ((words[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (words[0] === 0x2001 && words[1] === 0x0db8) return true; // documentation
  return false;
}

/**
 * True when a resolved address must never be contacted from the dashboard
 * server: loopback, unspecified, private (RFC 1918 / ULA), link-local (incl.
 * the cloud metadata address), CGNAT, multicast, reserved, and the IPv4-mapped
 * / NAT64 IPv6 forms of those. Anything that is not a valid IP is treated as
 * private so a resolver quirk cannot open the door.
 */
export function isPrivateAddress(address: string): boolean {
  const ip = String(address || '').trim();
  const family = net.isIP(ip);
  if (family === 4) return isPrivateIpv4(ip);
  if (family === 6) return isPrivateIpv6(ip);
  return true;
}

/**
 * Validate a URL the server is about to fetch. Returns the parsed URL or
 * throws `EgressError` with code `policy` (and a `reason`) describing why the
 * target is refused.
 */
export function validateEgressUrl(value: string | URL, options: EgressUrlOptions): EgressUrlResult {
  const purpose = options.purpose || 'Egress URL';
  const policy = (reason: EgressPolicyReason, message: string, host?: string) =>
    new EgressError('policy', message, host === undefined ? { reason } : { reason, host });

  let parsed: URL;
  try {
    parsed = value instanceof URL ? new URL(value.toString()) : new URL(String(value).trim());
  } catch (e) {
    throw policy('invalid_url', `${purpose} must be a valid HTTPS URL.`);
  }

  if (parsed.username || parsed.password) {
    throw policy('credentials', `${purpose} must not contain embedded credentials.`);
  }

  const host = parsed.hostname.toLowerCase();
  if (!host) {
    throw policy('invalid_url', `${purpose} must be a valid HTTPS URL.`);
  }
  // An explicit non-empty list replaces the operator allowlist; an empty or
  // blank list counts as "not provided" so it can never widen egress.
  const explicit = options.allowedHosts ? normaliseHosts(options.allowedHosts) : [];
  const allowed = new Set(explicit.length > 0 ? explicit : readEgressAllowedHosts());
  const comparable = stripTrailingDot(host);
  const allowlisted = allowed.has(comparable);

  // Loopback names and IP literals are never reachable, allowlisted or not. A
  // local-suffix name (`.internal`, `.local`, `.home.arpa`) is only reachable
  // when the operator allowlisted it by name (Q9: private receivers such as
  // `host.docker.internal` or an on-premises intel service) and the caller
  // did not opt out with `refuseLocalHostnames`.
  if (isLoopbackHostname(host) || ((!allowlisted || options.refuseLocalHostnames === true) && isLocalHostname(host))) {
    throw policy('host', `${purpose} cannot target localhost or a local hostname.`, host);
  }
  if (isIpLiteral(host)) {
    throw policy('host', `${purpose} cannot target an IP literal; use a public hostname.`, host);
  }
  if (allowed.size > 0 && !allowlisted) {
    throw policy(
      'allowlist',
      `${purpose} host ${comparable} is not allowed. Add it to ${EGRESS_ALLOWED_HOSTS_ENV_VAR} on the dashboard service.`,
      comparable
    );
  }

  if (parsed.protocol !== 'https:') {
    const insecureOk = parsed.protocol === 'http:' && options.allowInsecure === true && allowlisted;
    if (!insecureOk) {
      throw policy('scheme', `${purpose} must use HTTPS.`);
    }
  }

  return { ok: true, url: parsed, allowlisted };
}
