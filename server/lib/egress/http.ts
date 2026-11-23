// Bounded outbound HTTP for the dashboard server. Every third-party call
// (AI providers, enrichment lookups, direct webhooks) goes through
// `boundedFetch` so it always has a timeout, never follows redirects, and
// cannot read an unbounded response body into memory. The target URL is
// re-validated with `validateEgressUrl` at call time, and the hostname is
// resolved first so a public-looking name (`127.0.0.1.nip.io`, an attacker
// DNS record pointing at 10.x or 169.254.169.254) is refused before any
// connection is opened. That check is skipped only for a local-suffix name
// (`.internal`, `.local`, `.home.arpa`, see `isLocalHostname`) the operator
// allowlisted by name (explicitly or via
// WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS): such a name can only ever be a
// private receiver, so listing it is the documented opt-in (Q9,
// `host.docker.internal`). Every other allowlisted host, including the public
// ones an operator must list once the allowlist narrows egress
// (`api.abuseipdb.com`), keeps the resolved-address defence, so an allowlist
// never widens the address policy. Residual risk: DNS rebinding between this
// lookup and the connect (TOCTOU) is not defended.
//
// `allowInsecure` relaxes transport security for such a receiver and nothing
// else: plain http for any allowlisted host (policy decision, see
// `validateEgressUrl`), and an unverified TLS certificate only for an
// allowlisted local-suffix name (a lab MISP behind `misp.internal` serving a
// self-signed certificate). That https path goes through `https.request` with
// `rejectUnauthorized: false` for that one request; the global fetch and its
// process-wide trust store are never touched.

import * as dns from 'dns';
import * as https from 'https';
import type { IncomingMessage } from 'http';
import { ReadableStream as NodeReadableStream } from 'stream/web';

import { EgressError, EgressUrlOptions, isLocalHostname, isPrivateAddress, validateEgressUrl } from './url_policy';

export { EgressError, EgressErrorCode, EgressPolicyReason, isEgressError } from './url_policy';

export const DEFAULT_EGRESS_TIMEOUT_MS = 10000;
export const MAX_EGRESS_TIMEOUT_MS = 60000;
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

export interface BoundedFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** Whole-request deadline; default 10 s, clamped to 60 s. */
  timeoutMs?: number;
  /** Response body cap; the request is aborted once exceeded. Default 1 MiB. */
  maxResponseBytes?: number;
  /** Label for policy errors, e.g. "Webhook URL". */
  purpose?: string;
  /** See `validateEgressUrl`. */
  allowedHosts?: string[];
  /**
   * Permit plain http for an allowlisted host and, for an allowlisted
   * local-suffix name only, an unverified (self-signed) TLS certificate.
   */
  allowInsecure?: boolean;
  /**
   * Hostname resolver returning every address the name maps to; defaults to
   * `dns.promises.lookup(host, { all: true })`. Tests inject a fake.
   */
  resolve?: HostResolver;
}

export type HostResolver = (hostname: string) => Promise<string[]>;

/** Default resolver: the system lookup, every A/AAAA record. */
export const lookupAllAddresses: HostResolver = async (hostname) => {
  const records = await dns.promises.lookup(hostname, { all: true });
  return records.map((record) => record.address);
};

export interface BoundedFetchResult {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  /** Always false: an oversized body throws `too_large` instead of truncating. */
  truncated: false;
}

interface FetchLikeResponse {
  status: number;
  headers: { forEach(cb: (value: string, key: string) => void): void; get(name: string): string | null };
  body: ReadableStream<Uint8Array> | null;
}

function clampTimeout(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return DEFAULT_EGRESS_TIMEOUT_MS;
  return Math.min(Math.floor(value), MAX_EGRESS_TIMEOUT_MS);
}

function clampMaxBytes(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return DEFAULT_MAX_RESPONSE_BYTES;
  return Math.floor(value);
}

interface TransportInit {
  method: string;
  headers?: Record<string, string>;
  body?: string;
  signal: AbortSignal;
}

function toWebStream(res: IncomingMessage): ReadableStream<Uint8Array> {
  const stream = new NodeReadableStream<Uint8Array>({
    start(controller) {
      res.on('data', (chunk: Buffer) => controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)));
      res.on('end', () => controller.close());
      res.on('error', (e) => controller.error(e));
    },
    cancel() {
      res.destroy();
    },
  });
  return stream as unknown as ReadableStream<Uint8Array>;
}

/**
 * The one request shape that bypasses certificate verification: a native
 * `https.request` with `rejectUnauthorized: false`, used only when
 * `boundedFetch` has established that the target is an allowlisted
 * local-suffix receiver and the caller set `allowInsecure`. Same contract as
 * the fetch path: no redirects are followed (a 3xx is returned as-is), the
 * abort signal ends the request, and the body is read through the same
 * capped reader.
 */
export function insecureTlsRequest(target: URL, init: TransportInit): Promise<FetchLikeResponse> {
  return new Promise<FetchLikeResponse>((resolve, reject) => {
    const req = https.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        path: `${target.pathname}${target.search}`,
        method: init.method,
        headers: init.headers,
        rejectUnauthorized: false,
        signal: init.signal,
      },
      (res) => {
        const lower: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value === undefined) continue;
          lower[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
        }
        resolve({
          status: res.statusCode || 0,
          headers: {
            get: (name) => (name.toLowerCase() in lower ? lower[name.toLowerCase()] : null),
            forEach: (cb) => {
              for (const [key, value] of Object.entries(lower)) cb(value, key);
            },
          },
          body: toWebStream(res),
        });
      }
    );
    req.on('error', reject);
    if (init.body !== undefined) req.write(init.body);
    req.end();
  });
}

function plainHeaders(headers: FetchLikeResponse['headers']): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * Refuse a hostname that resolves (even partly) to a loopback, private,
 * link-local or otherwise non-public address. A name with no address at all
 * is a network error, exactly as the connect would have reported it.
 */
async function assertResolvesToPublicAddress(
  hostname: string,
  resolve: HostResolver,
  purpose: string,
  signal: AbortSignal,
  fail: (message: string, cause?: unknown) => EgressError
): Promise<void> {
  let addresses: string[];
  try {
    // The lookup cannot be cancelled, but the deadline still applies to it.
    addresses = await Promise.race([
      resolve(hostname),
      new Promise<never>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      }),
    ]);
  } catch (e) {
    throw fail(`Could not resolve ${hostname}`, e);
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new EgressError('network', `Could not resolve ${hostname}: no addresses.`);
  }
  const blocked = addresses.find((address) => isPrivateAddress(address));
  if (blocked !== undefined) {
    throw new EgressError(
      'policy',
      `${purpose} host ${hostname} resolves to a private or local address (${blocked}), which cannot be contacted.`,
      { reason: 'host', host: hostname }
    );
  }
}

export async function boundedFetch(
  url: string | URL,
  options: BoundedFetchOptions = {}
): Promise<BoundedFetchResult> {
  if (typeof fetch !== 'function') {
    throw new EgressError('network', 'The dashboard Node.js runtime does not have a global fetch available.');
  }

  const policyOptions: EgressUrlOptions = { purpose: options.purpose || 'Egress URL' };
  if (options.allowedHosts) policyOptions.allowedHosts = options.allowedHosts;
  if (options.allowInsecure !== undefined) policyOptions.allowInsecure = options.allowInsecure;
  const { url: target, allowlisted } = validateEgressUrl(url, policyOptions);

  const timeoutMs = clampTimeout(options.timeoutMs);
  const maxBytes = clampMaxBytes(options.maxResponseBytes);
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const fail = (message: string, cause?: unknown): EgressError => {
    if (timedOut) {
      return new EgressError('timeout', `Request to ${target.hostname} timed out after ${timeoutMs} ms.`);
    }
    const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
    return new EgressError('network', `${message}${detail}`);
  };

  try {
    // Only an allowlisted local-suffix name may resolve privately (see the
    // header comment); a public name stays subject to the address check even
    // when listed.
    const privateReceiver = allowlisted && isLocalHostname(target.hostname);
    if (!privateReceiver) {
      await assertResolvesToPublicAddress(
        target.hostname,
        options.resolve || lookupAllAddresses,
        policyOptions.purpose,
        controller.signal,
        fail
      );
    }

    // Unverified TLS is the private-receiver escape hatch only: an allowlisted
    // local-suffix name, https, and the caller's explicit `allowInsecure`.
    const skipTlsVerify = privateReceiver && options.allowInsecure === true && target.protocol === 'https:';

    let res: FetchLikeResponse;
    try {
      res = skipTlsVerify
        ? await insecureTlsRequest(target, {
            method: options.method || 'GET',
            headers: options.headers,
            body: options.body,
            signal: controller.signal,
          })
        : ((await fetch(target.toString(), {
            method: options.method || 'GET',
            headers: options.headers,
            body: options.body,
            redirect: 'manual',
            signal: controller.signal,
          })) as unknown as FetchLikeResponse);
    } catch (e) {
      throw fail(`Request to ${target.hostname} failed`, e);
    }

    if (res.status >= 300 && res.status < 400) {
      controller.abort();
      throw new EgressError(
        'redirect',
        `Request to ${target.hostname} answered with a redirect (${res.status}), which is not followed.`,
        { status: res.status }
      );
    }

    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      controller.abort();
      throw new EgressError(
        'too_large',
        `Response from ${target.hostname} declares ${declared} bytes; limit is ${maxBytes}.`,
        { status: res.status }
      );
    }

    const chunks: Buffer[] = [];
    let received = 0;
    if (res.body) {
      const reader = res.body.getReader();
      for (;;) {
        let step: ReadableStreamReadResult<Uint8Array>;
        try {
          step = await reader.read();
        } catch (e) {
          throw fail(`Reading the response from ${target.hostname} failed`, e);
        }
        if (step.done) break;
        const chunk = step.value;
        received += chunk.byteLength;
        if (received > maxBytes) {
          try {
            await reader.cancel();
          } catch (e) {
            // the abort below is what matters
          }
          controller.abort();
          throw new EgressError('too_large', `Response from ${target.hostname} exceeded ${maxBytes} bytes.`, {
            status: res.status,
          });
        }
        chunks.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
      }
    }

    return {
      status: res.status,
      headers: plainHeaders(res.headers),
      bodyText: Buffer.concat(chunks).toString('utf8'),
      truncated: false,
    };
  } finally {
    clearTimeout(timer);
  }
}
