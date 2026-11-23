import * as http from 'http';
import { AddressInfo } from 'net';

/**
 * Local stand-in for a generic HTTP enrichment source (step 6.6).
 *
 * Answers every GET with a fixed JSON verdict and records each request so a
 * spec can assert what the dashboard asked for. It listens on `0.0.0.0` on
 * purpose: the dashboard runs inside Docker and reaches this machine through
 * `host.docker.internal`, which `scripts/dev/e2e-deploy.sh` puts on
 * `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`. Only an allowlisted name with a
 * local suffix (`.internal`, `.local`, `.home.arpa`) may resolve to a private
 * address (every other allowlisted host must still resolve publicly), so a
 * `WAM_E2E_STUB_HOST` override must keep such a suffix; plain http is only
 * honoured for allowlisted hosts with the source's `allowInsecure` flag.
 */

export interface StubRequest {
  method: string;
  path: string;
  /** `?value=` / `?type=` query parameters as the dashboard rendered them. */
  query: Record<string, string>;
  headers: http.IncomingHttpHeaders;
}

export interface EnrichmentStubOptions {
  /** Body returned for every GET; default `{ verdict: 'malicious', score: 90, tags: ['test'] }`. */
  response?: unknown;
  /** Interface to bind; default `0.0.0.0` so the Docker stack can reach it. */
  host?: string;
  port?: number;
}

export interface EnrichmentStub {
  /** Port the stub listens on (random by default). */
  port: number;
  /** Base URL as seen from the Docker stack. */
  containerBaseUrl: string;
  /** `urlTemplate` for a `generic_http` source pointing at this stub. */
  urlTemplate: string;
  requests: StubRequest[];
  /** Resolve once at least `count` requests arrived (or reject on timeout). */
  waitForRequests(count: number, timeoutMs?: number): Promise<StubRequest[]>;
  close(): Promise<void>;
}

export const DEFAULT_STUB_RESPONSE = { verdict: 'malicious', score: 90, tags: ['test'] };

/** Hostname the dashboard container uses to reach this machine. */
export const STUB_CONTAINER_HOST = process.env.WAM_E2E_STUB_HOST || 'host.docker.internal';

export async function startEnrichmentStub(options: EnrichmentStubOptions = {}): Promise<EnrichmentStub> {
  const body = JSON.stringify(options.response ?? DEFAULT_STUB_RESPONSE);
  const requests: StubRequest[] = [];
  const waiters: Array<{ count: number; resolve: (list: StubRequest[]) => void }> = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://stub');
    const query: Record<string, string> = {};
    url.searchParams.forEach((value, key) => {
      query[key] = value;
    });
    requests.push({ method: req.method || 'GET', path: url.pathname, query, headers: req.headers });
    for (const waiter of waiters.splice(0)) {
      if (requests.length >= waiter.count) waiter.resolve(requests.slice());
      else waiters.push(waiter);
    }
    if (req.method !== 'GET') {
      res.writeHead(405, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'GET only' }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) });
    res.end(body);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, options.host ?? '0.0.0.0', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  const containerBaseUrl = `http://${STUB_CONTAINER_HOST}:${port}`;
  return {
    port,
    containerBaseUrl,
    urlTemplate: `${containerBaseUrl}/lookup?type={type}&value={value}`,
    requests,
    waitForRequests(count: number, timeoutMs = 30_000) {
      if (requests.length >= count) return Promise.resolve(requests.slice());
      return new Promise<StubRequest[]>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`enrichment stub saw ${requests.length}/${count} requests within ${timeoutMs} ms`)), timeoutMs);
        waiters.push({
          count,
          resolve: (list) => {
            clearTimeout(timer);
            resolve(list);
          },
        });
      });
    },
    close() {
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
