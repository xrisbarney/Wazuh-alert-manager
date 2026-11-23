import * as http from 'http';
import { AddressInfo } from 'net';
import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Local webhook receiver for the notifications bench (PLAN.md 1.5).
 *
 * Records every request (headers, raw body, path, time) so a spec can assert
 * what the dashboard (direct `webhook` channel) or the indexer (Notifications
 * `webhook` channel bound as `indexer_channel`) delivered. It listens on
 * `0.0.0.0` because both containers reach this machine through
 * `host.docker.internal` (`scripts/dev/e2e-deploy.sh` puts that name on
 * `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`; the indexer's Notifications
 * `host_deny_list` is empty on the dev stack). Override the hostname with
 * `WAM_E2E_STUB_HOST` (keep a local suffix: `.internal`, `.local`,
 * `.home.arpa`) and the port with `WAM_E2E_WEBHOOK_PORT` (default 18087).
 */

export interface ReceivedRequest {
  method: string;
  /** URL path without the query string (`/direct`, `/indexer`, ...). */
  path: string;
  headers: http.IncomingHttpHeaders;
  /** Raw request body, exactly as received (the HMAC input). */
  body: string;
  /** Parsed JSON body, or null when the body is not JSON. */
  json: any;
  at: string;
}

export interface WebhookReceiver {
  port: number;
  /** Base URL as seen from the Docker containers. */
  containerBaseUrl: string;
  requests: ReceivedRequest[];
  /** Requests whose path equals `path`. */
  byPath(path: string): ReceivedRequest[];
  /** Resolve once `predicate` matches a recorded request (or reject on timeout). */
  waitFor(predicate: (request: ReceivedRequest) => boolean, timeoutMs?: number, label?: string): Promise<ReceivedRequest>;
  close(): Promise<void>;
}

/** Hostname the containers use to reach this machine. */
export const RECEIVER_CONTAINER_HOST = process.env.WAM_E2E_STUB_HOST || 'host.docker.internal';
export const RECEIVER_DEFAULT_PORT = Number(process.env.WAM_E2E_WEBHOOK_PORT || 18087);

/** `sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`, the signature scheme of `server/lib/notifications/transports.ts`. */
export function expectedSignature(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`, 'utf8').digest('hex')}`;
}

/** True when the request's `x-wam-signature` verifies against `secret` (constant-time compare). */
export function verifySignature(request: ReceivedRequest, secret: string): boolean {
  const signature = String(request.headers['x-wam-signature'] || '');
  const timestamp = String(request.headers['x-wam-timestamp'] || '');
  if (!signature || !timestamp) return false;
  const expected = expectedSignature(secret, timestamp, request.body);
  const a = Buffer.from(signature, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function startWebhookReceiver(options: { port?: number; host?: string } = {}): Promise<WebhookReceiver> {
  const requests: ReceivedRequest[] = [];
  const waiters: Array<{ predicate: (request: ReceivedRequest) => boolean; resolve: (request: ReceivedRequest) => void }> = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      let json: any = null;
      try {
        json = body ? JSON.parse(body) : null;
      } catch (e) {
        json = null;
      }
      const url = new URL(req.url || '/', 'http://receiver');
      const record: ReceivedRequest = { method: req.method || 'GET', path: url.pathname, headers: req.headers, body, json, at: new Date().toISOString() };
      requests.push(record);
      for (const waiter of waiters.splice(0)) {
        if (waiter.predicate(record)) waiter.resolve(record);
        else waiters.push(waiter);
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, received: requests.length }));
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? RECEIVER_DEFAULT_PORT, options.host ?? '0.0.0.0', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    containerBaseUrl: `http://${RECEIVER_CONTAINER_HOST}:${port}`,
    requests,
    byPath: (path) => requests.filter((request) => request.path === path),
    waitFor(predicate, timeoutMs = 60_000, label = 'webhook request') {
      const existing = requests.find(predicate);
      if (existing) return Promise.resolve(existing);
      return new Promise<ReceivedRequest>((resolve, reject) => {
        const timer = setTimeout(() => {
          const index = waiters.findIndex((waiter) => waiter.resolve === done);
          if (index >= 0) waiters.splice(index, 1);
          reject(new Error(`${label} not received within ${timeoutMs} ms (${requests.length} request(s) seen: ${requests.map((r) => r.path).join(', ') || 'none'})`));
        }, timeoutMs);
        const done = (request: ReceivedRequest) => {
          clearTimeout(timer);
          resolve(request);
        };
        waiters.push({ predicate, resolve: done });
      });
    },
    close() {
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
