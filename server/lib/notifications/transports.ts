import { createHmac, randomUUID } from 'crypto';
import {
  META_INDEX,
  NOTIFICATIONS_OUTBOX_INDEX,
  NOTIFICATION_FORBIDDEN_HINT,
  NOTIFICATION_WEBHOOK_CONTENT_TYPE,
  NOTIFICATION_WEBHOOK_MAX_RESPONSE_BYTES,
  NOTIFICATION_WEBHOOK_TIMEOUT_MS,
} from '../../../common/constants';
import type { NotificationChannel } from '../../../common/types';
import { BoundedFetchOptions, BoundedFetchResult, boundedFetch, isEgressError } from '../egress/http';
import { mustacheEscape } from './render';

/**
 * The two delivery transports (step 1.1; shared with the dispatcher of 1.2).
 *
 * - `sendWebhook`: direct POST from the dashboard server through
 *   `boundedFetch` (egress policy, 10-s deadline, 64 KiB response cap, no
 *   redirects). The body is the JSON payload; the request carries
 *   `x-wam-event`, `x-wam-delivery` (uuid), `x-wam-timestamp` (ISO) and, when
 *   the channel has a secret, `x-wam-signature: sha256=<hex HMAC-SHA256 of
 *   "<timestamp>.<body>">`. A 2xx answer is a success.
 * - `sendIndexerChannel`: on-demand delivery through a Notifications channel.
 *   The indexer has no "send" REST API, so an inline, never-persisted
 *   query-level monitor (`enabled: false`) is executed with
 *   `POST /_plugins/_alerting/monitors/_execute?dryrun=false`; its one action
 *   targets the channel with the rendered subject and message. The delivery
 *   status comes back inline in `trigger_results`.
 */

export interface DeliveryResult {
  ok: boolean;
  /** Receiver HTTP status (webhook) or the channel's delivery status code (indexer channel); null when none was reported. */
  statusCode: number | null;
  error: string | null;
  /** `x-wam-delivery` of a webhook send; the monitor name suffix of an indexer send. */
  deliveryId: string;
  durationMs: number;
}

export type FetchLike = (url: string | URL, options?: BoundedFetchOptions) => Promise<BoundedFetchResult>;

export interface SendWebhookOptions {
  fetch?: FetchLike;
  now?: Date;
  deliveryId?: string;
}

export const WEBHOOK_SIGNATURE_PREFIX = 'sha256=';

/** `sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`, the value receivers recompute to verify a delivery. */
export function signWebhookBody(secret: string, timestamp: string, body: string): string {
  return `${WEBHOOK_SIGNATURE_PREFIX}${createHmac('sha256', secret).update(`${timestamp}.${body}`, 'utf8').digest('hex')}`;
}

/** Request headers of a webhook delivery: operator headers first, the plugin's own on top (never overridable). */
export function webhookHeaders(
  channel: Pick<NotificationChannel, 'webhook'>,
  input: { event: string; deliveryId: string; timestamp: string; signature: string | null }
): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(channel.webhook?.headers || {})) headers[name.toLowerCase()] = value;
  headers['content-type'] = NOTIFICATION_WEBHOOK_CONTENT_TYPE;
  headers['x-wam-event'] = input.event;
  headers['x-wam-delivery'] = input.deliveryId;
  headers['x-wam-timestamp'] = input.timestamp;
  if (input.signature) headers['x-wam-signature'] = input.signature;
  else delete headers['x-wam-signature'];
  return headers;
}

/**
 * POST `payload` to a direct webhook channel. `client` is accepted for
 * symmetry with `sendIndexerChannel` (the dispatcher calls both the same way)
 * and is not used. Never throws for a delivery failure: the result says why.
 */
export async function sendWebhook(
  _client: any,
  channel: NotificationChannel,
  secret: string,
  payload: Record<string, any>,
  options: SendWebhookOptions = {}
): Promise<DeliveryResult> {
  const started = Date.now();
  const deliveryId = options.deliveryId || randomUUID();
  const fail = (error: string, statusCode: number | null = null): DeliveryResult => ({
    ok: false,
    statusCode,
    error,
    deliveryId,
    durationMs: Date.now() - started,
  });
  if (channel.kind !== 'webhook' || !channel.webhook?.url) return fail('Channel is not a webhook channel.');
  const timestamp = (options.now || new Date()).toISOString();
  const body = JSON.stringify(payload);
  const event = typeof payload?.event === 'string' ? payload.event : 'notification';
  const signature = secret ? signWebhookBody(secret, timestamp, body) : null;
  const headers = webhookHeaders(channel, { event, deliveryId, timestamp, signature });
  const fetchImpl = options.fetch || boundedFetch;
  try {
    const res = await fetchImpl(channel.webhook.url, {
      method: 'POST',
      headers,
      body,
      timeoutMs: NOTIFICATION_WEBHOOK_TIMEOUT_MS,
      maxResponseBytes: NOTIFICATION_WEBHOOK_MAX_RESPONSE_BYTES,
      purpose: `Webhook "${channel.name}" URL`,
      allowInsecure: channel.webhook.allowInsecure === true,
    });
    const ok = res.status >= 200 && res.status < 300;
    return {
      ok,
      statusCode: res.status,
      error: ok ? null : `Receiver answered HTTP ${res.status}${res.bodyText ? `: ${res.bodyText.slice(0, 200)}` : ''}`,
      deliveryId,
      durationMs: Date.now() - started,
    };
  } catch (e: any) {
    if (isEgressError(e)) return fail(e.message, typeof e.status === 'number' ? e.status : null);
    return fail(e?.message || String(e));
  }
}

export const ALERTING_EXECUTE_PATH = '/_plugins/_alerting/monitors/_execute';

export interface IndexerMessage {
  subject: string;
  message: string;
}

export interface SendIndexerChannelOptions {
  /** Index the monitor's (size 0, match_all) search input reads; default: the outbox when it exists, else META_INDEX. */
  inputIndex?: string;
  deliveryId?: string;
  /** Resolves the search input index when `inputIndex` is not given (tests inject a fake). */
  indexExists?: (client: any, index: string) => Promise<boolean>;
}

async function defaultIndexExists(client: any, index: string): Promise<boolean> {
  try {
    const res = await client.indices.exists({ index });
    const body = res?.body ?? res;
    return body === true || body?.statusCode === 200;
  } catch (e) {
    return false;
  }
}

/** The search input index of the inline monitor: the outbox once step 1.2 created it, else the meta index (nothing is created here). */
export async function resolveMonitorInputIndex(client: any, indexExists: (client: any, index: string) => Promise<boolean> = defaultIndexExists): Promise<string> {
  return (await indexExists(client, NOTIFICATIONS_OUTBOX_INDEX)) ? NOTIFICATIONS_OUTBOX_INDEX : META_INDEX;
}

/** The inline (never persisted) query-level monitor whose single action delivers `message` through `configId`. */
export function buildInlineMonitor(configId: string, message: IndexerMessage, options: { inputIndex: string; deliveryId: string }) {
  const name = `wam-notification-${options.deliveryId}`;
  return {
    type: 'monitor',
    monitor_type: 'query_level_monitor',
    name,
    enabled: false,
    schedule: { period: { interval: 1000, unit: 'DAYS' } },
    inputs: [
      {
        search: {
          indices: [options.inputIndex],
          query: { size: 0, query: { match_all: {} } },
        },
      },
    ],
    triggers: [
      {
        query_level_trigger: {
          name: 'wam-notify',
          severity: '1',
          condition: { script: { source: 'return true', lang: 'painless' } },
          actions: [
            {
              name,
              destination_id: configId,
              subject_template: { source: mustacheEscape(message.subject), lang: 'mustache' },
              message_template: { source: mustacheEscape(message.message), lang: 'mustache' },
              throttle_enabled: false,
            },
          ],
        },
      },
    ],
  };
}

function toStatusCode(value: unknown): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() !== '' ? Number(value) : NaN;
  return Number.isFinite(n) ? Math.floor(n) : null;
}

function deliveryStatusesOf(actionResult: any): Array<{ statusCode: number | null; statusText: string | null }> {
  const found: Array<{ statusCode: number | null; statusText: string | null }> = [];
  const push = (status: any) => {
    if (!status || typeof status !== 'object') return;
    found.push({ statusCode: toStatusCode(status.status_code), statusText: typeof status.status_text === 'string' ? status.status_text : null });
  };
  push(actionResult?.delivery_status);
  // Alerting 2.x stores the Notifications event (a JSON string) as `output.messageId`:
  // `{"event_source":...,"status_list":[{"config_id":..,"delivery_status":{"status_code":"200","status_text":".."}}]}`.
  let messageId = actionResult?.output?.messageId;
  if (typeof messageId === 'string' && messageId.trim().startsWith('{')) {
    try {
      messageId = JSON.parse(messageId);
    } catch (e) {
      messageId = null;
    }
  }
  if (messageId && typeof messageId === 'object') {
    const statusList = Array.isArray(messageId.status_list) ? messageId.status_list : [];
    for (const entry of statusList) push(entry?.delivery_status);
    push(messageId.delivery_status);
  }
  return found;
}

/**
 * Interpret an `_execute` response: an action error, a non-2xx
 * `delivery_status.status_code` or a top-level error is a failure; an action
 * that reports no status and no error counts as delivered (email / SNS report
 * text only).
 */
export function parseExecuteResponse(body: any): { ok: boolean; statusCode: number | null; error: string | null } {
  if (!body || typeof body !== 'object') return { ok: false, statusCode: null, error: 'Empty response from the Alerting plugin.' };
  if (body.error) {
    const error = typeof body.error === 'string' ? body.error : body.error?.reason || JSON.stringify(body.error).slice(0, 300);
    return { ok: false, statusCode: toStatusCode(body.status), error };
  }
  // A failed search input (no read on the input index for the acting user,
  // index missing) leaves the trigger results empty or action-less; name it.
  const inputError = body.input_results && typeof body.input_results === 'object' ? body.input_results.error : null;
  if (inputError) {
    const error = typeof inputError === 'string' ? inputError : inputError?.reason || JSON.stringify(inputError);
    return { ok: false, statusCode: null, error: String(error).slice(0, 300) };
  }
  const triggers = body.trigger_results && typeof body.trigger_results === 'object' ? Object.values<any>(body.trigger_results) : [];
  if (triggers.length === 0) return { ok: false, statusCode: null, error: 'The Alerting plugin reported no trigger results.' };
  let actions = 0;
  let statusCode: number | null = null;
  for (const trigger of triggers) {
    if (trigger?.error) return { ok: false, statusCode: null, error: String(trigger.error).slice(0, 300) };
    const results = trigger?.action_results && typeof trigger.action_results === 'object' ? Object.values<any>(trigger.action_results) : [];
    for (const action of results) {
      actions += 1;
      if (!action || typeof action !== 'object') return { ok: false, statusCode: null, error: 'The Alerting plugin reported an empty action result.' };
      if (action?.error) return { ok: false, statusCode: null, error: String(action.error).slice(0, 300) };
      if (action?.throttled === true) return { ok: false, statusCode: null, error: 'The action was throttled.' };
      for (const status of deliveryStatusesOf(action)) {
        if (status.statusCode !== null) statusCode = status.statusCode;
        if (status.statusCode !== null && (status.statusCode < 200 || status.statusCode >= 300)) {
          return { ok: false, statusCode: status.statusCode, error: status.statusText || `Channel delivery answered ${status.statusCode}.` };
        }
      }
    }
  }
  if (actions === 0) return { ok: false, statusCode: null, error: 'The trigger ran but no action was executed.' };
  return { ok: true, statusCode, error: null };
}

/**
 * Deliver `message` through the Notifications channel `configId` as `client`
 * (the current user for a test send, `asInternalUser` for the dispatcher).
 * Never throws for a delivery failure: a 403 (missing `alerting_full_access`
 * / `monitor/execute`) or a plugin error is returned as the result's error.
 */
export async function sendIndexerChannel(
  client: any,
  configId: string,
  message: IndexerMessage,
  options: SendIndexerChannelOptions = {}
): Promise<DeliveryResult> {
  const started = Date.now();
  const deliveryId = options.deliveryId || randomUUID();
  const finish = (parsed: { ok: boolean; statusCode: number | null; error: string | null }): DeliveryResult => ({
    ...parsed,
    deliveryId,
    durationMs: Date.now() - started,
  });
  if (!configId) return finish({ ok: false, statusCode: null, error: 'No Notifications channel id.' });
  try {
    const inputIndex = options.inputIndex || (await resolveMonitorInputIndex(client, options.indexExists));
    const res = await client.transport.request({
      method: 'POST',
      path: ALERTING_EXECUTE_PATH,
      querystring: { dryrun: false },
      body: buildInlineMonitor(configId, message, { inputIndex, deliveryId }),
    });
    return finish(parseExecuteResponse(res?.body ?? res));
  } catch (e: any) {
    const status = e?.meta?.statusCode ?? e?.statusCode;
    const reason = e?.meta?.body?.error?.reason || e?.meta?.body?.message || e?.message || String(e);
    const hint =
      status === 403
        ? ` The acting user needs the alerting monitor/execute permission (hint: ${NOTIFICATION_FORBIDDEN_HINT}).`
        : status === 404
        ? ' The Alerting plugin is not available on this indexer.'
        : '';
    return finish({ ok: false, statusCode: typeof status === 'number' ? status : null, error: `${String(reason).slice(0, 300)}${hint}` });
  }
}
