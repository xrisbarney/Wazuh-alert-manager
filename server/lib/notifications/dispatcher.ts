import { Logger } from '../../../../../src/core/server';
import {
  META_INDEX,
  NOTIFICATIONS_INDEX,
  NOTIFICATION_DISPATCHER_LEASE_ID,
  NOTIFICATION_DISPATCHER_LEASE_RENEW_EVERY,
  NOTIFICATION_DISPATCHER_STATUS_DOC_ID,
  NOTIFICATION_DISPATCHER_STATUS_IDLE_WRITE_MS,
  NOTIFICATION_DISPATCHER_STATUS_MAX_ERRORS,
  NOTIFICATION_MISSING_KEY_RETRY_MS,
  NOTIFICATION_OUTBOX_PAGE,
} from '../../../common/constants';
import type { NotificationChannel, NotificationDelivery, NotificationDispatcherStatus, NotificationSettings } from '../../../common/types';
import type { AlertManagerConfigType } from '../../config';
import { assertManagedWriteTarget } from '../index_namespace';
import { acquireOrRenewLease, holderId, releaseLease } from '../lease';
import { ClaimedNotification, claimDue, markFailed, markSent, releaseClaim } from './outbox';
import { NotificationPayload, renderText } from './render';
import { findChannel, getNotificationChannels, resolveWebhookSecret } from './settings';
import { DeliveryResult, sendIndexerChannel, sendWebhook } from './transports';

/**
 * Outbox dispatcher (step 1.2). One replica (the `notification_dispatcher`
 * lease holder) ticks every `notifications.dispatcher.tickSeconds` (default
 * 5 s) as the dashboard service user (`asInternalUser`): it claims up to 50
 * due entries, resolves each entry's channel from the cached settings and
 * delivers through `sendWebhook` (direct, HMAC-signed) or
 * `sendIndexerChannel` (inline Alerting `_execute` targeting a Notifications
 * channel), then records the outcome (`markSent` / `markFailed`: backoff,
 * dead-letter after NOTIFICATION_MAX_ATTEMPTS, 403 verbatim with the role
 * hint). Nothing thrown by one entry stops the others; the tick's summary
 * and its last ten errors go to the meta doc `notification_dispatcher_status`.
 * The lease is renewed every NOTIFICATION_DISPATCHER_LEASE_RENEW_EVERY
 * entries (and whenever a third of the TTL has elapsed): a batch of slow
 * receivers can outlast the TTL, and once another replica holds the lease
 * this one releases its remaining claims back to `pending` and does not touch
 * the status doc.
 */

export const NOTIFICATION_DISPATCHER_STATUS_DOCUMENT_TYPE = 'notification_dispatcher_status';

// ---------------------------------------------------------------------------
// Runtime (what GET /notifications/status reports for this replica)
// ---------------------------------------------------------------------------

interface Runtime {
  enabled: boolean | null;
  tickSeconds: number;
}

let runtime: Runtime = { enabled: null, tickSeconds: 5 };

export function setNotificationDispatcherRuntime(config: Pick<AlertManagerConfigType, 'notifications'> | null | undefined): void {
  const dispatcher = config?.notifications?.dispatcher;
  runtime = {
    enabled: dispatcher ? dispatcher.enabled !== false : null,
    tickSeconds: typeof dispatcher?.tickSeconds === 'number' ? dispatcher.tickSeconds : 5,
  };
}

export function getNotificationDispatcherRuntime(): Runtime {
  return { ...runtime };
}

/** Lease TTL for a tick length: three ticks, at least 30 s. */
export function notificationDispatcherLeaseTtlMs(tickSeconds: number): number {
  return Math.max(tickSeconds * 3, 30) * 1000;
}

function errorMessage(e: any): string {
  return e?.message || String(e);
}

function isNotFound(e: any): boolean {
  return (e?.meta?.statusCode || e?.statusCode) === 404;
}

// ---------------------------------------------------------------------------
// One entry
// ---------------------------------------------------------------------------

export type DispatchOutcome = 'sent' | 'failed' | 'dead' | 'lost';

/** Test seams: the two transports and the secret resolver. */
export interface DispatchDeps {
  sendWebhook?: typeof sendWebhook;
  sendIndexerChannel?: typeof sendIndexerChannel;
  resolveWebhookSecret?: typeof resolveWebhookSecret;
  now?: Date;
}

export interface DispatchResult {
  outcome: DispatchOutcome;
  error: string | null;
}

function deliveryOf(channel: NotificationChannel, result: DeliveryResult): NotificationDelivery {
  return { transport: channel.kind, deliveryId: result.deliveryId || null, statusCode: result.statusCode ?? null, durationMs: result.durationMs ?? null };
}

/**
 * Deliver one claimed entry and record the outcome. A channel that no longer
 * exists or is disabled dead-letters the entry (the administrator can retry
 * it after repairing the channel). A webhook secret that cannot be resolved
 * (no encryption key or undecryptable: the typed 409) is a failure retried in
 * one hour, not on the backoff table, so a missing key never produces a retry
 * storm. Any other error from the secret lookup (a meta-index read failure)
 * is rethrown: the claim stays `sending` for the stale reclaim and no
 * attempt is consumed.
 */
export async function dispatchOne(client: any, claimed: ClaimedNotification, settings: NotificationSettings, deps: DispatchDeps = {}): Promise<DispatchResult> {
  const now = deps.now;
  const doc = claimed.source;
  const channel = findChannel(settings, doc.channel_id);
  if (!channel) {
    const marked = await markFailed(client, claimed, `Channel "${doc.channel_id}" no longer exists in the notification settings.`, { dead: true, now });
    return { outcome: marked.applied ? 'dead' : 'lost', error: marked.last_error };
  }
  if (!channel.enabled) {
    const reason = channel.invalid
      ? `Channel "${doc.channel_id}" is blocked by the egress policy: ${channel.invalid}`
      : `Channel "${doc.channel_id}" is disabled.`;
    const marked = await markFailed(client, claimed, reason, { dead: true, now });
    return { outcome: marked.applied ? 'dead' : 'lost', error: marked.last_error };
  }
  const payload = (doc.payload || {}) as NotificationPayload;
  let result: DeliveryResult;
  if (channel.kind === 'webhook') {
    let secret: string;
    try {
      secret = await (deps.resolveWebhookSecret || resolveWebhookSecret)(client, channel);
    } catch (e: any) {
      if (e?.statusCode !== 409) throw e;
      const marked = await markFailed(client, claimed, errorMessage(e), { statusCode: null, retryAfterMs: NOTIFICATION_MISSING_KEY_RETRY_MS, now });
      return { outcome: marked.applied ? marked.status === 'dead' ? 'dead' : 'failed' : 'lost', error: marked.last_error };
    }
    result = await (deps.sendWebhook || sendWebhook)(client, channel, secret, payload, { now });
  } else {
    result = await (deps.sendIndexerChannel || sendIndexerChannel)(
      client,
      channel.indexer_channel?.configId || '',
      { subject: doc.subject, message: renderText(doc.event, payload) },
      { inputIndex: NOTIFICATIONS_INDEX }
    );
  }
  const delivery = deliveryOf(channel, result);
  if (result.ok) {
    const applied = await markSent(client, claimed, delivery, { now });
    return { outcome: applied ? 'sent' : 'lost', error: null };
  }
  const marked = await markFailed(client, claimed, result.error || 'Delivery failed.', { statusCode: result.statusCode, delivery, now });
  return { outcome: marked.applied ? marked.status === 'dead' ? 'dead' : 'failed' : 'lost', error: marked.last_error };
}

// ---------------------------------------------------------------------------
// Status doc
// ---------------------------------------------------------------------------

function statusFromSource(source: any): NotificationDispatcherStatus | null {
  if (!source || source.document_type !== NOTIFICATION_DISPATCHER_STATUS_DOCUMENT_TYPE) return null;
  const count = (value: unknown) => (typeof value === 'number' && Number.isFinite(value) ? value : 0);
  const errors = Array.isArray(source.errors)
    ? source.errors
        .filter((entry: any) => entry && typeof entry.message === 'string')
        .map((entry: any) => ({ at: String(entry.at ?? ''), message: String(entry.message) }))
    : [];
  return {
    last_tick_at: String(source.last_tick_at ?? ''),
    holder: String(source.holder ?? ''),
    claimed: count(source.claimed),
    sent: count(source.sent),
    failed: count(source.failed),
    dead: count(source.dead),
    errors,
  };
}

export async function readNotificationDispatcherStatus(client: any): Promise<NotificationDispatcherStatus | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: NOTIFICATION_DISPATCHER_STATUS_DOC_ID });
    return statusFromSource(res?.body?._source);
  } catch (e: any) {
    if (isNotFound(e)) return null;
    throw e;
  }
}

async function writeStatus(client: any, status: NotificationDispatcherStatus): Promise<void> {
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: NOTIFICATION_DISPATCHER_STATUS_DOC_ID,
    body: { document_type: NOTIFICATION_DISPATCHER_STATUS_DOCUMENT_TYPE, ...status },
  });
}

/**
 * An idle tick (nothing claimed, no errors) by the same holder rewrites the
 * status doc only when the stored one is older than
 * NOTIFICATION_DISPATCHER_STATUS_IDLE_WRITE_MS: at the default 5-s tick the
 * meta index would otherwise take a read + index every tick for a
 * `last_tick_at` change alone.
 */
export function isIdleStatusWriteSkippable(
  previous: NotificationDispatcherStatus | null,
  result: Pick<DispatcherTickResult, 'claimed' | 'errors'>,
  holder: string,
  now: Date
): boolean {
  if (!previous || result.claimed !== 0 || result.errors.length !== 0 || previous.holder !== holder) return false;
  const last = new Date(previous.last_tick_at).getTime();
  return Number.isFinite(last) && now.getTime() - last < NOTIFICATION_DISPATCHER_STATUS_IDLE_WRITE_MS;
}

/** Give the undelivered claims back to `pending`; a claim already reclaimed by another replica (409) is left to it. */
async function releaseClaims(client: any, claims: ClaimedNotification[], now: Date | undefined, logger?: Logger): Promise<number> {
  let released = 0;
  for (const claim of claims) {
    try {
      if (await releaseClaim(client, claim, { now })) released += 1;
    } catch (e: any) {
      // The claim stays `sending` and is reclaimed after NOTIFICATION_CLAIM_STALE_MS.
      logger?.warn(`wazuh-alert-manager notifications: could not release claim ${claim.id}: ${errorMessage(e)}`);
    }
  }
  return released;
}

// ---------------------------------------------------------------------------
// Tick + loop
// ---------------------------------------------------------------------------

export interface DispatcherTickOptions {
  holder: string;
  ttlMs: number;
  now?: Date;
  logger?: Logger;
  /** Test seam: replaces `getNotificationChannels`. */
  settings?: NotificationSettings;
  deps?: DispatchDeps;
  limit?: number;
}

export interface DispatcherTickResult {
  acquired: boolean;
  claimed: number;
  sent: number;
  failed: number;
  dead: number;
  /** Claims lost to another replica after a stale reclaim (nothing written). */
  lost: number;
  /** True when the lease renewal failed mid-batch: the remaining claims were released and the status doc left alone. */
  leaseLost: boolean;
  /** Claims given back to `pending` after the lease was lost. */
  released: number;
  errors: string[];
}

/**
 * One dispatcher pass: lease, settings, claim, deliver each (renewing the
 * lease as it goes), status doc. Never throws: an unexpected error is logged,
 * recorded in the status doc and ends the tick early. When notifications are
 * globally disabled nothing is claimed (entries stay pending until an
 * administrator enables them). A replica that loses the lease mid-batch
 * releases the claims it has not delivered yet and skips the status write.
 */
export async function tickNotificationDispatcher(client: any, options: DispatcherTickOptions): Promise<DispatcherTickResult> {
  const { holder, ttlMs, logger } = options;
  const nowDate = options.now || new Date();
  const now = nowDate.toISOString();
  const result: DispatcherTickResult = { acquired: false, claimed: 0, sent: 0, failed: 0, dead: 0, lost: 0, leaseLost: false, released: 0, errors: [] };
  // The clock for lease renewals: the injected `now` in tests, wall clock otherwise.
  const leaseNow = () => (options.now ? nowDate.getTime() : Date.now());
  const renewLease = async () =>
    (await acquireOrRenewLease(client, { leaseId: NOTIFICATION_DISPATCHER_LEASE_ID, holder, ttlMs, now: leaseNow(), logger })).acquired;
  try {
    if (!(await renewLease())) return result;
  } catch (e: any) {
    logger?.error(`wazuh-alert-manager notifications: lease error: ${errorMessage(e)}`);
    return result;
  }
  result.acquired = true;

  try {
    const settings = options.settings || (await getNotificationChannels(client, logger));
    if (settings.enabled) {
      const claimed = await claimDue(client, { now: options.now, limit: options.limit ?? NOTIFICATION_OUTBOX_PAGE, holder });
      result.claimed = claimed.length;
      let sinceRenewal = 0;
      let renewedAt = Date.now();
      for (let i = 0; i < claimed.length; i += 1) {
        const entry = claimed[i];
        // Slow receivers (10 s webhook timeout, 30 s inline `_execute`) can
        // outlast the TTL within one batch: renew before the lease lapses.
        if (sinceRenewal >= NOTIFICATION_DISPATCHER_LEASE_RENEW_EVERY || Date.now() - renewedAt >= ttlMs / 3) {
          let held = false;
          try {
            held = await renewLease();
          } catch (e: any) {
            logger?.error(`wazuh-alert-manager notifications: lease renewal error: ${errorMessage(e)}`);
          }
          if (!held) {
            result.leaseLost = true;
            result.released = await releaseClaims(client, claimed.slice(i), options.now, logger);
            const message = `batch stopped after ${i} of ${claimed.length}: lease lost to another replica (${result.released} claims released)`;
            result.errors.push(message);
            logger?.warn(`wazuh-alert-manager notifications: ${message}`);
            break;
          }
          sinceRenewal = 0;
          renewedAt = Date.now();
        }
        sinceRenewal += 1;
        try {
          const outcome = await dispatchOne(client, entry, settings, { ...(options.deps || {}), now: options.deps?.now ?? options.now });
          if (outcome.outcome === 'sent') result.sent += 1;
          else if (outcome.outcome === 'failed') result.failed += 1;
          else if (outcome.outcome === 'dead') result.dead += 1;
          else result.lost += 1;
          if (outcome.error) result.errors.push(`${entry.id} (${entry.source.event} -> ${entry.source.channel_id}): ${outcome.error}`);
        } catch (e: any) {
          // A storage failure while recording the outcome: the claim stays
          // `sending` and is reclaimed after NOTIFICATION_CLAIM_STALE_MS.
          const message = `${entry.id} (${entry.source.event} -> ${entry.source.channel_id}): unexpected error: ${errorMessage(e)}`;
          result.errors.push(message);
          logger?.error(`wazuh-alert-manager notifications: ${message}`);
        }
      }
    }
  } catch (e: any) {
    const message = `tick failed: ${errorMessage(e)}`;
    result.errors.push(message);
    logger?.error(`wazuh-alert-manager notifications: ${message}`);
  }

  // Only the holder writes the status doc; a replica that lost the lease
  // leaves the new holder's record alone.
  if (result.leaseLost) return result;

  try {
    let previous: NotificationDispatcherStatus | null = null;
    try {
      previous = await readNotificationDispatcherStatus(client);
    } catch (e: any) {
      logger?.debug(`wazuh-alert-manager notifications: previous status unreadable: ${errorMessage(e)}`);
    }
    if (isIdleStatusWriteSkippable(previous, result, holder, nowDate)) return result;
    const errors = [...(previous?.errors || []), ...result.errors.map((message) => ({ at: now, message: message.slice(0, 512) }))].slice(
      -NOTIFICATION_DISPATCHER_STATUS_MAX_ERRORS
    );
    await writeStatus(client, { last_tick_at: now, holder, claimed: result.claimed, sent: result.sent, failed: result.failed, dead: result.dead, errors });
  } catch (e: any) {
    logger?.warn(`wazuh-alert-manager notifications: status write failed: ${errorMessage(e)}`);
  }
  return result;
}

/**
 * Background loop next to the SLA scanner: one tick every
 * `notifications.dispatcher.tickSeconds`, overlapping ticks prevented, lease
 * released on stop. Returns the stop function.
 */
export function startNotificationDispatcher(client: any, config: AlertManagerConfigType, logger: Logger): () => void {
  setNotificationDispatcherRuntime(config);
  const tickSeconds = config.notifications?.dispatcher?.tickSeconds ?? 5;
  const ttlMs = notificationDispatcherLeaseTtlMs(tickSeconds);
  const holder = holderId();
  let stopped = false;
  let running = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const schedule = () => {
    if (!stopped) timer = setTimeout(tick, tickSeconds * 1000);
  };

  const tick = async () => {
    if (stopped || running) return;
    running = true;
    try {
      const result = await tickNotificationDispatcher(client, { holder, ttlMs, logger });
      if (result.claimed) {
        logger.info(
          `wazuh-alert-manager notifications: claimed ${result.claimed}, sent ${result.sent}, failed ${result.failed}, dead ${result.dead}${
            result.lost ? `, lost ${result.lost}` : ''
          }${result.released ? `, released ${result.released}` : ''}`
        );
      }
    } catch (e: any) {
      logger.error(`wazuh-alert-manager notifications: unexpected error: ${errorMessage(e)}`);
    } finally {
      running = false;
      schedule();
    }
  };

  schedule();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    releaseLease(client, { leaseId: NOTIFICATION_DISPATCHER_LEASE_ID, holder, logger }).catch(() => {});
  };
}
