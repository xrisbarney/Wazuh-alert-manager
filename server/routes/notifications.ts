import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  NOTIFICATION_CHANNEL_KINDS,
  NOTIFICATION_CONFIG_ID_MAX_LENGTH,
  NOTIFICATION_EVENTS,
  NOTIFICATION_MAX_CHANNELS,
  NOTIFICATION_MAX_WEBHOOK_HEADERS,
  NOTIFICATION_SETTINGS_DOC_ID,
  NOTIFICATION_CHANNEL_NAME_MAX_LENGTH,
  NOTIFICATION_FORBIDDEN_HINT,
  NOTIFICATION_OUTBOX_LIST_MAX,
  NOTIFICATION_OUTBOX_PAGE,
  NOTIFICATION_RETRIED_ACTION,
  NOTIFICATION_STATUSES,
  TARGET_WAZUH_MAJOR,
} from '../../common';
import type {
  IndexerChannelsResponse,
  NotificationChannel,
  NotificationDispatcherStatus,
  NotificationOutboxEntry,
  NotificationOutboxListResponse,
  NotificationRetryResponse,
  NotificationSettingsResponse,
  NotificationStatusResponse,
  NotificationTestResponse,
} from '../../common';
import { NOTIFICATION_SETTINGS_UPDATED_ACTION, appendActivity } from '../lib/activity';
import { getNotificationDispatcherRuntime, readNotificationDispatcherStatus } from '../lib/notifications/dispatcher';
import { countOutboxByStatus, getOutboxEntry, listOutbox, retryOutboxEntry } from '../lib/notifications/outbox';
import { requirePluginAdmin } from '../lib/authorization';
import { readEgressAllowedHosts } from '../lib/egress/url_policy';
import { getEncryptionKey } from '../lib/secrets_config';
import { listIndexerChannels } from '../lib/notifications/channels';
import { projectCaseEvent, renderSubject, renderText } from '../lib/notifications/render';
import {
  LoadedNotificationSettings,
  findChannel,
  loadNotificationSettings,
  notificationSettingsAuditSummary,
  resolveWebhookSecret,
  saveNotificationSettings,
} from '../lib/notifications/settings';
import { sendIndexerChannel, sendWebhook } from '../lib/notifications/transports';

const eventSchema = schema.oneOf(NOTIFICATION_EVENTS.map((event) => schema.literal(event)) as any);
const outboxStatusSchema = schema.oneOf(NOTIFICATION_STATUSES.map((status) => schema.literal(status)) as any);

/** GET /notifications/outbox query (step 1.2). */
export const outboxQuerySchema = schema.object({
  status: schema.maybe(outboxStatusSchema),
  channelId: schema.maybe(schema.string({ minLength: 1, maxLength: 64 })),
  event: schema.maybe(eventSchema),
  cursor: schema.maybe(schema.string({ minLength: 1, maxLength: 512 })),
  limit: schema.number({ defaultValue: NOTIFICATION_OUTBOX_PAGE, min: 1, max: NOTIFICATION_OUTBOX_LIST_MAX }),
});

const outboxIdSchema = schema.object({ id: schema.string({ minLength: 1, maxLength: 512 }) });

/**
 * PUT body: the whole channel list. Shape only; `normaliseNotificationSettings`
 * (run inside the settings doc write) does the semantic checks (ids, kinds,
 * egress policy on URLs, reserved headers) and answers 400.
 */
const channelSchema = schema.object(
  {
    id: schema.string({ minLength: 1, maxLength: 64 }),
    name: schema.string({ minLength: 1, maxLength: NOTIFICATION_CHANNEL_NAME_MAX_LENGTH }),
    kind: schema.oneOf(NOTIFICATION_CHANNEL_KINDS.map((kind) => schema.literal(kind)) as any),
    enabled: schema.boolean({ defaultValue: false }),
    events: schema.arrayOf(eventSchema, { defaultValue: [], maxSize: NOTIFICATION_EVENTS.length }),
    indexer_channel: schema.maybe(schema.object({ configId: schema.string({ minLength: 1, maxLength: NOTIFICATION_CONFIG_ID_MAX_LENGTH }) })),
    webhook: schema.maybe(
      schema.object({
        url: schema.string({ minLength: 1, maxLength: 2048 }),
        /** New plaintext secret; '' or absent keeps the stored one, null clears it. */
        secret: schema.maybe(schema.nullable(schema.string({ maxLength: 1024 }))),
        /** Echoed read-only flag, accepted and ignored. */
        secretConfigured: schema.maybe(schema.boolean()),
        headers: schema.maybe(schema.recordOf(schema.string({ maxLength: 128 }), schema.string({ maxLength: 2048 }))),
        contentType: schema.maybe(schema.literal('application/json')),
        allowInsecure: schema.maybe(schema.boolean()),
      })
    ),
  },
  { unknowns: 'forbid' }
);

export const notificationSettingsBodySchema = schema.object({
  enabled: schema.boolean({ defaultValue: false }),
  channels: schema.arrayOf(channelSchema, { defaultValue: [], maxSize: NOTIFICATION_MAX_CHANNELS }),
});

function failure(response: any, e: any) {
  const statusCode = e?.statusCode || e?.meta?.statusCode || 500;
  if (statusCode === 400) return response.badRequest({ body: { message: e.message } });
  if (statusCode === 403) return response.forbidden({ body: { message: e.message } });
  if (statusCode === 404) return response.notFound({ body: { message: e.message } });
  return response.customError({ statusCode, body: { message: e.message } });
}

function settingsBody(loaded: LoadedNotificationSettings): NotificationSettingsResponse {
  return {
    enabled: loaded.enabled,
    channels: loaded.channels,
    encryptionConfigured: Boolean(getEncryptionKey()),
    egressAllowedHosts: readEgressAllowedHosts(),
    wazuhMajor: Number(TARGET_WAZUH_MAJOR),
    updated_at: loaded.updated_at,
    updated_by: loaded.updated_by,
  };
}

/**
 * The non-administrator view: which channels exist and what they receive,
 * without the receiver URL, the extra headers (the natural home of API-key
 * style tokens), the invalid reason (it names the host) or the server's
 * egress allowlist.
 */
export function redactedSettingsBody(loaded: LoadedNotificationSettings): NotificationSettingsResponse {
  return {
    enabled: loaded.enabled,
    channels: loaded.channels.map(({ id, name, kind, enabled, events }) => ({ id, name, kind, enabled, events })),
    encryptionConfigured: Boolean(getEncryptionKey()),
    wazuhMajor: Number(TARGET_WAZUH_MAJOR),
    redacted: true,
    updated_at: loaded.updated_at,
    updated_by: loaded.updated_by,
  };
}

/** What a non-administrator sees in place of a recorded delivery error. */
export const NOTIFICATION_REDACTED_ERROR = 'Delivery failed; an administrator can read the recorded error.';

/**
 * The non-administrator view of an outbox entry: no lease holder
 * (`claimed_by` is hostname + pid, like the status doc's `holder`) and the
 * recorded error reduced to its class. `last_error` is verbatim transport
 * text: the receiver hostname (egress policy, DNS and timeout messages), up
 * to 200 bytes of the receiver's response body, or the channel's `invalid`
 * reason, none of which the redacted settings answer either. What stays is
 * the HTTP status (already in `last_status_code`) and the role hint of a
 * 403, which names the plugin's role and nothing about the receiver.
 */
export function redactOutboxEntry(entry: NotificationOutboxEntry): NotificationOutboxEntry {
  const { claimed_by, claimed_at, payload, ...rest } = entry;
  if (!entry.last_error) return { ...rest, last_error: null };
  const code = typeof entry.last_status_code === 'number' ? ` (HTTP ${entry.last_status_code})` : '';
  const hint = entry.last_status_code === 403 && entry.last_error.includes(NOTIFICATION_FORBIDDEN_HINT) ? ` Hint: ${NOTIFICATION_FORBIDDEN_HINT}.` : '';
  return { ...rest, last_error: `${NOTIFICATION_REDACTED_ERROR.replace(';', `${code};`)}${hint}` };
}

/** The non-administrator view of the dispatcher status: no lease holder, and no error texts (built from the same transport strings). */
export function redactDispatcherStatus(status: NotificationDispatcherStatus): NotificationDispatcherStatus {
  const { holder, ...rest } = status;
  return { ...rest, errors: [] };
}

/** True for a plugin administrator; a 403 from the check is the ordinary non-admin answer, anything else propagates. */
async function callerIsAdmin(context: any, request: any): Promise<boolean> {
  try {
    await requirePluginAdmin(context, request);
    return true;
  } catch (e: any) {
    if (e?.statusCode === 403) return false;
    throw e;
  }
}

/** The fixed payload of a test send: no case, no alert, a note naming the channel. */
export function testPayload(channel: NotificationChannel, now: Date = new Date()) {
  return projectCaseEvent('test', null, { actor: 'settings:test', message: `Test notification for channel "${channel.name}" (${channel.id}).` }, { now });
}

/**
 * Send the fixed test payload through `channel` as `client` (the current user
 * in the route: an `indexer_channel` test therefore needs that user's
 * alerting `monitor/execute` grant, like the dispatcher needs it for the
 * dashboard service user).
 */
export async function runChannelTest(
  client: any,
  channel: NotificationChannel,
  deps: { sendWebhook?: typeof sendWebhook; sendIndexerChannel?: typeof sendIndexerChannel; now?: Date } = {}
): Promise<NotificationTestResponse> {
  const payload = testPayload(channel, deps.now);
  let result: { ok: boolean; statusCode: number | null; error: string | null; durationMs: number };
  if (channel.kind === 'webhook') {
    const secret = await resolveWebhookSecret(client, channel);
    result = await (deps.sendWebhook || sendWebhook)(client, channel, secret, payload, { now: deps.now });
  } else {
    result = await (deps.sendIndexerChannel || sendIndexerChannel)(client, channel.indexer_channel?.configId || '', {
      subject: renderSubject('test', payload),
      message: renderText('test', payload),
    });
  }
  return { channelId: channel.id, kind: channel.kind, ok: result.ok, statusCode: result.statusCode, error: result.error, durationMs: result.durationMs };
}

export function defineNotificationRoutes(router: IRouter) {
  defineNotificationOutboxRoutes(router);
  // Any signed-in user may read the bindings (which channels an event
  // reaches); only administrators get the channel configs (webhook URL,
  // headers, allowlist). Secrets never leave the server for anyone.
  router.get({ path: `${API_ROOT}/notifications/settings`, validate: false }, async (context, request, response) => {
    try {
      const admin = await callerIsAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const loaded = await loadNotificationSettings(client);
      return response.ok({ body: admin ? settingsBody(loaded) : redactedSettingsBody(loaded) });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.put(
    { path: `${API_ROOT}/notifications/settings`, validate: { body: notificationSettingsBodySchema } },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        let before: string = 'unreadable';
        try {
          before = notificationSettingsAuditSummary(await loadNotificationSettings(client));
        } catch (e) {
          // A document that no longer validates is repaired by this save; the audit says so.
        }
        const { enabled, channels } = request.body as any;
        const saved = await saveNotificationSettings(client, { enabled, channels }, { updatedBy: identity.name });
        await appendActivity(client, {
          targetType: 'system',
          targetId: NOTIFICATION_SETTINGS_DOC_ID,
          user: identity.name,
          action: NOTIFICATION_SETTINGS_UPDATED_ACTION,
          from: before,
          to: notificationSettingsAuditSummary(saved),
        });
        return response.ok({ body: settingsBody(saved) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  // The Notifications channel picker: listed as the current user so the
  // Security plugin decides; a 403 is a normal (empty) answer here.
  router.get({ path: `${API_ROOT}/notifications/channels`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const body: IndexerChannelsResponse = await listIndexerChannels(client, { wazuhMajor: Number(TARGET_WAZUH_MAJOR) });
      return response.ok({ body });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.post(
    {
      path: `${API_ROOT}/notifications/test/{channelId}`,
      validate: { params: schema.object({ channelId: schema.string({ minLength: 1, maxLength: 64 }) }) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { channelId } = request.params as any;
        const settings = await loadNotificationSettings(client);
        const channel = findChannel(settings, channelId);
        if (!channel) return response.notFound({ body: { message: `Notification channel "${channelId}" is not saved. Save the settings first.` } });
        return response.ok({ body: await runChannelTest(client, channel) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}

// ---------------------------------------------------------------------------
// Outbox (step 1.2)
// ---------------------------------------------------------------------------

export function defineNotificationOutboxRoutes(router: IRouter) {
  // Any signed-in user may see the queue (what was sent where, with what
  // outcome); the payload itself is only answered to administrators below,
  // and non-administrators get the entries without the lease holder and
  // with the recorded error reduced to its class (`redactOutboxEntry`).
  router.get({ path: `${API_ROOT}/notifications/outbox`, validate: { query: outboxQuerySchema } }, async (context, request, response) => {
    try {
      const admin = await callerIsAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const { status, channelId, event, cursor, limit } = request.query as any;
      const page = await listOutbox(client, { status, channelId, event, cursor, limit });
      const body: NotificationOutboxListResponse = admin ? page : { ...page, items: page.items.map(redactOutboxEntry) };
      return response.ok({ body });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.get({ path: `${API_ROOT}/notifications/outbox/{id}`, validate: { params: outboxIdSchema } }, async (context, request, response) => {
    try {
      await requirePluginAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const { id } = request.params as any;
      const entry = await getOutboxEntry(client, id);
      if (!entry) return response.notFound({ body: { message: `Outbox entry "${id}" was not found.` } });
      return response.ok({ body: entry });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  router.post({ path: `${API_ROOT}/notifications/outbox/{id}/retry`, validate: { params: outboxIdSchema } }, async (context, request, response) => {
    try {
      const identity = await requirePluginAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const { id } = request.params as any;
      const before = await getOutboxEntry(client, id);
      const entry = await retryOutboxEntry(client, id);
      await appendActivity(client, {
        targetType: 'system',
        targetId: entry.id,
        user: identity.name,
        action: NOTIFICATION_RETRIED_ACTION,
        from: before?.status ?? null,
        to: entry.status,
        details: { event: entry.event, channel_id: entry.channel_id, target_type: entry.target_type, target_id: entry.target_id, attempts: entry.attempts },
      });
      const body: NotificationRetryResponse = { id: entry.id, status: entry.status, next_attempt_at: entry.next_attempt_at, attempts: entry.attempts };
      return response.ok({ body });
    } catch (e: any) {
      return failure(response, e);
    }
  });

  // Dispatcher status (last tick of the lease holder, this replica's config)
  // plus the queue's counts by status. The lease holder (hostname + pid) and
  // the error texts are answered only to administrators, like the SLA
  // scanner's status.
  router.get({ path: `${API_ROOT}/notifications/status`, validate: false }, async (context, request, response) => {
    try {
      const admin = await callerIsAdmin(context, request);
      const client = context.core.opensearch.client.asCurrentUser;
      const runtime = getNotificationDispatcherRuntime();
      const stored = await readNotificationDispatcherStatus(client);
      const status = stored && !admin ? redactDispatcherStatus(stored) : stored;
      const body: NotificationStatusResponse = {
        enabled: runtime.enabled,
        tickSeconds: runtime.tickSeconds,
        status,
        counts: await countOutboxByStatus(client),
      };
      return response.ok({ body });
    } catch (e: any) {
      return failure(response, e);
    }
  });
}

// Re-exported for the route test (unused values keep the schema caps honest).
export const NOTIFICATION_ROUTE_LIMITS = { channels: NOTIFICATION_MAX_CHANNELS, headers: NOTIFICATION_MAX_WEBHOOK_HEADERS };
