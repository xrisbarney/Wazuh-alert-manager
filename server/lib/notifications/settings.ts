import {
  NOTIFICATION_CHANNEL_ID_PATTERN,
  NOTIFICATION_CHANNEL_KINDS,
  NOTIFICATION_CHANNEL_NAME_MAX_LENGTH,
  NOTIFICATION_CONFIG_ID_MAX_LENGTH,
  NOTIFICATION_EVENTS,
  NOTIFICATION_MAX_CHANNELS,
  NOTIFICATION_MAX_WEBHOOK_HEADERS,
  NOTIFICATION_SETTINGS_CACHE_TTL_MS,
  NOTIFICATION_SETTINGS_DOC_ID,
  NOTIFICATION_WEBHOOK_CONTENT_TYPE,
} from '../../../common/constants';
import type {
  NotificationChannel,
  NotificationChannelKind,
  NotificationEvent,
  NotificationSettings,
  NotificationWebhookConfig,
} from '../../../common/types';
import { validateEgressUrl } from '../egress/url_policy';
import { SettingsEnvelope, defineSettingsDoc, typedError } from '../plugin_settings';
import { ENCRYPTION_KEY_ENV_VAR, getEncryptionKey } from '../secrets_config';

/**
 * Notification settings document (`notification_settings` in META_INDEX,
 * step 1.1).
 *
 * `channels[]` binds delivery channels to events. `channels[].webhook.secret`
 * is the only secret (encrypted at rest, masked to `secretConfigured` on
 * read). Readers that only need the bindings go through
 * `getNotificationChannels`, which caches the masked document per process for
 * NOTIFICATION_SETTINGS_CACHE_TTL_MS (30 s) and never throws; the webhook
 * secret is resolved separately by `resolveWebhookSecret` at send time.
 * `PUT /notifications/settings` calls `invalidateNotificationSettingsCache()`
 * after the write; other dashboard replicas pick the change up within the TTL.
 */

/** Stored shape: `NotificationWebhookConfig` plus the encrypted secret. */
export interface StoredNotificationWebhook extends Omit<NotificationWebhookConfig, 'secretConfigured'> {
  secret?: string;
}

export interface StoredNotificationChannel extends Omit<NotificationChannel, 'webhook'> {
  webhook?: StoredNotificationWebhook;
}

export interface NotificationSettingsDoc {
  enabled: boolean;
  channels: StoredNotificationChannel[];
}

export interface LoadedNotificationSettings extends NotificationSettings, SettingsEnvelope {}

export const CHANNEL_ID = NOTIFICATION_CHANNEL_ID_PATTERN;
const KINDS = new Set<string>(NOTIFICATION_CHANNEL_KINDS);
const EVENTS = new Set<string>(NOTIFICATION_EVENTS);
const HEADER_NAME = /^[A-Za-z0-9-]{1,128}$/;
/** Header names a direct webhook may not set: the transport owns them. */
export const RESERVED_WEBHOOK_HEADERS = new Set([
  'content-type',
  'content-length',
  'host',
  'authorization',
  'x-wam-event',
  'x-wam-delivery',
  'x-wam-timestamp',
  'x-wam-signature',
]);

function bad(message: string): never {
  throw typedError(message, 400);
}

function cleanString(value: unknown, max: number): string {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function normaliseEvents(raw: unknown, label: string): NotificationEvent[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) bad(`${label}: events must be a list.`);
  const out: NotificationEvent[] = [];
  for (const item of raw) {
    const event = String(item);
    if (!EVENTS.has(event)) bad(`${label}: unknown event "${event.slice(0, 64)}". Allowed: ${NOTIFICATION_EVENTS.join(', ')}.`);
    if (!out.includes(event as NotificationEvent)) out.push(event as NotificationEvent);
  }
  // Keep the canonical order so audits and the UI are stable.
  return NOTIFICATION_EVENTS.filter((event) => out.includes(event));
}

export function normaliseWebhookHeaders(raw: unknown, label: string): Record<string, string> | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'object' || Array.isArray(raw)) bad(`${label}: headers must be an object of header name to value.`);
  const out: Record<string, string> = {};
  const seen = new Set<string>();
  for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
    const key = name.trim();
    if (!HEADER_NAME.test(key)) bad(`${label}: invalid header name "${name.slice(0, 64)}" (letters, digits and "-" only).`);
    const lower = key.toLowerCase();
    if (RESERVED_WEBHOOK_HEADERS.has(lower)) bad(`${label}: header "${key}" is set by the plugin and cannot be overridden.`);
    if (seen.has(lower)) bad(`${label}: header "${key}" is listed more than once.`);
    if (typeof value !== 'string' || /[\r\n\0]/.test(value)) bad(`${label}: header "${key}" must be a single-line string.`);
    seen.add(lower);
    out[key] = value.trim().slice(0, 2048);
  }
  const count = Object.keys(out).length;
  if (count > NOTIFICATION_MAX_WEBHOOK_HEADERS) bad(`${label}: at most ${NOTIFICATION_MAX_WEBHOOK_HEADERS} headers.`);
  return count > 0 ? out : undefined;
}

/**
 * How a webhook URL that fails the egress policy is treated. `enforce` (the
 * write path) throws a 400; `flag` (the read path) keeps the channel,
 * forced `enabled: false`, with the reason in `invalid`, so an allowlist
 * narrowed after the save never makes the whole document unreadable and the
 * other channels keep delivering. `boundedFetch` re-checks the policy at send
 * time, so a flagged channel could not be used even if it were enabled.
 */
export interface NormaliseOptions {
  egress?: 'enforce' | 'flag';
}

function normaliseChannel(raw: any, index: number, options: NormaliseOptions): StoredNotificationChannel {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad(`channels[${index}] must be an object.`);
  // The id is validated exactly as submitted, never rewritten: plugin_settings
  // re-attaches `channels[].webhook.secret` to the validated element by id, so
  // a normalised id would silently drop the secret.
  const id = typeof raw.id === 'string' ? raw.id : '';
  if (!CHANNEL_ID.test(id)) bad(`channels[${index}]: id must be 1-64 lower-case letters, digits, "-" or "_" (no spaces or upper-case).`);
  const kind = cleanString(raw.kind, 32) as NotificationChannelKind;
  if (!KINDS.has(kind)) bad(`Channel "${id}": kind must be one of ${NOTIFICATION_CHANNEL_KINDS.join(', ')}.`);
  const name = cleanString(raw.name, NOTIFICATION_CHANNEL_NAME_MAX_LENGTH);
  if (!name) bad(`Channel "${id}": name is required.`);
  const label = `Channel "${name}"`;
  if (raw.enabled !== undefined && typeof raw.enabled !== 'boolean') bad(`${label}: enabled must be a boolean.`);

  const channel: StoredNotificationChannel = {
    id,
    name,
    kind,
    enabled: raw.enabled === true,
    events: normaliseEvents(raw.events, label),
  };

  if (kind === 'indexer_channel') {
    const config = raw.indexer_channel && typeof raw.indexer_channel === 'object' ? raw.indexer_channel : {};
    const configId = cleanString(config.configId, NOTIFICATION_CONFIG_ID_MAX_LENGTH);
    if (!configId) bad(`${label}: select a Notifications channel (configId).`);
    if (/[\s\/]/.test(configId)) bad(`${label}: configId must be a single Notifications config id.`);
    channel.indexer_channel = { configId };
  } else {
    const config = raw.webhook && typeof raw.webhook === 'object' ? raw.webhook : {};
    const url = cleanString(config.url, 2048);
    if (!url) bad(`${label}: a webhook channel needs its receiver URL.`);
    const allowInsecure = config.allowInsecure === true;
    let invalid: string | null = null;
    try {
      validateEgressUrl(url, { purpose: `${label} URL`, allowInsecure });
    } catch (e: any) {
      const message = e?.message || `${label}: URL is not an allowed egress target.`;
      if (options.egress === 'flag') invalid = String(message).slice(0, 300);
      else bad(message);
    }
    if (config.contentType !== undefined && config.contentType !== NOTIFICATION_WEBHOOK_CONTENT_TYPE) {
      bad(`${label}: contentType is fixed to ${NOTIFICATION_WEBHOOK_CONTENT_TYPE}.`);
    }
    const webhook: StoredNotificationWebhook = { url, contentType: NOTIFICATION_WEBHOOK_CONTENT_TYPE };
    const headers = normaliseWebhookHeaders(config.headers, label);
    if (headers) webhook.headers = headers;
    if (allowInsecure) webhook.allowInsecure = true;
    channel.webhook = webhook;
    if (invalid) {
      channel.enabled = false;
      channel.invalid = invalid;
    }
  }
  return channel;
}

/**
 * Validate and normalise the merged document (secrets are not present here).
 * Throws a 400 TypedError; with `{ egress: 'flag' }` a webhook URL outside the
 * current egress policy is flagged instead of thrown (see NormaliseOptions).
 */
export function normaliseNotificationSettings(
  doc: Partial<NotificationSettingsDoc> | Record<string, unknown> | null | undefined,
  options: NormaliseOptions = {}
): NotificationSettingsDoc {
  const input: any = doc && typeof doc === 'object' ? doc : {};
  if (input.enabled !== undefined && typeof input.enabled !== 'boolean') bad('enabled must be a boolean.');
  const list = input.channels === undefined || input.channels === null ? [] : input.channels;
  if (!Array.isArray(list)) bad('channels must be a list.');
  if (list.length > NOTIFICATION_MAX_CHANNELS) bad(`At most ${NOTIFICATION_MAX_CHANNELS} notification channels can be configured.`);
  const seen = new Set<string>();
  const channels = list.map((raw: unknown, index: number) => {
    const channel = normaliseChannel(raw, index, options);
    if (seen.has(channel.id)) bad(`Channel id "${channel.id}" is used more than once.`);
    seen.add(channel.id);
    return channel;
  });
  return { enabled: input.enabled === true, channels };
}

export const notificationSettings = defineSettingsDoc<NotificationSettingsDoc>({
  docId: NOTIFICATION_SETTINGS_DOC_ID,
  defaults: { enabled: false, channels: [] },
  secretFields: ['channels[].webhook.secret'],
  // The write path enforces the egress policy (400).
  validate: (doc) => normaliseNotificationSettings(doc, { egress: 'enforce' }),
});

function maskedToSettings(masked: any): NotificationSettings {
  // The masked document carries `webhook.secretConfigured` beside each webhook;
  // re-validate the shape so a hand-edited document never reaches a caller
  // unchecked. The egress policy is only flagged here: it is read from the
  // environment at call time, so a stored URL may fall outside it later and
  // must still load (the admin repairs it in the UI; the channel is disabled).
  const valid = normaliseNotificationSettings(masked, { egress: 'flag' });
  const channels: NotificationChannel[] = valid.channels.map((channel, index) => {
    const raw = Array.isArray(masked?.channels) ? masked.channels[index] : undefined;
    if (channel.kind !== 'webhook' || !channel.webhook) return channel as NotificationChannel;
    const secretConfigured = raw?.webhook?.secretConfigured === true;
    return { ...channel, webhook: { ...channel.webhook, secretConfigured } } as NotificationChannel;
  });
  return { enabled: valid.enabled, channels };
}

/** The stored settings, masked (no secrets) and validated. Throws on a storage failure. */
export async function loadNotificationSettings(client: any): Promise<LoadedNotificationSettings> {
  const doc = await notificationSettings.read(client);
  return { ...maskedToSettings(doc), updated_at: doc.updated_at, updated_by: doc.updated_by };
}

/**
 * Replace `enabled` and the channel list (a full replace: the list comes from
 * the patch; a webhook secret is kept when the element omits it or sends ''
 * / `{hasSecret: true}`, replaced by a non-empty string, cleared by null) and
 * refresh the local cache with the saved document.
 */
export async function saveNotificationSettings(
  client: any,
  patch: Partial<NotificationSettings> | Record<string, unknown>,
  options: { updatedBy: string }
): Promise<LoadedNotificationSettings> {
  const input: any = patch && typeof patch === 'object' ? patch : {};
  // Shape + policy check before the write so a bad list never reaches the encrypt pass.
  normaliseNotificationSettings({ enabled: input.enabled, channels: input.channels ?? [] }, { egress: 'enforce' });
  const saved = await notificationSettings.write(client, { enabled: input.enabled === true, channels: input.channels ?? [] }, { actor: options.updatedBy });
  const settings = maskedToSettings(saved);
  invalidateNotificationSettingsCache();
  primeNotificationSettingsCache(settings);
  return { ...settings, updated_at: saved.updated_at, updated_by: saved.updated_by };
}

interface SettingsCache {
  settings: NotificationSettings;
  expiresAt: number;
}

let cache: SettingsCache | null = null;
let inFlight: Promise<NotificationSettings> | null = null;
/** Bumped by every invalidate/prime so an overlapping read cannot overwrite a newer cache (see sla/policy.ts). */
let generation = 0;

export interface NotificationSettingsLogger {
  warn?(message: string): void;
  debug?(message: string): void;
}

function cloneSettings(settings: NotificationSettings): NotificationSettings {
  return JSON.parse(JSON.stringify(settings));
}

const EMPTY: NotificationSettings = { enabled: false, channels: [] };

export interface GetNotificationChannelsOptions {
  /**
   * Rethrow a read failure instead of answering the last cached (or the
   * empty) settings. For a producer whose skip is final (the rule `notify`
   * action: a globally disabled answer consumes the trigger and nothing is
   * replayed), so a transient meta-index error must stay a retryable failure.
   * A fresh cache is still used.
   */
  throwOnError?: boolean;
}

/**
 * The cached, masked settings (30-s TTL per process) for dispatchers and
 * emitters. Never throws by default: a read failure logs (when a logger is
 * given) and answers the last cached document, else the empty (disabled)
 * settings; `throwOnError` rethrows it instead.
 */
export async function getNotificationChannels(
  client: any,
  logger?: NotificationSettingsLogger,
  options: GetNotificationChannelsOptions = {}
): Promise<NotificationSettings> {
  const now = Date.now();
  if (cache && cache.expiresAt > now) return cache.settings;
  if (options.throwOnError) {
    const startedAt = generation;
    const loaded = await loadNotificationSettings(client);
    const settings: NotificationSettings = { enabled: loaded.enabled, channels: loaded.channels };
    if (generation === startedAt) cache = { settings, expiresAt: Date.now() + NOTIFICATION_SETTINGS_CACHE_TTL_MS };
    return settings;
  }
  if (inFlight) return inFlight;
  const startedAt = generation;
  inFlight = (async () => {
    try {
      const loaded = await loadNotificationSettings(client);
      const settings: NotificationSettings = { enabled: loaded.enabled, channels: loaded.channels };
      if (generation !== startedAt) return cache ? cache.settings : settings;
      cache = { settings, expiresAt: Date.now() + NOTIFICATION_SETTINGS_CACHE_TTL_MS };
      return settings;
    } catch (e: any) {
      const message = `wazuh-alert-manager notifications: could not read ${NOTIFICATION_SETTINGS_DOC_ID}, using ${
        cache ? 'the last cached' : 'the empty'
      } settings: ${e?.message || String(e)}`;
      if (logger?.warn) logger.warn(message);
      else logger?.debug?.(message);
      return cache ? cache.settings : cloneSettings(EMPTY);
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

/** Drop the process-local cache so the next `getNotificationChannels` re-reads the document. */
export function invalidateNotificationSettingsCache(): void {
  cache = null;
  generation += 1;
}

/** Seed the cache (after a save, or in tests) without a read. */
export function primeNotificationSettingsCache(settings: NotificationSettings, ttlMs: number = NOTIFICATION_SETTINGS_CACHE_TTL_MS): void {
  cache = { settings: cloneSettings(settings), expiresAt: Date.now() + ttlMs };
  generation += 1;
}

/** Enabled channels bound to `event` (empty when notifications are globally disabled). */
export function channelsForEvent(settings: NotificationSettings | null | undefined, event: NotificationEvent): NotificationChannel[] {
  if (!settings || settings.enabled !== true) return [];
  return (settings.channels || []).filter((channel) => channel.enabled && channel.events.includes(event));
}

export function findChannel(settings: NotificationSettings | null | undefined, id: string): NotificationChannel | null {
  return (settings?.channels || []).find((channel) => channel.id === id) || null;
}

/**
 * The decrypted HMAC secret of a webhook channel ('' when none is stored).
 * Server-side only. A missing WAZUH_ALERT_MANAGER_ENCRYPTION_KEY, or one that
 * no longer decrypts the stored value, is a typed 409 so the test route and
 * the dispatcher can surface it as a configuration conflict.
 */
export async function resolveWebhookSecret(client: any, channel: Pick<NotificationChannel, 'id' | 'kind'>): Promise<string> {
  if (channel.kind !== 'webhook') return '';
  let doc: NotificationSettingsDoc & SettingsEnvelope;
  try {
    doc = await notificationSettings.readWithSecrets(client);
  } catch (e: any) {
    if (e?.statusCode === 500 && /decrypt/.test(String(e?.message || ''))) throw typedError(e.message, 409);
    throw e;
  }
  const stored = (doc.channels || []).find((entry) => entry.id === channel.id);
  const secret = stored?.webhook?.secret;
  if (typeof secret === 'string' && secret.length > 0 && !getEncryptionKey()) {
    throw typedError(
      `Cannot use the webhook secret of channel "${channel.id}": the ${ENCRYPTION_KEY_ENV_VAR} environment variable is not set for the wazuh-dashboard service.`,
      409
    );
  }
  return typeof secret === 'string' ? secret : '';
}

/** Compact audit summary of a settings document (`from`/`to` of `notification_settings_updated`). */
export function notificationSettingsAuditSummary(settings: NotificationSettings): string {
  const channels = settings.channels || [];
  const ids = channels.map((channel) => `${channel.id}:${channel.kind}${channel.enabled ? '' : '(off)'}`).join(',');
  return `enabled=${settings.enabled === true};channels=${channels.length}${ids ? `;${ids}` : ''}`;
}
