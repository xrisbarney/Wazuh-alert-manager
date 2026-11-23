import { NOTIFICATION_INDEXER_CHANNEL_TYPES, TARGET_WAZUH_MAJOR } from '../../../common';
import type { IndexerChannelSummary, IndexerChannelWarning, IndexerChannelsResponse } from '../../../common';

/**
 * Channel listing of the indexer Notifications plugin (step 1.1).
 *
 * `GET /_plugins/_notifications/configs` is called AS THE CURRENT USER so the
 * Security plugin's `notifications_read_access` decides what is visible: a
 * 403 answers `access: 'forbidden'` with an empty list (the picker shows an
 * empty state, never an error toast), a 404 / "no handler" answers
 * `'unavailable'` (plugin absent). Only channel config types are requested;
 * `smtp_account` / `email_group` / `ses_account` are not delivery targets.
 */

export const NOTIFICATIONS_CONFIGS_PATH = '/_plugins/_notifications/configs';
export const NOTIFICATIONS_CONFIGS_MAX_ITEMS = 100;

export interface ListIndexerChannelsOptions {
  /** Build target line; 5 enables the `disabled_placeholder` hint (5.0 ships four disabled `default_*` channels). */
  wazuhMajor?: number;
}

function headerParams(config: any): Record<string, string> {
  const params = config?.webhook?.header_params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) return {};
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(params)) out[String(name).toLowerCase()] = String(value ?? '');
  return out;
}

/**
 * Warnings for one channel config. A webhook channel's `header_params` are
 * sent verbatim; the indexer defaults to `application/json` only when the map
 * is empty (verified on 4.14.10), so a non-empty map without an explicit
 * `Content-Type: application/json` delivers `text/plain`.
 */
export function channelWarnings(item: any, wazuhMajor: number): IndexerChannelWarning[] {
  const warnings: IndexerChannelWarning[] = [];
  const config = item?.config || {};
  if (config.config_type === 'webhook') {
    const headers = headerParams(config);
    const names = Object.keys(headers);
    if (names.length > 0) {
      const contentType = headers['content-type'];
      if (!contentType || !/^application\/json\b/i.test(contentType.trim())) warnings.push('missing_json_content_type');
    }
  }
  if (wazuhMajor === 5 && typeof item?.config_id === 'string' && item.config_id.startsWith('default_') && config.is_enabled === false) {
    warnings.push('disabled_placeholder');
  }
  return warnings;
}

export function summariseChannel(item: any, wazuhMajor: number): IndexerChannelSummary | null {
  const configId = typeof item?.config_id === 'string' ? item.config_id : '';
  if (!configId) return null;
  const config = item.config || {};
  const type = typeof config.config_type === 'string' ? config.config_type : '';
  if (!(NOTIFICATION_INDEXER_CHANNEL_TYPES as readonly string[]).includes(type)) return null;
  return {
    configId,
    name: typeof config.name === 'string' && config.name.trim() ? config.name.trim().slice(0, 256) : configId,
    type,
    isEnabled: config.is_enabled !== false,
    warnings: channelWarnings(item, wazuhMajor),
  };
}

function statusOf(error: any): number | undefined {
  const status = error?.meta?.statusCode ?? error?.statusCode ?? error?.status;
  return typeof status === 'number' ? status : undefined;
}

function isHandlerMissing(error: any): boolean {
  const text = String(error?.meta?.body?.error?.reason || error?.meta?.body?.error || error?.message || '');
  return /no handler found|unknown plugin|not found/i.test(text);
}

/**
 * List the Notifications channels visible to `client` (an `asCurrentUser`
 * client in the route). Never throws for the expected access outcomes.
 */
export async function listIndexerChannels(client: any, options: ListIndexerChannelsOptions = {}): Promise<IndexerChannelsResponse> {
  const wazuhMajor = options.wazuhMajor ?? Number(TARGET_WAZUH_MAJOR);
  let body: any;
  try {
    const res = await client.transport.request({
      method: 'GET',
      path: NOTIFICATIONS_CONFIGS_PATH,
      querystring: {
        config_type: NOTIFICATION_INDEXER_CHANNEL_TYPES.join(','),
        max_items: NOTIFICATIONS_CONFIGS_MAX_ITEMS,
      },
    });
    body = res?.body ?? res;
  } catch (e: any) {
    const status = statusOf(e);
    if (status === 403 || status === 401) {
      return {
        channels: [],
        access: 'forbidden',
        message: 'Your account cannot list Notifications channels. Ask an administrator for the notifications_read_access role.',
      };
    }
    if (status === 404 || isHandlerMissing(e)) {
      return { channels: [], access: 'unavailable', message: 'The Notifications plugin is not available on this indexer.' };
    }
    return { channels: [], access: 'unavailable', message: `Could not list Notifications channels: ${e?.message || String(e)}` };
  }
  const list: any[] = Array.isArray(body?.config_list) ? body.config_list : [];
  const channels: IndexerChannelSummary[] = [];
  for (const item of list) {
    const summary = summariseChannel(item, wazuhMajor);
    if (summary) channels.push(summary);
  }
  channels.sort((a, b) => a.name.localeCompare(b.name) || a.configId.localeCompare(b.configId));
  return { channels, access: 'ok' };
}
