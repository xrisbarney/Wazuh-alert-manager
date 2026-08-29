import { META_INDEX } from '../../common';
import { AlertManagerConfigType } from '../config';
import { assertManagedWriteTarget } from './index_namespace';

export const SYNC_SETTINGS_ID = 'sync_settings';

export interface SyncRuntimeSettings {
  enabled: boolean;
  intervalSeconds: number;
}

export async function loadSyncSettings(client: any, config?: AlertManagerConfigType): Promise<SyncRuntimeSettings> {
  const fallback = config
    ? { enabled: config.sync.enabled, intervalSeconds: config.sync.intervalSeconds }
    : { enabled: true, intervalSeconds: 60 };
  try {
    const result: any = await client.get({ index: META_INDEX, id: SYNC_SETTINGS_ID });
    const source = result?.body?._source || {};
    return {
      enabled: source.enabled ?? fallback.enabled,
      intervalSeconds: Math.max(15, Number(source.intervalSeconds || fallback.intervalSeconds)),
    };
  } catch (e) {
    return fallback;
  }
}

export async function saveSyncSettings(
  client: any,
  settings: SyncRuntimeSettings,
  actor: string
): Promise<SyncRuntimeSettings> {
  const normalized = {
    enabled: Boolean(settings.enabled),
    intervalSeconds: Math.max(15, Math.min(3600, Math.round(settings.intervalSeconds))),
  };
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: SYNC_SETTINGS_ID,
    body: { ...normalized, updated_at: new Date().toISOString(), updated_by: actor, source: 'workbench' },
    refresh: 'wait_for',
  });
  return normalized;
}
