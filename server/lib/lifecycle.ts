import { Logger } from '../../../../src/core/server';
import {
  ACTIVITY_READ_ALIAS,
  ACTIVITY_WRITE_ALIAS,
  ALERTS_READ_ALIAS,
  ALERTS_WRITE_ALIAS,
  CASES_READ_ALIAS,
  CASES_WRITE_ALIAS,
  EVIDENCE_READ_ALIAS,
  EVIDENCE_WRITE_ALIAS,
  META_INDEX,
} from '../../common';
import { AlertManagerConfigType } from '../config';
import { activityMapping, alertStatusMapping, casesMapping, evidenceMapping } from './mappings';
import { assertManagedWriteTarget } from './index_namespace';

export const LIFECYCLE_SETTINGS_ID = 'lifecycle_settings';

export interface LifecycleSettings {
  enabled: boolean;
  rolloverAge: string;
  rolloverSize: string;
  operationalRetentionDays: number;
  activityRetentionDays: number;
  caseRetentionDays: number;
  evidenceRetentionDays: number;
}

function configSettings(config: AlertManagerConfigType): LifecycleSettings {
  return {
    enabled: config.lifecycle.enabled,
    rolloverAge: config.lifecycle.rolloverAge,
    rolloverSize: config.lifecycle.rolloverPrimarySize,
    operationalRetentionDays: config.lifecycle.operationalRetentionDays,
    activityRetentionDays: config.lifecycle.activityRetentionDays,
    caseRetentionDays: config.lifecycle.caseRetentionDays,
    evidenceRetentionDays: config.lifecycle.evidenceRetentionDays,
  };
}

export async function ensureLifecycleSettings(client: any, config: AlertManagerConfigType) {
  const existing: any = await client.search({
    index: META_INDEX,
    body: { size: 0, query: { ids: { values: [LIFECYCLE_SETTINGS_ID] } } },
  });
  const total = existing?.body?.hits?.total;
  const count = typeof total === 'number' ? total : Number(total?.value || 0);
  if (count > 0) return;
  try {
    await client.create({
      index: assertManagedWriteTarget(META_INDEX),
      id: LIFECYCLE_SETTINGS_ID,
      body: { ...configSettings(config), updated_at: new Date().toISOString(), source: 'config_defaults' },
    });
  } catch (e: any) {
    if (e?.meta?.statusCode !== 409) throw e;
  }
}

export async function loadLifecycleSettings(
  client: any,
  config?: AlertManagerConfigType
): Promise<LifecycleSettings | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: LIFECYCLE_SETTINGS_ID });
    const source = res.body._source || {};
    const fallback = config ? configSettings(config) : source;
    return {
      enabled: source.enabled ?? fallback.enabled,
      rolloverAge: source.rolloverAge || fallback.rolloverAge,
      rolloverSize: source.rolloverSize || fallback.rolloverSize,
      operationalRetentionDays: source.operationalRetentionDays ?? fallback.operationalRetentionDays,
      activityRetentionDays: source.activityRetentionDays ?? fallback.activityRetentionDays,
      caseRetentionDays: source.caseRetentionDays ?? fallback.caseRetentionDays ?? 365,
      evidenceRetentionDays: source.evidenceRetentionDays ?? fallback.evidenceRetentionDays ?? 730,
    };
  } catch (e) {
    return config ? configSettings(config) : null;
  }
}

interface Family {
  name: 'alerts' | 'activity' | 'cases' | 'evidence';
  readAlias: string;
  writeAlias: string;
  mapping: any;
}

const FAMILIES: Family[] = [
  { name: 'alerts', readAlias: ALERTS_READ_ALIAS, writeAlias: ALERTS_WRITE_ALIAS, mapping: alertStatusMapping },
  { name: 'activity', readAlias: ACTIVITY_READ_ALIAS, writeAlias: ACTIVITY_WRITE_ALIAS, mapping: activityMapping },
  { name: 'cases', readAlias: CASES_READ_ALIAS, writeAlias: CASES_WRITE_ALIAS, mapping: casesMapping },
  { name: 'evidence', readAlias: EVIDENCE_READ_ALIAS, writeAlias: EVIDENCE_WRITE_ALIAS, mapping: evidenceMapping },
];

/**
 * The lifecycle is plugin-managed instead of depending on cluster-wide ISM
 * policy privileges. This preserves install-and-go deployment on stock Wazuh
 * while still using OpenSearch's atomic rollover API. The request includes the
 * current mapping so a new generation does not depend on an index template.
 */
export async function runLifecycleOnce(client: any, config: AlertManagerConfigType, logger: Logger) {
  const settings = await loadLifecycleSettings(client, config);
  if (!settings?.enabled) return;
  for (const family of FAMILIES) {
    assertManagedWriteTarget(family.writeAlias);
    try {
      const result: any = await client.indices.rollover({
        alias: family.writeAlias,
        body: {
          conditions: {
            max_age: settings.rolloverAge,
            // Supported by the OpenSearch 2.19.x line used across Wazuh
            // 4.12-4.14. `max_primary_shard_size` is an Elasticsearch-only
            // condition and is rejected by these OpenSearch releases.
            max_size: settings.rolloverSize,
          },
          mappings: family.mapping,
          aliases: { [family.readAlias]: {} },
        },
      });
      if (result?.body?.rolled_over) {
        logger.info(
          `wazuh-alert-manager lifecycle: rolled ${family.name} from ${result.body.old_index} to ${result.body.new_index}`
        );
      }
    } catch (e: any) {
      logger.warn(`wazuh-alert-manager lifecycle: ${family.name} rollover check failed: ${e.message}`);
    }
  }
}

export function startLifecycleJob(client: any, config: AlertManagerConfigType, logger: Logger): () => void {
  runLifecycleOnce(client, config, logger).catch((e) =>
    logger.warn(`wazuh-alert-manager lifecycle: startup check failed: ${e.message}`)
  );
  const timer = setInterval(() => {
    runLifecycleOnce(client, config, logger).catch((e) =>
      logger.warn(`wazuh-alert-manager lifecycle: scheduled check failed: ${e.message}`)
    );
  }, 5 * 60 * 1000);
  return () => clearInterval(timer);
}

export async function lifecycleStatus(client: any) {
  const result: any = {};
  for (const family of FAMILIES) {
    try {
      const aliases: any = await client.indices.getAlias({ name: family.readAlias });
      result[family.name] = {
        mode: 'plugin_managed',
        readAlias: family.readAlias,
        writeAlias: family.writeAlias,
        generations: Object.keys(aliases?.body || {}).sort(),
      };
    } catch (e: any) {
      result[family.name] = { mode: 'plugin_managed', error: e.message };
    }
  }
  return result;
}
