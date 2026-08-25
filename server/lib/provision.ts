import { Logger } from '../../../../src/core/server';
import { ALERT_STATUS_INDEX, COMMENTS_INDEX, CASES_INDEX, META_INDEX, RULES_INDEX } from '../../common';
import { alertStatusMapping, commentsMapping, casesMapping, metaMapping, rulesMapping } from './mappings';

// Bump whenever a mapping in ./mappings.ts gains a field or dynamic_template.
// A fresh install creates indices with the current mapping and records this
// version; an upgraded install has an older (or absent) version and runs
// ensureMappingAdditions() once to PUT the new fields onto its existing indices.
const MAPPING_VERSION = 3;
const MAPPING_VERSION_DOC_ID = 'mapping_version';

const MANAGED_INDICES: Array<[string, any]> = [
  [ALERT_STATUS_INDEX, alertStatusMapping],
  [COMMENTS_INDEX, commentsMapping],
  [CASES_INDEX, casesMapping],
  [META_INDEX, metaMapping],
  [RULES_INDEX, rulesMapping],
];

async function ensureIndex(client: any, index: string, mappings: any, logger: Logger) {
  const exists = await client.indices.exists({ index });
  if (exists.body) {
    return;
  }
  try {
    await client.indices.create({ index, body: { mappings } });
    logger.info(`Created index ${index}`);
  } catch (e: any) {
    // Another dashboard node may have created it concurrently.
    if (e?.meta?.statusCode !== 400) {
      logger.error(`Failed to create index ${index}: ${e.message}`);
      throw e;
    }
  }
}

async function getStoredMappingVersion(client: any): Promise<number> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: MAPPING_VERSION_DOC_ID });
    return res?.body?._source?.version ?? 0;
  } catch (e) {
    // Not found on a fresh install, or META not yet readable - treat as 0.
    return 0;
  }
}

/**
 * Applies additive mapping changes (new fields, new dynamic_templates) to
 * indices that ALREADY EXIST. Index creation only ever runs on a brand-new
 * install, so without this an upgraded deployment would never receive a field
 * added in a later release. PUT _mapping is additive - it accepts new fields
 * and dynamic_templates and is a no-op for identical existing ones; it only
 * rejects an incompatible change to an existing field's type, which we log
 * rather than crash on so the plugin still starts.
 */
export async function ensureMappingAdditions(client: any, logger: Logger) {
  const stored = await getStoredMappingVersion(client);
  if (stored >= MAPPING_VERSION) {
    return;
  }
  logger.info(`wazuh-alert-manager: applying mapping additions (stored v${stored} -> v${MAPPING_VERSION})`);
  for (const [index, mapping] of MANAGED_INDICES) {
    try {
      const exists = await client.indices.exists({ index });
      if (!exists.body) {
        continue; // ensureIndex will create it with the current mapping
      }
      const body: any = {};
      if (mapping.dynamic_templates) {
        body.dynamic_templates = mapping.dynamic_templates;
      }
      if (mapping.properties) {
        body.properties = mapping.properties;
      }
      await client.indices.putMapping({ index, body });
      logger.info(`wazuh-alert-manager: applied mapping additions to ${index}`);
    } catch (e: any) {
      logger.error(
        `wazuh-alert-manager: could not apply mapping additions to ${index}: ${e.message}. ` +
          'New indexed fields for this release may be missing until this is resolved.'
      );
    }
  }
  try {
    await client.index({
      index: META_INDEX,
      id: MAPPING_VERSION_DOC_ID,
      body: { version: MAPPING_VERSION, updated_at: new Date().toISOString() },
    });
  } catch (e: any) {
    logger.error(`wazuh-alert-manager: failed to record mapping version: ${e.message}`);
  }
}

/**
 * Creates the indices this plugin owns if they don't already exist, then
 * applies any additive mapping changes to indices that predate this release.
 * Safe to call on every server start.
 */
export async function ensureIndices(client: any, logger: Logger) {
  await Promise.all(MANAGED_INDICES.map(([index, mapping]) => ensureIndex(client, index, mapping, logger)));
  await ensureMappingAdditions(client, logger);
}
