import { Logger } from '../../../../src/core/server';
import { ALERT_STATUS_INDEX, COMMENTS_INDEX, CASES_INDEX, META_INDEX } from '../../common';
import { alertStatusMapping, commentsMapping, casesMapping, metaMapping } from './mappings';

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

/**
 * Creates the indices this plugin owns if they don't already exist.
 * Safe to call on every server start.
 */
export async function ensureIndices(client: any, logger: Logger) {
  await Promise.all([
    ensureIndex(client, ALERT_STATUS_INDEX, alertStatusMapping, logger),
    ensureIndex(client, COMMENTS_INDEX, commentsMapping, logger),
    ensureIndex(client, CASES_INDEX, casesMapping, logger),
    ensureIndex(client, META_INDEX, metaMapping, logger),
  ]);
}
