import { Logger } from '../../../../src/core/server';
import { ALERT_STATUS_INDEX, META_INDEX } from '../../common';
import { AlertManagerConfigType } from '../config';
import { acquireOrRenewLock, releaseLock, generateHolderId } from './sync_lock';

const SYNC_STATE_DOC_ID = 'sync_state';

async function getLastRun(client: any, config: AlertManagerConfigType): Promise<string> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: SYNC_STATE_DOC_ID });
    if (res?.body?._source?.value) {
      return res.body._source.value;
    }
  } catch (e) {
    // Not found on first run - fall through to the default lookback window.
  }
  const lookbackMs = config.sync.initialLookbackMinutes * 60 * 1000;
  return new Date(Date.now() - lookbackMs).toISOString();
}

async function setLastRun(client: any, value: string) {
  await client.index({
    index: META_INDEX,
    id: SYNC_STATE_DOC_ID,
    body: { value, updated_at: new Date().toISOString() },
  });
}

/**
 * Copies new/updated alerts from the Wazuh alerts indices into
 * wazuh-alert-status using a scripted partial-update upsert, so any
 * status/case/comment-history the plugin has already recorded on a
 * document is preserved even if that alert falls into a later sync window.
 */
export async function runSyncOnce(
  client: any,
  config: AlertManagerConfigType,
  logger: Logger,
  holderId: string,
  ttlSeconds: number
) {
  const lastRun = await getLastRun(client, config);
  const now = new Date().toISOString();

  const must: any[] = [{ range: { '@timestamp': { gt: lastRun, lte: now } } }];
  if (config.sync.minRuleLevel != null) {
    must.push({ range: { 'rule.level': { gte: config.sync.minRuleLevel } } });
  }

  let hits: any[] = [];
  try {
    const results: any = await client.search({
      index: config.sync.sourceIndexPattern,
      size: config.sync.batchSize,
      body: { query: { bool: { must } } },
    });
    hits = results?.body?.hits?.hits || [];
  } catch (e: any) {
    logger.error(`wazuh-alert-manager sync: failed to query source index: ${e.message}`);
    return;
  }

  if (hits.length === 0) {
    await setLastRun(client, now);
    return;
  }

  if (hits.length >= config.sync.batchSize) {
    logger.warn(
      `wazuh-alert-manager sync: hit the batch size limit (${config.sync.batchSize}) for window ${lastRun} - ${now}. ` +
        'Some alerts may be delayed to the next sync cycle. Consider lowering sync.intervalSeconds.'
    );
  }

  // Re-validate we still hold the lock before writing - the search above can
  // take long enough that another replica has already taken over the lease.
  if (!(await acquireOrRenewLock(client, holderId, ttlSeconds, logger))) {
    logger.warn('wazuh-alert-manager sync: lost the sync lock before bulk upsert, aborting this tick');
    return;
  }

  const body: any[] = [];
  for (const hit of hits) {
    body.push({ update: { _index: ALERT_STATUS_INDEX, _id: hit._id } });
    body.push({
      scripted_upsert: true,
      upsert: {},
      script: {
        lang: 'painless',
        source: `
          for (entry in params.doc.entrySet()) {
            ctx._source[entry.getKey()] = entry.getValue();
          }
          if (ctx._source.status == null) {
            ctx._source.status = 'open';
          }
        `,
        params: { doc: hit._source },
      },
    });
  }

  try {
    const bulkRes: any = await client.bulk({ body });
    if (bulkRes?.body?.errors) {
      const failed = bulkRes.body.items.filter((i: any) => i.update?.error);
      logger.error(
        `wazuh-alert-manager sync: ${failed.length}/${hits.length} bulk updates failed. First error: ${JSON.stringify(
          failed[0]?.update?.error
        )}`
      );
    }
  } catch (e: any) {
    logger.error(`wazuh-alert-manager sync: bulk upsert failed: ${e.message}`);
    return; // don't advance the watermark if the write failed entirely
  }

  // Re-validate again before committing the watermark - the bulk upsert
  // itself can be what pushes this tick past the lease.
  if (!(await acquireOrRenewLock(client, holderId, ttlSeconds, logger))) {
    logger.warn('wazuh-alert-manager sync: lost the sync lock before committing the watermark, aborting this tick');
    return;
  }

  await setLastRun(client, now);
  logger.debug(`wazuh-alert-manager sync: copied ${hits.length} alerts (${lastRun} - ${now})`);
}

export function startSyncJob(client: any, config: AlertManagerConfigType, logger: Logger): () => void {
  if (!config.sync.enabled) {
    logger.info('wazuh-alert-manager: background sync disabled via config');
    return () => {};
  }

  let stopped = false;
  const holderId = generateHolderId();
  // TTL scales with the sync interval (and never drops below 2 minutes) so a
  // slower-configured interval doesn't make the lock look stale between ticks.
  const ttlSeconds = Math.max(config.sync.intervalSeconds * 3, 120);
  let holdingLock = false;
  // Guards against a tick still being in flight (e.g. a slow search/bulk)
  // when the next setInterval fire comes around, which would otherwise let
  // this same process run two overlapping runSyncOnce calls.
  let running = false;

  const tick = () => {
    if (stopped || running) return;
    running = true;
    acquireOrRenewLock(client, holderId, ttlSeconds, logger)
      .then((acquired) => {
        if (stopped) {
          // Shutdown raced this acquisition - don't leave the lock held by
          // a process that's already on its way out.
          if (acquired) {
            releaseLock(client, holderId, logger).catch(() => {});
          }
          return;
        }
        if (!acquired) {
          if (holdingLock) {
            logger.info('wazuh-alert-manager sync: lost the sync lock to another replica, pausing sync here');
          }
          holdingLock = false;
          logger.debug('wazuh-alert-manager sync: another replica holds the sync lock, skipping this tick');
          return;
        }
        holdingLock = true;
        return runSyncOnce(client, config, logger, holderId, ttlSeconds);
      })
      .catch((e) => logger.error(`wazuh-alert-manager sync: unexpected error: ${e.message}`))
      .finally(() => {
        running = false;
      });
  };

  tick();
  const timer = setInterval(tick, config.sync.intervalSeconds * 1000);

  return () => {
    stopped = true;
    clearInterval(timer);
    if (holdingLock) {
      releaseLock(client, holderId, logger).catch(() => {});
    }
  };
}
