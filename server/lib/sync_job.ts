import { Logger } from '../../../../src/core/server';
import { ALERT_STATUS_INDEX, META_INDEX } from '../../common';
import { AlertManagerConfigType } from '../config';

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
export async function runSyncOnce(client: any, config: AlertManagerConfigType, logger: Logger) {
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

  await setLastRun(client, now);
  logger.debug(`wazuh-alert-manager sync: copied ${hits.length} alerts (${lastRun} - ${now})`);
}

export function startSyncJob(client: any, config: AlertManagerConfigType, logger: Logger): () => void {
  if (!config.sync.enabled) {
    logger.info('wazuh-alert-manager: background sync disabled via config');
    return () => {};
  }

  let stopped = false;
  const tick = () => {
    if (stopped) return;
    runSyncOnce(client, config, logger).catch((e) =>
      logger.error(`wazuh-alert-manager sync: unexpected error: ${e.message}`)
    );
  };

  tick();
  const timer = setInterval(tick, config.sync.intervalSeconds * 1000);

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
