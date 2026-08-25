import { Logger } from '../../../../src/core/server';
import { ALERT_STATUS_INDEX, META_INDEX } from '../../common';
import { AlertManagerConfigType } from '../config';
import { acquireOrRenewLock, releaseLock, generateHolderId } from './sync_lock';
import { evaluateCorrelationRules } from './correlation_eval';

const SYNC_STATE_DOC_ID = 'sync_state';

// Fields this plugin writes onto an alert document and therefore must never let
// a resync of the source alert overwrite. Keep in sync with the plugin-owned
// properties in server/lib/mappings.ts (alertStatusMapping).
const PLUGIN_OWNED_FIELDS = [
  'status',
  'case_id',
  'assigned_to',
  'related_alert_ids',
  'ai_analysis',
  'updated_at',
  'updated_by',
  'history',
];

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
      // Sort ascending so a full batch is the OLDEST alerts in the window and
      // the watermark can advance to the last one we actually copied. Without
      // a sort, OpenSearch returns an arbitrary batchSize subset and anything
      // past it in a >batchSize window is never synced - the window closes on
      // the next tick and those alerts are lost permanently.
      body: { query: { bool: { must } }, sort: [{ '@timestamp': { order: 'asc' } }] },
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

  // When the batch is full there are more alerts in this window than one tick
  // can carry. Advance the watermark only as far as the last alert we actually
  // copied (they are sorted ascending), so the next tick resumes from there
  // and nothing is skipped. Only an empty/partial batch is safe to fast-forward
  // to `now`.
  const batchFull = hits.length >= config.sync.batchSize;
  const lastHitTs = hits[hits.length - 1]?._source?.['@timestamp'];
  const nextWatermark = batchFull && lastHitTs ? lastHitTs : now;
  if (batchFull) {
    logger.warn(
      `wazuh-alert-manager sync: batch size limit (${config.sync.batchSize}) reached for window ${lastRun} - ${now}. ` +
        `Continuing from ${nextWatermark} on the next tick. Lower sync.intervalSeconds to drain faster.`
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
        // Copy every field from the source alert EXCEPT the ones this plugin
        // owns - status, case_id, assignment, AI analysis, audit history, etc.
        // The loop is key-agnostic, so without this guard a same-named field in
        // a Wazuh alert would silently clobber an analyst's triage state on the
        // next resync of that document.
        source: `
          for (entry in params.doc.entrySet()) {
            if (!params.protected.contains(entry.getKey())) {
              ctx._source[entry.getKey()] = entry.getValue();
            }
          }
          if (ctx._source.status == null) {
            ctx._source.status = 'open';
          }
        `,
        params: { doc: hit._source, protected: PLUGIN_OWNED_FIELDS },
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

  await setLastRun(client, nextWatermark);
  logger.debug(
    `wazuh-alert-manager sync: copied ${hits.length} alerts (${lastRun} - ${now}); watermark now ${nextWatermark}`
  );

  // Escalate correlated bursts into cases. Wrapped so a rule-engine failure can
  // never break alert ingestion. Runs under the same lease held above (single
  // writer). We must refresh the status index first: the burst evaluator counts
  // this tick's alerts via search, and a burst that arrives entirely within one
  // tick is only a candidate in THIS tick's evaluation (its alerts leave the
  // next tick's window). Without a refresh those just-written docs are not yet
  // searchable, so the count races the ~1s refresh interval and a burst can be
  // silently missed. An explicit refresh makes single-tick burst detection
  // deterministic.
  try {
    await client.indices.refresh({ index: ALERT_STATUS_INDEX });
  } catch (e: any) {
    logger.warn(`wazuh-alert-manager sync: status-index refresh before correlation failed: ${e.message}`);
  }
  try {
    await evaluateCorrelationRules(client, hits, logger);
  } catch (e: any) {
    logger.error(`wazuh-alert-manager: correlation-rule evaluation failed: ${e.message}`);
  }
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
