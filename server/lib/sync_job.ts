import { Logger } from '../../../../src/core/server';
import { ALERTS_WRITE_ALIAS, META_INDEX, SYNC_DLQ_INDEX } from '../../common';
import { AlertManagerConfigType } from '../config';
import { acquireOrRenewLock, releaseLock, generateHolderId } from './sync_lock';
import {
  activateAutomationEvents,
  enqueueAutomationEvents,
  reconcileAutomationAdmissions,
  recordAutomationEnqueueFailure,
} from './automation_queue';
import { assertManagedWriteTarget, assertSafeSourcePattern, isManagedPhysicalIndex } from './index_namespace';
import { resolveAlerts } from './index_resolution';
import { projectOperationalAlert } from './operational_projection';
import { loadSyncSettings } from './sync_settings';

const SYNC_STATE_DOC_ID = 'sync_state';
const RETIRED_ALERT_DOC_PREFIX = 'retired-alert:';
const MAX_RETIREMENT_RECORDS = 1000;
const ARCHIVE_STATE_PRIORITY: Record<string, number> = { managed: 0, restored: 1, completed: 2, purging: 3, purged: 4 };

// Fields this plugin writes onto an alert document and therefore must never let
// a resync of the source alert overwrite. Keep in sync with the plugin-owned
// properties in server/lib/mappings.ts (alertStatusMapping).
const PLUGIN_OWNED_FIELDS = [
  'ingested_at',
  'state_version',
  'status',
  'case_id',
  'assigned_to',
  'related_alert_ids',
  'ai_analysis',
  'updated_at',
  'updated_by',
  'history',
];

interface SyncState {
  completed_at: string;
  initialized?: boolean;
  window_from?: string | null;
  window_to?: string | null;
  search_after?: any[] | null;
  pit_id?: string | null;
}

async function getSyncState(client: any, config: AlertManagerConfigType): Promise<SyncState> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: SYNC_STATE_DOC_ID });
    const source = res?.body?._source;
    if (source?.completed_at || source?.value) {
      return {
        completed_at: source.completed_at || source.value,
        initialized: true,
        window_from: source.window_from || null,
        window_to: source.window_to || null,
        search_after: source.search_after || null,
        pit_id: source.pit_id || null,
      };
    }
  } catch (e) {
    // Not found on first run - fall through to the default lookback window.
  }
  const lookbackMs = config.sync.initialLookbackMinutes * 60 * 1000;
  return { completed_at: new Date(Date.now() - lookbackMs).toISOString() };
}

async function setSyncState(client: any, state: SyncState) {
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: SYNC_STATE_DOC_ID,
    body: { ...state, value: state.completed_at, updated_at: new Date().toISOString() },
  });
}

async function recordDlq(client: any, failed: any[], projected: any[]) {
  if (!failed.length) return;
  const now = new Date().toISOString();
  const body: any[] = [];
  for (const item of failed) {
    const operation = item.item?.update || {};
    const doc = projected[item.position] || {};
    body.push({ index: { _index: assertManagedWriteTarget(SYNC_DLQ_INDEX) } });
    body.push({
      alert_uid: doc.alert_uid,
      source_index: doc.source_index,
      source_id: doc.source_id,
      timestamp: doc['@timestamp'],
      failed_at: now,
      attempts: 1,
      error: operation.error,
      source: doc,
    });
  }
  await client.bulk({ body });
}

async function archivedAlertStates(client: any, alertIds: string[]): Promise<Map<string, string>> {
  const states = new Map<string, string>();
  if (!alertIds.length) return states;
  const managed: any = await client.search({
    index: 'wazuh-alert-status-v2-*',
    body: {
      size: alertIds.length,
      query: { ids: { values: alertIds } },
      collapse: { field: 'alert_uid' },
      _source: false,
    },
  });
  const managedHits = managed?.body?.hits?.hits;
  if (!Array.isArray(managedHits)) throw new Error('Managed alert identity search returned no hits');
  for (const hit of managedHits) {
    if (isManagedPhysicalIndex(hit._index, 'wazuh-alert-status-v2-')) states.set(String(hit._id), 'managed');
  }
  const tombstoneIds = alertIds.map((id) => `${RETIRED_ALERT_DOC_PREFIX}${id}`);
  const tombstones: any = await client.mget({
    index: META_INDEX,
    body: { ids: tombstoneIds },
    _source: ['document_type', 'alert_uid', 'retiring_index'],
  });
  const tombstoneDocs = tombstones?.body?.docs;
  if (!Array.isArray(tombstoneDocs) || tombstoneDocs.length !== alertIds.length) {
    throw new Error('Purged alert tombstone lookup returned incomplete identity evidence');
  }
  const expectedTombstones = new Map(tombstoneIds.map((id, position) => [id, alertIds[position]]));
  const returnedTombstones = new Set<string>();
  for (const doc of tombstoneDocs) {
    const tombstoneId = typeof doc?._id === 'string' ? doc._id : '';
    const alertId = expectedTombstones.get(tombstoneId);
    if (!alertId || returnedTombstones.has(tombstoneId) || typeof doc?.found !== 'boolean') {
      throw new Error('Purged alert tombstone lookup returned malformed identity evidence');
    }
    returnedTombstones.add(tombstoneId);
    if (doc.found === false) continue;
    const source = doc._source;
    if (source?.document_type !== 'retired_alert' || source?.alert_uid !== alertId ||
        typeof source?.retiring_index !== 'string' ||
        !isManagedPhysicalIndex(source.retiring_index, 'wazuh-alert-status-v2-')) {
      throw new Error(`Purged alert tombstone ${tombstoneId} is malformed`);
    }
    states.set(alertId, 'purged');
  }
  const records: any = await client.search({
    index: META_INDEX,
    body: {
      size: MAX_RETIREMENT_RECORDS,
      track_total_hits: true,
      // _id prefix queries are not supported on _id; retire_by status is the
      // mapped discriminator. Activity retirement records share `completed`,
      // so the loop below skips anything whose retiring_index is not an alert
      // generation.
      query: { terms: { status: ['completed', 'restored', 'purging'] } },
      _source: ['status', 'retiring_index'],
    },
  });
  const hits = records?.body?.hits?.hits;
  if (!Array.isArray(hits)) throw new Error('Retirement metadata search returned no hits');
  const rawTotal = records?.body?.hits?.total;
  const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal?.value ?? hits.length);
  if (total > hits.length) throw new Error(`Retirement metadata exceeds safe scan limit (${MAX_RETIREMENT_RECORDS})`);
  for (const hit of hits) {
    const record = hit._source || {};
    if (!['completed', 'restored', 'purging'].includes(record.status)) continue;
    if (typeof record.retiring_index !== 'string') {
      throw new Error(`Retirement metadata ${hit._id || '<unknown>'} is incomplete`);
    }
    if (!isManagedPhysicalIndex(record.retiring_index, 'wazuh-alert-status-v2-')) continue;
    const archived: any = await client.mget({
      index: record.retiring_index,
      body: { ids: alertIds },
      _source: false,
    });
    const docs = archived?.body?.docs;
    if (!Array.isArray(docs) || docs.length !== alertIds.length) {
      throw new Error(`Archive ${record.retiring_index} returned incomplete identity evidence`);
    }
    const returnedIds = new Set<string>();
    for (const doc of docs) {
      const id = typeof doc?._id === 'string' ? doc._id : '';
      if (!alertIds.includes(id) || returnedIds.has(id) || typeof doc?.found !== 'boolean') {
        throw new Error(`Archive ${record.retiring_index} returned malformed identity evidence`);
      }
      returnedIds.add(id);
      if (doc.found === false) continue;
      const current = states.get(id);
      if (!current || ARCHIVE_STATE_PRIORITY[record.status] > ARCHIVE_STATE_PRIORITY[current]) {
        states.set(id, record.status);
      }
    }
  }
  return states;
}

async function createSourcePit(client: any, index: string, keepAlive: string): Promise<any> {
  if (typeof client.createPit === 'function') {
    return client.createPit({ index, keep_alive: keepAlive });
  }
  // OpenSearch Dashboards 2.19 defaults to the 1.x JS client, whose generated
  // API predates PIT even though its OpenSearch server supports the REST API.
  if (typeof client.transport?.request === 'function') {
    return client.transport.request({
      method: 'POST',
      path: `/${index}/_search/point_in_time`,
      querystring: { keep_alive: keepAlive },
    });
  }
  throw new Error('OpenSearch client does not support point-in-time requests');
}

async function deleteSourcePit(client: any, pitId: string): Promise<void> {
  const body = { pit_id: [pitId] };
  if (typeof client.deletePit === 'function') {
    await client.deletePit({ body });
    return;
  }
  if (typeof client.transport?.request === 'function') {
    await client.transport.request({ method: 'DELETE', path: '/_search/point_in_time', body });
  }
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
  assertSafeSourcePattern(config.sync.sourceIndexPattern);
  try {
    await reconcileAutomationAdmissions(client);
  } catch (e: any) {
    logger.error(`wazuh-alert-manager sync: automation admission reconciliation failed: ${e.message}`);
  }
  const state = await getSyncState(client, config);
  const overlapMs = config.sync.overlapSeconds * 1000;
  const windowFrom =
    state.window_from || new Date(new Date(state.completed_at).getTime() - overlapMs).toISOString();
  const windowTo = state.window_to || new Date().toISOString();

  const must: any[] = [{ range: { '@timestamp': { gte: windowFrom, lte: windowTo } } }];
  if (config.sync.minRuleLevel != null) {
    must.push({ range: { 'rule.level': { gte: config.sync.minRuleLevel } } });
  }

  const keepAlive = `${Math.max(ttlSeconds, 120)}s`;
  let pitId = state.pit_id || null;
  if (!pitId) {
    try {
      const pit: any = await createSourcePit(client, config.sync.sourceIndexPattern, keepAlive);
      pitId = pit?.body?.pit_id || pit?.body?.id;
      if (!pitId) throw new Error('OpenSearch returned no PIT id');
    } catch (e: any) {
      logger.error(`wazuh-alert-manager sync: failed to open source PIT: ${e.message}`);
      return;
    }
  }

  let hits: any[] = [];
  try {
    const results: any = await client.search({
      size: config.sync.batchSize,
      body: {
        pit: { id: pitId, keep_alive: keepAlive },
        query: { bool: { must } },
        // PIT freezes the shard view while _doc is the sortable, efficient
        // tie-breaker supported by the OpenSearch versions shipped by Wazuh.
        // If the PIT expires, we restart this frozen window from
        // its beginning; idempotent upserts may replay documents but skip none.
        sort: [{ '@timestamp': { order: 'asc' } }, { _doc: { order: 'asc' } }],
        ...(state.search_after ? { search_after: state.search_after } : {}),
      },
    });
    hits = results?.body?.hits?.hits || [];
  } catch (e: any) {
    logger.error(`wazuh-alert-manager sync: failed to query source index: ${e.message}`);
    // A search_after value is meaningful only for the PIT that produced it.
    // Clear both together so expiry or node loss causes safe replay, not gaps.
    try {
      await setSyncState(client, {
        completed_at: state.completed_at,
        window_from: windowFrom,
        window_to: windowTo,
        search_after: null,
        pit_id: null,
      });
    } catch (stateError: any) {
      logger.error(`wazuh-alert-manager sync: failed to reset source PIT cursor: ${stateError.message}`);
    }
    return;
  }

  if (hits.length === 0) {
    await setSyncState(client, {
      completed_at: windowTo,
      window_from: null,
      window_to: null,
      search_after: null,
      pit_id: null,
    });
    try {
      await deleteSourcePit(client, pitId);
    } catch (e: any) {
      logger.debug(`wazuh-alert-manager sync: source PIT cleanup failed: ${e.message}`);
    }
    return;
  }

  // When the batch is full there are more alerts in this window than one tick
  // can carry. Advance the watermark only as far as the last alert we actually
  // copied (they are sorted ascending), so the next tick resumes from there
  // and nothing is skipped. Only an empty/partial batch is safe to fast-forward
  // to `now`.
  const batchFull = hits.length >= config.sync.batchSize;
  const nextSearchAfter = hits[hits.length - 1]?.sort || null;
  if (batchFull) {
    logger.warn(
      `wazuh-alert-manager sync: batch size limit (${config.sync.batchSize}) reached for window ${windowFrom} - ${windowTo}. ` +
        'Continuing with a persisted search_after cursor on the next tick.'
    );
  }

  // Re-validate we still hold the lock before writing - the search above can
  // take long enough that another replica has already taken over the lease.
  if (!(await acquireOrRenewLock(client, holderId, ttlSeconds, logger))) {
    logger.warn('wazuh-alert-manager sync: lost the sync lock before bulk upsert, aborting this tick');
    return;
  }

  const projected = hits.map((hit) => projectOperationalAlert(hit));
  let existingLocations: Map<string, any>;
  let archivedStates: Map<string, string>;
  try {
    const alertIds = projected.map((doc) => doc.alert_uid);
    [existingLocations, archivedStates] = await Promise.all([
      resolveAlerts(client, alertIds),
      archivedAlertStates(client, alertIds),
    ]);
  } catch (e: any) {
    logger.error(`wazuh-alert-manager sync: failed to resolve managed alert evidence: ${e.message}`);
    return;
  }

  // Staged queue documents form the durable per-alert outbox. Write them
  // before the operational upsert so a crash can never leave a newly inserted
  // alert in the gap between storage and automation admission.
  // Existing operational documents are overlap/upgrade replay and are not
  // admitted; a genuinely new late alert is admitted regardless of timestamp.
  const automationEvents = projected.filter((doc) =>
    !existingLocations.has(doc.alert_uid) && !archivedStates.has(doc.alert_uid)
  );
  let activatableAutomationEvents: typeof automationEvents = [];
  try {
    const enqueueResult = await enqueueAutomationEvents(client, automationEvents);
    const candidateIds = new Set<string>(enqueueResult.candidateAlertUids || automationEvents.map((event) => event.alert_uid));
    activatableAutomationEvents = automationEvents.filter((event) => candidateIds.has(event.alert_uid));
    if (enqueueResult.failed) {
      logger.error(
        `wazuh-alert-manager sync: ${enqueueResult.failed}/${automationEvents.length} automation queue items failed and were recorded in the automation DLQ`
      );
    }
  } catch (error: any) {
    logger.error(`wazuh-alert-manager sync: automation enqueue failed: ${error.message}`);
    if (error.automationAdmissionUnsafe) {
      logger.error('wazuh-alert-manager sync: ingestion aborted because no durable automation admission marker exists');
      return;
    }
    try {
      await recordAutomationEnqueueFailure(client, automationEvents, error);
    } catch (dlqError: any) {
      logger.error(`wazuh-alert-manager sync: automation enqueue failure could not be recorded: ${dlqError.message}`);
    }
  }

  const body: any[] = [];
  const writableProjected: any[] = [];
  for (const doc of projected) {
    // A completed retirement is authoritative for archive-only documents.
    // Explicitly restored records may repair a missing live projection, but
    // their prior managed identity still prevents first-ingestion automation.
    const archivedState = archivedStates.get(doc.alert_uid);
    if (!existingLocations.has(doc.alert_uid) &&
        (archivedState === 'managed' || archivedState === 'completed' || archivedState === 'purging' ||
         archivedState === 'purged')) continue;
    // After rollover an existing alert still belongs to its original physical
    // generation. Updating the write alias would create the same _id in the
    // new generation during overlap replay, so resolve existing documents and
    // reserve the write alias strictly for genuinely new alerts.
    const target = existingLocations.get(doc.alert_uid)?.index || ALERTS_WRITE_ALIAS;
    writableProjected.push(doc);
    body.push({ update: { _index: assertManagedWriteTarget(target), _id: doc.alert_uid } });
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
          // Protected workflow fields must not be overwritten on overlap
          // replay, but a scripted upsert starts with an empty document. Seed
          // the immutable admission boundary and workflow defaults once (and
          // repair early v2 documents that were created without them).
          if (ctx._source.ingested_at == null) {
            ctx._source.ingested_at = params.doc.ingested_at;
          }
          if (ctx._source.state_version == null) {
            ctx._source.state_version = params.doc.state_version;
          }
          if (ctx._source.status == null) {
            ctx._source.status = params.doc.status == null ? 'open' : params.doc.status;
          }
          if (!ctx._source.containsKey('case_id')) {
            ctx._source.case_id = params.doc.case_id;
          }
          if (!ctx._source.containsKey('assigned_to')) {
            ctx._source.assigned_to = params.doc.assigned_to;
          }
          if (!ctx._source.containsKey('related_alert_ids')) {
            ctx._source.related_alert_ids = params.doc.related_alert_ids;
          }
        `,
        params: { doc, protected: PLUGIN_OWNED_FIELDS },
      },
    });
  }

  try {
    // Publish the whole sync batch once. Automation workers can then resolve
    // every queued document without forcing an expensive index refresh for
    // each individual alert.
    const operationChunks: any[][] = [];
    const docsPerChunk = 1000;
    for (let offset = 0; offset < body.length; offset += docsPerChunk * 2) {
      operationChunks.push(body.slice(offset, offset + docsPerChunk * 2));
    }
    const chunkResults: any[] = new Array(operationChunks.length);
    let chunkCursor = 0;
    const bulkWorkers = Array.from(
      { length: Math.min(2, operationChunks.length) },
      async () => {
        while (chunkCursor < operationChunks.length) {
          const position = chunkCursor++;
          const chunk = operationChunks[position];
          const last = position === operationChunks.length - 1;
          chunkResults[position] = await client.bulk({
            body: chunk,
            // Tests and older clients without an indices namespace still
            // receive the original visibility guarantee. Production performs
            // one explicit refresh after both bounded request lanes finish.
            ...(!client.indices?.refresh && last ? { refresh: 'wait_for' } : {}),
          });
        }
      }
    );
    await Promise.all(bulkWorkers);
    const bulkItems: any[] = [];
    let bulkErrors = false;
    for (const response of chunkResults) {
      bulkErrors = bulkErrors || response?.body?.errors === true;
      bulkItems.push(...(response?.body?.items || []));
    }
    if (body.length && client.indices?.refresh) {
      await client.indices.refresh({
        index: Array.from(new Set(body
          .filter((item: any) => item.update?._index)
          .map((item: any) => item.update._index))),
      });
    }
    if (bulkErrors || bulkItems.length !== writableProjected.length) {
      const failed = bulkItems
        .map((item: any, position: number) => ({ item, position }))
        .filter((x: any) => x.item.update?.error);
      try {
        await recordDlq(client, failed, writableProjected);
      } catch (dlqError: any) {
        logger.error(`wazuh-alert-manager sync: failed to record DLQ items: ${dlqError.message}`);
      }
      logger.error(
        `wazuh-alert-manager sync: ${failed.length || 'incomplete response'}/${hits.length} bulk updates failed. First error: ${JSON.stringify(
          failed[0]?.item?.update?.error
        )}`
      );
      // Do not advance the cursor past an unaccounted source document. The
      // successful upserts are idempotent and will replay on the next tick.
      return;
    }
  } catch (e: any) {
    logger.error(`wazuh-alert-manager sync: bulk upsert failed: ${e.message}`);
    return; // don't advance the watermark if the write failed entirely
  }

  try {
    await activateAutomationEvents(client, activatableAutomationEvents);
  } catch (e: any) {
    // Keep the cursor in place. Staged records are also recovered by the
    // automation admission reconciler, so a crash here cannot create a gap.
    logger.error(`wazuh-alert-manager sync: automation activation failed: ${e.message}`);
    return;
  }

  // Re-validate again before committing the watermark - the bulk upsert
  // itself can be what pushes this tick past the lease.
  if (!(await acquireOrRenewLock(client, holderId, ttlSeconds, logger))) {
    logger.warn('wazuh-alert-manager sync: lost the sync lock before committing the watermark, aborting this tick');
    return;
  }

  await setSyncState(
    client,
    batchFull
      ? {
          completed_at: state.completed_at,
          window_from: windowFrom,
          window_to: windowTo,
          search_after: nextSearchAfter,
          pit_id: pitId,
        }
      : {
          completed_at: windowTo,
          window_from: null,
          window_to: null,
          search_after: null,
          pit_id: null,
        }
  );
  if (!batchFull) {
    try {
      await deleteSourcePit(client, pitId);
    } catch (e: any) {
      logger.debug(`wazuh-alert-manager sync: source PIT cleanup failed: ${e.message}`);
    }
  }
  logger.debug(
    `wazuh-alert-manager sync: copied ${hits.length} alerts (${windowFrom} - ${windowTo}); ` +
      (batchFull ? 'window cursor checkpointed' : `watermark now ${windowTo}`)
  );
  return batchFull;
}

export function startSyncJob(client: any, config: AlertManagerConfigType, logger: Logger): () => void {
  let stopped = false;
  const holderId = generateHolderId();
  let holdingLock = false;
  // Guards against a tick still being in flight (e.g. a slow search/bulk)
  // when the next setInterval fire comes around, which would otherwise let
  // this same process run two overlapping runSyncOnce calls.
  let running = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let nextIntervalSeconds = config.sync.intervalSeconds;

  const schedule = (delayMs = nextIntervalSeconds * 1000) => {
    if (!stopped) timer = setTimeout(tick, delayMs);
  };

  const tick = async () => {
    if (stopped || running) return;
    running = true;
    let continueWindowImmediately = false;
    const runtime = await loadSyncSettings(client, config);
    nextIntervalSeconds = runtime.intervalSeconds;
    const ttlSeconds = Math.max(runtime.intervalSeconds * 3, 120);
    if (!runtime.enabled) {
      running = false;
      schedule();
      return;
    }
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
        return runSyncOnce(client, config, logger, holderId, ttlSeconds)
          .then((batchFull) => { continueWindowImmediately = batchFull === true; });
      })
      .catch((e) => logger.error(`wazuh-alert-manager sync: unexpected error: ${e.message}`))
      .finally(() => {
        running = false;
        // A full batch means a persisted PIT cursor still has unread alerts in
        // the same frozen window. Continue immediately instead of idling for a
        // normal polling interval; interval pacing resumes after the window is
        // drained or on any failure.
        schedule(continueWindowImmediately ? 0 : nextIntervalSeconds * 1000);
      });
  };

  tick();

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    if (holdingLock) {
      releaseLock(client, holderId, logger).catch(() => {});
    }
  };
}
