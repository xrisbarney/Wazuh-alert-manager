import crypto from 'crypto';
import { Logger } from '../../../../src/core/server';
import {
  ACTIVITY_WRITE_ALIAS,
  ALERTS_READ_ALIAS,
  ALERTS_WRITE_ALIAS,
  CASES_WRITE_ALIAS,
  LEGACY_ALERT_STATUS_INDEX,
  LEGACY_CASES_INDEX,
  LEGACY_COMMENTS_INDEX,
  LEGACY_META_INDEX,
  LEGACY_RULES_INDEX,
  META_INDEX,
  MIGRATION_INDEX,
  RULES_INDEX,
  AI_SETTINGS_DOC_ID,
} from '../../common';
import { AlertManagerConfigType } from '../config';
import { assertManagedWriteTarget, assertSafeSourcePattern } from './index_namespace';
import { projectLegacyOperationalAlert } from './operational_projection';
import { canonicalizeRuleSchema } from './rule_schema_migration';
import { acquireOrRenewLock, generateHolderId, releaseLock } from './sync_lock';

const MIGRATION_ID = 'legacy-v1-to-v2';
const MIGRATION_LOCK_ID = 'migration-lock';
const MAX_SCROLL_BATCH_SIZE = 500;

async function exists(client: any, index: string): Promise<boolean> {
  try {
    const res: any = await client.indices.exists({ index });
    return Boolean(res.body);
  } catch (e) {
    return false;
  }
}

function eventId(parts: any[]): string {
  return crypto.createHash('sha256').update(parts.map((p) => String(p ?? '')).join('\u0000')).digest('hex');
}

async function saveState(client: any, fields: Record<string, any>) {
  await client.index({
    index: assertManagedWriteTarget(MIGRATION_INDEX),
    id: MIGRATION_ID,
    body: { migration_id: MIGRATION_ID, ...fields, updated_at: new Date().toISOString() },
    refresh: 'wait_for',
  });
}

async function loadState(client: any): Promise<any> {
  try {
    const res: any = await client.get({ index: MIGRATION_INDEX, id: MIGRATION_ID });
    return res.body._source || {};
  } catch (e) {
    return {};
  }
}

function assertBulkSucceeded(result: any, expectedItems: number, message: string) {
  const items: any[] = result?.body?.items || [];
  const failed = items.some((item) => {
    const operation: any = Object.values(item || {})[0];
    const status = Number(operation?.status);
    return !operation || operation.error || !Number.isInteger(status) || status < 200 || status >= 300;
  });
  if (result?.body?.errors || items.length !== expectedItems || failed) throw new Error(message);
}

function insertOnlyUpdate(index: string, id: string, doc: any): any[] {
  return [
    { update: { _index: assertManagedWriteTarget(index), _id: id } },
    {
      upsert: doc,
      script: { lang: 'painless', source: "ctx.op = 'none'" },
    },
  ];
}

async function sourceLocations(client: any, sourcePattern: string, legacyHits: any[]): Promise<Map<string, any>> {
  const ids = legacyHits.map((h) => h._id);
  const found = new Map<string, any[]>();
  if (!ids.length) return new Map();
  try {
    const res: any = await client.search({
      index: assertSafeSourcePattern(sourcePattern),
      body: { size: Math.min(ids.length * 3, 10000), query: { ids: { values: ids } } },
    });
    for (const hit of res.body.hits.hits || []) {
      const values = found.get(hit._id) || [];
      values.push(hit);
      found.set(hit._id, values);
    }
  } catch (e) {
    return new Map();
  }

  const resolved = new Map<string, any>();
  for (const legacy of legacyHits) {
    const candidates = found.get(legacy._id) || [];
    if (candidates.length === 1) {
      resolved.set(legacy._id, candidates[0]);
      continue;
    }
    const src = legacy._source || {};
    const exact = candidates.filter(
      (h) =>
        h._source?.['@timestamp'] === src['@timestamp'] &&
        String(h._source?.rule?.id ?? '') === String(src.rule?.id ?? '') &&
        String(h._source?.agent?.name ?? '') === String(src.agent?.name ?? '')
    );
    if (exact.length === 1) resolved.set(legacy._id, exact[0]);
  }
  return resolved;
}

async function migrateAlertBatch(client: any, hits: any[], sourcePattern: string) {
  const locations = await sourceLocations(client, sourcePattern, hits);
  const projected = hits.map((hit) => {
    const location = locations.get(hit._id);
    const doc = projectLegacyOperationalAlert(
      hit,
      location ? { index: location._index, id: location._id } : null
    );
    doc.legacy_id = hit._id;
    doc.migrated_from_legacy = true;
    return doc;
  });

  const alertBody: any[] = [];
  const mapBody: any[] = [];
  const activityBody: any[] = [];
  projected.forEach((doc, i) => {
    const legacy = hits[i];
    alertBody.push({ update: { _index: assertManagedWriteTarget(ALERTS_WRITE_ALIAS), _id: doc.alert_uid } });
    alertBody.push({
      scripted_upsert: true,
      upsert: doc,
      script: {
        lang: 'painless',
        source: `
          if (ctx._source.migrated_from_legacy != true) {
            for (entry in params.doc.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }
          }
        `,
        params: { doc },
      },
    });
    mapBody.push({ index: { _index: assertManagedWriteTarget(MIGRATION_INDEX), _id: `alert:${legacy._id}` } });
    mapBody.push({
      migration_id: MIGRATION_ID,
      legacy_id: legacy._id,
      alert_uid: doc.alert_uid,
      source_index: doc.source_index,
      source_resolved: doc.source_resolved,
      updated_at: new Date().toISOString(),
    });
    const history: any[] = legacy._source?.history || [];
    history.forEach((entry, ordinal) => {
      activityBody.push(
        ...insertOnlyUpdate(
          ACTIVITY_WRITE_ALIAS,
          eventId(['legacy-history', legacy._id, entry.timestamp, entry.action, ordinal]),
          {
            event_type: 'audit',
            target_type: 'alert',
            target_id: doc.alert_uid,
            alert_id: doc.alert_uid,
            timestamp: entry.timestamp,
            created_at: entry.timestamp,
            user: entry.user,
            author: entry.user,
            action: entry.action,
            from: entry.from ?? null,
            to: entry.to ?? null,
            source: 'legacy_migration',
          }
        )
      );
    });
  });

  const alertRes: any = await client.bulk({ body: alertBody });
  assertBulkSucceeded(alertRes, projected.length, 'One or more legacy alert documents failed to migrate');
  const mapRes: any = await client.bulk({ body: mapBody });
  assertBulkSucceeded(mapRes, projected.length, 'One or more legacy alert identity mappings failed to migrate');
  if (activityBody.length) {
    const activityRes: any = await client.bulk({ body: activityBody });
    assertBulkSucceeded(
      activityRes,
      activityBody.length / 2,
      'One or more legacy history events failed to migrate'
    );
  }
  return projected.length;
}

async function mapLegacyIds(client: any, ids: string[]): Promise<Map<string, string>> {
  const unique = Array.from(new Set(ids.filter(Boolean)));
  const out = new Map<string, string>();
  if (!unique.length) return out;
  const res: any = await client.mget({
    index: MIGRATION_INDEX,
    body: { ids: unique.map((id) => `alert:${id}`) },
  });
  for (const doc of res.body.docs || []) {
    if (doc.found && doc._source?.legacy_id && doc._source?.alert_uid) {
      out.set(doc._source.legacy_id, doc._source.alert_uid);
    }
  }
  return out;
}

async function forEachPage(
  client: any,
  index: string,
  query: any,
  handler: (hits: any[]) => Promise<void>,
  source: any = true,
  batchSize = MAX_SCROLL_BATCH_SIZE
) {
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index,
      scroll: '2m',
      size: Math.min(batchSize, MAX_SCROLL_BATCH_SIZE),
      body: { query, sort: ['_doc'], _source: source },
    });
    for (;;) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      await handler(hits);
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // An expired scroll has already released its resources.
      }
    }
  }
}

async function remapRelatedAlertIds(client: any, batchSize: number) {
  await forEachPage(
    client,
    ALERTS_READ_ALIAS,
    {
      bool: {
        filter: [{ term: { migrated_from_legacy: true } }, { exists: { field: 'related_alert_ids' } }],
      },
    },
    async (hits) => {
      const legacyIds = hits.flatMap((hit) => hit._source?.related_alert_ids || []);
      const map = await mapLegacyIds(client, legacyIds);
      const bulk: any[] = [];
      for (const hit of hits) {
        const related = (hit._source?.related_alert_ids || [])
          .map((id: string) => map.get(id))
          .filter(Boolean);
        bulk.push({ update: { _index: assertManagedWriteTarget(hit._index), _id: hit._id } });
        bulk.push({
          script: {
            lang: 'painless',
            source: `
              if (ctx._source.legacy_related_ids_migrated != true) {
                ctx._source.related_alert_ids = params.related;
                ctx._source.legacy_related_ids_migrated = true;
              }
            `,
            params: { related },
          },
        });
      }
      if (bulk.length) {
        const result: any = await client.bulk({ body: bulk });
        assertBulkSucceeded(result, bulk.length / 2, 'One or more related-alert references failed to migrate');
      }
    },
    true,
    batchSize
  );
}

async function migrateCases(client: any, batchSize: number) {
  if (!(await exists(client, LEGACY_CASES_INDEX))) return;
  await forEachPage(
    client,
    LEGACY_CASES_INDEX,
    { match_all: {} },
    async (hits) => {
      const ids = hits.flatMap((hit) => hit._source?.alert_ids || []);
      const map = await mapLegacyIds(client, ids);
      const bulk: any[] = [];
      for (const hit of hits) {
        const source = hit._source || {};
        const doc = {
          ...source,
          case_uid: hit._id,
          alert_ids: (source.alert_ids || []).map((id: string) => map.get(id)).filter(Boolean),
        };
        bulk.push(...insertOnlyUpdate(CASES_WRITE_ALIAS, hit._id, doc));
      }
      if (bulk.length) {
        const result: any = await client.bulk({ body: bulk });
        assertBulkSucceeded(result, bulk.length / 2, 'One or more cases failed to migrate');
      }
    },
    true,
    batchSize
  );
}

async function migrateComments(client: any, batchSize: number) {
  if (!(await exists(client, LEGACY_COMMENTS_INDEX))) return;
  await forEachPage(client, LEGACY_COMMENTS_INDEX, { match_all: {} }, async (hits) => {
    const map = await mapLegacyIds(client, hits.map((hit) => hit._source?.alert_id).filter(Boolean));
    const bulk: any[] = [];
    for (const hit of hits) {
      const source = hit._source || {};
      const alertId = source.alert_id ? map.get(source.alert_id) || null : null;
      const doc = {
        event_type: 'comment',
        target_type: alertId ? 'alert' : 'case',
        target_id: alertId || source.case_id,
        alert_id: alertId,
        case_id: source.case_id || null,
        text: source.text,
        author: source.author,
        user: source.author,
        created_at: source.created_at,
        timestamp: source.created_at,
        source: 'legacy_migration',
      };
      bulk.push(...insertOnlyUpdate(ACTIVITY_WRITE_ALIAS, hit._id, doc));
    }
    if (bulk.length) {
      const result: any = await client.bulk({ body: bulk });
      assertBulkSucceeded(result, bulk.length / 2, 'One or more comments failed to migrate');
    }
  }, true, batchSize);
}

async function copyIndex(
  client: any,
  legacyIndex: string,
  targetIndex: string,
  batchSize: number,
  transform: (source: any) => any = (source) => source
) {
  if (!(await exists(client, legacyIndex))) return;
  await forEachPage(client, legacyIndex, { match_all: {} }, async (hits) => {
    const bulk: any[] = [];
    for (const hit of hits) bulk.push(...insertOnlyUpdate(targetIndex, hit._id, transform(hit._source)));
    if (bulk.length) {
      const result: any = await client.bulk({ body: bulk });
      assertBulkSucceeded(result, bulk.length / 2, `One or more documents from ${legacyIndex} failed to migrate`);
    }
  }, true, batchSize);
}

async function migrateAiSettings(client: any) {
  if (!(await exists(client, LEGACY_META_INDEX))) return;
  try {
    const res: any = await client.get({ index: LEGACY_META_INDEX, id: AI_SETTINGS_DOC_ID });
    await client.create({ index: assertManagedWriteTarget(META_INDEX), id: AI_SETTINGS_DOC_ID, body: res.body._source });
  } catch (e: any) {
    if (e?.meta?.statusCode === 409) return;
    // AI settings were never configured; nothing to migrate.
  }
}

/**
 * Idempotent, non-destructive v1 -> v2 migration. Legacy indices are read only
 * and are deliberately retained after completion for operator-controlled
 * rollback and cleanup.
 */
export async function migrateLegacyData(client: any, config: AlertManagerConfigType, logger: Logger) {
  if (!config.migration.enabled || !(await exists(client, LEGACY_ALERT_STATUS_INDEX))) return;
  const prior = await loadState(client);
  if (prior.status === 'completed') return;

  const holderId = `${generateHolderId()}-${MIGRATION_LOCK_ID}`;
  if (!(await acquireOrRenewLock(client, holderId, 600, logger))) {
    logger.info('wazuh-alert-manager migration: another dashboard replica is migrating legacy data');
    return;
  }

  let migrated = Number(prior.migrated || 0);
  let phase = prior.phase === 'related-data' ? 'related-data' : 'alerts';
  let completedBatches = 0;
  const batchSize = Math.min(config.migration.batchSize, MAX_SCROLL_BATCH_SIZE);

  try {
    if (phase === 'alerts') {
      // Scroll IDs are intentionally not persisted. A restart replays the alert
      // phase from the beginning through deterministic, non-overwriting writes.
      migrated = 0;
      await saveState(client, {
        phase: 'alerts',
        status: 'running',
        started_at: prior.started_at || new Date().toISOString(),
        migrated,
        failed: 0,
        checkpoint: JSON.stringify({ strategy: 'idempotent_replay', completed_batches: completedBatches }),
      });
      await forEachPage(
        client,
        LEGACY_ALERT_STATUS_INDEX,
        { match_all: {} },
        async (hits) => {
          migrated += await migrateAlertBatch(client, hits, config.sync.sourceIndexPattern);
          completedBatches += 1;
          await saveState(client, {
            phase: 'alerts',
            status: 'running',
            started_at: prior.started_at || new Date().toISOString(),
            migrated,
            failed: 0,
            checkpoint: JSON.stringify({ strategy: 'idempotent_replay', completed_batches: completedBatches }),
          });
          if (!(await acquireOrRenewLock(client, holderId, 600, logger))) {
            throw new Error('Lost migration leader lock');
          }
        },
        true,
        batchSize
      );
    }

    phase = 'related-data';
    await saveState(client, { phase: 'related-data', status: 'running', migrated, failed: 0, checkpoint: null });
    await remapRelatedAlertIds(client, batchSize);
    await migrateCases(client, batchSize);
    await migrateComments(client, batchSize);
    await copyIndex(client, LEGACY_RULES_INDEX, RULES_INDEX, batchSize, canonicalizeRuleSchema);
    await migrateAiSettings(client);
    await saveState(client, {
      phase: 'complete',
      status: 'completed',
      migrated,
      failed: 0,
      checkpoint: null,
      completed_at: new Date().toISOString(),
      details: { legacy_indices_retained: true },
    });
    logger.info(`wazuh-alert-manager migration: migrated ${migrated} legacy alerts; legacy indices retained`);
  } catch (e: any) {
    await saveState(client, {
      phase,
      status: 'failed',
      migrated,
      failed: 1,
      checkpoint:
        phase === 'alerts'
          ? JSON.stringify({ strategy: 'idempotent_replay', completed_batches: completedBatches })
          : null,
      details: { message: e.message },
    });
    logger.error(`wazuh-alert-manager migration failed safely: ${e.message}`);
    throw e;
  } finally {
    await releaseLock(client, holderId, logger);
  }
}
