import { Logger } from '../../../../src/core/server';
import { MIGRATION_INDEX, RULES_INDEX } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { normalizeEntityExpression } from './entity_expression';

export const CANONICAL_RULE_SCHEMA_VERSION = 2;
export const DEFAULT_CASE_ROUTING = 'separate_by_group';

const MIGRATION_ID = 'saved-rule-schema-v2';
const LOCK_ID = `${MIGRATION_ID}-lock`;
const BATCH_SIZE = 200;
const LEASE_MS = 5 * 60 * 1000;
const WAIT_MS = 250;

/** Convert legacy rule shapes to the canonical write schema without touching storage metadata or counters. */
export function canonicalizeRuleSchema(input: any): any {
  const output = { ...input };
  const sourceTrigger = input.trigger || {};
  const legacyEntity = sourceTrigger.entity || input.entity;
  const windowMinutes = sourceTrigger.windowMinutes ?? input.windowMinutes;
  const threshold = sourceTrigger.threshold ?? input.threshold;
  const type = sourceTrigger.type || (legacyEntity ? 'burst' : 'per_alert');
  const expression = sourceTrigger.entityExpression ||
    (legacyEntity
      ? {
          version: 1,
          groups: [
            {
              id: 'group-1',
              order: 0,
              predicates: [{ id: 'predicate-1', order: 0, entity: legacyEntity, operator: 'exists' }],
            },
          ],
        }
      : { version: 1, groups: [] });
  const defaultPeriod = type === 'burst' && Number.isInteger(windowMinutes) ? windowMinutes : 0;

  output.schemaVersion = CANONICAL_RULE_SCHEMA_VERSION;
  if (!input.actions && input.caseSeverity) {
    output.actions = { createCase: true, caseSeverity: input.caseSeverity };
  }
  output.trigger = {
    type,
    entityExpression: normalizeEntityExpression(expression),
    routing: sourceTrigger.routing || DEFAULT_CASE_ROUTING,
    cooldown: sourceTrigger.cooldown || { durationMinutes: defaultPeriod },
    rearm: sourceTrigger.rearm || {
      type: type === 'burst' ? 'after_quiet_period' : 'immediate',
      quietPeriodMinutes: defaultPeriod,
    },
    ...(type === 'burst' ? { windowMinutes, threshold } : {}),
  };
  delete output.entity;
  delete output.windowMinutes;
  delete output.threshold;
  delete output.caseSeverity;
  return output;
}

function canonicalJson(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function state(client: any): Promise<any> {
  try {
    const result: any = await client.get({ index: MIGRATION_INDEX, id: MIGRATION_ID });
    return result.body?._source || {};
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) === 404) return {};
    throw error;
  }
}

async function saveState(client: any, fields: any) {
  await client.index({
    index: assertManagedWriteTarget(MIGRATION_INDEX),
    id: MIGRATION_ID,
    refresh: 'wait_for',
    body: { migration_id: MIGRATION_ID, ...fields, updated_at: new Date().toISOString() },
  });
}

async function acquireLease(client: any, holderId: string): Promise<boolean> {
  const body = {
    holder_id: holderId,
    expires_at: new Date(Date.now() + LEASE_MS).toISOString(),
    updated_at: new Date().toISOString(),
  };
  try {
    await client.create({ index: assertManagedWriteTarget(MIGRATION_INDEX), id: LOCK_ID, body });
    return true;
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) !== 409) throw error;
  }
  const current: any = await client.get({ index: MIGRATION_INDEX, id: LOCK_ID });
  const source = current.body?._source || {};
  if (source.holder_id !== holderId && Date.parse(source.expires_at || '') > Date.now()) return false;
  try {
    await client.index({
      index: assertManagedWriteTarget(MIGRATION_INDEX),
      id: LOCK_ID,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body,
    });
    return true;
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) === 409) return false;
    throw error;
  }
}

async function releaseLease(client: any, holderId: string) {
  try {
    const current: any = await client.get({ index: MIGRATION_INDEX, id: LOCK_ID });
    if (current.body?._source?.holder_id !== holderId) return;
    await client.delete({
      index: assertManagedWriteTarget(MIGRATION_INDEX),
      id: LOCK_ID,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
    });
  } catch (error: any) {
    // The lease expires naturally; release is only a startup latency optimization.
  }
}

async function ownsLease(client: any, holderId: string): Promise<boolean> {
  try {
    const current: any = await client.get({ index: MIGRATION_INDEX, id: LOCK_ID });
    return current.body?._source?.holder_id === holderId &&
      Date.parse(current.body?._source?.expires_at || '') > Date.now();
  } catch (error) {
    return false;
  }
}

async function writeCanonicalRule(client: any, hit: any): Promise<boolean> {
  let current = hit;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const canonical = canonicalizeRuleSchema(current._source || {});
    if (canonicalJson(canonical) === canonicalJson(current._source || {})) return false;
    try {
      await client.index({
        index: assertManagedWriteTarget(RULES_INDEX),
        id: current._id,
        if_seq_no: current._seq_no,
        if_primary_term: current._primary_term,
        body: canonical,
        refresh: 'wait_for',
      });
      return true;
    } catch (error: any) {
      if ((error?.meta?.statusCode || error?.statusCode) !== 409) throw error;
      const latest: any = await client.get({ index: RULES_INDEX, id: current._id });
      if (latest.body?._source?.document_type === 'rule_revision') return false;
      current = { _id: current._id, ...latest.body };
    }
  }
  throw new Error(`Rule ${hit._id} changed repeatedly during schema migration`);
}

/**
 * Upgrade all persisted primary rules before workers can observe them. Scroll
 * cursors are deliberately ephemeral: interruption resumes by replaying the
 * idempotent scan, while OCC prevents overwriting a concurrent route update.
 */
export async function migrateSavedRuleSchemas(client: any, logger: Logger): Promise<void> {
  if ((await state(client)).status === 'completed') return;
  const holderId = `rule-schema-${process.pid}-${Math.random().toString(16).slice(2)}`;

  while (!(await acquireLease(client, holderId))) {
    if ((await state(client)).status === 'completed') return;
    await new Promise((resolve) => setTimeout(resolve, WAIT_MS));
  }

  let scrollId: string | undefined;
  let scanned = 0;
  let migrated = 0;
  try {
    if ((await state(client)).status === 'completed') return;
    await saveState(client, { status: 'running', scanned: 0, migrated: 0, checkpoint: 'idempotent_replay' });
    let page: any = await client.search({
      index: RULES_INDEX,
      scroll: '2m',
      size: BATCH_SIZE,
      body: {
        sort: ['_doc'],
        seq_no_primary_term: true,
        query: { bool: { must_not: [{ exists: { field: 'document_type' } }] } },
      },
    });
    for (;;) {
      scrollId = page.body?._scroll_id || scrollId;
      const hits = page.body?.hits?.hits || [];
      if (!hits.length) break;
      for (const hit of hits) {
        scanned += 1;
        if (await writeCanonicalRule(client, hit)) migrated += 1;
      }
      if (!(await acquireLease(client, holderId))) throw new Error('Lost saved-rule schema migration lease');
      await saveState(client, { status: 'running', scanned, migrated, checkpoint: 'idempotent_replay' });
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
    if (!(await acquireLease(client, holderId))) throw new Error('Lost saved-rule schema migration lease');
    await saveState(client, { status: 'completed', scanned, migrated, checkpoint: null, completed_at: new Date().toISOString() });
    logger.info(`wazuh-alert-manager rule migration: canonicalized ${migrated} of ${scanned} saved rules`);
  } catch (error: any) {
    if (await ownsLease(client, holderId)) {
      await saveState(client, { status: 'failed', scanned, migrated, checkpoint: 'idempotent_replay', error: error.message });
    }
    throw error;
  } finally {
    if (scrollId) {
      try { await client.clearScroll({ scrollId }); } catch (error) { /* expired scroll */ }
    }
    await releaseLease(client, holderId);
  }
}
