import * as os from 'os';
import * as crypto from 'crypto';
import { Logger } from '../../../../src/core/server';
import {
  AUTOMATION_ADMISSION_RECONCILE_BATCH,
  AUTOMATION_BULK_MAX_ACTIONS,
  AUTOMATION_BULK_MAX_BYTES,
  AUTOMATION_DEFAULT_MAX_BACKLOG,
  AUTOMATION_DEFAULT_MAX_DEFERRED,
  AUTOMATION_DLQ_INDEX,
  AUTOMATION_EXECUTIONS_INDEX,
  AUTOMATION_QUEUE_INDEX,
  AUTOMATION_MAX_ENABLED_RULES,
  AUTOMATION_MAX_RULE_SNAPSHOT_BYTES,
  AUTOMATION_RULESET_SNAPSHOT_PREFIX,
  AUTOMATION_SETTINGS_DOC_ID,
  AUTOMATION_WORKER_LEASE_ID,
  RULES_INDEX,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { evaluateCorrelationRules } from './correlation_eval';
import { evaluateAlertMatch } from './correlation';
import { evaluateEntityExpression } from './entity_expression';
import { normalizeAutomationRules } from './automation_planner';
import { resolveAlerts } from './index_resolution';

const MAX_ATTEMPTS = 8;
const BASE_BACKOFF_MS = 5000;
const MAX_BACKOFF_MS = 5 * 60 * 1000;
const DEFAULT_LEASE_SECONDS = 120;
const DEFAULT_POLL_MS = 5000;
const DEFAULT_WORKER_CONCURRENCY = 8;
// Amortize fixed rule-window and case-route costs across a bounded cohort.
// 256 projections remain well below the evaluator's 4,096-link safety limit
// while avoiding dozens of repeated reconciliation cycles at high volume.
const DEFAULT_WORKER_BATCH_SIZE = 256;
const ADMISSION_RECONCILE_INTERVAL_MS = 5000;
const SNAPSHOT_CACHE_SIZE = 32;

export interface AutomationEvent {
  alert_uid: string;
  [key: string]: any;
}

export interface AutomationSettings {
  paused: boolean;
  maxBacklog: number;
  maxDeferred: number;
}

export interface AutomationRulesetSnapshot {
  id: string;
  rules: any[];
  revisions: Array<{ id: string; revision: number }>;
}

interface AutomationAdmission {
  event: AutomationEvent;
  snapshotId: string;
  revisions: Array<{ id: string; revision: number }>;
  admissionCutoff?: string;
  workerLane?: number;
}

interface Fence {
  holderId: string;
  generation: number;
  token: string;
}

interface QueueClaim {
  id: string;
  source: any;
  fence: Fence;
}

const defaultSettings = (): AutomationSettings => ({
  paused: false,
  maxBacklog: AUTOMATION_DEFAULT_MAX_BACKLOG,
  maxDeferred: AUTOMATION_DEFAULT_MAX_DEFERRED,
});

function errorDetails(error: any) {
  return { message: error?.message || String(error), name: error?.name, statusCode: error?.meta?.statusCode };
}

function isConflict(error: any) {
  return error?.meta?.statusCode === 409;
}

function ownershipLostError() {
  return Object.assign(new Error('automation execution ownership was lost'), { ownershipLost: true });
}

function randomToken() {
  return crypto.randomBytes(16).toString('hex');
}

function bulkLineBytes(value: any): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8') + 1;
}

/** Split metadata/source pairs without ever splitting one bulk operation. */
export function chunkBulkPairs(body: any[]): any[][] {
  if (body.length % 2 !== 0) throw new Error('bulk body must contain metadata/source pairs');
  const chunks: any[][] = [];
  let chunk: any[] = [];
  let bytes = 0;
  for (let offset = 0; offset < body.length; offset += 2) {
    const pair = [body[offset], body[offset + 1]];
    const pairBytes = bulkLineBytes(pair[0]) + bulkLineBytes(pair[1]);
    if (pairBytes > AUTOMATION_BULK_MAX_BYTES) {
      throw new Error(`automation bulk item exceeds ${AUTOMATION_BULK_MAX_BYTES} bytes`);
    }
    if (chunk.length && (chunk.length / 2 >= AUTOMATION_BULK_MAX_ACTIONS || bytes + pairBytes > AUTOMATION_BULK_MAX_BYTES)) {
      chunks.push(chunk);
      chunk = [];
      bytes = 0;
    }
    chunk.push(...pair);
    bytes += pairBytes;
  }
  if (chunk.length) chunks.push(chunk);
  return chunks;
}

async function executeBulkPairs(client: any, body: any[]): Promise<any[]> {
  const chunks = chunkBulkPairs(body);
  const results: any[][] = new Array(chunks.length);
  // A 10k sync batch contains many bounded bulk requests. Sending a small
  // number concurrently removes network round-trip serialization while still
  // applying backpressure to OpenSearch and preserving item order for callers.
  const concurrency = Math.min(4, chunks.length);
  let cursor = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (cursor < chunks.length) {
      const position = cursor++;
      const chunk = chunks[position];
      const result: any = await client.bulk({ body: chunk });
      const chunkItems = result?.body?.items || [];
      if (chunkItems.length !== chunk.length / 2) throw new Error('automation bulk returned an incomplete item list');
      results[position] = chunkItems;
    }
  });
  await Promise.all(workers);
  const items: any[] = [];
  for (const result of results) {
    items.push(...result);
  }
  return items;
}

export function automationEventId(alertUid: string): string {
  return alertUid;
}

export function automationExecutionId(eventId: string, rulesetSnapshot = 'rules-v1'): string {
  return `event:${eventId}:rules:${rulesetSnapshot}`;
}

export function automationWorkerLane(eventId: string): number {
  const prefix = crypto.createHash('sha256').update(eventId).digest().readUInt32BE(0);
  return prefix % DEFAULT_WORKER_CONCURRENCY;
}

export function automationAdmissionLane(snapshot: AutomationRulesetSnapshot, event: AutomationEvent): number {
  const matchingRuleIds = candidateRuleIds(normalizeAutomationRules(snapshot.rules as any[]), event);
  // Shared rate-limit and trigger documents are rule-scoped. Rule-affine
  // sharding removes avoidable OCC contention while non-candidates retain the
  // full lane fan-out needed for high-volume negative traffic.
  return automationWorkerLane(matchingRuleIds.length ? matchingRuleIds.join('|') : automationEventId(event.alert_uid));
}

function candidateRuleIds(rules: ReturnType<typeof normalizeAutomationRules>, event: AutomationEvent): string[] {
  return rules
    .filter((rule) => {
      if (!rule.enabled || !evaluateAlertMatch(rule, event).matched) return false;
      const expression = rule.trigger.entityExpression;
      return !expression?.groups?.length || evaluateEntityExpression(expression, event).matched;
    })
    .map((rule) => rule.id)
    .sort();
}

export function retryDelayMs(attempts: number): number {
  return Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * Math.pow(2, Math.max(0, attempts - 1)));
}

export async function loadAutomationSettings(client: any): Promise<AutomationSettings> {
  try {
    const result: any = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: AUTOMATION_SETTINGS_DOC_ID });
    const source = result?.body?._source || {};
    return {
      paused: source.paused === true,
      maxBacklog: Math.max(1, Number(source.max_backlog) || AUTOMATION_DEFAULT_MAX_BACKLOG),
      maxDeferred: Math.max(1, Number(source.max_deferred) || AUTOMATION_DEFAULT_MAX_DEFERRED),
    };
  } catch (error: any) {
    if (error?.meta?.statusCode === 404) return defaultSettings();
    throw error;
  }
}

export async function ensureAutomationSettings(client: any): Promise<void> {
  const result: any = await client.search({
    index: AUTOMATION_EXECUTIONS_INDEX,
    body: { size: 0, query: { ids: { values: [AUTOMATION_SETTINGS_DOC_ID] } } },
  });
  const total = result?.body?.hits?.total;
  const count = typeof total === 'number' ? total : Number(total?.value || 0);
  if (count > 0) return;
  try {
    await client.create({
      index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX),
      id: AUTOMATION_SETTINGS_DOC_ID,
      body: {
        execution_id: AUTOMATION_SETTINGS_DOC_ID,
        state: 'settings',
        paused: false,
        max_backlog: AUTOMATION_DEFAULT_MAX_BACKLOG,
        max_deferred: AUTOMATION_DEFAULT_MAX_DEFERRED,
        updated_at: new Date().toISOString(),
        updated_by: 'system',
      },
    });
  } catch (error: any) {
    if (!isConflict(error)) throw error;
  }
}

export async function saveAutomationSettings(
  client: any,
  settings: AutomationSettings,
  updatedBy: string
): Promise<AutomationSettings> {
  const normalized = {
    paused: settings.paused === true,
    maxBacklog: Math.max(1, Math.floor(settings.maxBacklog)),
    maxDeferred: Math.max(1, Math.floor(settings.maxDeferred)),
  };
  await client.index({
    index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX),
    id: AUTOMATION_SETTINGS_DOC_ID,
    refresh: 'wait_for',
    body: {
      execution_id: AUTOMATION_SETTINGS_DOC_ID,
      state: 'settings',
      paused: normalized.paused,
      max_backlog: normalized.maxBacklog,
      max_deferred: normalized.maxDeferred,
      updated_at: new Date().toISOString(),
      updated_by: updatedBy,
    },
  });
  return normalized;
}

function canonicalize(value: any): any {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== 'object') return value;
  return Object.keys(value).sort().reduce((result: any, key) => {
    if (value[key] !== undefined) result[key] = canonicalize(value[key]);
    return result;
  }, {});
}

function snapshotRule(hit: any) {
  const source = hit._source || {};
  return canonicalize({
    id: hit._id,
    schemaVersion: source.schemaVersion,
    name: source.name,
    enabled: true,
    revision: Number(source.revision || 0),
    priority: source.priority,
    sortOrder: source.sortOrder,
    processingMode: source.processingMode,
    match: source.match,
    trigger: source.trigger,
    actions: source.actions,
    preconditions: source.preconditions,
    safety: source.safety,
    effective_from: source.effective_from,
    state_epoch: source.state_epoch,
    // Preserve the legacy definition inputs still normalized by the evaluator.
    entity: source.entity,
    windowMinutes: source.windowMinutes,
    threshold: source.threshold,
    caseSeverity: source.caseSeverity,
  });
}

async function captureRulesetSnapshot(client: any): Promise<AutomationRulesetSnapshot> {
  const result: any = await client.search({
    index: RULES_INDEX,
    body: {
      size: AUTOMATION_MAX_ENABLED_RULES + 1,
      track_total_hits: true,
      _source: [
        'schemaVersion', 'name', 'enabled', 'revision', 'priority', 'sortOrder', 'processingMode',
        'match', 'trigger', 'actions', 'preconditions', 'safety', 'effective_from', 'state_epoch',
        'entity', 'windowMinutes', 'threshold', 'caseSeverity',
      ],
      query: { term: { enabled: true } },
    },
  });
  const hits = result?.body?.hits?.hits || [];
  const rawTotal = result?.body?.hits?.total;
  const total = typeof rawTotal === 'number' ? rawTotal : rawTotal?.value;
  if (!Array.isArray(hits) || (typeof total === 'number' && total > AUTOMATION_MAX_ENABLED_RULES) || hits.length > AUTOMATION_MAX_ENABLED_RULES) {
    throw Object.assign(new Error(`Active automation rules exceed snapshot limit (${AUTOMATION_MAX_ENABLED_RULES})`), {
      automationRulesOverLimit: true,
    });
  }
  const rules = hits.map(snapshotRule).sort((left: any, right: any) => String(left.id).localeCompare(String(right.id)));
  const serialized = JSON.stringify(canonicalize(rules));
  if (Buffer.byteLength(serialized, 'utf8') > AUTOMATION_MAX_RULE_SNAPSHOT_BYTES) {
    throw Object.assign(
      new Error(`Active automation rule snapshot exceeds ${AUTOMATION_MAX_RULE_SNAPSHOT_BYTES} bytes`),
      { automationRulesOverLimit: true }
    );
  }
  return {
    id: crypto.createHash('sha256').update(serialized).digest('hex'),
    rules,
    revisions: rules.map((rule: any) => ({ id: rule.id, revision: rule.revision })),
  };
}

function snapshotDocumentId(snapshotId: string) {
  return `${AUTOMATION_RULESET_SNAPSHOT_PREFIX}${snapshotId}`;
}

// Ruleset snapshots are content-addressed and immutable. Cache them per
// OpenSearch client so high-volume workers do not reload and re-hash the same
// definition for every queued alert.
const rulesetSnapshotCaches = new WeakMap<object, Map<string, Promise<AutomationRulesetSnapshot>>>();

async function persistRulesetSnapshot(client: any, snapshot: AutomationRulesetSnapshot): Promise<void> {
  try {
    await client.create({
      index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX),
      id: snapshotDocumentId(snapshot.id),
      body: {
        execution_id: snapshotDocumentId(snapshot.id),
        document_type: 'ruleset_snapshot',
        snapshot_sha256: snapshot.id,
        rules_snapshot: snapshot.rules,
        rule_revisions: snapshot.revisions,
        created_at: new Date().toISOString(),
      },
    });
  } catch (error: any) {
    if (!isConflict(error)) throw error;
  }
}

async function loadRulesetSnapshot(client: any, snapshotId: string): Promise<AutomationRulesetSnapshot> {
  if (!snapshotId) throw new Error('automation event has no ruleset snapshot reference');
  let cache = rulesetSnapshotCaches.get(client);
  if (!cache) {
    cache = new Map();
    rulesetSnapshotCaches.set(client, cache);
  }
  const cached = cache.get(snapshotId);
  if (cached) return cached;
  const pending = (async () => {
    const result: any = await client.get({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: snapshotDocumentId(snapshotId),
    });
    const source = result?.body?._source || {};
    const rules = source.rules_snapshot;
    if (source.document_type !== 'ruleset_snapshot' || source.snapshot_sha256 !== snapshotId || !Array.isArray(rules)) {
      throw new Error(`automation ruleset snapshot ${snapshotId} is missing or invalid`);
    }
    const serialized = JSON.stringify(canonicalize(rules));
    const actual = crypto.createHash('sha256').update(serialized).digest('hex');
    if (actual !== snapshotId) throw new Error(`automation ruleset snapshot ${snapshotId} failed integrity validation`);
    return { id: snapshotId, rules, revisions: source.rule_revisions || [] };
  })();
  cache.set(snapshotId, pending);
  while (cache.size > SNAPSHOT_CACHE_SIZE) {
    const oldest = cache.keys().next().value;
    if (!oldest) break;
    cache.delete(oldest);
  }
  try {
    return await pending;
  } catch (error) {
    cache.delete(snapshotId);
    throw error;
  }
}

async function writeDlq(
  client: any,
  events: AutomationEvent[],
  stage: string,
  error: any,
  attempts = 0,
  rulesetSnapshot = 'rules-v1',
  revisions: Array<{ id: string; revision: number }> = [],
  admissionCutoff?: string
) {
  if (!events.length) return;
  const failedAt = new Date().toISOString();
  const body: any[] = [];
  for (const event of events) {
    const eventId = automationEventId(event.alert_uid);
    body.push({ index: { _index: assertManagedWriteTarget(AUTOMATION_DLQ_INDEX), _id: `${stage}:${eventId}` } });
    body.push({
      event_id: eventId,
      execution_id: automationExecutionId(eventId, rulesetSnapshot),
      ruleset_snapshot: rulesetSnapshot,
      rule_revisions: revisions,
      admission_cutoff: admissionCutoff,
      alert_uid: event.alert_uid,
      stage,
      failed_at: failedAt,
      attempts,
      error: errorDetails(error),
      payload: event,
    });
  }
  const items = await executeBulkPairs(client, body);
  const failed = items.filter((item: any) => {
    const operation = item.index;
    return !operation || operation.error || operation.status < 200 || operation.status >= 300;
  });
  if (failed.length || items.length !== events.length) {
    throw new Error(`automation DLQ bulk write failed for ${failed.length || 'unknown'} item(s)`);
  }
}

export async function recordAutomationEnqueueFailure(client: any, events: AutomationEvent[], error: any) {
  const admissions = await loadAdmissions(client, events.map((event) => automationEventId(event.alert_uid)));
  if (!admissions.length) {
    await writeDlq(client, events, 'enqueue', error);
    return;
  }
  for (const admission of admissions) {
    await writeDlq(client, [admission.event], 'enqueue', error, 0, admission.snapshotId, admission.revisions, admission.admissionCutoff);
    await finishAdmissions(client, [admission], 'admission_dlq');
  }
}

async function queueCounts(client: any): Promise<{ active: number; deferred: number }> {
  const result: any = await client.search({
    index: AUTOMATION_QUEUE_INDEX,
    body: {
      size: 0,
      query: { terms: { state: ['staged', 'pending', 'claimed', 'retry', 'deferred'] } },
      aggs: { states: { terms: { field: 'state', size: 10 } } },
    },
  });
  const states = Object.fromEntries(
    (result?.body?.aggregations?.states?.buckets || []).map((bucket: any) => [bucket.key, bucket.doc_count])
  );
  return {
    active: Number(states.staged || 0) + Number(states.pending || 0) + Number(states.claimed || 0) + Number(states.retry || 0),
    deferred: Number(states.deferred || 0),
  };
}

function admissionId(eventId: string) {
  return `automation-admission:${eventId}`;
}

async function createAdmissions(client: any, events: AutomationEvent[], snapshot: AutomationRulesetSnapshot) {
  const now = new Date().toISOString();
  const body: any[] = [];
  for (const event of events) {
    const eventId = automationEventId(event.alert_uid);
    const workerLane = automationAdmissionLane(snapshot, event);
    body.push({ create: { _index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX), _id: admissionId(eventId) } });
    body.push({
      execution_id: admissionId(eventId), event_id: eventId, alert_uid: event.alert_uid,
      state: 'admission_pending', admission_reason: 'first_ingestion', ruleset_snapshot: snapshot.id,
      rule_revisions: snapshot.revisions,
      worker_lane: workerLane,
      admission_cutoff: now,
      payload: event, started_at: now, updated_at: now,
    });
  }
  const items = await executeBulkPairs(client, body);
  const unsafe = items.length !== events.length || items.some((item: any) => {
    const operation = item.create;
    return !operation || (operation.status !== 409 && (operation.error || operation.status < 200 || operation.status >= 300));
  });
  if (unsafe) throw Object.assign(new Error('automation admission marker write failed'), { automationAdmissionUnsafe: true });
}

async function loadAdmissions(client: any, eventIds: string[]): Promise<AutomationAdmission[]> {
  if (!eventIds.length) return [];
  const result: any = await client.mget({
    index: AUTOMATION_EXECUTIONS_INDEX,
    body: { ids: eventIds.map(admissionId) },
  });
  return (result?.body?.docs || []).filter((doc: any) =>
    doc.found !== false && doc._source?.admission_reason === 'first_ingestion'
  ).map((doc: any) => ({
    event: doc._source.payload,
    snapshotId: doc._source.ruleset_snapshot,
    revisions: doc._source.rule_revisions || [],
    admissionCutoff: doc._source.admission_cutoff,
    workerLane: doc._source.worker_lane,
  }));
}

async function finishAdmissions(client: any, admissions: AutomationAdmission[], state: string) {
  if (!admissions.length) return;
  const now = new Date().toISOString();
  const body: any[] = [];
  for (const admission of admissions) {
    body.push({ update: { _index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX), _id: admissionId(automationEventId(admission.event.alert_uid)) } });
    body.push({ doc: { state, completed_at: now, updated_at: now } });
  }
  await executeBulkPairs(client, body);
}

async function enqueueAdmissions(
  client: any,
  admissions: AutomationAdmission[],
  finishAdmissionMarkers = true
) {
  if (!admissions.length) return { enqueued: 0, deferred: 0, duplicates: 0, failed: 0 };
  const [settings, counts] = await Promise.all([
    loadAutomationSettings(client),
    queueCounts(client),
  ]);
  const now = new Date().toISOString();
  const body: any[] = [];
  let admitted = counts.active;
  let deferredCount = counts.deferred;
  const overflow: AutomationAdmission[] = [];
  const submitted: AutomationAdmission[] = [];
  for (const admission of admissions) {
    const { event, snapshotId, revisions, admissionCutoff, workerLane } = admission;
    const eventId = automationEventId(event.alert_uid);
    const defer = settings.paused || admitted >= settings.maxBacklog;
    if (defer && deferredCount >= settings.maxDeferred) {
      overflow.push(admission);
      continue;
    }
    if (defer) deferredCount += 1;
    else admitted += 1;
    body.push({ create: { _index: assertManagedWriteTarget(AUTOMATION_QUEUE_INDEX), _id: eventId } });
    body.push({
      event_id: eventId,
      alert_uid: event.alert_uid,
      event_timestamp: event['@timestamp'] || event.ingested_at || now,
      worker_lane: Number.isInteger(workerLane) ? workerLane : automationWorkerLane(eventId),
      ruleset_snapshot: snapshotId,
      rule_revisions: revisions,
      admission_cutoff: admissionCutoff,
      // The operational alert is written after durable admission. Workers may
      // only claim this record after sync publishes it below.
      state: 'staged',
      target_state: defer ? 'deferred' : 'pending',
      enqueued_at: now,
      available_at: now,
      attempts: 0,
      payload: event,
    });
    submitted.push(admission);
  }

  const items = body.length ? await executeBulkPairs(client, body) : [];
  const failedAdmissions: AutomationAdmission[] = [];
  const admittedAdmissions: AutomationAdmission[] = [];
  let enqueued = 0;
  let deferred = 0;
  let duplicates = 0;
  submitted.forEach((admission, position) => {
    const operation = items[position]?.create;
    if (operation?.status >= 200 && operation?.status < 300 && !operation.error) {
      const source = body[position * 2 + 1];
      if (source.target_state === 'deferred') deferred += 1;
      else enqueued += 1;
      admittedAdmissions.push(admission);
    } else if (operation?.status === 409) {
      duplicates += 1;
      admittedAdmissions.push(admission);
    } else failedAdmissions.push(admission);
  });
  if (finishAdmissionMarkers) await finishAdmissions(client, admittedAdmissions, 'admitted');
  for (const admission of failedAdmissions) {
    await writeDlq(client, [admission.event], 'enqueue-item', new Error('queue bulk item failed'), 0, admission.snapshotId, admission.revisions, admission.admissionCutoff);
    if (finishAdmissionMarkers) await finishAdmissions(client, [admission], 'admission_dlq');
  }
  for (const admission of overflow) {
    await writeDlq(client, [admission.event], 'admission', new Error('automation deferred backlog limit reached'), 0, admission.snapshotId, admission.revisions, admission.admissionCutoff);
    if (finishAdmissionMarkers) await finishAdmissions(client, [admission], 'admission_dlq');
  }
  return { enqueued, deferred, duplicates, failed: failedAdmissions.length + overflow.length };
}

export async function activateAutomationEvents(client: any, events: AutomationEvent[]): Promise<number> {
  const ids = Array.from(new Set(events.map((event) => automationEventId(event.alert_uid)).filter(Boolean)));
  if (!ids.length) return 0;
  const now = new Date().toISOString();
  const body: any[] = [];
  for (const id of ids) {
    body.push({ update: {
      _index: assertManagedWriteTarget(AUTOMATION_QUEUE_INDEX),
      _id: id,
      retry_on_conflict: 3,
    } });
    body.push({ script: {
      lang: 'painless',
      source:
        'if (ctx._source.state == "staged") { ctx._source.state = ctx._source.target_state == null ? "pending" : ctx._source.target_state; ' +
        'ctx._source.target_state = null; ctx._source.available_at = params.now; ctx._source.updated_at = params.now; } else { ctx.op = "noop"; }',
      params: { now },
    } });
  }
  const items = await executeBulkPairs(client, body);
  const invalid = items.filter((item: any) => {
    const operation = item.update;
    return !operation || operation.error || operation.status < 200 || operation.status >= 300;
  });
  if (items.length !== ids.length || invalid.length) {
    throw new Error(`automation queue activation failed for ${invalid.length || 'unknown'} item(s)`);
  }
  return items.filter((item: any) => item.update?.result !== 'noop').length;
}

async function reconcileStagedAutomationEvents(client: any): Promise<number> {
  const result: any = await client.search({
    index: AUTOMATION_QUEUE_INDEX,
    body: {
      size: AUTOMATION_ADMISSION_RECONCILE_BATCH,
      _source: false,
      sort: [{ enqueued_at: 'asc' }, { event_id: 'asc' }],
      query: { term: { state: 'staged' } },
    },
  });
  const ids = (result?.body?.hits?.hits || []).map((hit: any) => String(hit._id));
  if (!ids.length) return 0;
  const locations = await resolveAlerts(client, ids);
  return activateAutomationEvents(
    client,
    ids.filter((id: string) => locations.has(id)).map((alert_uid: string) => ({ alert_uid }))
  );
}

/** Candidate queue records retain the exact ingestion-time ruleset. */
export async function enqueueAutomationEvents(client: any, events: AutomationEvent[]) {
  if (!events.length) return { enqueued: 0, deferred: 0, duplicates: 0, failed: 0, candidateAlertUids: [] as string[] };
  try {
    const snapshot = await captureRulesetSnapshot(client);
    const normalizedRules = normalizeAutomationRules(snapshot.rules as any[]);
    const candidates = events.map((event) => ({
      event,
      matchingRuleIds: candidateRuleIds(normalizedRules, event),
    })).filter((candidate) => candidate.matchingRuleIds.length > 0);
    if (!candidates.length) {
      return { enqueued: 0, deferred: 0, duplicates: 0, failed: 0, candidateAlertUids: [] as string[] };
    }
    await persistRulesetSnapshot(client, snapshot);
    const admissionCutoff = new Date().toISOString();
    // The staged queue document is itself the durable admission record: it
    // contains the immutable ruleset reference, cutoff, lane, and full event
    // payload. The operational bulk is not attempted until every queue create
    // has a durable outcome. If this process dies during the queue bulk, the
    // sync cursor remains unchanged and deterministic IDs safely replay it.
    // This removes two per-alert admission-index writes from the ingestion hot
    // path while retaining the older marker reconciler for upgrade recovery.
    const admissions: AutomationAdmission[] = candidates.map(({ event, matchingRuleIds }) => ({
      event,
      snapshotId: snapshot.id,
      revisions: snapshot.revisions || [],
      admissionCutoff,
      workerLane: automationWorkerLane(matchingRuleIds.join('|')),
    }));
    return {
      ...(await enqueueAdmissions(client, admissions, false)),
      candidateAlertUids: candidates.map(({ event }) => event.alert_uid),
    };
  } catch (error: any) {
    // A user-created legacy over-limit ruleset disables automation admission
    // for this batch, but must never halt native alert ingestion.
    if (!error.automationRulesOverLimit) error.automationAdmissionUnsafe = true;
    throw error;
  }
}

/** Recover only unfinished, explicitly marked first-ingestion admissions. */
export async function reconcileAutomationAdmissions(client: any) {
  const result: any = await client.search({
    index: AUTOMATION_EXECUTIONS_INDEX,
    body: {
      size: AUTOMATION_ADMISSION_RECONCILE_BATCH,
      sort: [{ started_at: 'asc' }, { execution_id: 'asc' }],
      query: { term: { state: 'admission_pending' } },
    },
  });
  const admissions: AutomationAdmission[] = (result?.body?.hits?.hits || [])
    .filter((hit: any) => hit._source?.admission_reason === 'first_ingestion')
    .map((hit: any) => ({
      event: hit._source.payload,
      snapshotId: hit._source.ruleset_snapshot,
      revisions: hit._source.rule_revisions || [],
      admissionCutoff: hit._source.admission_cutoff,
      workerLane: hit._source.worker_lane,
    })).filter((admission: AutomationAdmission) => admission.event?.alert_uid && admission.snapshotId);
  const admissionResult = await enqueueAdmissions(client, admissions);
  await reconcileStagedAutomationEvents(client);
  return admissionResult;
}

function workerHolderId() {
  return `${os.hostname()}-${process.pid}-automation-${crypto.randomBytes(4).toString('hex')}`;
}

export function automationWorkerLeaseId(lane: number): string {
  if (!Number.isInteger(lane) || lane < 0 || lane >= DEFAULT_WORKER_CONCURRENCY) {
    throw new Error(`automation worker lane must be between 0 and ${DEFAULT_WORKER_CONCURRENCY - 1}`);
  }
  return lane === 0 ? AUTOMATION_WORKER_LEASE_ID : `${AUTOMATION_WORKER_LEASE_ID}:${lane}`;
}

async function acquireWorkerLease(
  client: any,
  holderId: string,
  ttlSeconds: number,
  workerLeaseId = AUTOMATION_WORKER_LEASE_ID
): Promise<Fence | null> {
  const now = Date.now();
  let current: any;
  try {
    current = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: workerLeaseId });
  } catch (error: any) {
    if (error?.meta?.statusCode !== 404) throw error;
    const fence = { holderId, generation: 1, token: randomToken() };
    try {
      await client.create({
        index: AUTOMATION_EXECUTIONS_INDEX,
        id: workerLeaseId,
        body: {
          execution_id: workerLeaseId,
          state: 'lease',
          holder_id: holderId,
          fencing_generation: fence.generation,
          lease_token: fence.token,
          lease_expires_at: new Date(now + ttlSeconds * 1000).toISOString(),
          updated_at: new Date(now).toISOString(),
        },
      });
      return fence;
    } catch (createError: any) {
      if (isConflict(createError)) return null;
      throw createError;
    }
  }
  const source = current.body._source || {};
  const expired = Date.parse(source.lease_expires_at || '') <= now;
  if (source.holder_id !== holderId && !expired) return null;
  const sameOwner = source.holder_id === holderId && !expired;
  const fence = {
    holderId,
    generation: sameOwner ? Number(source.fencing_generation || 1) : Number(source.fencing_generation || 0) + 1,
    token: sameOwner ? String(source.lease_token) : randomToken(),
  };
  try {
    await client.update({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: workerLeaseId,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc: {
        holder_id: holderId,
        fencing_generation: fence.generation,
        lease_token: fence.token,
        lease_expires_at: new Date(now + ttlSeconds * 1000).toISOString(),
        updated_at: new Date(now).toISOString(),
      } },
    });
    return fence;
  } catch (error: any) {
    if (isConflict(error)) return null;
    throw error;
  }
}

function owns(source: any, fence: Fence, state?: string) {
  return (!state || source.state === state) &&
    source.holder_id === fence.holderId &&
    Number(source.fencing_generation) === fence.generation &&
    source.lease_token === fence.token;
}

async function renewOwnedLease(client: any, index: string, id: string, fence: Fence, ttlSeconds: number, state: string) {
  try {
    const current: any = await client.get({ index, id });
    if (!owns(current.body._source || {}, fence, state)) return false;
    await client.update({
      index,
      id,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc: {
        lease_expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
        updated_at: new Date().toISOString(),
      } },
    });
    return true;
  } catch (error: any) {
    if (error?.meta?.statusCode === 404 || isConflict(error)) return false;
    throw error;
  }
}

async function releaseWorkerLease(
  client: any,
  fence: Fence,
  workerLeaseId = AUTOMATION_WORKER_LEASE_ID
) {
  try {
    const current: any = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: workerLeaseId });
    if (!owns(current.body._source || {}, fence, 'lease')) return;
    await client.delete({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: workerLeaseId,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
    });
  } catch (error) {
    // Expiry is the failover path when best-effort release cannot complete.
  }
}

async function claimNext(
  client: any,
  fence: Fence,
  leaseSeconds: number,
  workerLeaseId = AUTOMATION_WORKER_LEASE_ID
): Promise<QueueClaim | null> {
  const settings = await loadAutomationSettings(client);
  if (settings.paused) return null;
  const now = new Date().toISOString();
  const result: any = await client.search({
    index: AUTOMATION_QUEUE_INDEX,
    seq_no_primary_term: true,
    body: {
      size: 50,
      sort: [
        { available_at: 'asc' },
        { event_timestamp: { order: 'asc', missing: '_last', unmapped_type: 'date' } },
        { enqueued_at: 'asc' },
        { event_id: 'asc' },
      ],
      query: { bool: { should: [
        { term: { state: 'pending' } },
        { term: { state: 'deferred' } },
        { bool: { must: [{ term: { state: 'retry' } }, { range: { available_at: { lte: now } } }] } },
        { bool: { must: [{ term: { state: 'claimed' } }, { range: { lease_expires_at: { lte: now } } }] } },
      ], minimum_should_match: 1 } },
    },
  });
  for (const hit of result?.body?.hits?.hits || []) {
    let current: any;
    try {
      current = await client.get({ index: AUTOMATION_QUEUE_INDEX, id: hit._id });
    } catch (error: any) {
      if (error?.meta?.statusCode === 404) continue;
      throw error;
    }
    const currentSource = current?.body?._source || {};
    const state = currentSource.state;
    const available = Date.parse(currentSource.available_at || '') <= Date.now();
    const leaseExpired = Date.parse(currentSource.lease_expires_at || '') <= Date.now();
    if (state !== 'pending' && state !== 'deferred' &&
        !(state === 'retry' && available) && !(state === 'claimed' && leaseExpired)) continue;
    if (!(await renewOwnedLease(
      client,
      AUTOMATION_EXECUTIONS_INDEX,
      workerLeaseId,
      fence,
      leaseSeconds,
      'lease'
    ))) return null;
    const claimedAt = new Date().toISOString();
    const claimFence = { ...fence, token: randomToken() };
    const source = {
      ...currentSource,
      state: 'claimed',
      holder_id: claimFence.holderId,
      fencing_generation: claimFence.generation,
      lease_token: claimFence.token,
      claimed_at: claimedAt,
      lease_expires_at: new Date(Date.now() + leaseSeconds * 1000).toISOString(),
      attempts: Number(currentSource.attempts || 0) + 1,
    };
    try {
      await client.update({
        index: AUTOMATION_QUEUE_INDEX,
        id: hit._id,
        if_seq_no: current.body._seq_no,
        if_primary_term: current.body._primary_term,
        body: { doc: source },
      });
      return { id: hit._id, source, fence: claimFence };
    } catch (error: any) {
      if (!isConflict(error)) throw error;
    }
  }
  return null;
}

async function updateClaim(client: any, claim: QueueClaim, doc: any) {
  try {
    const current: any = await client.get({ index: AUTOMATION_QUEUE_INDEX, id: claim.id });
    if (!owns(current.body._source || {}, claim.fence, 'claimed')) return false;
    await client.update({
      index: AUTOMATION_QUEUE_INDEX,
      id: claim.id,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc },
    });
    return true;
  } catch (error: any) {
    if (isConflict(error)) return false;
    throw error;
  }
}

async function claimExecution(
  client: any,
  claim: QueueClaim,
  workerFence: Fence,
  leaseSeconds: number,
  workerLeaseId = AUTOMATION_WORKER_LEASE_ID
) {
  const rulesetSnapshot = claim.source.ruleset_snapshot || 'rules-v1';
  const executionId = automationExecutionId(claim.source.event_id, rulesetSnapshot);
  const now = Date.now();
  const doc = {
    execution_id: executionId,
    event_id: claim.source.event_id,
    alert_uid: claim.source.alert_uid,
    ruleset_snapshot: rulesetSnapshot,
    rule_revisions: claim.source.rule_revisions || [],
    admission_cutoff: claim.source.admission_cutoff,
    state: 'running',
    holder_id: claim.fence.holderId,
    fencing_generation: claim.fence.generation,
    lease_token: claim.fence.token,
    attempts: claim.source.attempts,
    started_at: new Date(now).toISOString(),
    updated_at: new Date(now).toISOString(),
    lease_expires_at: new Date(now + leaseSeconds * 1000).toISOString(),
  };
  let current: any;
  try {
    current = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: executionId });
  } catch (error: any) {
    if (error?.meta?.statusCode !== 404) throw error;
    const workerOwned = await renewOwnedLease(
      client, AUTOMATION_EXECUTIONS_INDEX, workerLeaseId, workerFence, leaseSeconds, 'lease'
    );
    const queueOwned = workerOwned && await renewOwnedLease(
      client, AUTOMATION_QUEUE_INDEX, claim.id, claim.fence, leaseSeconds, 'claimed'
    );
    if (!queueOwned) return { executionId, completed: false, lost: true };
    try {
      await client.create({ index: AUTOMATION_EXECUTIONS_INDEX, id: executionId, body: doc });
      return { executionId, completed: false };
    } catch (createError: any) {
      if (isConflict(createError)) return { executionId, completed: false, busy: true };
      throw createError;
    }
  }
  const source = current.body._source || {};
  if (source.state === 'completed') return { executionId, completed: true };
  if (!owns(source, claim.fence) && Date.parse(source.lease_expires_at || '') > now) {
    return { executionId, completed: false, busy: true };
  }
  const workerOwned = await renewOwnedLease(
    client, AUTOMATION_EXECUTIONS_INDEX, workerLeaseId, workerFence, leaseSeconds, 'lease'
  );
  const queueOwned = workerOwned && await renewOwnedLease(
    client, AUTOMATION_QUEUE_INDEX, claim.id, claim.fence, leaseSeconds, 'claimed'
  );
  if (!queueOwned) return { executionId, completed: false, lost: true };
  try {
    await client.update({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: executionId,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc },
    });
    return { executionId, completed: false };
  } catch (error: any) {
    if (isConflict(error)) return { executionId, completed: false, busy: true };
    throw error;
  }
}

async function updateOwnedExecution(client: any, executionId: string, fence: Fence, doc: any) {
  try {
    const current: any = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: executionId });
    if (!owns(current?.body?._source || {}, fence, 'running')) return false;
    await client.update({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: executionId,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc },
    });
    return true;
  } catch (error: any) {
    if (isConflict(error)) return false;
    throw error;
  }
}

function startHeartbeat(
  client: any,
  workerFence: Fence,
  claim: QueueClaim,
  executionId: string,
  leaseSeconds: number,
  workerLeaseId = AUTOMATION_WORKER_LEASE_ID
) {
  let stopped = false;
  let lost = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let inFlight: Promise<void> = Promise.resolve();
  const intervalMs = Math.max(1000, Math.min(30000, Math.floor(leaseSeconds * 1000 / 3)));
  const beat = () => {
    inFlight = (async () => {
      const worker = await renewOwnedLease(
        client, AUTOMATION_EXECUTIONS_INDEX, workerLeaseId, workerFence, leaseSeconds, 'lease'
      );
      const queue = worker && await renewOwnedLease(
        client, AUTOMATION_QUEUE_INDEX, claim.id, claim.fence, leaseSeconds, 'claimed'
      );
      const execution = queue && await renewOwnedLease(
        client, AUTOMATION_EXECUTIONS_INDEX, executionId, claim.fence, leaseSeconds, 'running'
      );
      if (!execution) lost = true;
    })().catch(() => { lost = true; }).finally(() => {
      if (!stopped && !lost) timer = setTimeout(beat, intervalMs);
    });
  };
  timer = setTimeout(beat, intervalMs);
  return {
    async stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      await inFlight;
      return !lost;
    },
  };
}

export async function runAutomationWorkerOnce(
  client: any,
  logger: Logger,
  holderId: string,
  leaseSeconds = DEFAULT_LEASE_SECONDS,
  evaluator: typeof evaluateCorrelationRules = evaluateCorrelationRules,
  workerLeaseId = AUTOMATION_WORKER_LEASE_ID
) {
  const workerFence = await acquireWorkerLease(client, holderId, leaseSeconds, workerLeaseId);
  if (!workerFence) return false;
  const claim = await claimNext(client, workerFence, leaseSeconds, workerLeaseId);
  if (!claim) return false;
  const execution = await claimExecution(client, claim, workerFence, leaseSeconds, workerLeaseId);
  if (execution.lost) return false;
  if (execution.busy) {
    await updateClaim(client, claim, {
      state: 'retry',
      available_at: new Date(Date.now() + retryDelayMs(claim.source.attempts)).toISOString(),
      holder_id: null,
      lease_expires_at: null,
      lease_token: null,
    });
    return false;
  }
  if (execution.completed) {
    return updateClaim(client, claim, {
      state: 'completed', completed_at: new Date().toISOString(), holder_id: null,
      lease_expires_at: null, lease_token: null,
    });
  }

  const heartbeat = startHeartbeat(client, workerFence, claim, execution.executionId, leaseSeconds, workerLeaseId);
  try {
    // Resolve immutable definitions at execution time. Missing or corrupt
    // snapshots fail closed and are retried/DLQ'd without consulting live rules.
    const snapshot = await loadRulesetSnapshot(client, claim.source.ruleset_snapshot);
    const guard = {
      async assertOwned() {
        let worker: any;
        let queue: any;
        let running: any;
        try {
          [worker, queue, running] = await Promise.all([
            client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: workerLeaseId }),
            client.get({ index: AUTOMATION_QUEUE_INDEX, id: claim.id }),
            client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: execution.executionId }),
          ]);
        } catch {
          throw ownershipLostError();
        }
        const now = Date.now();
        const workerSource = worker?.body?._source || {};
        const queueSource = queue?.body?._source || {};
        const runningSource = running?.body?._source || {};
        if (!owns(workerSource, workerFence, 'lease') ||
            !owns(queueSource, claim.fence, 'claimed') ||
            !owns(runningSource, claim.fence, 'running') ||
            !(Date.parse(workerSource.lease_expires_at || '') > now) ||
            !(Date.parse(queueSource.lease_expires_at || '') > now) ||
            !(Date.parse(runningSource.lease_expires_at || '') > now)) {
          throw ownershipLostError();
        }
      },
      async check() {
        try { await this.assertOwned(); return true; } catch (error) { return false; }
      },
    };
    const outcome = await (evaluator as any)(
      client,
      [{ _id: claim.source.alert_uid, _source: claim.source.payload }],
      logger,
      undefined,
      { ...snapshot, admission_cutoff: claim.source.admission_cutoff },
      guard
    );
    if (!(await heartbeat.stop())) {
      logger.warn(`wazuh-alert-manager automation: event ${claim.source.event_id} lost its lease during evaluation`);
      return false;
    }
    if (outcome.status !== 'terminal_success') {
      const error: any = new Error(
        `automation evaluation has ${outcome.failures.length} retryable failure(s): ${outcome.failures
          .map((failure) => `${failure.stage}: ${failure.message}`).join('; ')}`
      );
      error.outcome = outcome;
      throw error;
    }
    const completedAt = new Date().toISOString();
    const completed = await updateOwnedExecution(client, execution.executionId, claim.fence, {
      state: 'completed', completed_at: completedAt, updated_at: completedAt, lease_expires_at: null,
      applied_rule_ids: outcome.appliedRuleIds, counters: outcome.counters,
    });
    if (!completed) return false;
    return updateClaim(client, claim, {
      state: 'completed', completed_at: completedAt, holder_id: null, lease_expires_at: null, lease_token: null,
    });
  } catch (error: any) {
    const heartbeatOwned = await heartbeat.stop();
    if (!heartbeatOwned) return false;
    const attempts = claim.source.attempts;
    const exhausted = attempts >= MAX_ATTEMPTS;
    const now = new Date().toISOString();
    const failureRecorded = await updateOwnedExecution(client, execution.executionId, claim.fence, {
      state: exhausted ? 'dlq' : 'retry', updated_at: now, lease_expires_at: null, last_error: errorDetails(error),
    });
    if (!failureRecorded) {
      logger.warn(`wazuh-alert-manager automation: event ${claim.source.event_id} lost its execution lease`);
      return false;
    }
    if (exhausted) {
      await writeDlq(
        client,
        [claim.source.payload],
        'execution',
        error,
        attempts,
        claim.source.ruleset_snapshot,
        claim.source.rule_revisions || [],
        claim.source.admission_cutoff
      );
    }
    await updateClaim(client, claim, exhausted
      ? { state: 'dlq', holder_id: null, lease_expires_at: null, lease_token: null, last_error: errorDetails(error) }
      : {
          state: 'retry', available_at: new Date(Date.now() + retryDelayMs(attempts)).toISOString(),
          holder_id: null, lease_expires_at: null, lease_token: null, last_error: errorDetails(error),
        });
    logger.error(`wazuh-alert-manager automation: event ${claim.source.event_id} failed (attempt ${attempts}): ${error.message}`);
    return false;
  }
}

export async function runAutomationWorkerBatchOnce(
  client: any,
  logger: Logger,
  holderId: string,
  lane: number,
  leaseSeconds = DEFAULT_LEASE_SECONDS,
  batchSize = DEFAULT_WORKER_BATCH_SIZE,
  evaluator: typeof evaluateCorrelationRules = evaluateCorrelationRules
) {
  const workerLeaseId = automationWorkerLeaseId(lane);
  const workerFence = await acquireWorkerLease(client, holderId, leaseSeconds, workerLeaseId);
  if (!workerFence) return false;
  const claims = await claimBatch(client, workerFence, leaseSeconds, workerLeaseId, lane, batchSize);
  if (!claims.length) return false;
  const { runnable, completed, busy } = await claimBatchExecutions(client, claims, leaseSeconds);
  const now = new Date().toISOString();
  if (completed.length) {
    await transitionBatchOwned(
      client,
      AUTOMATION_QUEUE_INDEX,
      completed.map((claim) => ({ id: claim.id, fence: claim.fence, state: 'claimed' })),
      () => ({ state: 'completed', completed_at: now, holder_id: null, lease_expires_at: null, lease_token: null })
    );
  }
  if (busy.length) {
    await transitionBatchOwned(
      client,
      AUTOMATION_QUEUE_INDEX,
      busy.map((claim) => ({ id: claim.id, fence: claim.fence, state: 'claimed' })),
      (item) => {
        const claim = busy.find((candidate) => candidate.id === item.id)!;
        return {
          state: 'retry',
          available_at: new Date(Date.now() + retryDelayMs(claim.source.attempts)).toISOString(),
          holder_id: null,
          lease_expires_at: null,
          lease_token: null,
        };
      }
    );
  }
  if (!runnable.length) return completed.length > 0 || busy.length > 0;

  let lastOwnershipCheck = 0;
  const guard = {
    async assertOwned() {
      // One lane lease fences the whole batch. Cache a successful read briefly;
      // the heartbeat renews document leases and final scripts still verify
      // every claim token before acknowledging durable work.
      if (Date.now() - lastOwnershipCheck < 1000) return;
      await assertBatchOwned(client, workerLeaseId, workerFence, runnable);
      lastOwnershipCheck = Date.now();
    },
    async check() {
      try { await this.assertOwned(); return true; } catch (error) { return false; }
    },
  };
  const heartbeat = startBatchHeartbeat(client, workerLeaseId, workerFence, runnable, leaseSeconds);
  let outcome: any;
  try {
    const snapshot = await loadRulesetSnapshot(client, runnable[0].claim.source.ruleset_snapshot);
    outcome = await (evaluator as any)(
      client,
      runnable.map((execution) => ({
        _id: execution.claim.source.alert_uid,
        _source: execution.claim.source.payload,
      })),
      logger,
      undefined,
      { ...snapshot, admission_cutoff: runnable[0].claim.source.admission_cutoff },
      guard
    );
    await guard.assertOwned();
  } catch (error: any) {
    outcome = {
      status: 'retryable_failure', counters: {}, appliedRuleIds: [],
      failures: [{ stage: error?.ownershipLost ? 'execution_state' : 'rule_loading', message: error?.message || String(error) }],
    };
  }
  if (!(await heartbeat.stop())) return false;

  if (outcome.status === 'terminal_success') {
    const completedAt = new Date().toISOString();
    const executionDone = await transitionBatchOwned(
      client,
      AUTOMATION_EXECUTIONS_INDEX,
      runnable.map((execution) => ({ id: execution.executionId, fence: execution.claim.fence, state: 'running' })),
      () => ({
        state: 'completed', completed_at: completedAt, updated_at: completedAt, lease_expires_at: null,
        applied_rule_ids: outcome.appliedRuleIds, counters: outcome.counters,
      })
    );
    if (!executionDone) return false;
    return transitionBatchOwned(
      client,
      AUTOMATION_QUEUE_INDEX,
      runnable.map((execution) => ({ id: execution.claim.id, fence: execution.claim.fence, state: 'claimed' })),
      () => ({ state: 'completed', completed_at: completedAt, holder_id: null, lease_expires_at: null, lease_token: null })
    );
  }

  const error: any = new Error(
    `automation batch evaluation has ${outcome.failures?.length || 1} retryable failure(s): ${(outcome.failures || [])
      .map((failure: any) => `${failure.stage}: ${failure.message}`).join('; ')}`
  );
  error.outcome = outcome;
  const exhausted = runnable.filter((execution) => execution.claim.source.attempts >= MAX_ATTEMPTS);
  const retrying = runnable.filter((execution) => execution.claim.source.attempts < MAX_ATTEMPTS);
  const failedAt = new Date().toISOString();
  if (exhausted.length) {
    await writeDlq(
      client,
      exhausted.map((execution) => execution.claim.source.payload),
      'execution',
      error,
      MAX_ATTEMPTS,
      exhausted[0].claim.source.ruleset_snapshot,
      exhausted[0].claim.source.rule_revisions || [],
      exhausted[0].claim.source.admission_cutoff
    );
  }
  await transitionBatchOwned(
    client,
    AUTOMATION_EXECUTIONS_INDEX,
    runnable.map((execution) => ({ id: execution.executionId, fence: execution.claim.fence, state: 'running' })),
    (item) => {
      const execution = runnable.find((candidate) => candidate.executionId === item.id)!;
      return {
        state: execution.claim.source.attempts >= MAX_ATTEMPTS ? 'dlq' : 'retry',
        updated_at: failedAt,
        lease_expires_at: null,
        last_error: errorDetails(error),
      };
    }
  );
  await transitionBatchOwned(
    client,
    AUTOMATION_QUEUE_INDEX,
    runnable.map((execution) => ({ id: execution.claim.id, fence: execution.claim.fence, state: 'claimed' })),
    (item) => {
      const execution = runnable.find((candidate) => candidate.claim.id === item.id)!;
      const isExhausted = execution.claim.source.attempts >= MAX_ATTEMPTS;
      return {
        state: isExhausted ? 'dlq' : 'retry',
        ...(isExhausted ? {} : { available_at: new Date(Date.now() + retryDelayMs(execution.claim.source.attempts)).toISOString() }),
        holder_id: null,
        lease_expires_at: null,
        lease_token: null,
        last_error: errorDetails(error),
      };
    }
  );
  logger.error(
    `wazuh-alert-manager automation: batch of ${runnable.length} events failed ` +
    `(${retrying.length} retrying, ${exhausted.length} DLQ): ${error.message}`
  );
  return true;
}

export function startAutomationWorker(client: any, logger: Logger): () => void {
  let stopped = false;
  const lanes = Array.from({ length: DEFAULT_WORKER_CONCURRENCY }, (_, lane) => ({
    lane,
    holderId: `${workerHolderId()}-lane-${lane}`,
    leaseId: automationWorkerLeaseId(lane),
    running: false,
    timer: null as ReturnType<typeof setTimeout> | null,
  }));
  let reconcileRunning = false;
  let lastReconcileAt = 0;
  const schedule = (lane: typeof lanes[number], delay = DEFAULT_POLL_MS) => {
    if (!stopped) lane.timer = setTimeout(() => tick(lane), delay);
  };
  const tick = async (lane: typeof lanes[number]) => {
    if (stopped || lane.running) return;
    lane.running = true;
    try {
      // Recovery is independent of source sync progress and remains safe across
      // replicas because both admission and queue IDs are deterministic. It is
      // periodic rather than part of every event's hot path.
      if (lane.lane === 0 && !reconcileRunning && Date.now() - lastReconcileAt >= ADMISSION_RECONCILE_INTERVAL_MS) {
        reconcileRunning = true;
        try {
          await reconcileAutomationAdmissions(client);
          lastReconcileAt = Date.now();
        } finally {
          reconcileRunning = false;
        }
      }
      const processed = await runAutomationWorkerBatchOnce(
        client,
        logger,
        lane.holderId,
        lane.lane
      );
      lane.running = false;
      schedule(lane, processed ? 0 : DEFAULT_POLL_MS);
    } catch (error: any) {
      logger.error(`wazuh-alert-manager automation worker: ${error.message}`);
      lane.running = false;
      schedule(lane);
    }
  };
  lanes.forEach((lane) => tick(lane));
  return () => {
    stopped = true;
    lanes.forEach((lane) => {
      if (lane.timer) clearTimeout(lane.timer);
      // The holder check prevents shutdown from deleting a successor's lease.
      acquireWorkerLease(client, lane.holderId, DEFAULT_LEASE_SECONDS, lane.leaseId).then((fence) => {
        if (fence) return releaseWorkerLease(client, fence, lane.leaseId);
      }).catch(() => {});
    });
  };
}

function laneQuery(lane: number, now: string) {
  const laneFilter = lane === 0
    ? { bool: { should: [
        { term: { worker_lane: 0 } },
        { bool: { must_not: [{ exists: { field: 'worker_lane' } }] } },
      ], minimum_should_match: 1 } }
    : { term: { worker_lane: lane } };
  return { bool: {
    filter: [laneFilter],
    must: [{ bool: { should: [
      { term: { state: 'pending' } },
      { term: { state: 'deferred' } },
      { bool: { must: [{ term: { state: 'retry' } }, { range: { available_at: { lte: now } } }] } },
      { bool: { must: [{ term: { state: 'claimed' } }, { range: { lease_expires_at: { lte: now } } }] } },
    ], minimum_should_match: 1 } }],
  } };
}

async function claimBatch(
  client: any,
  fence: Fence,
  leaseSeconds: number,
  workerLeaseId: string,
  lane: number,
  batchSize = DEFAULT_WORKER_BATCH_SIZE
): Promise<QueueClaim[]> {
  const settings = await loadAutomationSettings(client);
  if (settings.paused) return [];
  const now = new Date().toISOString();
  const result: any = await client.search({
    index: AUTOMATION_QUEUE_INDEX,
    seq_no_primary_term: true,
    body: {
      size: batchSize,
      sort: [
        { available_at: 'asc' },
        { event_timestamp: { order: 'asc', missing: '_last', unmapped_type: 'date' } },
        { enqueued_at: 'asc' },
        { event_id: 'asc' },
      ],
      query: laneQuery(lane, now),
    },
  });
  const hits = result?.body?.hits?.hits || [];
  if (!hits.length) return [];
  if (!(await renewOwnedLease(
    client, AUTOMATION_EXECUTIONS_INDEX, workerLeaseId, fence, leaseSeconds, 'lease'
  ))) return [];

  // A single evaluator call must use one immutable snapshot and admission
  // cutoff. The sorted queue naturally groups sync admissions; retain that
  // boundary explicitly when a lane crosses between batches.
  const first = hits[0]?._source || {};
  const candidates = hits.filter((hit: any) =>
    hit?._source?.ruleset_snapshot === first.ruleset_snapshot &&
    hit?._source?.admission_cutoff === first.admission_cutoff
  );
  const claimedAt = new Date().toISOString();
  const claimFence = { ...fence, token: randomToken() };
  const expiry = new Date(Date.now() + leaseSeconds * 1000).toISOString();
  const body: any[] = [];
  const claims: QueueClaim[] = [];
  for (const hit of candidates) {
    const source = {
      ...(hit._source || {}),
      state: 'claimed',
      holder_id: claimFence.holderId,
      fencing_generation: claimFence.generation,
      lease_token: claimFence.token,
      claimed_at: claimedAt,
      lease_expires_at: expiry,
      attempts: Number(hit?._source?.attempts || 0) + 1,
    };
    body.push({ update: {
      _index: assertManagedWriteTarget(AUTOMATION_QUEUE_INDEX),
      _id: hit._id,
      if_seq_no: hit._seq_no,
      if_primary_term: hit._primary_term,
    } });
    body.push({ doc: source });
    claims.push({ id: hit._id, source, fence: claimFence });
  }
  const items = body.length ? await executeBulkPairs(client, body) : [];
  return claims.filter((_claim, index) => {
    const operation = items[index]?.update;
    return operation && !operation.error && operation.status >= 200 && operation.status < 300;
  });
}

interface BatchExecution {
  claim: QueueClaim;
  executionId: string;
}

async function claimBatchExecutions(
  client: any,
  claims: QueueClaim[],
  leaseSeconds: number
): Promise<{ runnable: BatchExecution[]; completed: QueueClaim[]; busy: QueueClaim[] }> {
  if (!claims.length) return { runnable: [], completed: [], busy: [] };
  const ids = claims.map((claim) => automationExecutionId(
    claim.source.event_id,
    claim.source.ruleset_snapshot || 'rules-v1'
  ));
  const existing: any = await client.mget({
    index: AUTOMATION_EXECUTIONS_INDEX,
    body: { ids },
  });
  const docs = existing?.body?.docs || [];
  if (docs.length !== claims.length) throw new Error('automation execution mget returned an incomplete batch');
  const now = Date.now();
  const body: any[] = [];
  const submitted: Array<{ claim: QueueClaim; executionId: string }> = [];
  const completed: QueueClaim[] = [];
  const busy: QueueClaim[] = [];
  claims.forEach((claim, index) => {
    const executionId = ids[index];
    const current = docs[index];
    const currentSource = current?._source || {};
    if (current?.found !== false && currentSource.state === 'completed') {
      completed.push(claim);
      return;
    }
    if (current?.found !== false && !owns(currentSource, claim.fence) &&
        Date.parse(currentSource.lease_expires_at || '') > now) {
      busy.push(claim);
      return;
    }
    const record = {
      execution_id: executionId,
      event_id: claim.source.event_id,
      alert_uid: claim.source.alert_uid,
      ruleset_snapshot: claim.source.ruleset_snapshot || 'rules-v1',
      rule_revisions: claim.source.rule_revisions || [],
      admission_cutoff: claim.source.admission_cutoff,
      state: 'running',
      holder_id: claim.fence.holderId,
      fencing_generation: claim.fence.generation,
      lease_token: claim.fence.token,
      attempts: claim.source.attempts,
      started_at: new Date(now).toISOString(),
      updated_at: new Date(now).toISOString(),
      lease_expires_at: new Date(now + leaseSeconds * 1000).toISOString(),
    };
    body.push(current?.found === false
      ? { create: { _index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX), _id: executionId } }
      : { update: { _index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX), _id: executionId } });
    body.push(current?.found === false ? record : { doc: record });
    submitted.push({ claim, executionId });
  });
  const items = body.length ? await executeBulkPairs(client, body) : [];
  const runnable: BatchExecution[] = [];
  submitted.forEach((item, index) => {
    const operation = items[index]?.create || items[index]?.update;
    if (operation && !operation.error && operation.status >= 200 && operation.status < 300) runnable.push(item);
    else busy.push(item.claim);
  });
  return { runnable, completed, busy };
}

async function transitionBatchOwned(
  client: any,
  index: string,
  items: Array<{ id: string; fence: Fence; state: string }>,
  docFor: (item: { id: string; fence: Fence; state: string }) => any
): Promise<boolean> {
  if (!items.length) return true;
  const body: any[] = [];
  for (const item of items) {
    body.push({ update: { _index: assertManagedWriteTarget(index), _id: item.id } });
    body.push({ script: {
      lang: 'painless',
      source:
        'if (ctx._source.state != params.state || ctx._source.holder_id != params.holder || ' +
        'ctx._source.fencing_generation != params.generation || ctx._source.lease_token != params.token) ' +
        '{ ctx.op = "noop"; return; } for (entry in params.doc.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }',
      params: {
        state: item.state,
        holder: item.fence.holderId,
        generation: item.fence.generation,
        token: item.fence.token,
        doc: docFor(item),
      },
    } });
  }
  const results = await executeBulkPairs(client, body);
  return results.length === items.length && results.every((result: any) => {
    const operation = result.update;
    return operation && !operation.error && operation.status >= 200 && operation.status < 300 && operation.result !== 'noop';
  });
}

async function assertBatchOwned(
  client: any,
  workerLeaseId: string,
  workerFence: Fence,
  _executions: BatchExecution[]
): Promise<void> {
  const worker: any = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: workerLeaseId });
  const now = Date.now();
  const workerSource = worker?.body?._source || {};
  if (!owns(workerSource, workerFence, 'lease') || !(Date.parse(workerSource.lease_expires_at || '') > now)) {
    throw ownershipLostError();
  }
}

function startBatchHeartbeat(
  client: any,
  workerLeaseId: string,
  workerFence: Fence,
  executions: BatchExecution[],
  leaseSeconds: number
) {
  let stopped = false;
  let lost = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let inFlight: Promise<void> = Promise.resolve();
  const intervalMs = Math.max(1000, Math.min(30000, Math.floor(leaseSeconds * 1000 / 3)));
  const beat = () => {
    inFlight = (async () => {
      const worker = await renewOwnedLease(
        client, AUTOMATION_EXECUTIONS_INDEX, workerLeaseId, workerFence, leaseSeconds, 'lease'
      );
      const expiry = new Date(Date.now() + leaseSeconds * 1000).toISOString();
      const queue = worker && await transitionBatchOwned(
        client,
        AUTOMATION_QUEUE_INDEX,
        executions.map((execution) => ({ id: execution.claim.id, fence: execution.claim.fence, state: 'claimed' })),
        () => ({ lease_expires_at: expiry, updated_at: new Date().toISOString() })
      );
      const running = queue && await transitionBatchOwned(
        client,
        AUTOMATION_EXECUTIONS_INDEX,
        executions.map((execution) => ({ id: execution.executionId, fence: execution.claim.fence, state: 'running' })),
        () => ({ lease_expires_at: expiry, updated_at: new Date().toISOString() })
      );
      if (!running) lost = true;
    })().catch(() => { lost = true; }).finally(() => {
      if (!stopped && !lost) timer = setTimeout(beat, intervalMs);
    });
  };
  timer = setTimeout(beat, intervalMs);
  return {
    async stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      await inFlight;
      return !lost;
    },
  };
}

async function findDlqEvent(client: any, eventId: string) {
  const result: any = await client.search({
    index: AUTOMATION_DLQ_INDEX,
    seq_no_primary_term: true,
    body: {
      size: 1,
      query: { term: { event_id: eventId } },
      sort: [{ failed_at: 'desc' }, { event_id: 'asc' }, { stage: 'asc' }],
    },
  });
  return result?.body?.hits?.hits?.[0] || null;
}

export async function retryAutomationDlqEvent(client: any, eventId: string) {
  const hit = await findDlqEvent(client, eventId);
  if (!hit) {
    try {
      const queue: any = await client.get({ index: AUTOMATION_QUEUE_INDEX, id: eventId });
      const state = queue?.body?._source?.state;
      if (['pending', 'retry', 'claimed', 'completed'].includes(state)) return { eventId, state, idempotent: true };
    } catch (error: any) {
      if (error?.meta?.statusCode !== 404) throw error;
    }
    throw Object.assign(new Error('Automation DLQ event not found'), { statusCode: 404 });
  }
  const source = hit._source || {};
  if (!source.payload?.alert_uid) throw new Error('Automation DLQ event has no recoverable payload');
  const now = new Date().toISOString();
  const rulesetSnapshot = source.ruleset_snapshot || 'rules-v1';
  const ruleRevisions = source.rule_revisions || [];
  const admissionCutoff = source.admission_cutoff;
  let currentQueue: any = null;
  try {
    currentQueue = await client.get({ index: AUTOMATION_QUEUE_INDEX, id: eventId });
    const currentState = currentQueue?.body?._source?.state;
    if (currentState === 'claimed' || currentState === 'completed') {
      return { eventId, state: currentState, idempotent: true };
    }
  } catch (error: any) {
    if (error?.meta?.statusCode !== 404) throw error;
  }
  await client.update({
    index: assertManagedWriteTarget(AUTOMATION_QUEUE_INDEX),
    id: eventId,
    ...(currentQueue ? {
      if_seq_no: currentQueue.body._seq_no,
      if_primary_term: currentQueue.body._primary_term,
    } : {}),
    body: {
      doc: {
        state: 'retry', available_at: now, attempts: 0, holder_id: null,
        fencing_generation: null, lease_token: null, lease_expires_at: null, last_error: null,
        ruleset_snapshot: rulesetSnapshot,
        rule_revisions: ruleRevisions,
        admission_cutoff: admissionCutoff,
        event_timestamp: source.payload['@timestamp'] || source.payload.ingested_at || now,
      },
      upsert: {
        event_id: eventId, alert_uid: source.payload.alert_uid, ruleset_snapshot: rulesetSnapshot,
        rule_revisions: ruleRevisions,
        admission_cutoff: admissionCutoff,
        event_timestamp: source.payload['@timestamp'] || source.payload.ingested_at || now,
        state: 'retry', enqueued_at: now, available_at: now, attempts: 0, payload: source.payload,
      },
    },
  });
  const executionId = automationExecutionId(eventId, rulesetSnapshot);
  await client.update({
    index: assertManagedWriteTarget(AUTOMATION_EXECUTIONS_INDEX),
    id: executionId,
    body: {
      doc: {
        state: 'retry', updated_at: now, attempts: 0, holder_id: null,
        fencing_generation: null, lease_token: null, lease_expires_at: null, last_error: null,
        admission_cutoff: admissionCutoff,
      },
      upsert: {
        execution_id: executionId, event_id: eventId, alert_uid: source.payload.alert_uid,
        ruleset_snapshot: rulesetSnapshot, state: 'retry', updated_at: now, attempts: 0,
        rule_revisions: ruleRevisions, admission_cutoff: admissionCutoff,
      },
    },
  });
  try {
    await client.delete({
      index: assertManagedWriteTarget(AUTOMATION_DLQ_INDEX), id: hit._id,
      if_seq_no: hit._seq_no, if_primary_term: hit._primary_term,
    });
  } catch (error: any) {
    if (error?.meta?.statusCode !== 404 && !isConflict(error)) throw error;
  }
  return { eventId, state: 'retry', attempts: 0 };
}

function encodeCursor(sort: any[]) {
  return Buffer.from(JSON.stringify(sort), 'utf8').toString('base64');
}

function decodeCursor(cursor?: string): any[] | undefined {
  if (!cursor) return undefined;
  try {
    const value = JSON.parse(Buffer.from(cursor, 'base64').toString('utf8'));
    if (!Array.isArray(value)) throw new Error();
    return value;
  } catch (error) {
    throw Object.assign(new Error('Invalid automation DLQ cursor'), { statusCode: 400 });
  }
}

export async function listAutomationDlq(client: any, limit = 50, cursor?: string) {
  const result: any = await client.search({
    index: AUTOMATION_DLQ_INDEX,
    body: {
      size: Math.min(200, Math.max(1, limit)),
      sort: [{ failed_at: 'desc' }, { event_id: 'asc' }, { stage: 'asc' }],
      ...(cursor ? { search_after: decodeCursor(cursor) } : {}),
      query: { match_all: {} },
    },
  });
  const hits = result?.body?.hits?.hits || [];
  return {
    items: hits.map((hit: any) => ({ id: hit._id, ...hit._source })),
    nextCursor: hits.length === Math.min(200, Math.max(1, limit)) ? encodeCursor(hits[hits.length - 1].sort) : null,
  };
}

export async function resolveAutomationDlqEvent(client: any, id: string) {
  try {
    await client.delete({ index: assertManagedWriteTarget(AUTOMATION_DLQ_INDEX), id });
    return { id, resolved: true };
  } catch (error: any) {
    if (error?.meta?.statusCode === 404) return { id, resolved: true, idempotent: true };
    throw error;
  }
}

export async function automationQueueHealth(client: any) {
  const [queue, dlq, settings, lease]: any[] = await Promise.all([
    client.search({
      index: AUTOMATION_QUEUE_INDEX,
      body: {
        size: 0,
        // OpenSearch otherwise caps hits.total.value at 10,000. Queue capacity
        // and admission decisions must use the exact active backlog.
        track_total_hits: true,
        query: { terms: { state: ['pending', 'claimed', 'retry', 'deferred'] } },
        aggs: {
          oldest: { min: { field: 'enqueued_at' } },
          retries: { filter: { term: { state: 'retry' } } },
          states: { terms: { field: 'state', size: 10 } },
          max_fencing_generation: { max: { field: 'fencing_generation' } },
        },
      },
    }),
    client.count({ index: AUTOMATION_DLQ_INDEX, body: { query: { match_all: {} } } }),
    loadAutomationSettings(client),
    client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: AUTOMATION_WORKER_LEASE_ID }).catch((error: any) => {
      if (error?.meta?.statusCode === 404) return null;
      throw error;
    }),
  ]);
  const rawTotal = queue?.body?.hits?.total;
  const total = typeof rawTotal === 'number' ? rawTotal : rawTotal?.value ?? 0;
  const oldest = queue?.body?.aggregations?.oldest?.value_as_string || null;
  const states = Object.fromEntries(
    (queue?.body?.aggregations?.states?.buckets || []).map((bucket: any) => [bucket.key, bucket.doc_count])
  );
  const deferred = Number(states.deferred || 0);
  const active = total - deferred;
  return {
    lag: total,
    oldestEvent: oldest,
    oldestAgeSeconds: oldest ? Math.max(0, Math.floor((Date.now() - Date.parse(oldest)) / 1000)) : null,
    retries: queue?.body?.aggregations?.retries?.doc_count ?? 0,
    dlq: dlq?.body?.count ?? 0,
    states,
    paused: settings.paused,
    admissionOpen: !settings.paused && active < settings.maxBacklog && deferred < settings.maxDeferred,
    deferred,
    maxBacklog: settings.maxBacklog,
    maxDeferred: settings.maxDeferred,
    fencing: {
      generation: lease?.body?._source?.fencing_generation ?? null,
      holderId: lease?.body?._source?.holder_id ?? null,
      leaseExpiresAt: lease?.body?._source?.lease_expires_at ?? null,
      maxQueueGeneration: queue?.body?.aggregations?.max_fencing_generation?.value ?? null,
    },
  };
}
