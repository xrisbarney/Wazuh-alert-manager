import * as crypto from 'crypto';
import { Logger } from '../../../../src/core/server';
import {
  ALERT_STATUS_INDEX,
  AUTOMATION_EXECUTIONS_INDEX,
  CorrelationRule,
  MAX_AUTO_CASES_PER_RUN,
  RULES_INDEX,
} from '../../common';
import { buildMatchFilters, coverageRequirements, evaluateAlertMatch } from './correlation';
import { normalizeAutomationRules, planAutomation, NormalizedAutomationRule } from './automation_planner';
import { canonicalizeRuleSchema } from './rule_schema_migration';
import {
  evaluateEntityExpression,
  MatchingEntityGroup,
  matchingEntityGroupIdentity,
} from './entity_expression';
import { resolveAlerts } from './index_resolution';
import { buildReportingUpdate } from './reporting_fields';
import {
  applyAutomationCaseRoutes,
  AutomationCaseTrigger,
  automationMatchingKey,
  planAutomationCaseRoutes,
} from './automation_case_routing';

const RULE_ACTOR = 'correlation-rule';
const MAX_WINDOW_RESULTS = 1000;

export interface AutomationRulesetSnapshot {
  id: string;
  rules: any[];
  revisions?: Array<{ id: string; revision: number }>;
  /** Admission time for this immutable ruleset. Alerts become eligible when first ingested, not by event time. */
  effective_from?: string;
  effectiveFrom?: string;
  /** Immutable upper ingestion-time bound captured when this alert was admitted. */
  admission_cutoff?: string;
  admissionCutoff?: string;
}

export type AutomationExecutionOwnershipGuard =
  | (() => boolean | Promise<boolean>)
  | { isOwner: () => boolean | Promise<boolean> }
  | { assertOwned: () => boolean | void | Promise<boolean | void> };

export interface AutomationEvaluationLimits {
  maxMatches: number;
  maxStatusChanges: number;
  maxAssignments: number;
  maxCaseLinks: number;
  maxCaseCreations: number;
}

export const DEFAULT_AUTOMATION_LIMITS: AutomationEvaluationLimits = {
  maxMatches: 1000,
  maxStatusChanges: 1000,
  maxAssignments: 1000,
  // One worker batch can contain up to 64 anchors and multiple deduplicated
  // entity routes. Two hundred links forced otherwise healthy batches through
  // the retry path. This remains bounded, but is sized to let a normal batch
  // finish atomically on high-volume nodes.
  maxCaseLinks: 4096,
  maxCaseCreations: MAX_AUTO_CASES_PER_RUN,
};

export interface AutomationEvaluationCounters {
  matches: number;
  statusChanges: number;
  assignments: number;
  caseLinks: number;
  caseCreations: number;
  skippedBySafety: number;
}

export interface AutomationEvaluationFailure {
  stage:
    | 'rule_loading'
    | 'rate_limit'
    | 'alert_resolution'
    | 'window'
    | 'action_mutation'
    | 'case_dedup'
    | 'case_write'
    | 'evidence_linkage'
    | 'execution_state';
  message: string;
  ruleId?: string;
  alertId?: string;
  entityValue?: string;
}

export type AutomationEvaluationOutcome =
  | { status: 'terminal_success'; counters: AutomationEvaluationCounters; appliedRuleIds: string[] }
  | {
      status: 'retryable_failure';
      counters: AutomationEvaluationCounters;
      appliedRuleIds: string[];
      failures: AutomationEvaluationFailure[];
    };

export interface AutomationAlertSample {
  id: string;
  source: any;
}

export interface RuleTriggerEvaluation {
  rule: NormalizedAutomationRule;
  anchorAlertId: string;
  anchorTimestamp: string;
  group: MatchingEntityGroup;
  matchingKey: string;
  alertIds: string[];
  count: number;
  threshold: number;
  windowMinutes: number;
  truncated: boolean;
  triggered: boolean;
}

export interface AutomationTriggerState {
  armed: boolean;
  last_seen_at: string;
  last_fired_at: string | null;
  last_trigger_alert_id: string | null;
  activities?: Array<{ id: string; timestamp: string; triggered: boolean }>;
  fired_event_ids?: string[];
}

export function transitionAutomationTrigger(
  evaluation: RuleTriggerEvaluation,
  current?: AutomationTriggerState
): { fire: boolean; state?: AutomationTriggerState } {
  if (evaluation.rule.trigger.type === 'per_alert') return { fire: true, state: current };
  const activity = { id: evaluation.anchorAlertId, timestamp: evaluation.anchorTimestamp, triggered: evaluation.triggered };
  const activities = [...(current?.activities || [])];
  if (!activities.length && current?.last_fired_at) {
    activities.push({
      id: current.last_trigger_alert_id || '__legacy_fired__',
      timestamp: current.last_fired_at,
      triggered: true,
    });
  }
  if (!activities.length && current?.last_seen_at) {
    activities.push({ id: '__legacy_seen__', timestamp: current.last_seen_at, triggered: false });
  } else if (current?.last_seen_at && !activities.some((item) => item.timestamp === current.last_seen_at)) {
    activities.push({ id: '__legacy_seen__', timestamp: current.last_seen_at, triggered: false });
  }
  const existing = activities.findIndex((item) => item.id === activity.id);
  if (existing < 0) activities.push(activity);
  else activities[existing] = activity;
  activities.sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp) || left.id.localeCompare(right.id));
  const quietMs = Number(evaluation.rule.trigger.rearm?.quietPeriodMinutes || 0) * 60000;
  const cooldownMs = Number(evaluation.rule.trigger.cooldown?.durationMinutes || 0) * 60000;
  const recomputedFired = new Set<string>();
  let armed = true;
  let lastSeen = Number.NaN;
  let lastFired = Number.NaN;
  let lastFiredId: string | null = null;
  for (const item of activities) {
    const itemMs = Date.parse(item.timestamp);
    if (!Number.isFinite(itemMs)) continue;
    if (evaluation.rule.trigger.rearm?.type === 'immediate' ||
        (Number.isFinite(lastSeen) && itemMs - lastSeen >= quietMs)) armed = true;
    if (item.triggered && armed && (!Number.isFinite(lastFired) || itemMs - lastFired >= cooldownMs)) {
      recomputedFired.add(item.id);
      armed = false;
      lastFired = itemMs;
      lastFiredId = item.id;
    }
    lastSeen = itemMs;
  }
  const fired = new Set(current?.fired_event_ids?.length ? current.fired_event_ids : (
    current?.last_fired_at ? [current.last_trigger_alert_id || '__legacy_fired__'] : []
  ));
  const candidateMs = Date.parse(evaluation.anchorTimestamp);
  const existingFireTimes = activities
    .filter((item) => fired.has(item.id))
    .map((item) => Date.parse(item.timestamp))
    .filter(Number.isFinite);
  if (recomputedFired.has(evaluation.anchorAlertId) &&
      !existingFireTimes.some((value) => Math.abs(candidateMs - value) < cooldownMs)) {
    fired.add(evaluation.anchorAlertId);
  }
  if (fired.size) {
    const latestFired = activities.filter((item) => fired.has(item.id)).sort(
      (left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp) || right.id.localeCompare(left.id)
    )[0];
    if (latestFired) {
      lastFired = Date.parse(latestFired.timestamp);
      lastFiredId = latestFired.id;
    }
  }
  const last = activities[activities.length - 1];
  return {
    fire: fired.has(evaluation.anchorAlertId),
    state: {
      armed,
      last_seen_at: last?.timestamp || evaluation.anchorTimestamp,
      last_fired_at: Number.isFinite(lastFired) ? new Date(lastFired).toISOString() : null,
      last_trigger_alert_id: lastFiredId,
      activities,
      fired_event_ids: Array.from(fired).sort(),
    },
  };
}

const emptyCounters = (): AutomationEvaluationCounters => ({
  matches: 0,
  statusChanges: 0,
  assignments: 0,
  caseLinks: 0,
  caseCreations: 0,
  skippedBySafety: 0,
});

const messageOf = (error: any) => error?.reason || error?.caused_by?.reason || error?.message || String(error);
const hash = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
export const automationTriggerStateId = (matchingKey: string) => `trigger-state:${hash(matchingKey).slice(0, 48)}`;
const automationTriggerMarkerId = (matchingKey: string, alertId: string) =>
  `trigger:${hash(`${matchingKey}|${alertId}`).slice(0, 48)}`;
const timestamp = (source: any) => Date.parse(String(source?.['@timestamp'] || ''));
const compareSamples = (left: AutomationAlertSample, right: AutomationAlertSample) =>
  timestamp(left.source) - timestamp(right.source) || left.id.localeCompare(right.id);

async function mapConcurrent<T, R>(
  values: readonly T[],
  concurrency: number,
  operation: (value: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let cursor = 0;
  let firstFailure: any;
  const workers = Array.from({ length: Math.min(Math.max(1, concurrency), values.length) }, async () => {
    while (cursor < values.length && !firstFailure) {
      const index = cursor++;
      try {
        results[index] = await operation(values[index], index);
      } catch (error) {
        if (!firstFailure) firstFailure = error;
      }
    }
  });
  await Promise.all(workers);
  if (firstFailure) throw firstFailure;
  return results;
}

function defaultGroup(): MatchingEntityGroup {
  return { groupId: '__default__', order: 0, values: [] };
}

export function normalizeStoredAutomationRule(input: any): NormalizedAutomationRule {
  return normalizeAutomationRules([canonicalizeRuleSchema(input) as CorrelationRule])[0];
}

function groupsFor(rule: NormalizedAutomationRule, source: any): MatchingEntityGroup[] {
  const expression = rule.trigger.entityExpression!;
  if (!expression.groups.length) return [defaultGroup()];
  return evaluateEntityExpression(expression, source).matchingGroups;
}

function hasCoverage(rule: NormalizedAutomationRule, alerts: AutomationAlertSample[]): boolean {
  const required = coverageRequirements(rule.match);
  const ids = new Set<string>();
  const groups = new Set<string>();
  const agents = new Set<string>();
  for (const alert of alerts) {
    if (alert.source?.rule?.id != null) ids.add(String(alert.source.rule.id));
    for (const group of Array.isArray(alert.source?.rule?.groups) ? alert.source.rule.groups : []) groups.add(String(group));
    if (alert.source?.agent?.name != null) agents.add(String(alert.source.agent.name));
  }
  return required.ids.every((id) => ids.has(id)) && required.groups.every((group) => groups.has(group)) &&
    required.agents.every((agent) => agents.has(agent));
}

/** Shared live/preview trigger evaluator. Every OR group is evaluated and retained independently. */
export function evaluateRuleAtAlert(
  rule: NormalizedAutomationRule,
  anchor: AutomationAlertSample,
  samples: readonly AutomationAlertSample[],
  truncated = false,
  effectiveFrom?: string,
  admissionCutoff?: string
): RuleTriggerEvaluation[] {
  const effectiveMs = Date.parse(String(effectiveFrom || ''));
  const cutoffMs = Date.parse(String(admissionCutoff || ''));
  const eligible = (sample: AutomationAlertSample) => {
    const ingestedMs = Date.parse(String(sample.source?.ingested_at || ''));
    if (!Number.isFinite(effectiveMs) && !Number.isFinite(cutoffMs)) return true;
    return Number.isFinite(ingestedMs) &&
      (!Number.isFinite(effectiveMs) || ingestedMs >= effectiveMs) &&
      (!Number.isFinite(cutoffMs) || ingestedMs <= cutoffMs);
  };
  if (!eligible(anchor)) return [];
  if (!evaluateAlertMatch(rule, anchor.source).matched) return [];
  const anchorMs = timestamp(anchor.source);
  if (!Number.isFinite(anchorMs)) throw new Error(`Alert ${anchor.id} has no valid @timestamp`);
  const anchorGroups = groupsFor(rule, anchor.source);
  if (!anchorGroups.length) return [];
  return anchorGroups.map((group) => {
    const matchingKey = automationMatchingKey(rule.id, group);
    let matches = [anchor];
    let threshold = 1;
    let windowMinutes = 0;
    if (rule.trigger.type === 'burst') {
      threshold = Number(rule.trigger.threshold);
      windowMinutes = Number(rule.trigger.windowMinutes);
      const lower = anchorMs - windowMinutes * 60000;
      matches = samples.filter((sample) => {
        const value = timestamp(sample.source);
        if (!eligible(sample) || !Number.isFinite(value) || value < lower || value > anchorMs || !evaluateAlertMatch(rule, sample.source).matched) return false;
        return groupsFor(rule, sample.source).some(
          (candidate) => matchingEntityGroupIdentity(candidate) === matchingEntityGroupIdentity(group)
        );
      }).sort(compareSamples);
    }
    const triggered = matches.length >= threshold && hasCoverage(rule, matches);
    return {
      rule,
      anchorAlertId: anchor.id,
      anchorTimestamp: new Date(anchorMs).toISOString(),
      group,
      matchingKey,
      alertIds: matches.map((sample) => sample.id),
      count: matches.length,
      threshold,
      windowMinutes,
      truncated,
      triggered,
    };
  });
}

function retryable(counters: AutomationEvaluationCounters, rules: Set<string>, failures: AutomationEvaluationFailure[]): AutomationEvaluationOutcome {
  return { status: 'retryable_failure', counters, appliedRuleIds: Array.from(rules).sort(), failures };
}

async function loadRules(client: any, snapshot?: AutomationRulesetSnapshot): Promise<NormalizedAutomationRule[]> {
  if (snapshot) {
    // Presence, including an empty snapshot, is authoritative for this queued execution.
    return normalizeAutomationRules(snapshot.rules.map((rule) => canonicalizeRuleSchema(rule) as CorrelationRule));
  }
  const response: any = await client.search({ index: RULES_INDEX, body: { size: 200, query: { term: { enabled: true } } } });
  const hits = response?.body?.hits?.hits;
  if (!Array.isArray(hits)) throw new Error('Rule search response did not contain hits');
  const total = Number(response?.body?.hits?.total?.value ?? hits.length);
  if (total > hits.length) throw new Error(`Rule search returned ${hits.length} of ${total} rules`);
  return normalizeAutomationRules(hits.map((hit: any) => canonicalizeRuleSchema({ id: hit._id, ...(hit._source || {}) }) as CorrelationRule));
}

async function windowSamples(
  client: any,
  rule: NormalizedAutomationRule,
  latestAnchorTimestamp: string,
  effectiveFrom?: string,
  admissionCutoff?: string,
  earliestAnchorTimestamp = latestAnchorTimestamp
) {
  const from = new Date(Date.parse(earliestAnchorTimestamp) - Number(rule.trigger.windowMinutes) * 60000).toISOString();
  const response: any = await client.search({
    index: ALERT_STATUS_INDEX,
    body: {
      size: MAX_WINDOW_RESULTS + 1,
      track_total_hits: true,
      _source: true,
      sort: [{ '@timestamp': { order: 'asc' } }, { alert_uid: { order: 'asc' } }],
      query: {
        bool: {
          must: [
            { range: { '@timestamp': { gte: from, lte: latestAnchorTimestamp } } },
            ...(effectiveFrom || admissionCutoff ? [{ range: { ingested_at: {
              ...(effectiveFrom ? { gte: effectiveFrom } : {}),
              ...(admissionCutoff ? { lte: admissionCutoff } : {}),
            } } }] : []),
          ],
          filter: buildMatchFilters(rule.match),
        },
      },
    },
  });
  const hits = response?.body?.hits?.hits;
  if (!Array.isArray(hits)) throw new Error('Burst window response did not contain hits');
  const total = Number(response?.body?.hits?.total?.value ?? hits.length);
  return {
    samples: hits.slice(0, MAX_WINDOW_RESULTS).map((hit: any) => ({ id: String(hit._id), source: hit._source || {} })).sort(compareSamples),
    truncated: total > MAX_WINDOW_RESULTS || hits.length > MAX_WINDOW_RESULTS,
  };
}

function isConflict(error: any) {
  return error?.meta?.statusCode === 409;
}

async function assertOwnership(guard?: AutomationExecutionOwnershipGuard) {
  if (!guard) return;
  const owned = await (typeof guard === 'function'
    ? guard()
    : 'assertOwned' in guard
    ? guard.assertOwned()
    : guard.isOwner());
  if (owned === false) throw Object.assign(new Error('Automation execution ownership was lost'), { ownershipLost: true });
}

export const automationRateLimitStateId = (ruleId: string) => `rate-limit:${hash(ruleId).slice(0, 48)}`;

async function reserveRateLimit(
  client: any,
  evaluation: RuleTriggerEvaluation,
  guard?: AutomationExecutionOwnershipGuard
): Promise<boolean> {
  const limit = evaluation.rule.safety.rateLimit;
  if (!limit || !evaluation.triggered) return evaluation.triggered;
  const reservationId = `${evaluation.matchingKey}|${evaluation.anchorAlertId}`;
  const stateId = automationRateLimitStateId(evaluation.rule.id);
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await assertOwnership(guard);
    let current: any;
    try {
      current = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: stateId });
    } catch (error: any) {
      if (error?.meta?.statusCode !== 404) throw error;
      try {
        const reservedAt = new Date().toISOString();
        await client.create({
          index: AUTOMATION_EXECUTIONS_INDEX,
          id: stateId,
          body: {
            state: 'rate_limit', rule_id: evaluation.rule.id,
            reservations: [{ id: reservationId, timestamp: reservedAt }],
            updated_at: new Date().toISOString(),
          },
        });
        return true;
      } catch (error: any) {
        if (!isConflict(error)) throw error;
        continue;
      }
    }
    const source = current.body._source || {};
    const stored = Array.isArray(source.reservations) ? source.reservations : [];
    if (stored.some((item: any) => item.id === reservationId)) return true;
    const reservedAt = new Date().toISOString();
    const cutoff = Date.parse(reservedAt) - Number(limit.windowMinutes) * 60000;
    const active = stored.filter((item: any) => Date.parse(String(item.timestamp)) >= cutoff);
    if (active.length >= Number(limit.maxExecutions)) return false;
    const reservations = [...stored, { id: reservationId, timestamp: reservedAt }];
    try {
      await client.update({
        index: AUTOMATION_EXECUTIONS_INDEX, id: stateId,
        if_seq_no: current.body._seq_no, if_primary_term: current.body._primary_term,
        body: { doc: { reservations, updated_at: new Date().toISOString() } },
      });
      return true;
    } catch (error: any) {
      if (!isConflict(error)) throw error;
    }
  }
  throw new Error('Rate limit could not be reserved after OCC retries');
}

async function reserveTrigger(
  client: any,
  evaluation: RuleTriggerEvaluation,
  guard?: AutomationExecutionOwnershipGuard
): Promise<boolean> {
  if (typeof client.create !== 'function' || typeof client.get !== 'function') return evaluation.triggered;
  const markerId = automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId);
  try {
    await assertOwnership(guard);
    await client.create({
      index: AUTOMATION_EXECUTIONS_INDEX,
      id: markerId,
      body: { state: 'pending', rule_id: evaluation.rule.id, alert_uid: evaluation.anchorAlertId, updated_at: new Date().toISOString() },
    });
  } catch (error: any) {
    if (!isConflict(error)) throw error;
    const marker: any = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: markerId });
    if (marker?.body?._source?.state === 'completed') return false;
  }
  if (evaluation.rule.trigger.type === 'per_alert') return evaluation.triggered;

  const stateId = automationTriggerStateId(evaluation.matchingKey);
  for (let attempt = 0; attempt < 8; attempt += 1) {
    let current: any;
    try {
      current = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: stateId });
    } catch (error: any) {
      if (error?.meta?.statusCode !== 404) throw error;
      try {
        await assertOwnership(guard);
        await client.create({
          index: AUTOMATION_EXECUTIONS_INDEX,
          id: stateId,
          body: {
            state: 'trigger_state', rule_id: evaluation.rule.id, matching_key: evaluation.matchingKey,
            ...transitionAutomationTrigger(evaluation).state,
            updated_at: new Date().toISOString(),
          },
        });
        return evaluation.triggered;
      } catch (createError: any) {
        if (!isConflict(createError)) throw createError;
        continue;
      }
    }
    const source = current.body._source || {};
    const transition = transitionAutomationTrigger(evaluation, {
      armed: source.armed === true,
      last_seen_at: source.last_seen_at,
      last_fired_at: source.last_fired_at || null,
      last_trigger_alert_id: source.last_trigger_alert_id || null,
      activities: source.activities || [],
      fired_event_ids: source.fired_event_ids || [],
    });
    const nextState = transition.state!;
    try {
      await assertOwnership(guard);
      await client.update({
        index: AUTOMATION_EXECUTIONS_INDEX,
        id: stateId,
        if_seq_no: current.body._seq_no,
        if_primary_term: current.body._primary_term,
        body: { doc: {
          ...nextState,
          updated_at: new Date().toISOString(),
        } },
      });
      return transition.fire;
    } catch (error: any) {
      if (!isConflict(error)) throw error;
    }
  }
  throw new Error('Trigger state could not be reserved after OCC retries');
}

async function completeTrigger(client: any, evaluation: RuleTriggerEvaluation, guard?: AutomationExecutionOwnershipGuard) {
  if (typeof client.update !== 'function' || typeof client.create !== 'function') return;
  await assertOwnership(guard);
  const markerId = automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId);
  await client.update({ index: AUTOMATION_EXECUTIONS_INDEX, id: markerId, body: { doc: { state: 'completed', updated_at: new Date().toISOString() } } });
}

async function reserveImmediateTriggerBatch(
  client: any,
  entries: Array<{ evaluation: RuleTriggerEvaluation; index: number }>,
  guard?: AutomationExecutionOwnershipGuard
): Promise<boolean[]> {
  if (!entries.length) return [];
  if (typeof client.bulk !== 'function' || typeof client.mget !== 'function') {
    return mapConcurrent(entries, 8, ({ evaluation }) => reserveTrigger(client, evaluation, guard));
  }
  const eligible = await reserveTriggerMarkersBatch(client, entries, guard);
  return eligible.map((reserved, index) => reserved && entries[index].evaluation.triggered);
}

async function reserveTriggerMarkersBatch(
  client: any,
  entries: Array<{ evaluation: RuleTriggerEvaluation; index: number }>,
  guard?: AutomationExecutionOwnershipGuard
): Promise<boolean[]> {
  await assertOwnership(guard);
  const now = new Date().toISOString();
  const body: any[] = [];
  entries.forEach(({ evaluation }) => {
    body.push({ create: {
      _index: AUTOMATION_EXECUTIONS_INDEX,
      _id: automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId),
    } });
    body.push({
      state: 'pending', rule_id: evaluation.rule.id,
      alert_uid: evaluation.anchorAlertId, updated_at: now,
    });
  });
  const response: any = await client.bulk({ body });
  const items = response?.body?.items || [];
  if (items.length !== entries.length) throw new Error('Trigger reservation bulk returned an incomplete item list');
  const reserved = new Array<boolean>(entries.length);
  const conflicts: Array<{ position: number; id: string }> = [];
  items.forEach((item: any, position: number) => {
    const result = item?.create;
    if (result && !result.error && result.status >= 200 && result.status < 300) {
      reserved[position] = true;
    } else if (result?.status === 409) {
      conflicts.push({
        position,
        id: automationTriggerMarkerId(
          entries[position].evaluation.matchingKey,
          entries[position].evaluation.anchorAlertId
        ),
      });
    } else {
      throw new Error(`Trigger reservation failed with status ${result?.status || 'unknown'}: ${messageOf(result?.error)}`);
    }
  });
  if (conflicts.length) {
    const existing: any = await client.mget({
      index: AUTOMATION_EXECUTIONS_INDEX,
      body: { ids: conflicts.map((conflict) => conflict.id) },
    });
    const docs = existing?.body?.docs || [];
    if (docs.length !== conflicts.length) throw new Error('Trigger conflict lookup was incomplete');
    conflicts.forEach((conflict, offset) => {
      reserved[conflict.position] = docs[offset]?.found !== false && docs[offset]?._source?.state === 'completed'
        ? false
        : true;
    });
  }
  return reserved;
}

async function reserveBurstTriggerGroup(
  client: any,
  evaluations: RuleTriggerEvaluation[],
  guard?: AutomationExecutionOwnershipGuard
): Promise<boolean[]> {
  if (!evaluations.length) return [];
  if (typeof client.bulk !== 'function' || typeof client.mget !== 'function' ||
      typeof client.create !== 'function' || typeof client.get !== 'function') {
    const output: boolean[] = [];
    for (const evaluation of evaluations) output.push(await reserveTrigger(client, evaluation, guard));
    return output;
  }
  const markerEligible = await reserveTriggerMarkersBatch(
    client, evaluations.map((evaluation, index) => ({ evaluation, index })), guard
  );
  const output = new Array<boolean>(evaluations.length).fill(false);
  const active = evaluations
    .map((evaluation, index) => ({ evaluation, index }))
    .filter(({ index }) => markerEligible[index]);
  if (!active.length) return output;
  const stateId = automationTriggerStateId(evaluations[0].matchingKey);
  for (let attempt = 0; attempt < 8; attempt += 1) {
    let current: any = null;
    try {
      current = await client.get({ index: AUTOMATION_EXECUTIONS_INDEX, id: stateId });
    } catch (error: any) {
      if (error?.meta?.statusCode !== 404) throw error;
    }
    const source = current?.body?._source || {};
    let state: AutomationTriggerState | undefined = current ? {
      armed: source.armed === true,
      last_seen_at: source.last_seen_at,
      last_fired_at: source.last_fired_at || null,
      last_trigger_alert_id: source.last_trigger_alert_id || null,
      activities: source.activities || [],
      fired_event_ids: source.fired_event_ids || [],
    } : undefined;
    const ordered = [...active].sort((left, right) =>
      Date.parse(left.evaluation.anchorTimestamp) - Date.parse(right.evaluation.anchorTimestamp) ||
      left.evaluation.anchorAlertId.localeCompare(right.evaluation.anchorAlertId)
    );
    const existingActivities = state?.activities || [];
    const existingIds = new Set(existingActivities.map((item) => item.id));
    const lastSeenMs = Date.parse(String(state?.last_seen_at || ''));
    const canAppendChronologically = (!current || existingActivities.length > 0) && ordered.every(({ evaluation }) => {
      const value = Date.parse(evaluation.anchorTimestamp);
      return Number.isFinite(value) && (!Number.isFinite(lastSeenMs) || value >= lastSeenMs) &&
        !existingIds.has(evaluation.anchorAlertId);
    });
    if (canAppendChronologically) {
      const activities = [...existingActivities];
      const fired = new Set(state?.fired_event_ids || []);
      let armed = state?.armed ?? true;
      let lastSeen = lastSeenMs;
      let lastFired = Date.parse(String(state?.last_fired_at || ''));
      let lastFiredId = state?.last_trigger_alert_id || null;
      for (const { evaluation, index } of ordered) {
        const value = Date.parse(evaluation.anchorTimestamp);
        const quietMs = Number(evaluation.rule.trigger.rearm?.quietPeriodMinutes || 0) * 60000;
        const cooldownMs = Number(evaluation.rule.trigger.cooldown?.durationMinutes || 0) * 60000;
        if (evaluation.rule.trigger.rearm?.type === 'immediate' ||
            (Number.isFinite(lastSeen) && value - lastSeen >= quietMs)) armed = true;
        const fire = evaluation.triggered && armed &&
          (!Number.isFinite(lastFired) || value - lastFired >= cooldownMs);
        if (fire) {
          fired.add(evaluation.anchorAlertId);
          armed = false;
          lastFired = value;
          lastFiredId = evaluation.anchorAlertId;
        }
        activities.push({
          id: evaluation.anchorAlertId,
          timestamp: evaluation.anchorTimestamp,
          triggered: evaluation.triggered,
        });
        lastSeen = value;
        output[index] = fire;
      }
      state = {
        armed,
        last_seen_at: new Date(lastSeen).toISOString(),
        last_fired_at: Number.isFinite(lastFired) ? new Date(lastFired).toISOString() : null,
        last_trigger_alert_id: lastFiredId,
        activities,
        fired_event_ids: Array.from(fired).sort(),
      };
    } else {
      for (const { evaluation, index } of active) {
        const transition = transitionAutomationTrigger(evaluation, state);
        output[index] = transition.fire;
        state = transition.state;
      }
    }
    try {
      await assertOwnership(guard);
      const now = new Date().toISOString();
      if (current) {
        await client.update({
          index: AUTOMATION_EXECUTIONS_INDEX,
          id: stateId,
          if_seq_no: current.body._seq_no,
          if_primary_term: current.body._primary_term,
          body: { doc: { ...state, updated_at: now } },
        });
      } else {
        await client.create({
          index: AUTOMATION_EXECUTIONS_INDEX,
          id: stateId,
          body: {
            state: 'trigger_state', rule_id: evaluations[0].rule.id,
            matching_key: evaluations[0].matchingKey, ...state, updated_at: now,
          },
        });
      }
      return output;
    } catch (error: any) {
      if (!isConflict(error)) throw error;
    }
  }
  throw new Error('Batched trigger state could not be reserved after OCC retries');
}

async function completeTriggers(
  client: any,
  evaluations: RuleTriggerEvaluation[],
  guard?: AutomationExecutionOwnershipGuard
) {
  if (!evaluations.length) return;
  if (typeof client.bulk !== 'function' || typeof client.mget !== 'function') {
    await mapConcurrent(evaluations, 8, (evaluation) => completeTrigger(client, evaluation, guard));
    return;
  }
  await assertOwnership(guard);
  const body: any[] = [];
  const now = new Date().toISOString();
  evaluations.forEach((evaluation) => {
    body.push({ update: {
      _index: AUTOMATION_EXECUTIONS_INDEX,
      _id: automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId),
      retry_on_conflict: 3,
    } });
    body.push({ doc: { state: 'completed', updated_at: now } });
  });
  const response: any = await client.bulk({ body });
  const items = response?.body?.items || [];
  const failed = items.filter((item: any) =>
    !item?.update || item.update.error || item.update.status < 200 || item.update.status >= 300
  );
  if (items.length !== evaluations.length || failed.length) {
    throw new Error(`Trigger completion bulk failed for ${failed.length || 'unknown'} item(s)`);
  }
}

function bulkFailures(result: any, expected: number): string[] {
  const items = result?.body?.items;
  if (!Array.isArray(items) || items.length !== expected) return [`Bulk response contained ${Array.isArray(items) ? items.length : 0} item(s) for ${expected} operation(s)`];
  return items.flatMap((item: any, index: number) => {
    const detail = item?.update;
    const status = Number(detail?.status || 0);
    return detail && !detail.error && status >= 200 && status < 300 ? [] :
      [`Bulk item ${index} failed with status ${status || 'unknown'}: ${messageOf(detail?.error || 'missing operation result')}`];
  });
}

/** Execute one queued alert. A supplied ruleset snapshot is immutable and is never replaced by a live rule read. */
export async function evaluateCorrelationRules(
  client: any,
  syncedHits: any[],
  logger: Logger,
  limits: AutomationEvaluationLimits = DEFAULT_AUTOMATION_LIMITS,
  snapshot?: AutomationRulesetSnapshot,
  ownershipGuard?: AutomationExecutionOwnershipGuard
): Promise<AutomationEvaluationOutcome> {
  const counters = emptyCounters();
  const applied = new Set<string>();
  let continuationRequired = false;
  let rules: NormalizedAutomationRule[];
  try {
    rules = (await loadRules(client, snapshot)).filter((rule) => rule.enabled);
  } catch (error: any) {
    return retryable(counters, applied, [{ stage: 'rule_loading', message: messageOf(error) }]);
  }
  if (!rules.length || !syncedHits.length) return { status: 'terminal_success', counters, appliedRuleIds: [] };
  const boundedInput = syncedHits.slice(0, limits.maxMatches);
  counters.skippedBySafety += syncedHits.length - boundedInput.length;
  continuationRequired = syncedHits.length > boundedInput.length;
  // Admission payloads contain the immutable security fields used for rule
  // matching. Reject controls before resolving mutable workflow state from
  // managed storage. Most production alerts do not match automation rules, so
  // this keeps the hot-path cost proportional to candidates rather than total
  // Wazuh ingestion volume.
  const input = boundedInput.filter((hit) => {
    const source = hit._source || {};
    return rules.some((rule) =>
      evaluateAlertMatch(rule, source).matched && groupsFor(rule, source).length > 0
    );
  });
  if (!input.length) {
    return continuationRequired
      ? retryable(counters, applied, [{
          stage: 'execution_state',
          message: 'Automation safety cap reached; durable trigger markers retain the remaining work for continuation',
        }])
      : { status: 'terminal_success', counters, appliedRuleIds: [] };
  }
  let locations: Map<string, any>;
  try {
    locations = await resolveAlerts(client, input.map((hit) => String(hit._id)), true);
  } catch (error: any) {
    return retryable(counters, applied, [{ stage: 'alert_resolution', message: messageOf(error) }]);
  }
  const missing = input.map((hit) => String(hit._id)).filter((id) => !locations.has(id));
  if (missing.length) return retryable(counters, applied, missing.map((alertId) => ({ stage: 'alert_resolution', alertId, message: 'Alert was not found in managed storage' })));

  const current = input.map((hit) => {
    const resolved = locations.get(String(hit._id))!.source;
    const queued = hit._source || {};
    // Security/source fields are admission-time evidence. Only workflow fields may move while queued.
    return { id: String(hit._id), source: {
      ...queued,
      status: resolved?.status,
      assigned_to: resolved?.assigned_to,
      case_id: resolved?.case_id,
      ingested_at: resolved?.ingested_at,
      state_version: resolved?.state_version,
    } };
  });
  const evaluationTasks: Array<{ anchor: AutomationAlertSample; rule: NormalizedAutomationRule }> = [];
  for (const anchor of current) {
    for (const rule of rules) {
      // Reject non-candidates before a burst window search. At production
      // volume, querying a historical window for every enabled burst rule on
      // an alert that cannot match that rule is prohibitively expensive.
      if (evaluateAlertMatch(rule, anchor.source).matched && groupsFor(rule, anchor.source).length) {
        evaluationTasks.push({ anchor, rule });
      }
    }
  }
  let evaluationGroups: RuleTriggerEvaluation[][];
  try {
    evaluationGroups = new Array<RuleTriggerEvaluation[]>(evaluationTasks.length);
    const burstTasks = new Map<string, Array<{ index: number; anchor: AutomationAlertSample; rule: NormalizedAutomationRule }>>();
    evaluationTasks.forEach(({ anchor, rule }, index) => {
      if (rule.trigger.type === 'burst') {
        const group = burstTasks.get(rule.id) || [];
        group.push({ index, anchor, rule });
        burstTasks.set(rule.id, group);
      } else {
        const anchorMs = timestamp(anchor.source);
        if (!Number.isFinite(anchorMs)) throw new Error(`Alert ${anchor.id} has no valid @timestamp`);
        const effectiveFrom = snapshot?.effective_from || snapshot?.effectiveFrom || (rule as any).effective_from;
        const admissionCutoff = snapshot?.admission_cutoff || snapshot?.admissionCutoff;
        evaluationGroups[index] = evaluateRuleAtAlert(
          rule, anchor, [anchor], false, effectiveFrom, admissionCutoff
        );
      }
    });
    // A worker batch frequently contains dozens of anchors for the same burst
    // rule. Read their union window once, then let the pure evaluator apply
    // each anchor's exact lower/upper event-time boundary locally. This keeps
    // correctness identical while removing N duplicate historical searches.
    await mapConcurrent(Array.from(burstTasks.values()), 8, async (tasks) => {
      const rule = tasks[0].rule;
      const effectiveFrom = snapshot?.effective_from || snapshot?.effectiveFrom || (rule as any).effective_from;
      const admissionCutoff = snapshot?.admission_cutoff || snapshot?.admissionCutoff;
      if (snapshot && !Number.isFinite(Date.parse(String(admissionCutoff || '')))) {
        throw new Error(`Queued burst alert ${tasks[0].anchor.id} has no valid admission cutoff`);
      }
      const anchorTimes = tasks.map(({ anchor }) => {
        const value = timestamp(anchor.source);
        if (!Number.isFinite(value)) throw new Error(`Alert ${anchor.id} has no valid @timestamp`);
        return value;
      });
      const earliest = new Date(Math.min(...anchorTimes)).toISOString();
      const latest = new Date(Math.max(...anchorTimes)).toISOString();
      const window = await windowSamples(client, rule, latest, effectiveFrom, admissionCutoff, earliest);
      for (const { index, anchor } of tasks) {
        const samples = [...window.samples];
        const anchorIndex = samples.findIndex((sample) => sample.id === anchor.id);
        if (anchorIndex < 0) samples.push(anchor);
        else samples[anchorIndex] = anchor;
        evaluationGroups[index] = evaluateRuleAtAlert(
          rule, anchor, samples, window.truncated, effectiveFrom, admissionCutoff
        );
      }
    });
  } catch (error: any) {
    return retryable(counters, applied, [{ stage: 'window', message: messageOf(error) }]);
  }
  const evaluations = ([] as RuleTriggerEvaluation[]).concat(...evaluationGroups);

  const firing: RuleTriggerEvaluation[] = [];
  const triggerReservations = new Array<boolean>(evaluations.length);
  try {
    const immediate = evaluations
      .map((evaluation, index) => ({ evaluation, index }))
      .filter(({ evaluation }) => evaluation.rule.trigger.type === 'per_alert');
    const immediateReservations = await reserveImmediateTriggerBatch(client, immediate, ownershipGuard);
    immediate.forEach(({ index }, position) => {
      triggerReservations[index] = immediateReservations[position];
    });
    // Burst reservations for one rule/entity key remain ordered. Independent
    // entity keys have disjoint state documents and can progress concurrently.
    const burstGroups = new Map<string, number[]>();
    evaluations.forEach((evaluation, index) => {
      if (evaluation.rule.trigger.type === 'per_alert') return;
      const indices = burstGroups.get(evaluation.matchingKey) || [];
      indices.push(index);
      burstGroups.set(evaluation.matchingKey, indices);
    });
    await mapConcurrent(Array.from(burstGroups.values()), 8, async (indices) => {
      const reservations = await reserveBurstTriggerGroup(
        client, indices.map((index) => evaluations[index]), ownershipGuard
      );
      indices.forEach((index, position) => {
        triggerReservations[index] = reservations[position];
      });
    });
  } catch (error: any) {
    return retryable(counters, applied, [{ stage: 'execution_state', message: messageOf(error) }]);
  }
  const notFiring: RuleTriggerEvaluation[] = [];
  for (let index = 0; index < evaluations.length; index += 1) {
    const evaluation = evaluations[index];
    try {
      if (triggerReservations[index] && await reserveRateLimit(client, evaluation, ownershipGuard)) firing.push(evaluation);
      else notFiring.push(evaluation);
    } catch (error: any) {
      return retryable(counters, applied, [{
        stage: error?.ownershipLost ? 'execution_state' : 'rate_limit',
        ruleId: evaluation.rule.id,
        alertId: evaluation.anchorAlertId,
        message: messageOf(error),
      } as AutomationEvaluationFailure]);
    }
  }
  try {
    await completeTriggers(client, notFiring, ownershipGuard);
  } catch (error: any) {
    return retryable(counters, applied, [{ stage: 'execution_state', message: messageOf(error) }]);
  }
  const burstByAlert = new Map<string, Set<string>>();
  const eligibleByAlert = new Map<string, Set<string>>();
  for (const evaluation of firing) {
    const eligible = eligibleByAlert.get(evaluation.anchorAlertId) || new Set<string>();
    eligible.add(evaluation.rule.id);
    eligibleByAlert.set(evaluation.anchorAlertId, eligible);
    const ids = burstByAlert.get(evaluation.anchorAlertId) || new Set<string>();
    ids.add(evaluation.rule.id);
    burstByAlert.set(evaluation.anchorAlertId, ids);
  }
  const plans = planAutomation(current.map((alert) => ({
    ...alert,
    matchedBurstRuleIds: burstByAlert.get(alert.id),
    executionEligibleRuleIds: eligibleByAlert.get(alert.id) || new Set<string>(),
  })), rules);
  counters.matches = plans.reduce((sum, plan) => sum + plan.matched.length, 0);

  const operations: any[] = [];
  let operationCount = 0;
  const perRuleActions = new Map<string, number>();
  for (const plan of plans) {
    if (!plan.mutation) continue;
    const actions: any[] = [];
    const accepts = (ruleId: string | null) => {
      if (!ruleId) return false;
      const rule = rules.find((candidate) => candidate.id === ruleId)!;
      const used = perRuleActions.get(ruleId) || 0;
      if (rule.safety.maxActionsPerRun != null && used >= rule.safety.maxActionsPerRun) {
        counters.skippedBySafety += 1;
        continuationRequired = true;
        return false;
      }
      perRuleActions.set(ruleId, used + 1);
      return true;
    };
    let statusApplied: string | null = null;
    let assignmentApplied: string | null = null;
    if (plan.mutation.status && counters.statusChanges >= limits.maxStatusChanges) {
      counters.skippedBySafety += 1;
      continuationRequired = true;
    } else if (plan.mutation.status && accepts(plan.chosenStatusRuleId)) {
      actions.push({ marker: `status:${plan.chosenStatusRuleId}:${plan.alertId}`, field: 'status', value: plan.mutation.status, rule: plan.chosenStatusRuleId });
      counters.statusChanges += 1;
      statusApplied = plan.mutation.status;
    }
    if (plan.mutation.assigned_to && counters.assignments >= limits.maxAssignments) {
      counters.skippedBySafety += 1;
      continuationRequired = true;
    } else if (plan.mutation.assigned_to && accepts(plan.chosenAssignmentRuleId)) {
      actions.push({ marker: `assignment:${plan.chosenAssignmentRuleId}:${plan.alertId}`, field: 'assigned_to', value: plan.mutation.assigned_to, rule: plan.chosenAssignmentRuleId });
      counters.assignments += 1;
      assignmentApplied = plan.mutation.assigned_to;
    }
    if (statusApplied != null || assignmentApplied != null) {
      const reporting = buildReportingUpdate(
        locations.get(plan.alertId).source,
        { status: statusApplied, assignedTo: assignmentApplied },
        new Date().toISOString()
      );
      if (reporting) {
        actions.push({
          marker: `reporting:${plan.chosenStatusRuleId || plan.chosenAssignmentRuleId}:${plan.alertId}`,
          field: 'reporting',
          value: reporting,
          rule: plan.chosenStatusRuleId || plan.chosenAssignmentRuleId,
          merge: true,
        });
      }
    }
    if (!actions.length) continue;
    operationCount += 1;
    actions.forEach((action) => applied.add(action.rule));
    operations.push(
      { update: { _index: locations.get(plan.alertId).index, _id: plan.alertId } },
      { script: {
        lang: 'painless',
        source:
          'if (ctx._source.state_version != params.expected_state_version || ctx._source.status != params.expected_status || ctx._source.assigned_to != params.expected_assignment) { ctx.op = "noop"; return; } ' +
          'if (ctx._source.automation_action_markers == null) { ctx._source.automation_action_markers = []; } ' +
          'for (action in params.actions) { if (!ctx._source.automation_action_markers.contains(action.marker)) { ' +
          'if (action.merge == true) { ' +
          'if (ctx._source[action.field] == null) { ctx._source[action.field] = [:]; } ' +
          'for (entry in action.value.entrySet()) { ctx._source[action.field][entry.getKey()] = entry.getValue(); } ' +
          '} else { ' +
          'ctx._source[action.field] = action.value; ' +
          'if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(["timestamp":params.now,"user":params.actor,"action":"rule:" + action.rule,"from":null,"to":action.value]); while (ctx._source.history.size() > 1000) { ctx._source.history.remove(0); } ' +
          '} ' +
          'ctx._source.automation_action_markers.add(action.marker); } } ' +
          'ctx._source.state_version = (ctx._source.state_version == null ? 0 : ctx._source.state_version) + 1; ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor;',
        params: {
          actions,
          expected_state_version: locations.get(plan.alertId).source?.state_version,
          expected_status: locations.get(plan.alertId).source?.status,
          expected_assignment: locations.get(plan.alertId).source?.assigned_to,
          now: new Date().toISOString(), actor: RULE_ACTOR,
        },
      } }
    );
  }
  if (operations.length) {
    try {
      await assertOwnership(ownershipGuard);
      const response = await client.bulk({ body: operations });
      const failures = bulkFailures(response, operationCount);
      if (failures.length) return retryable(counters, applied, failures.map((message) => ({ stage: 'action_mutation', message })));
      counters.skippedBySafety += (response?.body?.items || []).filter(
        (item: any) => item?.update?.result === 'noop'
      ).length;
    } catch (error: any) {
      return retryable(counters, applied, [{ stage: 'action_mutation', message: messageOf(error) }]);
    }
  }

  const caseEvaluations = firing.filter((evaluation) =>
    evaluation.rule.actions.createCase &&
    plans.some((plan) => plan.alertId === evaluation.anchorAlertId && plan.matched.includes(evaluation.rule.id))
  );
  const processedCaseAlerts = new Map<string, Set<string>>();
  if (caseEvaluations.length && typeof client.mget === 'function') {
    try {
      const markerIds = caseEvaluations.map((evaluation) =>
        automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId)
      );
      const response: any = await client.mget({
        index: AUTOMATION_EXECUTIONS_INDEX,
        body: { ids: markerIds },
      });
      const markers = response?.body?.docs || [];
      if (markers.length !== caseEvaluations.length) {
        throw new Error('Case progress lookup returned an incomplete marker list');
      }
      caseEvaluations.forEach((evaluation, index) => {
        const marker = markers[index];
        if (marker?.found === false) throw new Error(`Case progress marker ${markerIds[index]} was not found`);
        processedCaseAlerts.set(
          `${evaluation.matchingKey}|${evaluation.anchorAlertId}`,
          new Set(marker?._source?.processed_case_alert_ids || [])
        );
      });
    } catch (error: any) {
      return retryable(counters, applied, [{ stage: 'execution_state', message: messageOf(error) }]);
    }
  } else if (caseEvaluations.length && typeof client.get === 'function') {
    try {
      await mapConcurrent(caseEvaluations, 8, async (evaluation) => {
        const marker: any = await client.get({
          index: AUTOMATION_EXECUTIONS_INDEX,
          id: automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId),
        });
        processedCaseAlerts.set(
          `${evaluation.matchingKey}|${evaluation.anchorAlertId}`,
          new Set(marker?.body?._source?.processed_case_alert_ids || [])
        );
      });
    } catch (error: any) {
      return retryable(counters, applied, [{ stage: 'execution_state', message: messageOf(error) }]);
    }
  }
  const caseTriggers: AutomationCaseTrigger[] = caseEvaluations.map((evaluation) => ({
    ruleId: evaluation.rule.id,
    ruleName: evaluation.rule.name,
    revision: Number(evaluation.rule.revision || 0),
    routing: evaluation.rule.trigger.routing!,
    severity: evaluation.rule.actions.caseSeverity || 'medium',
    assignedTo: evaluation.rule.actions.assignTo ? String(evaluation.rule.actions.assignTo) : null,
    group: evaluation.group,
    alertIds: evaluation.alertIds,
    threshold: evaluation.threshold,
    windowMinutes: evaluation.windowMinutes,
    count: evaluation.count,
    truncated: evaluation.truncated,
  }));
  if (caseTriggers.length) {
    try {
      let linksRemaining = Math.max(0, limits.maxCaseLinks);
      let creationSlots = Math.max(0, limits.maxCaseCreations);
      const creationSlotsByRule = new Map<string, number>();
      const routes = planAutomationCaseRoutes(caseTriggers);
      const planned: Array<{
        route: ReturnType<typeof planAutomationCaseRoutes>[number];
        selectedIds: string[];
        allowCreate: boolean;
      }> = [];
      for (const route of routes) {
        const routeProgress = new Set(caseEvaluations
          .filter((item) => route.matchingKeys.includes(item.matchingKey))
          .flatMap((item) => Array.from(processedCaseAlerts.get(`${item.matchingKey}|${item.anchorAlertId}`) || [])));
        const routeAlertIds = route.alertIds.filter((id) => !routeProgress.has(id));
        if (!routeAlertIds.length) continue;
        const rule = rules.find((candidate) => candidate.id === route.ruleId)!;
        const ruleLimit = rule.safety.maxCasesPerRun ?? Number.POSITIVE_INFINITY;
        if (!linksRemaining) {
          continuationRequired = true;
          counters.skippedBySafety += routeAlertIds.length;
          continue;
        }
        const selectedIds = routeAlertIds.slice(0, linksRemaining);
        if (selectedIds.length < routeAlertIds.length) {
          continuationRequired = true;
          counters.skippedBySafety += routeAlertIds.length - selectedIds.length;
        }
        linksRemaining -= selectedIds.length;
        const ruleSlots = creationSlotsByRule.get(route.ruleId) || 0;
        const allowCreate = creationSlots > 0 && ruleSlots < ruleLimit;
        if (allowCreate) {
          creationSlots -= 1;
          creationSlotsByRule.set(route.ruleId, ruleSlots + 1);
        }
        planned.push({ route, selectedIds, allowCreate });
      }
      // Separate entity groups have disjoint deterministic case identities and
      // can safely cross refresh barriers together. Consolidated/one-per-rule
      // routes stay sequential because their deduplication domains may overlap.
      const routeConcurrency = routes.every((route) => route.routing === 'separate_by_group') ? 8 : 1;
      const routedResults = await mapConcurrent(planned, routeConcurrency, async ({ route, selectedIds, allowCreate }) => {
        await assertOwnership(ownershipGuard);
        const routed = await applyAutomationCaseRoutes(
          client,
          [{ ...route, alertIds: selectedIds }],
          allowCreate ? 1 : 0,
          selectedIds.length,
          new Map([[route.ruleId, allowCreate ? 1 : 0]]),
          () => assertOwnership(ownershipGuard)
        );
        if (!routed.caseIds.length) {
          return { routed, selectedCount: selectedIds.length, incomplete: true };
        }

        const routeEvaluations = caseEvaluations.filter((item) => route.matchingKeys.includes(item.matchingKey));
        if (typeof client.bulk === 'function') {
          const progressBody: any[] = [];
          for (const evaluation of routeEvaluations) {
            const progressKey = `${evaluation.matchingKey}|${evaluation.anchorAlertId}`;
            const completed = processedCaseAlerts.get(progressKey) || new Set<string>();
            selectedIds.filter((id) => evaluation.alertIds.includes(id)).forEach((id) => completed.add(id));
            processedCaseAlerts.set(progressKey, completed);
            progressBody.push({ update: {
              _index: AUTOMATION_EXECUTIONS_INDEX,
              _id: automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId),
              retry_on_conflict: 3,
            } });
            progressBody.push({ doc: {
              processed_case_alert_ids: Array.from(completed).sort(),
              updated_at: new Date().toISOString(),
            } });
          }
          if (progressBody.length) {
            await assertOwnership(ownershipGuard);
            const progress: any = await client.bulk({ body: progressBody });
            const items = progress?.body?.items || [];
            const failed = items.filter((item: any) =>
              !item?.update || item.update.error || item.update.status < 200 || item.update.status >= 300
            );
            if (items.length !== routeEvaluations.length || failed.length) {
              throw new Error(`Case progress bulk failed for ${failed.length || 'unknown'} item(s)`);
            }
          }
        } else if (typeof client.update === 'function') {
          for (const evaluation of routeEvaluations) {
            const progressKey = `${evaluation.matchingKey}|${evaluation.anchorAlertId}`;
            const completed = processedCaseAlerts.get(progressKey) || new Set<string>();
            selectedIds.filter((id) => evaluation.alertIds.includes(id)).forEach((id) => completed.add(id));
            processedCaseAlerts.set(progressKey, completed);
            await assertOwnership(ownershipGuard);
            await client.update({
              index: AUTOMATION_EXECUTIONS_INDEX,
              id: automationTriggerMarkerId(evaluation.matchingKey, evaluation.anchorAlertId),
              body: { doc: { processed_case_alert_ids: Array.from(completed).sort(), updated_at: new Date().toISOString() } },
            });
          }
        }
        return { routed, selectedCount: selectedIds.length, incomplete: false };
      });
      for (const result of routedResults) {
        counters.caseCreations += result.routed.created;
        counters.caseLinks += result.routed.linked;
        if (result.incomplete) {
          continuationRequired = true;
          counters.skippedBySafety += result.selectedCount;
        }
      }
      caseTriggers.forEach((task) => applied.add(task.ruleId));
    } catch (error: any) {
      const message = messageOf(error);
      const stage = /dedup|returned .* case|reserve/i.test(message) ? 'case_dedup' : /Evidence/i.test(message) ? 'evidence_linkage' : 'case_write';
      return retryable(counters, applied, [{ stage, message } as AutomationEvaluationFailure]);
    }
  }
  // Cooldown/rearm suppresses duplicate case creation, not evidence. Once a
  // burst has crossed its threshold, every later alert in the same continuous
  // entity episode must extend the already-open deduplicated case. Route only
  // the new anchor here and set creation allowance to zero; the firing path
  // above remains the sole authority that may create the case.
  const firingIdentities = new Set(firing.map((evaluation) =>
    `${evaluation.matchingKey}\u0000${evaluation.anchorAlertId}`
  ));
  const extensionEvaluations = evaluations.filter((evaluation) =>
    evaluation.triggered &&
    evaluation.rule.trigger.type === 'burst' &&
    evaluation.rule.actions.createCase &&
    !firingIdentities.has(`${evaluation.matchingKey}\u0000${evaluation.anchorAlertId}`)
  );
  if (extensionEvaluations.length) {
    try {
      const extensionTriggers: AutomationCaseTrigger[] = extensionEvaluations.map((evaluation) => ({
        ruleId: evaluation.rule.id,
        ruleName: evaluation.rule.name,
        revision: Number(evaluation.rule.revision || 0),
        routing: evaluation.rule.trigger.routing!,
        severity: evaluation.rule.actions.caseSeverity || 'medium',
        assignedTo: evaluation.rule.actions.assignTo ? String(evaluation.rule.actions.assignTo) : null,
        group: evaluation.group,
        alertIds: [evaluation.anchorAlertId],
        threshold: evaluation.threshold,
        windowMinutes: evaluation.windowMinutes,
        count: evaluation.count,
        truncated: evaluation.truncated,
      }));
      const routes = planAutomationCaseRoutes(extensionTriggers);
      await assertOwnership(ownershipGuard);
      const routed = await applyAutomationCaseRoutes(
        client,
        routes,
        0,
        Math.max(0, limits.maxCaseLinks),
        new Map(rules.map((rule) => [rule.id, 0])),
        () => assertOwnership(ownershipGuard)
      );
      counters.caseLinks += routed.linked;
      extensionEvaluations.forEach((evaluation) => applied.add(evaluation.rule.id));
    } catch (error: any) {
      const message = messageOf(error);
      const stage = /dedup|returned .* case|reserve/i.test(message)
        ? 'case_dedup'
        : /Evidence/i.test(message)
        ? 'evidence_linkage'
        : 'case_write';
      return retryable(counters, applied, [{ stage, message } as AutomationEvaluationFailure]);
    }
  }
  if (continuationRequired) {
    return retryable(counters, applied, [{
      stage: 'execution_state',
      message: 'Automation safety cap reached; durable trigger markers retain the remaining work for continuation',
    }]);
  }
  try {
    await completeTriggers(client, firing, ownershipGuard);
  } catch (error: any) {
    return retryable(counters, applied, [{ stage: 'execution_state', message: messageOf(error) }]);
  }
  return { status: 'terminal_success', counters, appliedRuleIds: Array.from(applied).sort() };
}
