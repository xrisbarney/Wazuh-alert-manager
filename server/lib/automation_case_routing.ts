import * as crypto from 'crypto';
import { CASES_INDEX, CASES_WRITE_ALIAS, CorrelationCaseRouting, EVIDENCE_READ_ALIAS } from '../../common';
import { MatchingEntityGroup, matchingEntityGroupIdentity } from './entity_expression';
import { reconcileCaseEvidence } from './case_evidence_service';
import { buildHistoryEntry } from './history';
import { appendActivityOnce } from './activity';
import { resolveCase } from './case_index_resolution';

const ACTOR = 'correlation-rule';
const ACTIVE_CASE_STATUSES = new Set(['open', 'in_progress']);
const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const digest = (value: string) => crypto.createHash('sha256').update(value).digest('hex');

export interface AutomationCaseTrigger {
  ruleId: string;
  ruleName: string;
  revision: number;
  routing: CorrelationCaseRouting;
  severity: string;
  assignedTo: string | null;
  group: MatchingEntityGroup;
  alertIds: string[];
  threshold: number;
  windowMinutes: number;
  count: number;
  truncated: boolean;
}

export interface AutomationCaseRoute {
  ruleId: string;
  ruleName: string;
  revision: number;
  routing: CorrelationCaseRouting;
  severity: string;
  assignedTo: string | null;
  correlationKey: string;
  matchingKeys: string[];
  alertIds: string[];
  threshold: number;
  windowMinutes: number;
  count: number;
  truncated: boolean;
}

export interface AutomationCaseRoutingResult {
  created: number;
  extended: number;
  linked: number;
  conflicts: string[];
  caseIds: string[];
  /** Deterministic work not attempted because a run-level cap was reached. */
  remainder: AutomationCaseRoute[];
}

export type AutomationCaseRouteFence = () => Promise<void>;

export function automationMatchingKey(ruleId: string, group: MatchingEntityGroup): string {
  return `${ruleId}|${matchingEntityGroupIdentity(group)}`;
}

function overlap(left: AutomationCaseTrigger, right: AutomationCaseTrigger): boolean {
  const ids = new Set(left.alertIds);
  return right.alertIds.some((id) => ids.has(id));
}

function routeFor(tasks: AutomationCaseTrigger[]): AutomationCaseRoute {
  const first = tasks[0];
  const matchingKeys = Array.from(new Set(tasks.map((task) => automationMatchingKey(task.ruleId, task.group)))).sort();
  const scope = first.routing === 'one_per_rule'
    ? `${first.ruleId}|one_per_rule`
    : first.routing === 'separate_by_group'
    ? `${first.ruleId}|separate_by_group|${matchingKeys[0]}`
    // The smallest member is a stable initial claim. Persistent overlap lookup
    // below adopts and unions components as later bursts bridge them.
    : `${first.ruleId}|consolidate_overlapping|${matchingKeys[0]}`;
  return {
    ruleId: first.ruleId,
    ruleName: first.ruleName,
    revision: first.revision,
    routing: first.routing,
    severity: tasks.reduce(
      (value, task) => (SEVERITY_RANK[task.severity] > SEVERITY_RANK[value] ? task.severity : value),
      first.severity
    ),
    assignedTo: first.assignedTo,
    correlationKey: `${first.ruleId}|${first.routing}|${digest(scope).slice(0, 40)}`,
    matchingKeys,
    alertIds: Array.from(new Set(tasks.flatMap((task) => task.alertIds))).sort(),
    threshold: Math.max(...tasks.map((task) => task.threshold)),
    windowMinutes: Math.max(...tasks.map((task) => task.windowMinutes)),
    count: Math.max(...tasks.map((task) => task.count)),
    truncated: tasks.some((task) => task.truncated),
  };
}

/** Pure deterministic case routing. Overlap consolidation is scoped to connected alert-set components. */
export function planAutomationCaseRoutes(input: readonly AutomationCaseTrigger[]): AutomationCaseRoute[] {
  const output: AutomationCaseRoute[] = [];
  const byRule = new Map<string, AutomationCaseTrigger[]>();
  for (const task of input) {
    const tasks = byRule.get(task.ruleId) || [];
    tasks.push({ ...task, alertIds: Array.from(new Set(task.alertIds)).sort() });
    byRule.set(task.ruleId, tasks);
  }
  for (const ruleId of Array.from(byRule.keys()).sort()) {
    const tasks = byRule.get(ruleId)!.sort((a, b) =>
      automationMatchingKey(a.ruleId, a.group).localeCompare(automationMatchingKey(b.ruleId, b.group))
    );
    if (tasks[0].routing === 'one_per_rule') {
      output.push(routeFor(tasks));
      continue;
    }
    if (tasks[0].routing === 'separate_by_group') {
      output.push(...tasks.map((task) => routeFor([task])));
      continue;
    }
    const remaining = new Set(tasks.map((_, index) => index));
    while (remaining.size) {
      const seed = Math.min(...Array.from(remaining));
      remaining.delete(seed);
      const component = [tasks[seed]];
      let changed = true;
      while (changed) {
        changed = false;
        for (const index of Array.from(remaining).sort((a, b) => a - b)) {
          if (!component.some((task) => overlap(task, tasks[index]))) continue;
          component.push(tasks[index]);
          remaining.delete(index);
          changed = true;
        }
      }
      output.push(routeFor(component));
    }
  }
  return output.sort((a, b) => a.correlationKey.localeCompare(b.correlationKey));
}

function provenance(route: AutomationCaseRoute, linked: string[], conflicts: string[]) {
  return {
    threshold: route.threshold,
    window_minutes: route.windowMinutes,
    count: route.count,
    linked_alert_ids: linked,
    linked_count: linked.length,
    truncated: route.truncated,
    revision: route.revision,
    routing: route.routing,
    matching_keys: route.matchingKeys,
    evidence_conflicts: conflicts,
  };
}

async function findOrCreateCase(
  client: any,
  route: AutomationCaseRoute,
  now: string,
  allowCreate: boolean,
  fence: AutomationCaseRouteFence,
  attempt = 0
): Promise<{ id: string; created: boolean; adoptedAlertIds: string[]; duplicates: any[] } | null> {
  let response: any;
  try {
    response = await client.search({
      index: CASES_INDEX,
      body: {
        size: 100,
        track_total_hits: true,
        sort: [{ created_at: { order: 'asc' } }, { case_uid: { order: 'asc' } }],
        // correlation_keys is a bounded compatibility/adoption path for migrated
        // single-entity active cases that predate the canonical claim key.
        query: {
          bool: {
            minimum_should_match: 1,
            should: [
              { term: { correlation_key: route.correlationKey } },
              {
                bool: {
                  must: [{ terms: { correlation_keys: route.matchingKeys } }],
                  minimum_should_match: 1,
                  should: [
                    { term: { correlation_routing: route.routing } },
                    { bool: { must_not: [{ exists: { field: 'correlation_routing' } }] } },
                  ],
                },
              },
            ],
          },
        },
      },
    });
  } catch (error: any) {
    throw new Error(`Case dedup failed: ${error?.message || String(error)}`);
  }
  const hits = response?.body?.hits?.hits;
  if (!Array.isArray(hits)) throw new Error('Case dedup response did not contain hits');
  const total = Number(response?.body?.hits?.total?.value ?? hits.length);
  if (total > hits.length) throw new Error(`Case dedup returned ${hits.length} of ${total} case(s)`);
  const active = hits.filter((hit: any) => ACTIVE_CASE_STATUSES.has(hit._source?.status));
  if (active.length) {
    const canonical = active[0];
    const duplicates = active.slice(1);
    if (duplicates.some((hit: any) => hit._seq_no === undefined || hit._primary_term === undefined)) {
      throw new Error('Case consolidation requires OCC metadata for every duplicate case');
    }
    const adoptedAlertIds = await findEvidenceAlertIdsForCases(client, duplicates.map((hit: any) => String(hit._id)));
    const current = await resolveCase(client, String(canonical._id));
    if (ACTIVE_CASE_STATUSES.has(current.source?.status)) {
      return { id: String(canonical._id), created: false, adoptedAlertIds, duplicates };
    }
    // The case closed after search. Re-run against fresh state so a new generation
    // is claimed rather than reopening or extending the terminal document.
    if (attempt >= 2) throw new Error('Case dedup could not obtain a stable active-case claim');
    return findOrCreateCase(client, route, now, allowCreate, fence, attempt + 1);
  }
  if (!allowCreate) return null;

  // Every terminal incident advances the deterministic generation; no terminal case is reopened.
  for (let generation = hits.length; generation < hits.length + 3; generation += 1) {
    const id = `auto-${digest(`${route.correlationKey}|generation:${generation}`).slice(0, 32)}`;
    const createdEntry = buildHistoryEntry({ user: ACTOR, action: `rule:${route.ruleId}`, to: 'case_auto_created' });
    createdEntry.timestamp = now;
    try {
      await fence();
      await client.create({
        index: CASES_WRITE_ALIAS,
        id,
        refresh: 'wait_for',
        body: {
          case_uid: id,
          title: `${route.ruleName}: automated incident`,
          description: `Opened automatically by rule "${route.ruleName}".`,
          severity: route.severity || 'medium',
          status: 'open',
          assigned_to: route.assignedTo,
          alert_ids: [],
          correlation_key: route.correlationKey,
          correlation_keys: route.matchingKeys,
          correlation_routing: route.routing,
          correlation_provenance: provenance(route, [], []),
          created_by: ACTOR,
          created_at: now,
          updated_by: ACTOR,
          updated_at: now,
          closed_at: null,
          history: [createdEntry],
        },
      });
      return { id, created: true, adoptedAlertIds: [], duplicates: [] };
    } catch (error: any) {
      if (error?.meta?.statusCode !== 409) throw error;
      const existing = await resolveCase(client, id);
      if (ACTIVE_CASE_STATUSES.has(existing.source?.status)) {
        return { id, created: false, adoptedAlertIds: [], duplicates: [] };
      }
    }
  }
  throw new Error('Could not reserve a deterministic active-case generation');
}

async function findEvidenceAlertIdsForCases(client: any, caseIds: string[]): Promise<string[]> {
  if (!caseIds.length) return [];
  const alertIds = new Set<string>();
  let searchAfter: any[] | undefined;
  let expectedTotal: number | undefined;
  let discovered = 0;
  do {
    const response: any = await client.search({
      index: EVIDENCE_READ_ALIAS,
      body: {
        size: 1000,
        track_total_hits: true,
        _source: ['case_id', 'alert_id'],
        sort: [{ case_id: { order: 'asc' } }, { alert_id: { order: 'asc' } }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
        query: { terms: { case_id: caseIds } },
      },
    });
    const hits = response?.body?.hits?.hits;
    if (!Array.isArray(hits)) throw new Error('Evidence consolidation response did not contain hits');
    const total = Number(response?.body?.hits?.total?.value ?? hits.length);
    if (expectedTotal === undefined) expectedTotal = total;
    if (total !== expectedTotal) throw new Error('Evidence relationships changed during consolidation discovery');
    for (const hit of hits) {
      if (!caseIds.includes(String(hit?._source?.case_id)) || !hit?._source?.alert_id) {
        throw new Error('Evidence consolidation returned an invalid relationship');
      }
      alertIds.add(String(hit._source.alert_id));
    }
    discovered += hits.length;
    searchAfter = hits.length === 1000 ? hits[hits.length - 1]?.sort : undefined;
    if (hits.length === 1000 && !Array.isArray(searchAfter)) {
      throw new Error('Evidence consolidation page did not contain a search cursor');
    }
  } while (searchAfter);
  if (discovered !== expectedTotal) {
    throw new Error(`Evidence consolidation discovered ${discovered} of ${expectedTotal} relationship(s)`);
  }
  return Array.from(alertIds).sort();
}

async function closeDuplicateCases(
  client: any,
  duplicates: any[],
  now: string,
  fence: AutomationCaseRouteFence
): Promise<void> {
  for (const duplicate of duplicates) {
    const current = await resolveCase(client, String(duplicate._id));
    if (!ACTIVE_CASE_STATUSES.has(current.source?.status)) {
      throw new Error(`Duplicate case ${duplicate._id} changed state during consolidation`);
    }
    await fence();
    await client.update({
      index: current.index,
      id: duplicate._id,
      refresh: 'wait_for',
      if_seq_no: current.seqNo,
      if_primary_term: current.primaryTerm,
      body: {
        script: {
          lang: 'painless',
          source:
            'if (ctx._source.status != "open" && ctx._source.status != "in_progress") { throw new IllegalStateException("duplicate case is no longer active"); } ctx._source.status = "closed"; ctx._source.closed_at = params.now; ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor;',
          params: { now, actor: ACTOR },
        },
      },
    });
  }
}

function remainderRoute(route: AutomationCaseRoute, alertIds = route.alertIds): AutomationCaseRoute {
  return { ...route, alertIds: [...alertIds].sort() };
}

async function rollbackEmptyCase(client: any, caseId: string, fence: AutomationCaseRouteFence): Promise<void> {
  const current = await resolveCase(client, caseId);
  if (!ACTIVE_CASE_STATUSES.has(current.source?.status)) return;
  await fence();
  await client.delete({
    index: current.index,
    id: caseId,
    refresh: 'wait_for',
    if_seq_no: current.seqNo,
    if_primary_term: current.primaryTerm,
  });
}

async function updateActiveCase(
  client: any,
  caseId: string,
  route: AutomationCaseRoute,
  linkedAlertIds: string[],
  conflicts: string[],
  now: string,
  action: string,
  fence: AutomationCaseRouteFence
): Promise<void> {
  const current = await resolveCase(client, caseId);
  if (!ACTIVE_CASE_STATUSES.has(current.source?.status)) {
    throw new Error(`Active case ${caseId} closed during automation extension`);
  }
  const entry = buildHistoryEntry({ user: ACTOR, action, to: caseId });
  entry.timestamp = now;
  await fence();
  await client.update({
    index: current.index,
    id: caseId,
    refresh: 'wait_for',
    if_seq_no: current.seqNo,
    if_primary_term: current.primaryTerm,
    body: {
      script: {
        lang: 'painless',
        source:
          'if (ctx._source.status != "open" && ctx._source.status != "in_progress") { throw new IllegalStateException("case is terminal"); } ' +
          'def keys = new HashSet(); if (ctx._source.correlation_keys != null) { keys.addAll(ctx._source.correlation_keys); } keys.addAll(params.keys); def keyList = new ArrayList(keys); Collections.sort(keyList); ctx._source.correlation_keys = keyList; ' +
          'def old = ctx._source.correlation_provenance; def linked = new HashSet(); def conflicts = new HashSet(); def provenanceKeys = new HashSet(); ' +
          'if (old != null && old.linked_alert_ids != null) { linked.addAll(old.linked_alert_ids); } if (old != null && old.evidence_conflicts != null) { conflicts.addAll(old.evidence_conflicts); } ' +
          'if (old != null && old.matching_keys != null) { provenanceKeys.addAll(old.matching_keys); } provenanceKeys.addAll(params.keys); linked.addAll(params.linked); conflicts.addAll(params.conflicts); ' +
          'def provenanceKeyList = new ArrayList(provenanceKeys); def linkedList = new ArrayList(linked); def conflictList = new ArrayList(conflicts); Collections.sort(provenanceKeyList); Collections.sort(linkedList); Collections.sort(conflictList); ' +
          'params.provenance.matching_keys = provenanceKeyList; params.provenance.linked_alert_ids = linkedList; params.provenance.linked_count = linked.size(); params.provenance.evidence_conflicts = conflictList; ' +
          'ctx._source.correlation_provenance = params.provenance; if (params.ranks[params.severity] > params.ranks[ctx._source.severity]) { ctx._source.severity = params.severity; } ' +
          'if (ctx._source.history == null) { ctx._source.history = []; } ctx._source.history.add(params.entry); ctx._source.updated_at = params.now; ctx._source.updated_by = params.actor;',
        params: {
          keys: route.matchingKeys,
          linked: linkedAlertIds,
          conflicts,
          provenance: provenance(route, [], []),
          ranks: SEVERITY_RANK,
          severity: route.severity,
          entry,
          now,
          actor: ACTOR,
        },
      },
    },
  });
}

/** Concurrency-safe writes use deterministic case IDs; evidence ownership conflicts are stable skips. */
export async function applyAutomationCaseRoutes(
  client: any,
  routes: readonly AutomationCaseRoute[],
  maxCreations: number,
  maxLinks: number,
  maxCreationsByRule: ReadonlyMap<string, number> = new Map(),
  fence: AutomationCaseRouteFence = async () => undefined
): Promise<AutomationCaseRoutingResult> {
  const result: AutomationCaseRoutingResult = {
    created: 0, extended: 0, linked: 0, conflicts: [], caseIds: [], remainder: [],
  };
  const createdByRule = new Map<string, number>();
  let linksRemaining = Math.max(0, maxLinks);
  for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
    const route = routes[routeIndex];
    if (!linksRemaining) {
      result.remainder.push(...routes.slice(routeIndex).map((pending) => remainderRoute(pending)));
      break;
    }
    const now = new Date().toISOString();
    const ruleCreated = createdByRule.get(route.ruleId) || 0;
    const ruleLimit = maxCreationsByRule.get(route.ruleId) ?? Number.POSITIVE_INFINITY;
    const found = await findOrCreateCase(
      client,
      route,
      now,
      result.created < maxCreations && ruleCreated < ruleLimit,
      fence
    );
    if (!found) {
      result.remainder.push(remainderRoute(route));
      continue;
    }
    const candidateAlertIds = Array.from(new Set([...route.alertIds, ...found.adoptedAlertIds])).sort();
    if (found.duplicates.length && candidateAlertIds.length > linksRemaining) {
      throw new Error('Case consolidation exceeds the remaining evidence-link limit');
    }
    const requested = candidateAlertIds.slice(0, linksRemaining);
    if (requested.length < candidateAlertIds.length) {
      result.remainder.push(remainderRoute(route, candidateAlertIds.slice(requested.length)));
    }
    // Recheck immediately before each extension. A terminal case is never passed
    // to evidence reconciliation and therefore can never be reopened implicitly.
    const beforeLink = await resolveCase(client, found.id);
    if (!ACTIVE_CASE_STATUSES.has(beforeLink.source?.status)) {
      result.remainder.push(remainderRoute(route, requested));
      continue;
    }
    const linkage = await reconcileCaseEvidence(client, {
      caseId: found.id,
      linkAlertIds: requested,
      actor: ACTOR,
      action: 'auto_case_link',
      timestamp: now,
      allowMove: found.duplicates.length > 0,
      fence,
    });
    if (!linkage.ok) {
      if (found.created && linkage.linked === 0) await rollbackEmptyCase(client, found.id, fence);
      throw new Error(linkage.errors.map((error) => error.message).join('; ') || 'Evidence linkage was incomplete');
    }
    if (requested.length && linkage.linked === 0) {
      if (found.created) await rollbackEmptyCase(client, found.id, fence);
      throw new Error(`Evidence linkage deterministically linked 0 of ${requested.length} requested alert(s)`);
    }
    const linkedIds = new Set(linkage.linkedAlertIds);
    const missingAdoptions = found.adoptedAlertIds.filter((id) => !linkedIds.has(id));
    if (missingAdoptions.length) {
      throw new Error(`Case consolidation did not adopt ${missingAdoptions.length} authoritative evidence relationship(s)`);
    }
    const currentDuplicateEvidence = await findEvidenceAlertIdsForCases(
      client,
      found.duplicates.map((duplicate) => String(duplicate._id))
    );
    const relationshipsAddedDuringAdoption = currentDuplicateEvidence.filter((id) => !linkedIds.has(id));
    if (relationshipsAddedDuringAdoption.length) {
      throw new Error('Authoritative evidence relationships changed during case consolidation');
    }
    await closeDuplicateCases(client, found.duplicates, now, fence);
    linksRemaining -= requested.length;
    result.created += found.created ? 1 : 0;
    if (found.created) createdByRule.set(route.ruleId, ruleCreated + 1);
    result.extended += found.created ? 0 : 1;
    result.linked += linkage.newlyLinked;
    result.conflicts.push(...linkage.conflictedAlertIds);
    result.caseIds.push(found.id);
    const action = found.created ? 'case_auto_created_evidence' : 'case_auto_extended';
    await updateActiveCase(client, found.id, route, linkage.linkedAlertIds, linkage.conflictedAlertIds, now, action, fence);
    await fence();
    await appendActivityOnce(client, `case-route:${digest(`${found.id}|${action}|${route.correlationKey}|${requested.join('\u0000')}`)}`, {
      targetType: 'case', targetId: found.id, user: ACTOR, action,
      timestamp: now, source: 'automation', operationId: route.correlationKey, ruleRevision: route.revision,
    });
  }
  result.conflicts = Array.from(new Set(result.conflicts)).sort();
  return result;
}
