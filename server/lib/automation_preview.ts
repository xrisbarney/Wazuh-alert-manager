import {
  ALERT_STATUS_INDEX,
  AUTOMATION_EXECUTIONS_INDEX,
  CASES_INDEX,
  CorrelationRule,
  MAX_AUTO_CASES_PER_RUN,
  RULES_INDEX,
} from '../../common';
import { buildMatchFilters, evaluateAlertMatch } from './correlation';
import { normalizeAutomationRules, planAutomation } from './automation_planner';
import {
  AutomationAlertSample,
  AutomationTriggerState,
  automationRateLimitStateId,
  DEFAULT_AUTOMATION_LIMITS,
  automationTriggerStateId,
  evaluateRuleAtAlert,
  normalizeStoredAutomationRule,
  RuleTriggerEvaluation,
  transitionAutomationTrigger,
} from './correlation_eval';
import { planAutomationCaseRoutes } from './automation_case_routing';
import { canonicalizeRuleSchema } from './rule_schema_migration';

export const DEFAULT_PREVIEW_MAX_ALERTS = 5000;
export const DEFAULT_PREVIEW_TIMEOUT_MS = 10000;
const RULE_LIMIT = 200;
const PAGE_SIZE = 500;

export interface PreviewAlert extends AutomationAlertSample {}

export interface AutomationPreviewOptions {
  now?: Date;
  lookbackHours: number;
  maxAlerts?: number;
  timeoutMs?: number;
  representativeLimit?: number;
  triggerStates?: Readonly<Record<string, AutomationTriggerState>>;
  rateLimitReservations?: Readonly<Record<string, Array<{ id: string; timestamp: string }>>>;
  effectiveFrom?: string;
}

const timestamp = (alert: PreviewAlert) => Date.parse(String(alert.source?.['@timestamp'] || ''));
const compareAlerts = (left: PreviewAlert, right: PreviewAlert) =>
  timestamp(left) - timestamp(right) || left.id.localeCompare(right.id);

/** Write-free simulation using the exact canonical expression, window, planner, and routing functions used live. */
export function simulateAutomationPreview(
  candidateInput: CorrelationRule,
  alertsInput: PreviewAlert[],
  enabledRulesInput: CorrelationRule[],
  existingCaseKeys: ReadonlySet<string>,
  options: AutomationPreviewOptions
): any {
  const started = Date.now();
  const maxAlerts = options.maxAlerts ?? DEFAULT_PREVIEW_MAX_ALERTS;
  const representativeLimit = options.representativeLimit ?? 10;
  const now = (options.now || new Date()).getTime();
  const lookbackStart = now - options.lookbackHours * 3600000;
  const ordered = [...alertsInput].sort(compareAlerts);
  // A bounded preview retains the newest corpus, including each rule's maximum window before the lookback.
  const sampled = ordered.slice(-maxAlerts);
  const inLookback = sampled.filter((alert) => timestamp(alert) >= lookbackStart && timestamp(alert) <= now);
  const candidate = normalizeStoredAutomationRule({ ...candidateInput, enabled: true });
  const allRules = normalizeAutomationRules([
    ...enabledRulesInput.filter((rule) => rule.id !== candidate.id).map((rule) => canonicalizeRuleSchema(rule)),
    candidate,
  ] as CorrelationRule[]);
  const evaluations: RuleTriggerEvaluation[] = [];
  for (const alert of inLookback) {
    for (const rule of allRules) {
      evaluations.push(...evaluateRuleAtAlert(
        rule, alert, sampled, ordered.length > maxAlerts, options.effectiveFrom || (rule as any).effective_from
      ));
    }
  }
  const triggerStates = new Map<string, AutomationTriggerState>(Object.entries(options.triggerStates || {}));
  const rateReservations = new Map<string, Array<{ id: string; timestamp: string }>>(
    Object.entries(options.rateLimitReservations || {}).map(([id, values]) => [id, [...values]])
  );
  let candidateRateLimited = false;
  const firing = evaluations
    .slice()
    .sort((left, right) => Date.parse(left.anchorTimestamp) - Date.parse(right.anchorTimestamp) ||
      left.anchorAlertId.localeCompare(right.anchorAlertId) || left.matchingKey.localeCompare(right.matchingKey))
    .filter((evaluation) => {
      const transition = transitionAutomationTrigger(evaluation, triggerStates.get(evaluation.matchingKey));
      if (transition.state) triggerStates.set(evaluation.matchingKey, transition.state);
      if (!transition.fire) return false;
      const limit = evaluation.rule.safety.rateLimit;
      if (!limit) return true;
      const reservationId = `${evaluation.matchingKey}|${evaluation.anchorAlertId}`;
      const stored = rateReservations.get(evaluation.rule.id) || [];
      if (stored.some((item) => item.id === reservationId)) return true;
      const active = stored.filter((item) =>
        Date.parse(item.timestamp) >= now - Number(limit.windowMinutes) * 60000
      );
      if (active.length >= Number(limit.maxExecutions)) {
        if (evaluation.rule.id === candidate.id) candidateRateLimited = true;
        return false;
      }
      const reservations = [...stored, { id: reservationId, timestamp: new Date(now).toISOString() }];
      rateReservations.set(evaluation.rule.id, reservations);
      return true;
    });
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
  const plans = planAutomation(
    inLookback.map((alert) => ({
      ...alert,
      matchedBurstRuleIds: burstByAlert.get(alert.id),
      executionEligibleRuleIds: eligibleByAlert.get(alert.id) || new Set<string>(),
    })),
    allRules
  );
  const candidatePlans = plans.filter((plan) => plan.matched.includes(candidate.id));
  let actionsUsed = 0;
  let statusChanges = 0;
  let assignments = 0;
  let skippedBySafety = candidateRateLimited ? 1 : 0;
  for (const plan of plans) {
    for (const [value, ruleId, kind] of [
      [plan.mutation?.status, plan.chosenStatusRuleId, 'status'],
      [plan.mutation?.assigned_to, plan.chosenAssignmentRuleId, 'assignment'],
    ] as any[]) {
      if (!value || ruleId !== candidate.id) continue;
      if (candidate.safety.maxActionsPerRun != null && actionsUsed >= candidate.safety.maxActionsPerRun) {
        skippedBySafety += 1;
        continue;
      }
      if ((kind === 'status' && statusChanges >= DEFAULT_AUTOMATION_LIMITS.maxStatusChanges) ||
          (kind === 'assignment' && assignments >= DEFAULT_AUTOMATION_LIMITS.maxAssignments)) {
        skippedBySafety += 1;
        continue;
      }
      actionsUsed += 1;
      if (kind === 'status') statusChanges += 1;
      else assignments += 1;
    }
  }

  const candidateFiring = firing.filter((evaluation) => evaluation.rule.id === candidate.id);
  const routes = candidate.actions.createCase ? planAutomationCaseRoutes(candidateFiring.map((evaluation) => ({
    ruleId: candidate.id,
    ruleName: candidate.name,
    revision: Number(candidate.revision || 0),
    routing: candidate.trigger.routing!,
    severity: candidate.actions.caseSeverity || 'medium',
    assignedTo: candidate.actions.assignTo ? String(candidate.actions.assignTo) : null,
    group: evaluation.group,
    alertIds: evaluation.alertIds,
    threshold: evaluation.threshold,
    windowMinutes: evaluation.windowMinutes,
    count: evaluation.count,
    truncated: evaluation.truncated,
  }))) : [];
  const uniqueRoutes = Array.from(new Map(routes.map((route) => [route.correlationKey, route])).values());
  const caseLimit = Math.min(candidate.safety.maxCasesPerRun ?? MAX_AUTO_CASES_PER_RUN, MAX_AUTO_CASES_PER_RUN);
  let casesCreated = 0;
  let casesExtended = 0;
  let caseCapSkipped = 0;
  for (const route of uniqueRoutes) {
    const legacyKeys = candidateFiring
      .filter((evaluation) => route.matchingKeys.includes(evaluation.matchingKey))
      .flatMap((evaluation) => evaluation.group.values.map((value) => `${candidate.id}|${value.value}`));
    if (existingCaseKeys.has(route.correlationKey) || legacyKeys.some((key) => existingCaseKeys.has(key))) casesExtended += 1;
    else if (casesCreated < caseLimit) casesCreated += 1;
    else caseCapSkipped += 1;
  }
  const candidateEffectiveMs = Date.parse(String(options.effectiveFrom || (candidate as any).effective_from || ''));
  const matching = inLookback.filter((alert) => {
    if (!evaluateAlertMatch(candidate, alert.source).matched) return false;
    if (!Number.isFinite(candidateEffectiveMs)) return true;
    const ingestedMs = Date.parse(String(alert.source?.ingested_at || ''));
    return Number.isFinite(ingestedMs) && ingestedMs >= candidateEffectiveMs;
  });
  const missingEntities = matching.filter((alert) => evaluateRuleAtAlert(candidate, alert, [alert]).length === 0).length;
  const conflictPlans = plans.filter((plan) => plan.conflicts.some(
    (conflict) => conflict.chosenRuleId === candidate.id || conflict.rejectedRuleId === candidate.id
  ));
  return {
    triggerType: candidate.trigger.type,
    windowMinutes: candidate.trigger.windowMinutes || 0,
    lookbackHours: options.lookbackHours,
    matchingAlerts: matching.length,
    sampledAlerts: inLookback.length,
    totalAlerts: alertsInput.length,
    triggeringEntities: candidateFiring.map((evaluation) => ({
      entity: evaluation.matchingKey,
      groupId: evaluation.group.groupId,
      count: evaluation.count,
      alertIds: evaluation.alertIds,
      truncated: evaluation.truncated,
    })),
    plannedCaseRoutes: uniqueRoutes.map((route) => ({
      correlationKey: route.correlationKey,
      routing: route.routing,
      matchingKeys: route.matchingKeys,
      alertIds: route.alertIds,
      effect: existingCaseKeys.has(route.correlationKey) ? 'extend_active_case' : 'create_case',
    })),
    triggerStateKeys: Array.from(new Set(evaluations.map((evaluation) => evaluation.matchingKey))).sort(),
    wouldOpenCases: casesCreated,
    casesCreated,
    casesExtended,
    statusChanges,
    assignments,
    skips: candidatePlans.reduce((sum, plan) => sum + plan.skipped.filter((item) => item.ruleId === candidate.id).length, 0),
    conflicts: conflictPlans.flatMap((plan) => plan.conflicts.map((conflict) => ({ alertId: plan.alertId, ...conflict }))),
    skippedBySafety: skippedBySafety + caseCapSkipped,
    rateLimited: candidateRateLimited,
    missingEntities,
    missingEntityRate: matching.length ? missingEntities / matching.length : 0,
    representativeAlerts: matching.slice(0, representativeLimit).map((alert) => ({ id: alert.id, timestamp: alert.source?.['@timestamp'] || null })),
    truncated: ordered.length > maxAlerts,
    queryTimeMs: Date.now() - started,
  };
}

function normalizeStoredRule(hit: any): CorrelationRule {
  return canonicalizeRuleSchema({ id: String(hit._id), ...(hit._source || {}) }) as CorrelationRule;
}

/** Read-only OpenSearch adapter. */
export async function runAutomationPreview(client: any, candidate: CorrelationRule, options: AutomationPreviewOptions): Promise<any> {
  const started = Date.now();
  const timeoutMs = options.timeoutMs ?? DEFAULT_PREVIEW_TIMEOUT_MS;
  const maxAlerts = options.maxAlerts ?? DEFAULT_PREVIEW_MAX_ALERTS;
  const rulesResponse: any = await client.search({ index: RULES_INDEX, body: { size: RULE_LIMIT + 1, query: { term: { enabled: true } } } });
  const ruleHits = rulesResponse?.body?.hits?.hits || [];
  if (ruleHits.length > RULE_LIMIT) throw Object.assign(new Error(`Preview supports at most ${RULE_LIMIT} enabled rules.`), { statusCode: 413 });
  const enabledRules = ruleHits.map(normalizeStoredRule);
  const canonicalCandidate = canonicalizeRuleSchema(candidate);
  const corpusRules = [
    ...enabledRules.filter((rule: any) => rule.id !== (canonicalCandidate as any).id),
    canonicalCandidate,
  ];
  const maxWindow = Math.max(Number(canonicalCandidate.trigger.windowMinutes || 0), ...enabledRules.map((rule: any) => Number(rule.trigger.windowMinutes || 0)));
  const now = options.now || new Date();
  const from = new Date(now.getTime() - (options.lookbackHours * 60 + maxWindow) * 60000).toISOString();
  const alerts: PreviewAlert[] = [];
  let searchAfter: any[] | undefined;
  let total = 0;
  do {
    if (Date.now() - started > timeoutMs) throw Object.assign(new Error('Preview timed out.'), { statusCode: 408 });
    const response: any = await client.search({
      index: ALERT_STATUS_INDEX,
      body: {
        size: Math.min(PAGE_SIZE, maxAlerts + 1 - alerts.length), timeout: `${timeoutMs}ms`, track_total_hits: true,
        _source: true, sort: [{ '@timestamp': 'desc' }, { alert_uid: 'desc' }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
        query: {
          bool: {
            must: [{ range: { '@timestamp': { gte: from, lte: now.toISOString() } } }],
            should: corpusRules.map((rule: any) => ({ bool: {
              filter: [
                ...buildMatchFilters(rule.match),
                ...((options.effectiveFrom || rule.effective_from)
                  ? [{ range: { ingested_at: { gte: options.effectiveFrom || rule.effective_from } } }]
                  : []),
              ],
            } })),
            minimum_should_match: 1,
          },
        },
      },
    });
    const hits = response?.body?.hits?.hits || [];
    total = Number(response?.body?.hits?.total?.value ?? hits.length);
    alerts.push(...hits.map((hit: any) => ({ id: String(hit._id), source: hit._source || {} })));
    searchAfter = hits.length ? hits[hits.length - 1].sort : undefined;
    if (!hits.length || alerts.length > maxAlerts) break;
  } while (alerts.length < total);
  const preliminary = simulateAutomationPreview(canonicalCandidate, alerts, enabledRules, new Set(), options);
  const stateIds = preliminary.triggerStateKeys.map((matchingKey: string) => ({
    matchingKey,
    id: automationTriggerStateId(matchingKey),
  }));
  const triggerStates: Record<string, AutomationTriggerState> = {};
  if (stateIds.length) {
    const response: any = await client.mget({
      index: AUTOMATION_EXECUTIONS_INDEX,
      body: { ids: stateIds.map((item: any) => item.id) },
    });
    (response?.body?.docs || []).forEach((doc: any, index: number) => {
      if (doc.found && doc._source) triggerStates[stateIds[index].matchingKey] = doc._source;
    });
  }
  const rateLimitReservations: Record<string, Array<{ id: string; timestamp: string }>> = {};
  const rateRuleIds = corpusRules.filter((rule: any) => rule.safety?.rateLimit).map((rule: any) => String(rule.id));
  if (rateRuleIds.length) {
    const response: any = await client.mget({
      index: AUTOMATION_EXECUTIONS_INDEX,
      body: { ids: rateRuleIds.map(automationRateLimitStateId) },
    });
    (response?.body?.docs || []).forEach((doc: any, index: number) => {
      if (doc.found && Array.isArray(doc._source?.reservations)) {
        rateLimitReservations[rateRuleIds[index]] = doc._source.reservations;
      }
    });
  }
  const keys = preliminary.plannedCaseRoutes.map((route: any) => route.correlationKey);
  const existingKeys = new Set<string>();
  if (keys.length) {
    const response: any = await client.search({
      index: CASES_INDEX,
      body: { size: Math.min(keys.length, maxAlerts), _source: ['correlation_key'], query: { bool: { must: [{ terms: { correlation_key: keys } }, { terms: { status: ['open', 'in_progress'] } }] } } },
    });
    for (const hit of response?.body?.hits?.hits || []) if (hit._source?.correlation_key) existingKeys.add(hit._source.correlation_key);
  }
  const result = simulateAutomationPreview(canonicalCandidate, alerts, enabledRules, existingKeys, {
    ...options, triggerStates, rateLimitReservations,
  });
  result.totalAlerts = total;
  result.truncated = total > maxAlerts;
  result.queryTimeMs = Date.now() - started;
  return result;
}
