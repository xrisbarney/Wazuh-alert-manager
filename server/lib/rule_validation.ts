import { createHash } from 'crypto';
import { ALERT_STATUSES, CASE_SEVERITIES } from '../../common';
import { validateEntityExpression } from './entity_expression';
import { CANONICAL_RULE_SCHEMA_VERSION, canonicalizeRuleSchema } from './rule_schema_migration';

export const DEFAULT_RULE_PRIORITY = 100;
export const DEFAULT_RULE_SORT_ORDER = 0;

const DEFINITION_FIELDS = [
  'schemaVersion',
  'name',
  'priority',
  'sortOrder',
  'processingMode',
  'match',
  'trigger',
  'actions',
  'preconditions',
  'safety',
] as const;

export const emptyRuleCounters = () => ({
  matchedAlerts: 0,
  triggeredEntities: 0,
  actionsAttempted: 0,
  actionsSucceeded: 0,
  actionsSkipped: 0,
  actionsConflicted: 0,
  actionsFailed: 0,
  casesCreated: 0,
  casesExtended: 0,
  evidenceLinksWritten: 0,
});

const cleanArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) return undefined;
  const result = Array.from(new Set(value.map(String).map((item) => item.trim()).filter(Boolean)));
  return result.length ? result : undefined;
};

const mergeObject = (current: any, patch: any, key: string) =>
  patch[key] === undefined ? current[key] : { ...(current[key] || {}), ...(patch[key] || {}) };

/** Merge a partial edit without losing sibling fields in nested rule sections. */
export function mergeRulePatch(current: any, patch: any): any {
  return {
    ...current,
    ...patch,
    match: mergeObject(current, patch, 'match'),
    trigger: {
      ...mergeObject(current, patch, 'trigger'),
      cooldown:
        patch.trigger?.cooldown === undefined
          ? current.trigger?.cooldown
          : { ...(current.trigger?.cooldown || {}), ...(patch.trigger.cooldown || {}) },
      rearm:
        patch.trigger?.rearm === undefined
          ? current.trigger?.rearm
          : { ...(current.trigger?.rearm || {}), ...(patch.trigger.rearm || {}) },
    },
    actions: mergeObject(current, patch, 'actions'),
    preconditions: mergeObject(current, patch, 'preconditions'),
    safety: {
      ...mergeObject(current, patch, 'safety'),
      rateLimit:
        patch.safety?.rateLimit === undefined
          ? current.safety?.rateLimit
          : patch.safety.rateLimit === null
          ? null
          : { ...(current.safety?.rateLimit || {}), ...patch.safety.rateLimit },
    },
  };
}

/** Canonical write representation. This is intentionally never applied on reads. */
export function normalizeRule(input: any): any {
  const legacyActions = input.actions ? {} : { createCase: true, caseSeverity: input.caseSeverity };
  const actions = { ...legacyActions, ...(input.actions || {}) };
  const canonical = canonicalizeRuleSchema(input);
  const trigger = canonical.trigger;
  const match = input.match || {};
  const preconditions = input.preconditions || {};
  const safety = input.safety || {};

  return {
    ...canonical,
    name: typeof input.name === 'string' ? input.name.trim() : input.name,
    enabled: input.enabled === true,
    priority: input.priority ?? DEFAULT_RULE_PRIORITY,
    sortOrder: input.sortOrder ?? DEFAULT_RULE_SORT_ORDER,
    processingMode: input.processingMode || 'continue',
    match: {
      ruleGroups: cleanArray(match.ruleGroups),
      ruleGroupsMode: match.ruleGroupsMode || 'any',
      ruleIds: cleanArray(match.ruleIds),
      ruleIdsMode: match.ruleIdsMode || 'any',
      agentNames: cleanArray(match.agentNames),
      agentNamesMode: match.agentNamesMode || 'any',
      ...(match.minLevel == null ? {} : { minLevel: match.minLevel }),
    },
    trigger,
    actions: {
      createCase: actions.createCase === true,
      ...(actions.caseSeverity == null ? {} : { caseSeverity: actions.caseSeverity }),
      ...(actions.setStatus == null ? { setStatus: null } : { setStatus: actions.setStatus }),
      assignTo: typeof actions.assignTo === 'string' ? actions.assignTo.trim() || null : actions.assignTo ?? null,
    },
    preconditions: {
      statuses: cleanArray(preconditions.statuses),
      assignment: preconditions.assignment || 'unassigned',
    },
    safety: {
      acknowledgeMatchAll: safety.acknowledgeMatchAll === true,
      ...(safety.maxActionsPerRun == null ? {} : { maxActionsPerRun: safety.maxActionsPerRun }),
      ...(safety.maxCasesPerRun == null ? {} : { maxCasesPerRun: safety.maxCasesPerRun }),
      ...(safety.rateLimit == null ? {} : { rateLimit: { ...safety.rateLimit } }),
    },
  };
}

export interface RuleValidationResult {
  rule: any;
  errors: string[];
}

function canonicalJson(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Stable identity for material behavior. Activation state and storage metadata are deliberately excluded. */
export function ruleDefinitionFingerprint(input: any): string {
  const normalized = normalizeRule(input);
  const definition: any = {};
  for (const field of DEFINITION_FIELDS) definition[field] = normalized[field];
  return createHash('sha256').update(canonicalJson(definition)).digest('hex');
}

export function normalizeAndValidateRule(input: any): RuleValidationResult {
  const rule = normalizeRule(input);
  const errors: string[] = [];
  const actions = rule.actions;
  const trigger = rule.trigger;
  const match = rule.match;

  if (rule.schemaVersion !== CANONICAL_RULE_SCHEMA_VERSION) errors.push('Rule schema version must be 2.');
  if (!rule.name || rule.name.length > 200) errors.push('Name must contain between 1 and 200 characters.');
  if (!Number.isInteger(rule.priority) || rule.priority < 0 || rule.priority > 1000) {
    errors.push('Priority must be an integer between 0 and 1000.');
  }
  if (!Number.isInteger(rule.sortOrder) || rule.sortOrder < 0 || rule.sortOrder > 1000000) {
    errors.push('Sort order must be an integer between 0 and 1000000.');
  }
  if (!['continue', 'stop'].includes(rule.processingMode)) errors.push('Processing mode must be continue or stop.');
  if (!['per_alert', 'burst'].includes(trigger.type)) errors.push('Trigger type must be per_alert or burst.');
  errors.push(...validateEntityExpression(trigger.entityExpression));
  if (!['separate_by_group', 'consolidate_overlapping', 'one_per_rule'].includes(trigger.routing)) {
    errors.push('Case routing must be separate_by_group, consolidate_overlapping, or one_per_rule.');
  }
  if (!actions.createCase && !actions.setStatus && !actions.assignTo) {
    errors.push('Select at least one action: create case, set status, or assign to an analyst.');
  }
  if (trigger.type === 'per_alert' && [match.ruleGroupsMode, match.ruleIdsMode, match.agentNamesMode].includes('all')) {
    errors.push('All match mode is only supported by burst rules.');
  }
  if (trigger.type === 'burst') {
    if (!Number.isInteger(trigger.threshold) || trigger.threshold < 2 || trigger.threshold > 1000) {
      errors.push('The burst trigger threshold must be an integer between 2 and 1000.');
    }
    if (!Number.isInteger(trigger.windowMinutes) || trigger.windowMinutes < 1 || trigger.windowMinutes > 1440) {
      errors.push('The burst trigger window must be an integer between 1 and 1440 minutes.');
    }
  }
  if (actions.createCase && !CASE_SEVERITIES.includes(actions.caseSeverity)) {
    errors.push('The create case action needs a valid case severity.');
  }
  if (actions.setStatus != null && !ALERT_STATUSES.includes(actions.setStatus)) errors.push('Set status is invalid.');
  const hasMatch = !!(match.ruleGroups?.length || match.ruleIds?.length || match.agentNames?.length || match.minLevel != null);
  if (!hasMatch && !rule.safety.acknowledgeMatchAll) {
    errors.push('Matching all alerts requires safety.acknowledgeMatchAll=true.');
  }
  if (rule.preconditions.statuses?.some((status: string) => !ALERT_STATUSES.includes(status as any))) {
    errors.push('One or more precondition statuses are invalid.');
  }
  if (!['any', 'unassigned'].includes(rule.preconditions.assignment)) {
    errors.push('Assignment precondition must be any or unassigned.');
  }
  for (const [name, value] of [
    ['Maximum actions per run', rule.safety.maxActionsPerRun],
    ['Maximum cases per run', rule.safety.maxCasesPerRun],
  ] as Array<[string, any]>) {
    if (value != null && (!Number.isInteger(value) || value < 1 || value > 10000)) {
      errors.push(`${name} must be an integer between 1 and 10000.`);
    }
  }
  if (rule.safety.rateLimit) {
    const { maxExecutions, windowMinutes } = rule.safety.rateLimit;
    if (!Number.isInteger(maxExecutions) || maxExecutions < 1 || maxExecutions > 100000) {
      errors.push('Rate limit maxExecutions must be an integer between 1 and 100000.');
    }
    if (!Number.isInteger(windowMinutes) || windowMinutes < 1 || windowMinutes > 10080) {
      errors.push('Rate limit windowMinutes must be an integer between 1 and 10080.');
    }
  }
  const cooldown = trigger.cooldown?.durationMinutes;
  const rearm = trigger.rearm;
  if (trigger.type === 'per_alert') {
    if (cooldown !== 0) errors.push('Every matching alert triggers must use a zero-minute cooldown.');
    if (rearm?.type !== 'immediate' || rearm?.quietPeriodMinutes !== 0) {
      errors.push('Every matching alert triggers must rearm immediately with a zero-minute quiet period.');
    }
  } else {
    if (!Number.isInteger(cooldown) || cooldown < 1 || cooldown > 10080) {
      errors.push('Burst cooldown must be an integer between 1 and 10080 minutes.');
    }
    if (
      rearm?.type !== 'after_quiet_period' ||
      !Number.isInteger(rearm.quietPeriodMinutes) ||
      rearm.quietPeriodMinutes < 1 ||
      rearm.quietPeriodMinutes > 10080
    ) {
      errors.push('Burst rearm must use an after_quiet_period interval between 1 and 10080 minutes.');
    }
  }
  return { rule, errors };
}
