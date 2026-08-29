import { AlertStatus, CorrelationRule } from '../../common';
import { evaluateAlertMatch } from './correlation';

export const DEFAULT_AUTOMATION_PRIORITY = 100;
export const DEFAULT_AUTOMATION_SORT_ORDER = 0;

export interface NormalizedAutomationRule extends CorrelationRule {
  priority: number;
  sortOrder: number;
  processingMode: 'continue' | 'stop';
  preconditions: {
    statuses: AlertStatus[];
    assignment: 'any' | 'unassigned';
  };
  safety: NonNullable<CorrelationRule['safety']>;
}

export interface AutomationAlertInput {
  id: string;
  source: any;
  /** Burst IDs supplied by the window evaluator after threshold and All coverage pass. */
  matchedBurstRuleIds?: ReadonlySet<string>;
  /** When supplied by the evaluator, only rules with a reserved trigger/rate slot may cross the native action boundary. */
  executionEligibleRuleIds?: ReadonlySet<string>;
}

export type AutomationAction = 'rule' | 'status' | 'assignment';
export type AutomationSkipReason =
  | 'disabled'
  | 'not_matched'
  | 'burst_not_matched'
  | 'trigger_not_fired'
  | 'all_mode_requires_burst'
  | 'status_precondition'
  | 'assignment_requires_unassigned'
  | 'already_satisfied'
  | 'no_mutating_action';

export interface AutomationSkip {
  ruleId: string;
  action: AutomationAction;
  reason: AutomationSkipReason;
}

export interface AutomationConflict {
  field: 'status' | 'assignment';
  chosenRuleId: string;
  chosenValue: string;
  rejectedRuleId: string;
  rejectedValue: string;
}

export interface AutomationMutation {
  status?: AlertStatus;
  assigned_to?: string;
}

export interface AlertAutomationPlan {
  alertId: string;
  matched: string[];
  skipped: AutomationSkip[];
  conflicts: AutomationConflict[];
  chosenStatus: AlertStatus | null;
  chosenStatusRuleId: string | null;
  chosenAssignment: string | null;
  chosenAssignmentRuleId: string | null;
  rulesApplied: string[];
  stopReason: { ruleId: string; reason: 'rule_requested_stop' } | null;
  mutation: AutomationMutation | null;
}

const compareStrings = (left: string, right: string): number => (left < right ? -1 : left > right ? 1 : 0);

/** Read normalization keeps pre-policy stored rules executable with conservative defaults. */
export function normalizeAutomationRule(rule: CorrelationRule): NormalizedAutomationRule {
  const priority = Number(rule.priority);
  const sortOrder = Number(rule.sortOrder);
  return {
    ...rule,
    priority: Number.isFinite(priority) ? priority : DEFAULT_AUTOMATION_PRIORITY,
    sortOrder: Number.isFinite(sortOrder) ? sortOrder : DEFAULT_AUTOMATION_SORT_ORDER,
    processingMode: rule.processingMode === 'stop' ? 'stop' : 'continue',
    preconditions: {
      statuses: rule.preconditions?.statuses?.length ? [...rule.preconditions.statuses] : ['open'],
      assignment: rule.preconditions?.assignment === 'any' ? 'any' : 'unassigned',
    },
    safety: {
      acknowledgeMatchAll: rule.safety?.acknowledgeMatchAll === true,
      ...(rule.safety?.maxActionsPerRun == null ? {} : { maxActionsPerRun: rule.safety.maxActionsPerRun }),
      ...(rule.safety?.maxCasesPerRun == null ? {} : { maxCasesPerRun: rule.safety.maxCasesPerRun }),
      ...(rule.safety?.rateLimit == null ? {} : { rateLimit: { ...rule.safety.rateLimit } }),
    },
  };
}

export function normalizeAutomationRules(rules: readonly CorrelationRule[]): NormalizedAutomationRule[] {
  return rules.map(normalizeAutomationRule).sort(
    (left, right) =>
      left.priority - right.priority ||
      left.sortOrder - right.sortOrder ||
      compareStrings(String(left.id), String(right.id))
  );
}

function addAppliedRule(rulesApplied: string[], ruleId: string) {
  if (!rulesApplied.includes(ruleId)) rulesApplied.push(ruleId);
}

/** Pure planning step. It performs no writes and returns one combined mutation. */
export function planAlertAutomation(
  alert: AutomationAlertInput,
  rules: readonly CorrelationRule[]
): AlertAutomationPlan {
  const source = alert.source || {};
  const matched: string[] = [];
  const skipped: AutomationSkip[] = [];
  const conflicts: AutomationConflict[] = [];
  const rulesApplied: string[] = [];
  let chosenStatus: { value: AlertStatus; ruleId: string } | null = null;
  let chosenAssignment: { value: string; ruleId: string } | null = null;
  let stopReason: AlertAutomationPlan['stopReason'] = null;

  for (const rule of normalizeAutomationRules(rules)) {
    if (!rule.enabled) {
      skipped.push({ ruleId: rule.id, action: 'rule', reason: 'disabled' });
      continue;
    }
    const result = evaluateAlertMatch(rule, source);
    if (!result.supported) {
      skipped.push({ ruleId: rule.id, action: 'rule', reason: result.reason });
      continue;
    }
    if (!result.matched) {
      skipped.push({ ruleId: rule.id, action: 'rule', reason: 'not_matched' });
      continue;
    }
    if (alert.executionEligibleRuleIds && !alert.executionEligibleRuleIds.has(rule.id)) {
      skipped.push({ ruleId: rule.id, action: 'rule', reason: 'trigger_not_fired' });
      continue;
    }
    if (rule.trigger.type === 'burst' && !alert.matchedBurstRuleIds?.has(rule.id)) {
      skipped.push({ ruleId: rule.id, action: 'rule', reason: 'burst_not_matched' });
      continue;
    }

    matched.push(rule.id);
    let hasMutatingAction = false;
    const status = rule.actions?.setStatus || null;
    if (status) {
      hasMutatingAction = true;
      if (!rule.preconditions.statuses.includes(source.status)) {
        skipped.push({ ruleId: rule.id, action: 'status', reason: 'status_precondition' });
      } else if (!chosenStatus) {
        chosenStatus = { value: status, ruleId: rule.id };
        if (source.status === status) skipped.push({ ruleId: rule.id, action: 'status', reason: 'already_satisfied' });
        else addAppliedRule(rulesApplied, rule.id);
      } else if (chosenStatus.value !== status) {
        conflicts.push({
          field: 'status',
          chosenRuleId: chosenStatus.ruleId,
          chosenValue: chosenStatus.value,
          rejectedRuleId: rule.id,
          rejectedValue: status,
        });
      }
    }

    const assignment = rule.actions?.assignTo ? String(rule.actions.assignTo) : null;
    if (assignment) {
      hasMutatingAction = true;
      if (rule.preconditions.assignment === 'unassigned' && source.assigned_to != null && source.assigned_to !== '') {
        skipped.push({ ruleId: rule.id, action: 'assignment', reason: 'assignment_requires_unassigned' });
      } else if (!chosenAssignment) {
        chosenAssignment = { value: assignment, ruleId: rule.id };
        if (source.assigned_to === assignment) {
          skipped.push({ ruleId: rule.id, action: 'assignment', reason: 'already_satisfied' });
        } else addAppliedRule(rulesApplied, rule.id);
      } else if (chosenAssignment.value !== assignment) {
        conflicts.push({
          field: 'assignment',
          chosenRuleId: chosenAssignment.ruleId,
          chosenValue: chosenAssignment.value,
          rejectedRuleId: rule.id,
          rejectedValue: assignment,
        });
      }
    }

    if (!hasMutatingAction) skipped.push({ ruleId: rule.id, action: 'rule', reason: 'no_mutating_action' });
    if (rule.processingMode === 'stop') {
      stopReason = { ruleId: rule.id, reason: 'rule_requested_stop' };
      break;
    }
  }

  const mutation: AutomationMutation = {};
  if (chosenStatus && chosenStatus.value !== source.status) mutation.status = chosenStatus.value;
  if (chosenAssignment && chosenAssignment.value !== source.assigned_to) mutation.assigned_to = chosenAssignment.value;
  return {
    alertId: alert.id,
    matched,
    skipped,
    conflicts,
    chosenStatus: chosenStatus?.value || null,
    chosenStatusRuleId: chosenStatus?.ruleId || null,
    chosenAssignment: chosenAssignment?.value || null,
    chosenAssignmentRuleId: chosenAssignment?.ruleId || null,
    rulesApplied,
    stopReason,
    mutation: Object.keys(mutation).length ? mutation : null,
  };
}

export function planAutomation(
  alerts: readonly AutomationAlertInput[],
  rules: readonly CorrelationRule[]
): AlertAutomationPlan[] {
  return alerts.map((alert) => planAlertAutomation(alert, rules)).sort((a, b) => compareStrings(a.alertId, b.alertId));
}
