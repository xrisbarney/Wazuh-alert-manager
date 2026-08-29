import { CorrelationRule } from '../../common';
import { normalizeAutomationRules, planAlertAutomation, planAutomation } from './automation_planner';

const rule = (id: string, patch: Partial<CorrelationRule> = {}): CorrelationRule =>
  ({
    id,
    name: id,
    enabled: true,
    match: {},
    trigger: { type: 'per_alert' },
    actions: { createCase: false },
    ...patch,
  } as CorrelationRule);

const alert = (source: any = {}) => ({
  id: 'alert-1',
  source: { status: 'open', assigned_to: null, rule: { id: '100', groups: ['auth'], level: 8 }, ...source },
});

describe('automation planner ordering and conflicts', () => {
  test('normalizes lower numeric priority first and uses rule ID as a stable tie-break', () => {
    const ordered = normalizeAutomationRules([
      rule('z', { priority: 10 }),
      rule('b', { priority: 5 }),
      rule('a', { priority: 5 }),
      rule('default'),
    ]);

    expect(ordered.map((r) => [r.id, r.priority])).toEqual([
      ['a', 5],
      ['b', 5],
      ['z', 10],
      ['default', 100],
    ]);
  });

  test('uses sortOrder before rule ID and safely defaults legacy policy fields', () => {
    const stored = ['five', 'four', 'three', 'two', 'one'].map((id, index) =>
      rule(id, { priority: 10, sortOrder: index === 0 ? 2 : 1 })
    );

    const ordered = normalizeAutomationRules(stored);

    expect(ordered.map((candidate) => candidate.id)).toEqual(['four', 'one', 'three', 'two', 'five']);
    expect(ordered).toHaveLength(5);
    expect(ordered[0]).toEqual(
      expect.objectContaining({
        processingMode: 'continue',
        preconditions: { statuses: ['open'], assignment: 'unassigned' },
      })
    );
  });

  test('chooses the highest-priority proposal and reports later field conflicts', () => {
    const plan = planAlertAutomation(alert(), [
      rule('low', { priority: 20, actions: { createCase: false, setStatus: 'closed', assignTo: 'bob' } }),
      rule('high', { priority: 10, actions: { createCase: false, setStatus: 'in_progress', assignTo: 'alice' } }),
    ]);

    expect(plan.matched).toEqual(['high', 'low']);
    expect(plan.mutation).toEqual({ status: 'in_progress', assigned_to: 'alice' });
    expect(plan.chosenStatus).toBe('in_progress');
    expect(plan.chosenAssignment).toBe('alice');
    expect(plan.rulesApplied).toEqual(['high']);
    expect(plan.conflicts).toEqual([
      {
        field: 'status',
        chosenRuleId: 'high',
        chosenValue: 'in_progress',
        rejectedRuleId: 'low',
        rejectedValue: 'closed',
      },
      {
        field: 'assignment',
        chosenRuleId: 'high',
        chosenValue: 'alice',
        rejectedRuleId: 'low',
        rejectedValue: 'bob',
      },
    ]);
  });

  test('uses the ID tie-break independent of input order', () => {
    const a = rule('a-rule', { priority: 7, actions: { createCase: false, assignTo: 'alice' } });
    const z = rule('z-rule', { priority: 7, actions: { createCase: false, assignTo: 'zoe' } });

    expect(planAlertAutomation(alert(), [z, a]).chosenAssignment).toBe('alice');
    expect(planAlertAutomation(alert(), [a, z]).chosenAssignment).toBe('alice');
  });

  test('lets an already-satisfied higher-priority target block a lower conflict', () => {
    const plan = planAlertAutomation(alert({ assigned_to: 'alice' }), [
      rule('keep', {
        priority: 1,
        preconditions: { assignment: 'any' },
        actions: { createCase: false, assignTo: 'alice' },
      }),
      rule('replace', {
        priority: 2,
        preconditions: { assignment: 'any' },
        actions: { createCase: false, assignTo: 'bob' },
      }),
    ]);

    expect(plan.chosenAssignment).toBe('alice');
    expect(plan.mutation).toBeNull();
    expect(plan.conflicts).toContainEqual({
      field: 'assignment',
      chosenRuleId: 'keep',
      chosenValue: 'alice',
      rejectedRuleId: 'replace',
      rejectedValue: 'bob',
    });
  });

  test('combines non-conflicting winners into one mutation per alert', () => {
    const plan = planAlertAutomation(alert(), [
      rule('status', { actions: { createCase: false, setStatus: 'in_progress' } }),
      rule('assignment', { actions: { createCase: false, assignTo: 'alice' } }),
    ]);

    expect(plan.mutation).toEqual({ status: 'in_progress', assigned_to: 'alice' });
    expect(plan.rulesApplied).toEqual(['assignment', 'status']);
    expect(plan.conflicts).toEqual([]);
  });
});

describe('automation planner preconditions and analyst state', () => {
  test('protects non-open and assigned analyst state by default', () => {
    const plan = planAlertAutomation(alert({ status: 'in_progress', assigned_to: 'manual-owner' }), [
      rule('automation', { actions: { createCase: false, setStatus: 'closed', assignTo: 'robot' } }),
    ]);

    expect(plan.matched).toEqual(['automation']);
    expect(plan.mutation).toBeNull();
    expect(plan.rulesApplied).toEqual([]);
    expect(plan.skipped).toEqual([
      { ruleId: 'automation', action: 'status', reason: 'status_precondition' },
      { ruleId: 'automation', action: 'assignment', reason: 'assignment_requires_unassigned' },
    ]);
  });

  test('allows each conservative guard to be explicitly disabled', () => {
    const plan = planAlertAutomation(alert({ status: 'in_progress', assigned_to: 'manual-owner' }), [
      rule('override', {
        preconditions: { statuses: ['open', 'in_progress', 'closed'], assignment: 'any' },
        actions: { createCase: false, setStatus: 'closed', assignTo: 'robot' },
      }),
    ]);

    expect(plan.mutation).toEqual({ status: 'closed', assigned_to: 'robot' });
  });

  test('records already-satisfied actions without emitting a mutation', () => {
    const plan = planAlertAutomation(alert({ status: 'open', assigned_to: 'alice' }), [
      rule('same', {
        preconditions: { assignment: 'any' },
        actions: { createCase: false, setStatus: 'open', assignTo: 'alice' },
      }),
    ]);

    expect(plan.mutation).toBeNull();
    expect(plan.skipped).toEqual([
      { ruleId: 'same', action: 'status', reason: 'already_satisfied' },
      { ruleId: 'same', action: 'assignment', reason: 'already_satisfied' },
    ]);
  });
});

describe('automation planner processing control', () => {
  test('preserves native rule order while enforcing an evaluator eligibility boundary', () => {
    const plan = planAlertAutomation({ ...alert(), executionEligibleRuleIds: new Set(['second']) }, [
      rule('first', { priority: 1, actions: { createCase: false, setStatus: 'closed' } }),
      rule('second', { priority: 2, actions: { createCase: false, assignTo: 'alice' } }),
    ]);
    expect(plan.matched).toEqual(['second']);
    expect(plan.skipped).toContainEqual({ ruleId: 'first', action: 'rule', reason: 'trigger_not_fired' });
    expect(plan.mutation).toEqual({ assigned_to: 'alice' });
  });

  test('continues by default and stops after a matching stop rule', () => {
    const plan = planAlertAutomation(alert(), [
      rule('first', { priority: 1, actions: { createCase: false, assignTo: 'alice' } }),
      rule('stop', {
        priority: 2,
        processingMode: 'stop',
        actions: { createCase: false, setStatus: 'closed' },
      }),
      rule('never', { priority: 3, actions: { createCase: false, assignTo: 'zoe' } }),
    ]);

    expect(plan.matched).toEqual(['first', 'stop']);
    expect(plan.rulesApplied).toEqual(['first', 'stop']);
    expect(plan.stopReason).toEqual({ ruleId: 'stop', reason: 'rule_requested_stop' });
    expect(plan.skipped.some((item) => item.ruleId === 'never')).toBe(false);
  });

  test('does not stop on a non-matching stop rule', () => {
    const plan = planAlertAutomation(alert(), [
      rule('not-matched', {
        priority: 1,
        processingMode: 'stop',
        match: { ruleIds: ['other'] },
        actions: { createCase: false, setStatus: 'closed' },
      }),
      rule('later', { priority: 2, actions: { createCase: false, assignTo: 'alice' } }),
    ]);

    expect(plan.stopReason).toBeNull();
    expect(plan.chosenAssignment).toBe('alice');
  });

  test('returns batch plans in deterministic alert-ID order', () => {
    const plans = planAutomation([alert(), { ...alert(), id: 'alert-0' }], [
      rule('assign', { actions: { createCase: false, assignTo: 'alice' } }),
    ]);
    expect(plans.map((plan) => plan.alertId)).toEqual(['alert-0', 'alert-1']);
  });
});

describe('automation planner Any/All trigger semantics', () => {
  test('matches Any on a per-alert trigger', () => {
    const plan = planAlertAutomation(alert(), [
      rule('any', { match: { ruleIds: ['99', '100'], ruleIdsMode: 'any' }, actions: { createCase: false, setStatus: 'closed' } }),
    ]);
    expect(plan.matched).toEqual(['any']);
    expect(plan.chosenStatus).toBe('closed');
  });

  test('reports All, including agent All, as unsupported for per-alert triggers', () => {
    const plan = planAlertAutomation(alert(), [
      rule('ids-all', { match: { ruleIds: ['99', '100'], ruleIdsMode: 'all' } }),
      rule('agents-all', { match: { agentNames: ['one', 'two'], agentNamesMode: 'all' } }),
    ]);

    expect(plan.matched).toEqual([]);
    expect(plan.skipped).toEqual([
      { ruleId: 'agents-all', action: 'rule', reason: 'all_mode_requires_burst' },
      { ruleId: 'ids-all', action: 'rule', reason: 'all_mode_requires_burst' },
    ]);
  });

  test('applies a burst All rule only after the window evaluator marks it matched', () => {
    const burst = rule('burst-all', {
      match: { ruleIds: ['99', '100'], ruleIdsMode: 'all' },
      trigger: { type: 'burst', entity: 'agent', threshold: 2, windowMinutes: 5 },
      actions: { createCase: false, setStatus: 'closed' },
    });

    const pending = planAlertAutomation(alert(), [burst]);
    const fired = planAlertAutomation({ ...alert(), matchedBurstRuleIds: new Set(['burst-all']) }, [burst]);
    expect(pending.skipped).toContainEqual({ ruleId: 'burst-all', action: 'rule', reason: 'burst_not_matched' });
    expect(fired.matched).toEqual(['burst-all']);
    expect(fired.chosenStatus).toBe('closed');
  });
});
