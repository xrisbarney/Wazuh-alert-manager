import { mergeRulePatch, normalizeAndValidateRule, ruleDefinitionFingerprint } from './rule_validation';

const validRule = () => ({
  name: '  Suspicious burst  ',
  match: { ruleIds: [' 100 ', '100', '', '200'], ruleIdsMode: 'all' },
  trigger: { type: 'burst', entity: 'agent', threshold: 3, windowMinutes: 10 },
  actions: { createCase: true, caseSeverity: 'high', assignTo: ' analyst ' },
  safety: { acknowledgeMatchAll: false },
});

describe('automation rule normalization and validation', () => {
  test('trims scalar values and normalizes and deduplicates arrays', () => {
    const result = normalizeAndValidateRule(validRule());
    expect(result.errors).toEqual([]);
    expect(result.rule.name).toBe('Suspicious burst');
    expect(result.rule.match.ruleIds).toEqual(['100', '200']);
    expect(result.rule.actions.assignTo).toBe('analyst');
    expect(result.rule.enabled).toBe(false);
    expect(result.rule.schemaVersion).toBe(2);
    expect(result.rule.trigger).toMatchObject({
      type: 'burst',
      threshold: 3,
      windowMinutes: 10,
      routing: 'separate_by_group',
      cooldown: { durationMinutes: 10 },
      rearm: { type: 'after_quiet_period', quietPeriodMinutes: 10 },
    });
  });

  test('deep-merges a partial patch before validating cross-field rules', () => {
    const current = normalizeAndValidateRule(validRule()).rule;
    const merged = mergeRulePatch(current, { trigger: { threshold: 5 }, actions: { assignTo: 'tier-2' } });
    const result = normalizeAndValidateRule(merged);
    expect(result.errors).toEqual([]);
    expect(result.rule.trigger).toMatchObject({ type: 'burst', threshold: 5, windowMinutes: 10 });
    expect(result.rule.actions.createCase).toBe(true);
    expect(result.rule.actions.assignTo).toBe('tier-2');
  });

  test('rejects All semantics for per-alert rules', () => {
    const input = validRule();
    input.trigger = { type: 'per_alert' } as any;
    input.actions = { createCase: false, caseSeverity: 'high', assignTo: 'analyst' };
    expect(normalizeAndValidateRule(input).errors).toContain('All match mode is only supported by burst rules.');
  });

  test('allows per-alert deduplicated case creation', () => {
    const input = validRule();
    input.trigger = { type: 'per_alert' } as any;
    input.match.ruleIdsMode = 'any';
    const result = normalizeAndValidateRule(input);
    expect(result.errors).toEqual([]);
    expect(result.rule.actions.createCase).toBe(true);
    expect(result.rule.trigger.cooldown).toEqual({ durationMinutes: 0 });
    expect(result.rule.trigger.rearm).toEqual({ type: 'immediate', quietPeriodMinutes: 0 });
  });

  test('validates routing and explicit burst cooldown/rearm policy', () => {
    const input: any = validRule();
    input.trigger.routing = 'invalid';
    input.trigger.cooldown = { durationMinutes: 0 };
    input.trigger.rearm = { type: 'immediate', quietPeriodMinutes: 0 };
    const errors = normalizeAndValidateRule(input).errors;
    expect(errors).toContain('Case routing must be separate_by_group, consolidate_overlapping, or one_per_rule.');
    expect(errors).toContain('Burst cooldown must be an integer between 1 and 10080 minutes.');
    expect(errors).toContain('Burst rearm must use an after_quiet_period interval between 1 and 10080 minutes.');
  });

  test('requires explicit acknowledgement for an empty match', () => {
    const input = validRule();
    input.match = {} as any;
    expect(normalizeAndValidateRule(input).errors).toContain(
      'Matching all alerts requires safety.acknowledgeMatchAll=true.'
    );
    input.safety.acknowledgeMatchAll = true;
    expect(normalizeAndValidateRule(input).errors).toEqual([]);
  });

  test('uses conservative policy defaults', () => {
    const result = normalizeAndValidateRule(validRule()).rule;
    expect(result.priority).toBe(100);
    expect(result.sortOrder).toBe(0);
    expect(result.processingMode).toBe('continue');
    expect(result.preconditions.assignment).toBe('unassigned');
  });

  test('allows a partial update to clear a rate limit', () => {
    const current = { ...validRule(), safety: { acknowledgeMatchAll: false, rateLimit: { maxExecutions: 5, windowMinutes: 60 } } };
    const merged = mergeRulePatch(current, { safety: { rateLimit: null } });
    const result = normalizeAndValidateRule(merged);
    expect(result.errors).toEqual([]);
    expect(result.rule.safety.rateLimit).toBeUndefined();
  });

  test('fingerprints only the canonical material definition', () => {
    const first = { ...validRule(), enabled: false, revision: 2, updated_at: 'old' };
    const reordered = {
      updated_at: 'new',
      revision: 99,
      enabled: true,
      safety: first.safety,
      actions: first.actions,
      trigger: first.trigger,
      match: first.match,
      name: first.name,
    };
    expect(ruleDefinitionFingerprint(reordered)).toBe(ruleDefinitionFingerprint(first));
    expect(ruleDefinitionFingerprint({ ...first, actions: { ...first.actions, assignTo: 'other' } })).not.toBe(
      ruleDefinitionFingerprint(first)
    );
  });
});
