import { mergeRulePatch, normalizeAndValidateRule, ruleDefinitionFingerprint, ruleNotifyChannelIds } from './rule_validation';

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

describe('minAssetCriticality (step 6.4a)', () => {
  test('is normalised into match, counts as a restriction and changes the fingerprint', () => {
    const base = validRule();
    const withFloor = normalizeAndValidateRule({ ...base, match: { minAssetCriticality: 'high' } });
    expect(withFloor.errors).toEqual([]);
    expect(withFloor.rule.match).toMatchObject({ minAssetCriticality: 'high' });
    expect(normalizeAndValidateRule({ ...base, match: {} }).errors).toContain('Matching all alerts requires safety.acknowledgeMatchAll=true.');
    expect(ruleDefinitionFingerprint({ ...base, match: { minAssetCriticality: 'high' } })).not.toBe(
      ruleDefinitionFingerprint({ ...base, match: { minAssetCriticality: 'critical' } })
    );
    expect(normalizeAndValidateRule(base).rule.match.minAssetCriticality).toBeUndefined();
  });

  test('rejects an unknown criticality', () => {
    const result = normalizeAndValidateRule({ ...validRule(), match: { minAssetCriticality: 'urgent' } });
    expect(result.errors).toContain('Minimum asset criticality must be one of low, medium, high, critical.');
  });
});

describe('actions.applyTaskListId (step 2.2)', () => {
  test('is kept trimmed when it is a task list id on a create-case rule and omitted when empty', () => {
    const kept = normalizeAndValidateRule({ ...validRule(), actions: { createCase: true, caseSeverity: 'high', applyTaskListId: ' pb-0123456789abcdef ' } });
    expect(kept.errors).toEqual([]);
    expect(kept.rule.actions.applyTaskListId).toBe('pb-0123456789abcdef');
    for (const empty of ['', null, undefined]) {
      const cleared = normalizeAndValidateRule({ ...validRule(), actions: { createCase: true, caseSeverity: 'high', applyTaskListId: empty } });
      expect(cleared.errors).toEqual([]);
      expect(cleared.rule.actions).not.toHaveProperty('applyTaskListId');
    }
  });

  test('rejects a non-string or unsafe id and drops a stale task list when the create case action is off', () => {
    for (const bad of [42, {}, 'has space', '-x', 'a'.repeat(65)]) {
      const result = normalizeAndValidateRule({ ...validRule(), actions: { createCase: true, caseSeverity: 'high', applyTaskListId: bad } });
      expect(result.errors).toContain('Apply task list must be a task list id (1-64 letters, digits, "-" or "_").');
    }
    // The editor hides the task list select once create case is unchecked, so a
    // leftover selection must never block the save.
    const noCase = normalizeAndValidateRule({ ...validRule(), actions: { createCase: false, setStatus: 'closed', applyTaskListId: 'pb-1' } });
    expect(noCase.errors).toEqual([]);
    expect(noCase.rule.actions).not.toHaveProperty('applyTaskListId');
  });

  test('changes the definition fingerprint', () => {
    const base = ruleDefinitionFingerprint(validRule());
    const withTaskList = ruleDefinitionFingerprint({ ...validRule(), actions: { ...validRule().actions, applyTaskListId: 'pb-1' } });
    expect(withTaskList).not.toBe(base);
  });
});

describe('disposition on the close action (step 2.4)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { normalizeAndValidateRule: validate, ruleDefinitionFingerprint: fingerprint } = require('./rule_validation');
  const base = () => ({
    name: 'Close scanner noise', enabled: true, match: { ruleIds: ['5710'] }, trigger: { type: 'per_alert' },
    actions: { createCase: false, setStatus: 'closed' }, safety: { acknowledgeMatchAll: true },
  });

  test('keeps a valid disposition with setStatus closed and refuses an unknown one', () => {
    const ok = validate({ ...base(), actions: { createCase: false, setStatus: 'closed', disposition: 'false_positive' } });
    expect(ok.errors).toEqual([]);
    expect(ok.rule.actions).toEqual(expect.objectContaining({ setStatus: 'closed', disposition: 'false_positive' }));
    const bad = validate({ ...base(), actions: { createCase: false, setStatus: 'closed', disposition: 'resolved' } });
    expect(bad.errors).toContain('Disposition must be one of true_positive, false_positive, benign, duplicate or undetermined.');
  });

  test('drops the disposition when the status action is not a close (stale editor value, no error)', () => {
    for (const setStatus of ['in_progress', 'open', null]) {
      const result = validate({ ...base(), actions: { createCase: false, setStatus, assignTo: 'bob', disposition: 'benign' } });
      expect(result.errors).toEqual([]);
      expect(result.rule.actions).not.toHaveProperty('disposition');
    }
    const empty = validate({ ...base(), actions: { createCase: false, setStatus: 'closed', disposition: '' } });
    expect(empty.errors).toEqual([]);
    expect(empty.rule.actions).not.toHaveProperty('disposition');
  });

  test('changes the definition fingerprint', () => {
    const plain = fingerprint(validate(base()).rule);
    const withDisposition = fingerprint(validate({ ...base(), actions: { createCase: false, setStatus: 'closed', disposition: 'benign' } }).rule);
    expect(withDisposition).not.toBe(plain);
  });
});

describe('notify action (step 1.4)', () => {
  const notifyRule = (channelIds: unknown[]) => ({
    name: 'Notify SOC',
    match: { ruleIds: ['100'] },
    trigger: { type: 'per_alert' },
    actions: { createCase: false, notify: { channelIds } },
    safety: { acknowledgeMatchAll: false },
  });

  test('a rule with only notify is valid; normalisation trims and de-duplicates the ids and keeps the action', () => {
    const result = normalizeAndValidateRule(notifyRule([' soc-slack ', 'soc-slack', 'ops_mail', '']));
    expect(result.errors).toEqual([]);
    expect(result.rule.actions).toMatchObject({ createCase: false, setStatus: null, assignTo: null, notify: { channelIds: ['soc-slack', 'ops_mail'] } });
    expect(ruleNotifyChannelIds(result.rule)).toEqual(['soc-slack', 'ops_mail']);
  });

  test('combines with the other actions and changes the definition fingerprint', () => {
    const base = validRule();
    const withNotify = { ...base, actions: { ...base.actions, notify: { channelIds: ['soc-slack'] } } };
    const result = normalizeAndValidateRule(withNotify);
    expect(result.errors).toEqual([]);
    expect(result.rule.actions).toMatchObject({ createCase: true, caseSeverity: 'high', assignTo: 'analyst', notify: { channelIds: ['soc-slack'] } });
    expect(ruleDefinitionFingerprint(withNotify)).not.toBe(ruleDefinitionFingerprint(base));
  });

  test('an empty selection (or null) is dropped and then counts as no action', () => {
    for (const notify of [{ channelIds: [] }, { channelIds: ['  '] }, null]) {
      const input: any = notifyRule([]);
      input.actions.notify = notify;
      const result = normalizeAndValidateRule(input);
      expect(result.rule.actions.notify).toBeUndefined();
      expect(result.errors).toContain('Select at least one action: create case, set status, assign to an analyst, or notify channels.');
    }
    expect(ruleNotifyChannelIds({ actions: { notify: null } })).toEqual([]);
    expect(ruleNotifyChannelIds({ actions: { notify: { channelIds: 'soc' } } })).toEqual([]);
  });

  test('caps the list at 20 ids and refuses malformed ids by name', () => {
    const tooMany = normalizeAndValidateRule(notifyRule(Array.from({ length: 21 }, (_, index) => `channel-${index}`)));
    expect(tooMany.errors).toEqual(['Notify channels must name between 1 and 20 channel ids.']);
    expect(normalizeAndValidateRule(notifyRule(Array.from({ length: 20 }, (_, index) => `channel-${index}`))).errors).toEqual([]);
    const malformed = normalizeAndValidateRule(notifyRule(['Bad Id', 'ok-id', 'x'.repeat(65)]));
    expect(malformed.errors).toHaveLength(1);
    expect(malformed.errors[0]).toContain('"Bad Id"');
    expect(malformed.errors[0]).toContain(`"${'x'.repeat(65)}"`);
    expect(malformed.errors[0]).not.toContain('"ok-id"');
    const wrongShape: any = notifyRule([]);
    wrongShape.actions.notify = 'soc-slack';
    expect(normalizeAndValidateRule(wrongShape).errors).toContain('Notify channels must be an object with a channelIds list.');
  });

  test('a patch replaces the channel list as a whole and null clears it', () => {
    const current = normalizeAndValidateRule(notifyRule(['a', 'b'])).rule;
    expect(normalizeAndValidateRule(mergeRulePatch(current, { actions: { notify: { channelIds: ['c'] } } })).rule.actions.notify).toEqual({ channelIds: ['c'] });
    const cleared = normalizeAndValidateRule(mergeRulePatch(current, { actions: { notify: null, setStatus: 'closed' } }));
    expect(cleared.errors).toEqual([]);
    expect(cleared.rule.actions.notify).toBeUndefined();
    expect(normalizeAndValidateRule(mergeRulePatch(current, { name: 'renamed' })).rule.actions.notify).toEqual({ channelIds: ['a', 'b'] });
  });
});
