jest.mock('../lib/notifications/settings', () => {
  const actual = jest.requireActual('../lib/notifications/settings');
  return { ...actual, loadNotificationSettings: jest.fn() };
});
import { loadNotificationSettings } from '../lib/notifications/settings';
import {
  actionsSchema,
  requireKnownNotifyChannels,
  shouldValidateNotifyChannels,
  buildRollbackRule,
  applyRuleActivationMetadata,
  canonicalTriggerSchema,
  decodeRulesCursor,
  deletedRuleResponse,
  editableRuleSnapshot,
  repairRuleOperation,
  previewApprovalId,
  previewToken,
  requireDisabledEntityGroupEdit,
  requireCurrentPreview,
  requireEnabledRuleCapacity,
  ruleResponse,
  attachRuleExecutionState,
  defineRuleRoutes,
} from './rules';
import { API_ROOT, META_INDEX } from '../../common';
import { mergeRulePatch, normalizeAndValidateRule, ruleDefinitionFingerprint } from '../lib/rule_validation';

const pending = {
  operation_id: 'rule-operation:r1:000000000002',
  revision: {
    document_type: 'rule_revision',
    rule_id: 'r1',
    revision: 2,
    changed_at: '2026-01-01T00:00:00.000Z',
    changed_by: 'analyst',
    change_type: 'update',
    operation_id: 'rule-operation:r1:000000000002',
    snapshot: { name: 'Rule two', enabled: true },
  },
  audit: {
    targetType: 'rule',
    targetId: 'r1',
    user: 'analyst',
    action: 'rule_updated',
    source: 'rules_api',
    timestamp: '2026-01-01T00:00:00.000Z',
    operationId: 'rule-audit:r1:000000000002',
    ruleRevision: 2,
  },
};

const hit = () => ({
  _id: 'r1',
  _seq_no: 7,
  _primary_term: 2,
  _source: { name: 'Rule two', revision: 2, pending_operation: pending },
});

describe('rule persistence durability', () => {
  test('retains the outbox after a revision failure and repairs it on a later read', async () => {
    const client: any = {
      index: jest.fn().mockRejectedValueOnce(new Error('revision unavailable')),
      update: jest.fn().mockResolvedValue({ body: { _seq_no: 8, _primary_term: 2 } }),
    };
    const observer = { error: jest.fn(), increment: jest.fn() };

    const failed = await repairRuleOperation(client, hit(), observer);
    expect(failed._source.pending_operation).toBe(pending);
    expect(client.update).not.toHaveBeenCalled();

    client.index.mockResolvedValueOnce({}).mockResolvedValueOnce({});
    const repaired = await repairRuleOperation(client, hit(), observer);
    expect(repaired._source.pending_operation).toBeUndefined();
    expect(repaired._seq_no).toBe(8);
  });

  test('retains a durable retry record and reports an activity write failure', async () => {
    const client: any = {
      index: jest.fn().mockResolvedValueOnce({}).mockRejectedValueOnce(new Error('activity unavailable')),
      update: jest.fn(),
    };
    const observer = { error: jest.fn(), increment: jest.fn() };

    const failed = await repairRuleOperation(client, hit(), observer);
    expect(failed._source.pending_operation.operation_id).toBe(pending.operation_id);
    expect(observer.increment).toHaveBeenCalledWith('automation_audit_write_failures');
    expect(observer.error).toHaveBeenCalledWith(expect.stringContaining('durable outbox'));

    client.index.mockRejectedValueOnce({ statusCode: 409 }).mockResolvedValueOnce({});
    client.update.mockResolvedValueOnce({ body: { _seq_no: 8, _primary_term: 2 } });
    const repaired = await repairRuleOperation(client, hit(), observer);
    expect(repaired._source.pending_operation).toBeUndefined();
  });
});

describe('rule response and history contracts', () => {
  test('synthesizes revision one for a legacy rule response', () => {
    expect(ruleResponse({ _id: 'legacy', _source: { name: 'Legacy' }, _seq_no: 1, _primary_term: 1 })).toMatchObject({
      id: 'legacy',
      revision: 1,
    });
  });

  test('snapshots definitions only and rollback preserves telemetry while forcing disabled', () => {
    const current = { name: 'Current', enabled: true, matchCount: 14, lastFired: 'now', counters: { matchedAlerts: 9 } };
    expect(editableRuleSnapshot(current)).toEqual({ name: 'Current', enabled: true });
    expect(buildRollbackRule(current, { name: 'Old', enabled: true }, 4, 'later')).toMatchObject({
      name: 'Old',
      enabled: false,
      revision: 4,
      matchCount: 14,
      lastFired: 'now',
      counters: { matchedAlerts: 9 },
    });
  });

  test('rejects malformed cursor shapes', () => {
    const malformed = Buffer.from(JSON.stringify({ v: 1, pit: 'pit', sort: ['not-a-number'], includeDeleted: false })).toString('base64');
    expect(() => decodeRulesCursor(malformed)).toThrow('Invalid rules cursor');
  });

  test('returns the same successful tombstone for repeated delete calls', () => {
    const deleted = { _source: { revision: 3, deleted_at: 'now' }, _seq_no: 8, _primary_term: 2 };
    expect(deletedRuleResponse(deleted)).toEqual(deletedRuleResponse(deleted));
    expect(deletedRuleResponse(deleted)).toMatchObject({ deleted: true, tombstone: true, revision: 3 });
  });
});

describe('rule execution state join (step 12.3)', () => {
  const rules = [
    { id: 'r1', name: 'Fired', enabled: true, revision: 2 },
    { id: 'r2', name: 'Idle', enabled: true, revision: 1, lastFired: null },
  ];

  test('joins matchCount / lastFired / counters from the rule-execution companions with one mget', async () => {
    const client: any = {
      mget: jest.fn(async () => ({ body: { docs: [
        { _id: 'rule-execution:r1', found: true, _source: { document_type: 'rule_execution', rule_id: 'r1', matchCount: 44, lastFired: '2026-11-22T14:08:00.000Z', counters: { matchedAlerts: 44, triggeredEntities: 3 } } },
        { _id: 'rule-execution:r2', found: false },
      ] } })),
    };
    const joined = await attachRuleExecutionState(client, rules);
    expect(client.mget).toHaveBeenCalledTimes(1);
    expect(client.mget.mock.calls[0][0]).toEqual({ index: expect.stringContaining('wazuh-alert-manager-v2-rules'), body: { ids: ['rule-execution:r1', 'rule-execution:r2'] } });
    expect(joined[0]).toEqual({ ...rules[0], matchCount: 44, lastFired: '2026-11-22T14:08:00.000Z', counters: { matchedAlerts: 44, triggeredEntities: 3 } });
    expect(joined[1]).toBe(rules[1]);
  });

  test('an unavailable companion read leaves the responses untouched and is logged', async () => {
    const observer = { warn: jest.fn() };
    const client: any = { mget: jest.fn(async () => { throw new Error('mget refused'); }) };
    await expect(attachRuleExecutionState(client, rules, observer)).resolves.toEqual(rules);
    expect(observer.warn).toHaveBeenCalledWith(expect.stringContaining('mget refused'));
    await expect(attachRuleExecutionState(client, [], observer)).resolves.toEqual([]);
    expect(client.mget).toHaveBeenCalledTimes(1);
  });
});

describe('rule activation preview gate', () => {
  const draft = () =>
    normalizeAndValidateRule({
      name: 'Draft',
      enabled: false,
      match: { ruleIds: ['100'] },
      trigger: { type: 'per_alert' },
      actions: { createCase: false, setStatus: 'closed' },
    }).rule;

  test('blocks disabled to enabled when no successful current preview exists', async () => {
    const current = draft();
    const client = { get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }) };

    await expect(requireCurrentPreview(client, 'r1', 3, current, { ...current, enabled: true })).rejects.toMatchObject({
      statusCode: 409,
    });
    expect(client.get).toHaveBeenCalledWith({ index: META_INDEX, id: previewApprovalId('r1', 3) });
  });

  test('rejects stale definitions and tokens even at the same revision', async () => {
    const current = draft();
    const fingerprint = ruleDefinitionFingerprint(current);
    const client = {
      get: jest.fn().mockResolvedValue({
        body: {
          _source: {
            status: 'success',
            rule_id: 'r1',
            revision: 3,
            fingerprint,
            token: previewToken('r1', 3, fingerprint),
          },
        },
      }),
    };

    await expect(
      requireCurrentPreview(client, 'r1', 3, current, {
        ...current,
        enabled: true,
        actions: { ...current.actions, setStatus: 'in_progress' },
      })
    ).rejects.toMatchObject({ statusCode: 409 });
    client.get.mockResolvedValueOnce({
      body: { _source: { status: 'success', rule_id: 'r1', revision: 3, fingerprint, token: 'forged' } },
    });
    await expect(requireCurrentPreview(client, 'r1', 3, current, { ...current, enabled: true })).rejects.toMatchObject({
      statusCode: 409,
    });
  });

  test('allows the exact approved transition and does not gate disable or already-enabled edits', async () => {
    const current = draft();
    const next = { ...current, enabled: true };
    const fingerprint = ruleDefinitionFingerprint(next);
    const client = {
      get: jest.fn().mockResolvedValue({
        body: {
          _source: {
            status: 'success',
            rule_id: 'r1',
            revision: 3,
            fingerprint,
            token: previewToken('r1', 3, fingerprint),
          },
        },
      }),
    };

    await expect(requireCurrentPreview(client, 'r1', 3, current, next)).resolves.toBeUndefined();
    await expect(requireCurrentPreview(client, 'r1', 4, next, { ...next, enabled: false })).resolves.toBeUndefined();
    await expect(requireCurrentPreview(client, 'r1', 4, next, { ...next, name: 'Enabled edit' })).resolves.toBeUndefined();
    expect(client.get).toHaveBeenCalledTimes(1);
  });
});

describe('match scope asset criticality floor', () => {
  const current = () => ({
    name: 'Floor',
    enabled: false,
    match: { ruleGroups: ['authentication_failed'], minAssetCriticality: 'high' },
    trigger: { type: 'per_alert' },
    actions: { setStatus: 'in_progress' },
  });

  test('PUT { match: { minAssetCriticality: null } } clears a stored floor', () => {
    const merged = mergeRulePatch(current(), { match: { minAssetCriticality: null } });
    const result = normalizeAndValidateRule(merged);
    expect(result.errors).toEqual([]);
    expect(result.rule.match.minAssetCriticality).toBeUndefined();
    expect(result.rule.match.ruleGroups).toEqual(['authentication_failed']);
  });

  test('a patch that omits the field keeps the stored floor', () => {
    const result = normalizeAndValidateRule(mergeRulePatch(current(), { match: { ruleIds: ['5710'] } }));
    expect(result.rule.match.minAssetCriticality).toBe('high');
  });
});

describe('canonical mutation contract', () => {
  const trigger = () => ({
    type: 'burst',
    entityExpression: {
      version: 1,
      groups: [{
        id: 'source',
        order: 0,
        predicates: [{ id: 'source-ip', order: 0, entity: 'srcip', operator: 'exists' }],
      }],
    },
    routing: 'separate_by_group',
    cooldown: { durationMinutes: 5 },
    rearm: { type: 'after_quiet_period', quietPeriodMinutes: 5 },
    threshold: 2,
    windowMinutes: 5,
  });

  test('accepts grouped predicates, routing, cooldown, and rearm', () => {
    expect(canonicalTriggerSchema.validate(trigger())).toEqual(trigger());
  });

  test('rejects the legacy entity trigger shape on mutation', () => {
    expect(() => canonicalTriggerSchema.validate({
      type: 'burst', entity: 'srcip', threshold: 2, windowMinutes: 5,
    })).toThrow();
  });

  test('requires an enabled rule to be disabled and saved before group changes', () => {
    const current = { enabled: true, trigger: trigger() };
    const next = {
      enabled: false,
      trigger: {
        ...trigger(),
        entityExpression: { ...trigger().entityExpression, groups: [{
          id: 'agent', order: 0,
          predicates: [{ id: 'agent-name', order: 0, entity: 'agent', operator: 'exists' }],
        }] },
      },
    };
    expect(() => requireDisabledEntityGroupEdit(current, next)).toThrow('Disable and save');
    expect(() => requireDisabledEntityGroupEdit({ ...current, enabled: false }, next)).not.toThrow();
  });

  test('sets an ingestion activation boundary and rotates entity state only after disabled edits', () => {
    const current = { enabled: false, state_epoch: 'old', effective_from: null, trigger: trigger() };
    const enabled = applyRuleActivationMetadata(current, { ...current, enabled: true }, '2026-08-28T12:00:00.000Z');
    expect(enabled).toMatchObject({ effective_from: '2026-08-28T12:00:00.000Z', state_epoch: 'old' });

    const changed = applyRuleActivationMetadata(current, {
      ...current,
      trigger: { ...trigger(), entityExpression: { ...trigger().entityExpression, groups: [] } },
    }, '2026-08-28T12:00:00.000Z');
    expect(changed.state_epoch).not.toBe('old');
  });

  test('rejects the 201st enabled rule before mutation', async () => {
    const client = { count: jest.fn().mockResolvedValue({ body: { count: 200 } }) };
    await expect(requireEnabledRuleCapacity(client, { enabled: false }, { enabled: true })).rejects.toMatchObject({
      statusCode: 409,
    });
    await expect(requireEnabledRuleCapacity(client, { enabled: true }, { enabled: true })).resolves.toBeUndefined();
    expect(client.count).toHaveBeenCalledTimes(1);
  });
});

describe('notify action on the rule routes (step 1.4)', () => {
  const settings = (ids: string[]) => ({
    enabled: true,
    channels: ids.map((id) => ({ id, name: id, kind: 'webhook', enabled: id !== 'off', events: [] })),
  });

  test('actionsSchema accepts notify channel ids (nullable, empty allowed) and caps the list at 20', () => {
    expect(actionsSchema.validate({ notify: { channelIds: ['soc-slack'] } })).toEqual({ notify: { channelIds: ['soc-slack'] } });
    expect(actionsSchema.validate({ notify: { channelIds: [] } })).toEqual({ notify: { channelIds: [] } });
    expect(actionsSchema.validate({ notify: null })).toEqual({ notify: null });
    expect(actionsSchema.validate({ createCase: true, caseSeverity: 'high', notify: { channelIds: ['a', 'b'] } })).toMatchObject({ createCase: true, notify: { channelIds: ['a', 'b'] } });
    expect(() => actionsSchema.validate({ notify: { channelIds: Array.from({ length: 21 }, (_, i) => `c${i}`) } })).toThrow();
    expect(() => actionsSchema.validate({ notify: { channelIds: [''] } })).toThrow();
    expect(() => actionsSchema.validate({ notify: 'soc-slack' })).toThrow();
  });

  test('requireKnownNotifyChannels refuses unknown ids with a 400 naming them, accepts disabled channels, reads nothing without the action', async () => {
    const client = { get: jest.fn() };
    (loadNotificationSettings as jest.Mock).mockResolvedValue(settings(['soc-slack', 'off']));

    await expect(requireKnownNotifyChannels(client, { actions: { notify: { channelIds: ['soc-slack', 'off'] } } })).resolves.toBeUndefined();

    await expect(requireKnownNotifyChannels(client, { actions: { notify: { channelIds: ['soc-slack', 'ghost', 'gone'] } } })).rejects.toMatchObject({
      statusCode: 400,
      message: 'Unknown notification channel id(s): ghost, gone. Bind the channel in Settings > Notifications first.',
      body: { unknownChannelIds: ['ghost', 'gone'] },
    });
    expect(loadNotificationSettings).toHaveBeenCalledTimes(2);

    await expect(requireKnownNotifyChannels(client, { actions: { createCase: true } })).resolves.toBeUndefined();
    await expect(requireKnownNotifyChannels(client, { actions: { notify: null } })).resolves.toBeUndefined();
    expect(loadNotificationSettings).toHaveBeenCalledTimes(2);
  });

  test('PUT re-validates the channel ids only when the patch names them or the rule ends up enabled (a rule whose channel is gone can be disabled)', async () => {
    (loadNotificationSettings as jest.Mock).mockResolvedValue(settings(['soc-slack']));
    const stored = { name: 'Notify rule', enabled: true, actions: { notify: { channelIds: ['gone'] } } };

    // Channel removed from the settings afterwards: disabling the rule must not be refused.
    const disabling = mergeRulePatch(stored, { enabled: false });
    expect(shouldValidateNotifyChannels({ enabled: false }, disabling)).toBe(false);
    // ...and a plain edit of a disabled rule neither.
    expect(shouldValidateNotifyChannels({ name: 'Renamed' }, mergeRulePatch({ ...stored, enabled: false }, { name: 'Renamed' }))).toBe(false);
    // Enabling it, or touching the notify action, validates (and here refuses) the ids.
    const enabling = mergeRulePatch({ ...stored, enabled: false }, { enabled: true });
    expect(shouldValidateNotifyChannels({ enabled: true }, enabling)).toBe(true);
    await expect(requireKnownNotifyChannels({}, enabling)).rejects.toMatchObject({ statusCode: 400, body: { unknownChannelIds: ['gone'] } });
    expect(shouldValidateNotifyChannels({ actions: { notify: { channelIds: ['gone'] } } }, mergeRulePatch({ ...stored, enabled: false }, { actions: { notify: { channelIds: ['gone'] } } }))).toBe(true);
    expect(shouldValidateNotifyChannels({ actions: { notify: null } }, mergeRulePatch({ ...stored, enabled: false }, { actions: { notify: null } }))).toBe(true);
    // An edit of an enabled rule that leaves the action alone still validates (the stored ids are read, a valid list passes).
    const enabledEdit = mergeRulePatch({ ...stored, actions: { notify: { channelIds: ['soc-slack'] } } }, { name: 'Renamed' });
    expect(shouldValidateNotifyChannels({ name: 'Renamed' }, enabledEdit)).toBe(true);
    await expect(requireKnownNotifyChannels({}, enabledEdit)).resolves.toBeUndefined();
  });

  test('a storage failure while reading the channel list is not a 400', async () => {
    (loadNotificationSettings as jest.Mock).mockRejectedValue(Object.assign(new Error('meta unavailable'), { meta: { statusCode: 503 } }));
    await expect(requireKnownNotifyChannels({}, { actions: { notify: { channelIds: ['soc-slack'] } } })).rejects.toMatchObject({ message: 'meta unavailable', meta: { statusCode: 503 } });
  });
});

describe('single-rule routes carry the execution state (step 12.3 fix)', () => {
  const handlerFor = (method: 'get' | 'post' | 'put', path: string) => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() };
    defineRuleRoutes(router);
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration![1];
  };
  const responses = () => ({
    ok: jest.fn((payload: any) => ({ status: 200, ...payload })),
    notFound: jest.fn((payload: any) => ({ status: 404, ...payload })),
    customError: jest.fn((payload: any) => ({ status: payload.statusCode, ...payload })),
  });

  test('GET /rules/{id} joins the rule-execution companion with one mget', async () => {
    const client: any = {
      get: jest.fn(async () => ({ body: { _id: 'r1', _seq_no: 7, _primary_term: 2, _source: { name: 'Fired', enabled: true, revision: 2, pending_operation: pending, created_by: 'analyst' } } })),
      index: jest.fn(async () => ({ body: {} })),
      mget: jest.fn(async () => ({ body: { docs: [
        { _id: 'rule-execution:r1', found: true, _source: { document_type: 'rule_execution', rule_id: 'r1', matchCount: 44, lastFired: '2026-11-22T14:08:00.000Z', counters: { matchedAlerts: 44, triggeredEntities: 3 } } },
      ] } })),
    };
    const response = responses();
    const result: any = await handlerFor('get', '/rules/{id}')(
      { core: { opensearch: { client: { asCurrentUser: client } } }, wazuhAlertManager: { logger: { warn: jest.fn(), error: jest.fn() } } },
      { params: { id: 'r1' } },
      response
    );
    expect(response.ok).toHaveBeenCalledTimes(1);
    expect(client.mget).toHaveBeenCalledTimes(1);
    expect(client.mget.mock.calls[0][0].body).toEqual({ ids: ['rule-execution:r1'] });
    expect(result.body).toEqual(expect.objectContaining({ id: 'r1', name: 'Fired', revision: 2, matchCount: 44, lastFired: '2026-11-22T14:08:00.000Z', counters: { matchedAlerts: 44, triggeredEntities: 3 } }));
    expect(result.body.pending_operation).toBeUndefined();
  });
});
