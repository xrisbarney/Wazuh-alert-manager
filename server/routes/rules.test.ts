import {
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
} from './rules';
import { META_INDEX } from '../../common';
import { normalizeAndValidateRule, ruleDefinitionFingerprint } from '../lib/rule_validation';

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
