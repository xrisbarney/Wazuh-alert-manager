import { ALERTS_READ_ALIAS, CASES_INDEX, EVIDENCE_READ_ALIAS } from '../../common';
import { evidenceId } from './evidence';
import { reconcileCaseEvidence } from './case_evidence_service';

const ALERT_INDEX = 'wazuh-alert-status-v2-000001';
const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';

function bulkSuccess(body: any[]) {
  const items: any[] = [];
  for (let index = 0; index < body.length; ) {
    const action = body[index];
    const operation = Object.keys(action)[0];
    items.push({ [operation]: { status: operation === 'index' ? 201 : 200 } });
    index += operation === 'delete' ? 1 : 2;
  }
  return { body: { errors: false, items } };
}

function clientFor(options: {
  alerts?: Record<string, any>;
  relationships?: any[];
  metadata?: Record<string, string[]>;
  cases?: Record<string, any>;
  bulk?: (args: any, call: number) => Promise<any>;
} = {}) {
  const alerts = options.alerts || {};
  const relationships = options.relationships || [];
  const search = jest.fn(async (request: any) => {
    if (request.index === CASES_INDEX) {
      const ids: string[] = request.body.query.ids.values;
      return { body: { hits: { hits: ids.map((id) => ({
        _id: id, _index: CASE_INDEX, _seq_no: 1, _primary_term: 1,
        _source: options.cases?.[id] || { status: 'open' },
      })) } } };
    }
    if (request.index === ALERTS_READ_ALIAS) {
      const ids: string[] = request.body.query.ids.values;
      return {
        body: {
          hits: {
            hits: ids.filter((id) => alerts[id]).map((id) => ({ _id: id, _index: ALERT_INDEX, _source: alerts[id] })),
          },
        },
      };
    }
    if (request.index === EVIDENCE_READ_ALIAS && request.body.query.terms) {
      const ids = new Set(request.body.query.terms.alert_id);
      return { body: { hits: { hits: relationships.filter((hit) => ids.has(hit._source.alert_id)).map((hit, index) => ({
        _seq_no: hit._seq_no ?? index + 1, _primary_term: hit._primary_term ?? 1, ...hit,
      })) } } };
    }
    if (request.index === EVIDENCE_READ_ALIAS && request.body.query.term) {
      const caseId = request.body.query.term.case_id;
      const ids = options.metadata?.[caseId] || [];
      return { body: { hits: { hits: ids.map((id) => ({ _source: { alert_id: id } })) } } };
    }
    throw new Error(`Unexpected search: ${JSON.stringify(request)}`);
  });
  let bulkCall = 0;
  const bulk = jest.fn(async (request: any) => {
    bulkCall += 1;
    return options.bulk ? options.bulk(request, bulkCall) : bulkSuccess(request.body);
  });
  const update = jest.fn(async () => ({ body: { result: 'updated' } }));
  const get = jest.fn(async ({ id }: any) => ({
    body: {
      _seq_no: 1,
      _primary_term: 1,
      _source: options.cases?.[id] || { status: 'open' },
    },
  }));
  return { search, bulk, update, get };
}

describe('reconcileCaseEvidence', () => {
  test('leaves hot automation compatibility projection to the atomic case-route merge', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: null, source_index: 'wazuh-alerts-4.x', source_id: 'native-1' } },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1'], actor: 'correlation-rule', waitForRefresh: false,
    });

    expect(result).toEqual(expect.objectContaining({ ok: true, linkedAlertIds: ['a1'] }));
    expect(result.stages).toContainEqual({ stage: 'sync_case_metadata', attempted: 0, succeeded: 0, failed: 0 });
    expect(client.update).not.toHaveBeenCalled();
  });

  test('moves a resolved alert while preserving old evidence and rebuilding both case views', async () => {
    const client = clientFor({
      alerts: {
        a1: {
          case_id: 'old-case',
          source_index: 'wazuh-alerts-4.x',
          source_id: 'native-1',
          '@timestamp': '2026-08-28T01:02:03.000Z',
          rule: { id: '5502', level: 7, description: 'login failure' },
        },
      },
      relationships: [
        { _id: evidenceId('old-case', 'a1'), _source: { case_id: 'old-case', alert_id: 'a1', linked_at: 'old' } },
      ],
      metadata: { 'new-case': ['a1'], 'old-case': ['a1'] },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'new-case',
      linkAlertIds: ['a1'],
      actor: 'analyst',
      timestamp: '2026-08-28T02:00:00.000Z',
    });

    expect(result).toEqual(expect.objectContaining({ ok: true, linked: 1, newlyLinked: 1, moved: 1 }));
    const evidenceBulk = client.bulk.mock.calls[1][0].body;
    expect(evidenceBulk[0].create._id).toBe(evidenceId('new-case', 'a1'));
    expect(evidenceBulk[1]).toEqual(expect.objectContaining({
      case_id: 'new-case',
      alert_id: 'a1',
      source_index: 'wazuh-alerts-4.x',
      source_id: 'native-1',
      snapshot: expect.objectContaining({ rule: expect.objectContaining({ id: '5502' }) }),
    }));
    expect(client.bulk).toHaveBeenCalledTimes(2);
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({
      index: CASE_INDEX,
      id: 'new-case',
      body: { doc: expect.objectContaining({ alert_ids: ['a1'] }) },
    }));
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({
      index: CASE_INDEX,
      id: 'old-case',
      body: { doc: expect.objectContaining({ alert_ids: ['a1'] }) },
    }));
  });

  test('does not write an unknown alert ID and reports it for correction', async () => {
    const client = clientFor({ metadata: { c1: [] } });
    const result = await reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['missing'], actor: 'analyst',
    });

    expect(result.ok).toBe(false);
    expect(result.unknownAlertIds).toEqual(['missing']);
    expect(result.linked).toBe(0);
    expect(client.bulk).not.toHaveBeenCalled();
    expect(result.errors).toContainEqual(expect.objectContaining({ stage: 'resolve', alertId: 'missing' }));
  });

  test('validates each bulk item and does not advance a failed assignment to evidence', async () => {
    const client = clientFor({
      alerts: { a1: {}, a2: {} },
      metadata: { c1: ['a1'] },
      bulk: async (request, call) => {
        if (call === 1) {
          return {
            body: {
              errors: true,
              items: [
                { update: { status: 200 } },
                { update: { status: 429, error: { reason: 'rejected' } } },
              ],
            },
          };
        }
        return bulkSuccess(request.body);
      },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1', 'a2'], actor: 'rule',
    });

    expect(result.ok).toBe(false);
    expect(result.linkedAlertIds).toEqual(['a1']);
    expect(result.retryAlertIds).toEqual(['a2']);
    expect(result.stages).toContainEqual({ stage: 'assign_alerts', attempted: 2, succeeded: 1, failed: 1 });
    const evidenceBulk = client.bulk.mock.calls[1][0].body;
    expect(evidenceBulk).toHaveLength(2);
    expect(evidenceBulk[0].create._id).toBe(evidenceId('c1', 'a1'));
  });

  test('keeps old evidence when the replacement evidence write fails', async () => {
    const oldRelationship = {
      _id: evidenceId('old', 'a1'),
      _source: { case_id: 'old', alert_id: 'a1' },
    };
    const client = clientFor({
      alerts: { a1: { case_id: 'old' } },
      relationships: [oldRelationship],
      metadata: { c1: [], old: ['a1'] },
      bulk: async (request, call) => call === 2
        ? { body: { errors: true, items: [{ index: { status: 503, error: { reason: 'disk unavailable' } } }] } }
        : bulkSuccess(request.body),
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1'], actor: 'analyst',
    });

    expect(result.ok).toBe(false);
    expect(result.retryAlertIds).toEqual(['a1']);
    expect(client.bulk).toHaveBeenCalledTimes(3);
    expect(result.stages).toContainEqual({ stage: 'rollback_assignments', attempted: 1, succeeded: 1, failed: 0 });
    expect(result.stages).toContainEqual({ stage: 'remove_evidence', attempted: 0, succeeded: 0, failed: 0 });
  });

  test('stale unlink removes only stale evidence and conditionally preserves another case owner', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'new-owner' } },
      relationships: [{ _id: evidenceId('old-case', 'a1'), _source: { case_id: 'old-case', alert_id: 'a1' } }],
      metadata: { 'old-case': [] },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'old-case', unlinkAlertIds: ['a1'], actor: 'analyst',
    });

    expect(result).toEqual(expect.objectContaining({ ok: true, staleUnlinks: 1, unlinked: 1 }));
    const unlinkBulk = client.bulk.mock.calls[0][0].body;
    expect(unlinkBulk[1].script.source).toContain('ctx._source.case_id == params.case_id');
    expect(unlinkBulk[1].script.params.case_id).toBe('old-case');
    expect(client.bulk.mock.calls[1][0].body[0].delete._id).toBe(evidenceId('old-case', 'a1'));
  });

  test('does not delete authoritative evidence when clearing alert ownership fails', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'c1' } },
      relationships: [{ _id: evidenceId('c1', 'a1'), _source: { case_id: 'c1', alert_id: 'a1' } }],
      metadata: { c1: ['a1'] },
      bulk: async (_request, call) => call === 1
        ? { body: { errors: true, items: [{ update: { status: 503, error: { reason: 'alert write failed' } } }] } }
        : bulkSuccess(_request.body),
    });

    const result = await reconcileCaseEvidence(client, { caseId: 'c1', unlinkAlertIds: ['a1'], actor: 'analyst' });

    expect(result).toEqual(expect.objectContaining({ ok: false, unlinked: 0 }));
    expect(result.stages).toContainEqual({ stage: 'unlink_alerts', attempted: 1, succeeded: 0, failed: 1 });
    expect(result.stages).toContainEqual({ stage: 'remove_evidence', attempted: 0, succeeded: 0, failed: 0 });
    expect(client.bulk).toHaveBeenCalledTimes(1);
  });

  test('keeps recoverable evidence and reports failure when evidence deletion fails after clear', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'c1' } },
      relationships: [{ _id: evidenceId('c1', 'a1'), _seq_no: 8, _primary_term: 2, _source: { case_id: 'c1', alert_id: 'a1' } }],
      metadata: { c1: ['a1'] },
      bulk: async (request, call) => call === 2
        ? { body: { errors: true, items: [{ delete: { status: 503, error: { reason: 'evidence write failed' } } }] } }
        : bulkSuccess(request.body),
    });

    const result = await reconcileCaseEvidence(client, { caseId: 'c1', unlinkAlertIds: ['a1'], actor: 'analyst' });

    expect(result).toEqual(expect.objectContaining({ ok: false, unlinked: 0, retryAlertIds: ['a1'] }));
    expect(client.bulk.mock.calls[1][0].body[0].delete).toEqual(expect.objectContaining({
      _id: evidenceId('c1', 'a1'), if_seq_no: 8, if_primary_term: 2,
    }));
  });

  test('preserves linked_at on an idempotent retry and bounds compatibility metadata', async () => {
    const relationship = {
      _id: evidenceId('c1', 'a1'),
      _source: { case_id: 'c1', alert_id: 'a1', linked_at: '2026-01-01T00:00:00.000Z' },
    };
    const client = clientFor({
      alerts: { a1: { case_id: 'c1' } },
      relationships: [relationship],
      metadata: { c1: ['a1'] },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1'], actor: 'rule', compatibilityLimit: 1,
    });

    expect(result).toEqual(expect.objectContaining({ ok: true, linked: 1, newlyLinked: 0 }));
    expect(client.bulk.mock.calls[1][0].body[0].update).toEqual(expect.objectContaining({
      _id: evidenceId('c1', 'a1'), if_seq_no: 1, if_primary_term: 1,
    }));
    expect(client.bulk.mock.calls[1][0].body[1].script.source).toContain('ctx.op = "none"');
    expect(client.bulk.mock.calls[1][0].body[1].script.source).not.toContain('ctx._source.snapshot =');
    const metadataSearch = client.search.mock.calls.find(
      ([request]) => request.index === EVIDENCE_READ_ALIAS && request.body.query.term
    )![0];
    expect(metadataSearch.body.size).toBe(1);
    expect(metadataSearch.body.sort).toEqual([{ alert_id: { order: 'asc' } }]);
  });

  test('does not move or unlink a held relationship', async () => {
    const relationship = {
      _id: evidenceId('held-case', 'a1'),
      _index: 'wazuh-alert-manager-v2-evidence-000001',
      _source: { case_id: 'held-case', alert_id: 'a1', hold_reason: 'legal' },
    };
    const moveClient = clientFor({
      alerts: { a1: { case_id: 'held-case' } },
      relationships: [relationship],
      metadata: { 'new-case': [] },
    });
    const moved = await reconcileCaseEvidence(moveClient, {
      caseId: 'new-case', linkAlertIds: ['a1'], actor: 'analyst',
    });
    expect(moved.ok).toBe(false);
    expect(moved.errors).toContainEqual(expect.objectContaining({ alertId: 'a1', message: 'Held evidence cannot be moved.' }));
    expect(moveClient.bulk).not.toHaveBeenCalled();

    const unlinkClient = clientFor({
      alerts: { a1: { case_id: 'held-case' } },
      relationships: [relationship],
      metadata: { 'held-case': ['a1'] },
    });
    const unlinked = await reconcileCaseEvidence(unlinkClient, {
      caseId: 'held-case', unlinkAlertIds: ['a1'], actor: 'analyst',
    });
    expect(unlinked.ok).toBe(false);
    expect(unlinked.unlinked).toBe(0);
    expect(unlinkClient.bulk).not.toHaveBeenCalled();
  });

  test('does not mutate evidence after its case becomes terminal', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'closed-case' } },
      relationships: [{ _id: evidenceId('closed-case', 'a1'), _source: { case_id: 'closed-case', alert_id: 'a1' } }],
      metadata: { 'closed-case': ['a1'] },
      cases: { 'closed-case': { status: 'closed' } },
    });
    const result = await reconcileCaseEvidence(client, {
      caseId: 'closed-case', unlinkAlertIds: ['a1'], actor: 'analyst',
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toContainEqual(expect.objectContaining({
      alertId: 'a1', message: 'Terminal case evidence cannot be linked, moved, or unlinked.',
    }));
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('guards a manual move against a concurrent owner change', async () => {
    const client = clientFor({ alerts: { a1: { case_id: 'old' } }, metadata: { c1: [], old: ['a1'] } });
    await reconcileCaseEvidence(client, { caseId: 'c1', linkAlertIds: ['a1'], actor: 'analyst' });
    const assignment = client.bulk.mock.calls[0][0].body[1].script;
    expect(assignment.source).toContain('ctx._source.case_id != params.expected_case_id');
    expect(assignment.params.expected_case_id).toBe('old');
  });

  test('automation records an ownership conflict without stealing evidence', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'closed-case' } },
      relationships: [{ _id: evidenceId('closed-case', 'a1'), _source: { case_id: 'closed-case', alert_id: 'a1' } }],
      metadata: { 'new-case': [] },
      cases: { 'closed-case': { status: 'open' } },
    });
    const result = await reconcileCaseEvidence(client, {
      caseId: 'new-case', linkAlertIds: ['a1'], actor: 'correlation-rule', allowMove: false,
    });
    expect(result).toEqual(expect.objectContaining({ ok: true, linked: 0, moved: 0, conflictedAlertIds: ['a1'] }));
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test.each([null, 'stale-closed-case'])(
    'automation respects active evidence ownership when alert.case_id is %p',
    async (projectedCaseId) => {
      const client = clientFor({
        alerts: { a1: { case_id: projectedCaseId } },
        relationships: [{
          _id: evidenceId('active-owner', 'a1'),
          _source: { case_id: 'active-owner', alert_id: 'a1' },
        }],
        metadata: { 'new-case': [], 'active-owner': ['a1'] },
        cases: {
          'active-owner': { status: 'in_progress' },
          'stale-closed-case': { status: 'closed' },
        },
      });

      const result = await reconcileCaseEvidence(client, {
        caseId: 'new-case', linkAlertIds: ['a1'], actor: 'correlation-rule', allowMove: false,
      });

      expect(result).toEqual(expect.objectContaining({ ok: true, linked: 0, conflictedAlertIds: ['a1'] }));
      expect(client.bulk).not.toHaveBeenCalled();
    }
  );

  test('manual move uses authoritative evidence owner when alert.case_id is null', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: null } },
      relationships: [{
        _id: evidenceId('active-owner', 'a1'),
        _source: { case_id: 'active-owner', alert_id: 'a1' },
      }],
      metadata: { 'new-case': ['a1'], 'active-owner': ['a1'] },
      cases: { 'active-owner': { status: 'open' } },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'new-case', linkAlertIds: ['a1'], actor: 'analyst', allowMove: true,
    });

    expect(result).toEqual(expect.objectContaining({ ok: true, linked: 1, moved: 1 }));
    expect(client.bulk.mock.calls[1][0].body[0].create._id).toBe(evidenceId('new-case', 'a1'));
  });

  test('repairs stale alert ownership when the target already has authoritative evidence', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'stale-owner' } },
      relationships: [{
        _id: evidenceId('target', 'a1'),
        _source: { case_id: 'target', alert_id: 'a1', snapshot: { rule: { id: 'historical' } } },
      }],
      metadata: { target: ['a1'], 'stale-owner': [] },
      cases: { target: { status: 'open' }, 'stale-owner': { status: 'open' } },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'target', linkAlertIds: ['a1'], actor: 'correlation-rule', allowMove: false,
    });

    expect(result).toEqual(expect.objectContaining({ ok: true, linked: 1, conflictedAlertIds: [] }));
    expect(client.bulk.mock.calls[0][0].body[1].script.params).toEqual(expect.objectContaining({
      expected_case_id: 'stale-owner', allow_move: true,
    }));
    expect(client.bulk.mock.calls[1][0].body[1].script.source).not.toContain('ctx._source.snapshot =');
  });

  test('held active evidence blocks a move when alert.case_id is stale', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: null } },
      relationships: [{
        _id: evidenceId('active-owner', 'a1'),
        _source: { case_id: 'active-owner', alert_id: 'a1', relationship_state: 'held' },
      }],
      metadata: { 'new-case': [] },
      cases: { 'active-owner': { status: 'open' } },
    });

    const result = await reconcileCaseEvidence(client, {
      caseId: 'new-case', linkAlertIds: ['a1'], actor: 'analyst', allowMove: true,
    });

    expect(result.errors).toContainEqual(expect.objectContaining({ alertId: 'a1', message: 'Held evidence cannot be moved.' }));
    expect(client.bulk).not.toHaveBeenCalled();
  });

  test('links a new incident while preserving closed-case evidence', async () => {
    const old = { _id: evidenceId('closed-case', 'a1'), _source: { case_id: 'closed-case', alert_id: 'a1' } };
    const client = clientFor({
      alerts: { a1: { case_id: 'closed-case' } },
      relationships: [old],
      metadata: { 'new-case': ['a1'], 'closed-case': ['a1'] },
      cases: { 'closed-case': { status: 'closed' }, 'new-case': { status: 'open' } },
    });
    const result = await reconcileCaseEvidence(client, {
      caseId: 'new-case', linkAlertIds: ['a1'], actor: 'correlation-rule', allowMove: false,
    });
    expect(result).toEqual(expect.objectContaining({ ok: true, linked: 1, moved: 1 }));
    expect(client.bulk).toHaveBeenCalledTimes(2);
    expect(client.bulk.mock.calls[1][0].body[0].create._id).toBe(evidenceId('new-case', 'a1'));
  });

  test('uses OCC for existing evidence and compatibility metadata', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'c1' } },
      relationships: [{ _id: evidenceId('c1', 'a1'), _seq_no: 7, _primary_term: 3, _source: { case_id: 'c1', alert_id: 'a1' } }],
      metadata: { c1: ['a1'] },
    });
    await reconcileCaseEvidence(client, { caseId: 'c1', linkAlertIds: ['a1'], actor: 'analyst' });
    expect(client.bulk.mock.calls[1][0].body[0].update).toEqual(expect.objectContaining({ if_seq_no: 7, if_primary_term: 3 }));
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({ if_seq_no: 1, if_primary_term: 1 }));
  });

  test('stops before writing evidence when the fence is lost after alert assignment', async () => {
    const client = clientFor({ alerts: { a1: {} }, metadata: { c1: ['a1'] } });
    const fence = jest.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('automation lease lost'));

    await expect(reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1'], actor: 'rule', fence,
    })).rejects.toThrow('automation lease lost');

    expect(client.bulk).toHaveBeenCalledTimes(1);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('stops before rollback when the fence is lost after a failed evidence write', async () => {
    const client = clientFor({
      alerts: { a1: {} },
      metadata: { c1: [] },
      bulk: async (request, call) => call === 2
        ? { body: { errors: true, items: [{ create: { status: 503, error: { reason: 'write failed' } } }] } }
        : bulkSuccess(request.body),
    });
    const fence = jest.fn()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('automation lease lost'));

    await expect(reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1'], actor: 'rule', fence,
    })).rejects.toThrow('automation lease lost');

    expect(client.bulk).toHaveBeenCalledTimes(2);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('stops before removing evidence when the fence is lost after alert unlink', async () => {
    const client = clientFor({
      alerts: { a1: { case_id: 'c1' } },
      relationships: [{ _id: evidenceId('c1', 'a1'), _source: { case_id: 'c1', alert_id: 'a1' } }],
      metadata: { c1: [] },
    });
    const fence = jest.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('automation lease lost'));

    await expect(reconcileCaseEvidence(client, {
      caseId: 'c1', unlinkAlertIds: ['a1'], actor: 'rule', fence,
    })).rejects.toThrow('automation lease lost');

    expect(client.bulk).toHaveBeenCalledTimes(1);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('stops before rebuilding compatibility metadata when the fence is lost after evidence write', async () => {
    const client = clientFor({ alerts: { a1: {} }, metadata: { c1: ['a1'] } });
    const fence = jest.fn()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('automation lease lost'));

    await expect(reconcileCaseEvidence(client, {
      caseId: 'c1', linkAlertIds: ['a1'], actor: 'rule', fence,
    })).rejects.toThrow('automation lease lost');

    expect(client.bulk).toHaveBeenCalledTimes(2);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('does not destructively unlink archive-only evidence', async () => {
    const client = clientFor({
      relationships: [{
        _id: evidenceId('c1', 'archived'),
        _index: 'wazuh-alert-manager-v2-evidence-000001',
        _source: { case_id: 'c1', alert_id: 'archived', archive_index: 'wazuh-alert-status-v2-000001' },
      }],
      metadata: { c1: ['archived'] },
    });
    const result = await reconcileCaseEvidence(client, {
      caseId: 'c1', unlinkAlertIds: ['archived'], actor: 'analyst',
    });
    expect(result.ok).toBe(false);
    expect(result.unknownAlertIds).toEqual(['archived']);
    expect(result.unlinked).toBe(0);
    expect(client.bulk).not.toHaveBeenCalled();
  });
});
