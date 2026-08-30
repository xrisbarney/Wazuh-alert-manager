import { EVIDENCE_READ_ALIAS } from '../../common';
import { applyAutomationCaseRoutes, planAutomationCaseRoutes } from './automation_case_routing';
import { reconcileCaseEvidence } from './case_evidence_service';

jest.mock('./case_evidence_service', () => ({ reconcileCaseEvidence: jest.fn() }));

const group = (id: string, value: string) => ({
  groupId: id,
  order: id === 'a' ? 0 : 1,
  values: [{ predicateId: `p-${id}`, entity: 'srcip' as const, value }],
});

const trigger = (routing: any, id: string, alerts: string[], revision = 1): any => ({
  ruleId: 'rule-1',
  ruleName: 'Rule',
  revision,
  routing,
  severity: 'high',
  assignedTo: null,
  group: group(id, id === 'a' ? '10.0.0.1' : '10.0.0.2'),
  alertIds: alerts,
  threshold: 2,
  windowMinutes: 5,
  count: alerts.length,
  truncated: false,
});

describe('automation case routing planner', () => {
  test('separate_by_group keeps independently matching OR groups separate', () => {
    const routes = planAutomationCaseRoutes([
      trigger('separate_by_group', 'a', ['1', '2']),
      trigger('separate_by_group', 'b', ['2', '3']),
    ]);
    expect(routes).toHaveLength(2);
    expect(routes.every((route) => route.matchingKeys.length === 1)).toBe(true);
  });

  test('separate_by_group coalesces alerts with the same observed identity into one hot-case route', () => {
    const routes = planAutomationCaseRoutes([
      trigger('separate_by_group', 'a', ['1', '2']),
      trigger('separate_by_group', 'a', ['2', '3']),
      trigger('separate_by_group', 'b', ['9']),
    ]);

    expect(routes).toHaveLength(2);
    expect(routes.map((route) => route.alertIds)).toEqual(expect.arrayContaining([['1', '2', '3'], ['9']]));
  });

  test('consolidate_overlapping merges only connected alert sets', () => {
    const routes = planAutomationCaseRoutes([
      trigger('consolidate_overlapping', 'a', ['1', '2']),
      trigger('consolidate_overlapping', 'b', ['2', '3']),
      { ...trigger('consolidate_overlapping', 'c', ['9']), group: group('c', '10.0.0.3') },
    ]);
    expect(routes).toHaveLength(2);
    expect(routes.map((route) => route.alertIds)).toEqual(expect.arrayContaining([['1', '2', '3'], ['9']]));
  });

  test('one_per_rule combines disjoint groups and keys do not include revision', () => {
    const first = planAutomationCaseRoutes([
      trigger('one_per_rule', 'a', ['1'], 1),
      trigger('one_per_rule', 'b', ['9'], 1),
    ]);
    const revised = planAutomationCaseRoutes([
      trigger('one_per_rule', 'a', ['1'], 99),
      trigger('one_per_rule', 'b', ['9'], 99),
    ]);
    expect(first).toHaveLength(1);
    expect(first[0].alertIds).toEqual(['1', '9']);
    expect(first[0].correlationKey).toBe(revised[0].correlationKey);
  });

  test('keeps a stable consolidate claim for successive A+B then A bursts', () => {
    const combined = planAutomationCaseRoutes([
      trigger('consolidate_overlapping', 'a', ['1', '2']),
      trigger('consolidate_overlapping', 'b', ['2', '3']),
    ])[0];
    const later = planAutomationCaseRoutes([trigger('consolidate_overlapping', 'a', ['4'])])[0];
    expect(combined.correlationKey).toBe(later.correlationKey);
  });
});

const linked = (ids: string[]) => ({
  ok: true, requested: ids.length, resolved: ids.length, linked: ids.length, newlyLinked: ids.length,
  unlinked: 0, moved: 0, staleUnlinks: 0, unknownAlertIds: [], linkedAlertIds: ids,
  unlinkedAlertIds: [], retryAlertIds: [], retryCaseIds: [], conflictedAlertIds: [], stages: [], errors: [],
});

function routingClient(searchHits: any[] = [], evidenceHits: any[] = []) {
  const documents = new Map<string, any>(searchHits.map((hit) => [String(hit._id), hit._source]));
  let sequence = 10;
  return {
    search: jest.fn(async ({ index, body }: any) => {
      if (body.sort) expect(body.sort.some((entry: any) => Object.prototype.hasOwnProperty.call(entry, '_id'))).toBe(false);
      let hits = index === EVIDENCE_READ_ALIAS ? evidenceHits : searchHits;
      if (body.query?.ids) {
        const ids = new Set(body.query.ids.values);
        hits = Array.from(ids).filter((id) => documents.has(String(id))).map((id) => {
          const original = searchHits.find((hit) => String(hit._id) === String(id));
          return {
            _id: String(id), _index: 'wazuh-alert-manager-v2-cases-000001',
            _seq_no: original?._seq_no ?? sequence++, _primary_term: original?._primary_term ?? 1,
            _source: documents.get(String(id)),
          };
        });
      }
      return { body: { hits: { total: { value: hits.length }, hits } } };
    }),
    create: jest.fn(async ({ id, body }: any) => {
      if (documents.has(id)) throw Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
      documents.set(id, body);
      return { body: { result: 'created' } };
    }),
    get: jest.fn(async ({ id }: any) => ({ body: { _seq_no: sequence++, _primary_term: 1, _source: documents.get(id) } })),
    update: jest.fn(async () => ({ body: { result: 'updated' } })),
    delete: jest.fn(async ({ id }: any) => { documents.delete(id); return { body: { result: 'deleted' } }; }),
    index: jest.fn(async () => ({ body: { result: 'created' } })),
  };
}

describe('automation case routing writes', () => {
  beforeEach(() => {
    (reconcileCaseEvidence as jest.Mock).mockReset();
    (reconcileCaseEvidence as jest.Mock).mockImplementation(async (_client, input) => {
      await input.fence?.();
      return linked(input.linkAlertIds);
    });
  });

  test('adopts a bounded legacy active case and unions provenance', async () => {
    const route = planAutomationCaseRoutes([trigger('separate_by_group', 'a', ['1'])])[0];
    const client = routingClient([{
      _id: 'legacy-case', _seq_no: 4, _primary_term: 1,
      _source: { status: 'open', correlation_keys: route.matchingKeys, severity: 'medium' },
    }]);
    const result = await applyAutomationCaseRoutes(client, [route], 1, 10);
    expect(result).toEqual(expect.objectContaining({ created: 0, extended: 1, caseIds: ['legacy-case'], remainder: [] }));
    expect(client.search.mock.calls[0][0].body.sort).toEqual([
      { created_at: { order: 'asc' } },
      { case_uid: { order: 'asc' } },
    ]);
    expect(JSON.stringify(client.search.mock.calls[0][0].body.sort)).not.toContain('_id');
    const claimUpdate = client.update.mock.calls[0][0];
    expect(claimUpdate.body.script.source).toContain('keys.addAll(params.keys)');
    expect(claimUpdate.body.script.source).toContain('linked.addAll(params.linked)');
  });

  test('discovers duplicate relationships from evidence and adopts them before OCC closure', async () => {
    const route = planAutomationCaseRoutes([
      trigger('consolidate_overlapping', 'a', ['bridge']),
      trigger('consolidate_overlapping', 'b', ['bridge']),
    ])[0];
    const client = routingClient([
      { _id: 'canonical', _seq_no: 1, _primary_term: 1, _source: { status: 'open', alert_ids: ['a-old'], severity: 'medium' } },
      { _id: 'duplicate', _seq_no: 2, _primary_term: 1, _source: { status: 'in_progress', alert_ids: ['not-authoritative'], severity: 'high' } },
    ], [{
      _id: 'relationship', sort: ['relationship'],
      _source: { case_id: 'duplicate', alert_id: 'b-old' },
    }]);
    const result = await applyAutomationCaseRoutes(client, [route], 1, 10);
    expect(result.caseIds).toEqual(['canonical']);
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({
      id: 'duplicate', if_seq_no: expect.any(Number), if_primary_term: 1, refresh: false,
    }));
    expect(reconcileCaseEvidence).toHaveBeenCalledWith(client, expect.objectContaining({
      waitForRefresh: false,
      caseId: 'canonical', linkAlertIds: ['b-old', 'bridge'], allowMove: true, fence: expect.any(Function),
    }));
    expect((reconcileCaseEvidence as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(client.update.mock.invocationCallOrder[0]);
  });

  test('leaves duplicate cases open when authoritative evidence discovery is incomplete', async () => {
    const route = planAutomationCaseRoutes([trigger('consolidate_overlapping', 'a', ['bridge'])])[0];
    const client = routingClient([
      { _id: 'canonical', _seq_no: 1, _primary_term: 1, _source: { status: 'open', severity: 'medium' } },
      { _id: 'duplicate', _seq_no: 2, _primary_term: 1, _source: { status: 'open', severity: 'medium' } },
    ]);
    client.search.mockImplementation(async ({ index }: any) => index === EVIDENCE_READ_ALIAS
      ? { body: { hits: { total: { value: 2 }, hits: [{
          _id: 'only-one', _source: { case_id: 'duplicate', alert_id: 'a1' }, sort: ['only-one'],
        }] } } }
      : { body: { hits: { total: { value: 2 }, hits: [
          { _id: 'canonical', _seq_no: 1, _primary_term: 1, _source: { status: 'open', severity: 'medium' } },
          { _id: 'duplicate', _seq_no: 2, _primary_term: 1, _source: { status: 'open', severity: 'medium' } },
        ] } } });

    await expect(applyAutomationCaseRoutes(client, [route], 1, 10)).rejects.toThrow('discovered 1 of 2');
    expect(reconcileCaseEvidence).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
  });

  test('does not close a duplicate when authoritative evidence adoption fails', async () => {
    const route = planAutomationCaseRoutes([trigger('consolidate_overlapping', 'a', ['bridge'])])[0];
    const client = routingClient([
      { _id: 'canonical', _seq_no: 1, _primary_term: 1, _source: { status: 'open', severity: 'medium' } },
      { _id: 'duplicate', _seq_no: 2, _primary_term: 1, _source: { status: 'open', severity: 'medium' } },
    ], [{ _id: 'r1', _source: { case_id: 'duplicate', alert_id: 'a1' }, sort: ['r1'] }]);
    (reconcileCaseEvidence as jest.Mock).mockResolvedValue({
      ...linked([]), ok: false, requested: 2, errors: [{ message: 'injected adoption failure' }],
    });

    await expect(applyAutomationCaseRoutes(client, [route], 1, 10)).rejects.toThrow('injected adoption failure');
    expect(client.update).not.toHaveBeenCalled();
  });

  test('returns deterministic cap remainder instead of dropping work', async () => {
    const routes = planAutomationCaseRoutes([
      trigger('separate_by_group', 'a', ['1', '2']),
      trigger('separate_by_group', 'b', ['3']),
    ]);
    const result = await applyAutomationCaseRoutes(routingClient(), routes, 0, 1);
    expect(result.remainder).toEqual(routes);
  });

  test('concurrent deterministic creates converge on one active case', async () => {
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    const client = routingClient();
    const [first, second] = await Promise.all([
      applyAutomationCaseRoutes(client, [route], 1, 10),
      applyAutomationCaseRoutes(client, [route], 1, 10),
    ]);
    expect(new Set([...first.caseIds, ...second.caseIds]).size).toBe(1);
    expect(client.create).toHaveBeenCalledTimes(2);
  });

  test('refreshes the owned case family when a winning deterministic create is not yet searchable', async () => {
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    const client: any = routingClient();
    client.create.mockRejectedValue(Object.assign(new Error('conflict'), { meta: { statusCode: 409 } }));
    client.indices = { refresh: jest.fn(async () => ({})) };
    client.search
      .mockResolvedValueOnce({ body: { hits: { total: { value: 0 }, hits: [] } } })
      .mockResolvedValueOnce({ body: { hits: { total: { value: 0 }, hits: [] } } })
      .mockImplementation(async ({ body }: any) => {
        const id = String(body.query.ids.values[0]);
        return { body: { hits: { total: { value: 1 }, hits: [{
          _id: id, _index: 'wazuh-alert-manager-v2-cases-000001', _seq_no: 1, _primary_term: 1,
          _source: { status: 'open', severity: 'medium', correlation_key: route.correlationKey },
        }] } } };
      });

    const result = await applyAutomationCaseRoutes(client, [route], 1, 10);

    expect(result).toEqual(expect.objectContaining({ created: 0, extended: 1 }));
    expect(result.caseIds[0]).toMatch(/^auto-/);
    expect(client.indices.refresh).toHaveBeenCalledWith({ index: 'wazuh-alert-manager-v2-cases-read' });
  });

  test('uses an atomic conflict-retrying merge for hot-case provenance and compatibility IDs', async () => {
    const route = planAutomationCaseRoutes([trigger('separate_by_group', 'a', ['1'])])[0];
    const client = routingClient([{
      _id: 'active', _seq_no: 4, _primary_term: 1,
      _source: { status: 'open', correlation_key: route.correlationKey, severity: 'medium' },
    }]);
    await expect(applyAutomationCaseRoutes(client, [route], 1, 10)).resolves.toEqual(
      expect.objectContaining({ extended: 1, linked: 1 })
    );
    expect(client.update).toHaveBeenCalledTimes(1);
    expect(client.search.mock.calls.filter(([request]: any[]) => request.body?.query?.ids)).toHaveLength(3);
    expect(client.update).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-cases-000001', id: 'active', retry_on_conflict: 50,
      body: { script: expect.objectContaining({
        source: expect.stringContaining('ctx._source.alert_ids = compatibilityList'),
        params: expect.objectContaining({ linked: ['1'], compatibility_limit: 1000, history_limit: 200 }),
      }) },
    }));
  });

  test('keeps a deterministic case claim for durable retry when no requested evidence links', async () => {
    (reconcileCaseEvidence as jest.Mock).mockResolvedValue({ ...linked([]), requested: 1 });
    const client = routingClient();
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    await expect(applyAutomationCaseRoutes(client, [route], 1, 10)).rejects.toThrow('linked 0 of 1');
    expect(client.delete).not.toHaveBeenCalled();
  });

  test('creates a new generation when the prior generation is closed', async () => {
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    const client = routingClient([{
      _id: 'old', _source: { status: 'closed', correlation_key: route.correlationKey },
    }]);
    const result = await applyAutomationCaseRoutes(client, [route], 1, 10);
    expect(result.created).toBe(1);
    expect(result.caseIds[0]).not.toBe('old');
    expect(client.update.mock.calls.every(([request]) => request.id !== 'old')).toBe(true);
  });

  test('rechecks an active hit and advances generation when closure wins the race', async () => {
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    const closed = { _id: 'old', _source: { status: 'closed', correlation_key: route.correlationKey } };
    const client = routingClient([closed]);
    client.search.mockImplementationOnce(async () => ({
      body: { hits: { total: { value: 1 }, hits: [{ ...closed, _source: { ...closed._source, status: 'open' } }] } },
    }));
    const result = await applyAutomationCaseRoutes(client, [route], 1, 10);
    expect(result).toEqual(expect.objectContaining({ created: 1, extended: 0 }));
    expect(result.caseIds).not.toContain('old');
  });

  test('revalidates the fence before every visible mutation phase', async () => {
    const client = routingClient();
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    const fence = jest.fn(async () => undefined);

    await applyAutomationCaseRoutes(client, [route], 1, 10, new Map(), fence);

    expect(fence).toHaveBeenCalledTimes(4);
    expect((reconcileCaseEvidence as jest.Mock).mock.calls[0][1].fence).toBe(fence);
    const fenceOrders = fence.mock.invocationCallOrder;
    expect(fenceOrders[0]).toBeLessThan(client.create.mock.invocationCallOrder[0]);
    expect((reconcileCaseEvidence as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(fenceOrders[1]);
    expect(fenceOrders[2]).toBeLessThan(client.update.mock.invocationCallOrder[0]);
    expect(fenceOrders[3]).toBeLessThan(client.index.mock.invocationCallOrder[0]);
  });

  test('aborts later routing phases when the worker loses its fence', async () => {
    const client = routingClient();
    const route = planAutomationCaseRoutes([trigger('one_per_rule', 'a', ['1'])])[0];
    let checks = 0;
    const fence = jest.fn(async () => {
      checks += 1;
      if (checks === 2) throw new Error('automation lease lost');
    });

    await expect(applyAutomationCaseRoutes(client, [route], 1, 10, new Map(), fence)).rejects.toThrow(
      'automation lease lost'
    );
    expect(client.create).toHaveBeenCalledTimes(1);
    expect(reconcileCaseEvidence).toHaveBeenCalledTimes(1);
    expect(client.update).not.toHaveBeenCalled();
    expect(client.index).not.toHaveBeenCalled();
  });
});
