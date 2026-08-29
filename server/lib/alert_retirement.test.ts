import {
  executeAlertRetirement,
  planAlertRetirement,
  purgeRetiredAlertIndex,
  recoverPreparingAlertRetirements,
  startRetirementRecoveryJob,
  resolveCaseLinkedCarry,
  restoreRetiredAlertIndex,
} from './alert_retirement';
import { evidenceId } from './evidence';
import { ALERTS_READ_ALIAS, ALERTS_WRITE_ALIAS, CASES_INDEX, EVIDENCE_READ_ALIAS, META_INDEX } from '../../common';

const noopLogger = { info: jest.fn(), warn: jest.fn(), error: jest.fn() };

describe('resolveCaseLinkedCarry', () => {
  const closedHits = [
    { _id: 'c1', _source: { status: 'closed', case_id: 'case-active' } },
    { _id: 'c2', _source: { status: 'closed', case_id: 'case-closed' } },
    { _id: 'c3', _source: { status: 'closed', case_id: 'case-held' } },
  ];

  function client() {
    return {
      search: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: closedHits } } })),
      scroll: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      get: jest.fn(async ({ index, id }: any) => {
        if (index === CASES_INDEX) {
          const status = id === 'case-active' ? 'open' : 'closed';
          return { body: { _source: { status } } };
        }
        if (index === EVIDENCE_READ_ALIAS && id === evidenceId('case-held', 'c3')) {
          return { body: { _source: { hold_reason: 'legal' } } };
        }
        const e: any = new Error('not_found');
        e.meta = { statusCode: 404 };
        throw e;
      }),
    } as any;
  }

  test('carries only closed alerts whose case is active or held', async () => {
    const resolutions = await resolveCaseLinkedCarry(client(), 'wazuh-alert-status-v2-000001');
    const byId = new Map(resolutions.map((r) => [r.alertId, r]));
    expect(byId.get('c1')!.carry).toBe(true); // active case
    expect(byId.get('c2')!.carry).toBe(false); // closed, non-held case
    expect(byId.get('c3')!.carry).toBe(true); // explicit hold
    expect(byId.get('c1')!.caseStatus).toBe('open');
  });
});

describe('planAlertRetirement', () => {
  test('rejects non-managed, non-member, and current-write indices', async () => {
    await expect(planAlertRetirement({} as any, 'wazuh-alerts-4.x-1')).rejects.toThrow(
      /physical wazuh-alert-status-v2-/
    );
    await expect(planAlertRetirement({} as any, 'wazuh-alert-manager-v2-meta')).rejects.toThrow(
      /physical wazuh-alert-status-v2-/
    );
    const notMember: any = {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => ({
          body:
            name === ALERTS_READ_ALIAS
              ? {}
              : { 'wazuh-alert-status-v2-000002': { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } } },
        })),
      },
    };
    await expect(planAlertRetirement(notMember, 'wazuh-alert-status-v2-000001')).rejects.toThrow(
      /not a member/
    );
  });

  test('rejects retiring the current write generation', async () => {
    const retiring = 'wazuh-alert-status-v2-000002';
    const client: any = {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => ({
          body:
            name === ALERTS_READ_ALIAS
              ? { [retiring]: {} }
              : { [retiring]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } } },
        })),
      },
    };
    await expect(planAlertRetirement(client, retiring)).rejects.toThrow(/Roll over before retiring/);
  });

  test('computes case-aware carry counts', async () => {
    const retiring = 'wazuh-alert-status-v2-000001';
    const write = 'wazuh-alert-status-v2-000002';
    const closedHits = [
      { _id: 'c1', _source: { status: 'closed', case_id: 'case-active' } },
      { _id: 'c2', _source: { status: 'closed', case_id: 'case-closed' } },
    ];
    const client: any = {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => ({
          body:
            name === ALERTS_READ_ALIAS
              ? { [retiring]: {}, [write]: {} }
              : { [write]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } } },
        })),
      },
      count: jest.fn(async ({ body }: any) => {
        const q = JSON.stringify(body.query);
        if (q.includes('match_all')) return { body: { count: 10 } };
        if (q.includes('open')) return { body: { count: 3 } };
        return { body: { count: 2 } }; // closed case-linked
      }),
      search: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: closedHits } } })),
      scroll: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      get: jest.fn(async ({ index, id }: any) => {
        if (index === CASES_INDEX) return { body: { _source: { status: id === 'case-active' ? 'open' : 'closed' } } };
        const e: any = new Error('not_found');
        e.meta = { statusCode: 404 };
        throw e;
      }),
    };
    const plan = await planAlertRetirement(client, retiring);
    expect(plan.totalDocuments).toBe(10);
    expect(plan.activeDocuments).toBe(3);
    expect(plan.caseLinkedClosedDocuments).toBe(2);
    expect(plan.carriedCaseLinkedDocuments).toBe(1);
    expect(plan.archivedCaseLinkedDocuments).toBe(1);
    expect(plan.preservedDocuments).toBe(4);
    expect(plan.archiveOnlyDocuments).toBe(6);
    expect(plan.carriedCaseLinkedIds).toEqual(['c1']);
    expect(plan.archivedCaseLinks).toEqual([{ alertId: 'c2', caseId: 'case-closed' }]);
  });
});

describe('executeAlertRetirement', () => {
  const retiring = 'wazuh-alert-status-v2-000001';
  const write = 'wazuh-alert-status-v2-000002';
  const activeHits = [{ _id: 'a1', _source: { status: 'open' } }];
  const closedHits = [
    { _id: 'c1', _source: { status: 'closed', case_id: 'case-active' } },
    { _id: 'c2', _source: { status: 'closed', case_id: 'case-closed' } },
  ];

  function client(overrides: any = {}) {
    return {
      indices: {
        getAlias: jest.fn(async ({ name, index }: any) => index
          ? { body: { [index]: { aliases: {} } } }
          : {
              body:
                name === ALERTS_READ_ALIAS
                  ? { [retiring]: {}, [write]: {} }
                  : {
                      [retiring]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: false } } },
                      [write]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } },
                    },
            }),
        exists: jest.fn(async () => ({ body: true })),
        create: jest.fn(async () => ({})),
        delete: jest.fn(async () => ({})),
        putSettings: jest.fn(async () => ({})),
        refresh: jest.fn(async () => ({})),
        updateAliases: jest.fn(async () => ({})),
      },
      count: jest.fn(async ({ body }: any) => {
        const q = JSON.stringify(body.query);
        if (q.includes('match_all')) return { body: { count: 3 } };
        if (q.includes('open')) return { body: { count: 1 } };
        return { body: { count: 2 } }; // closed case-linked
      }),
      search: jest.fn(async ({ body }: any) => {
        const q = JSON.stringify(body.query);
        if (q.includes('open')) return { body: { _scroll_id: 's-active', hits: { hits: activeHits } } };
        return { body: { _scroll_id: 's-closed', hits: { hits: closedHits } } };
      }),
      scroll: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { errors: false, items: [] } })),
      get: jest.fn(async ({ index, id }: any) => {
        if (index === CASES_INDEX) return { body: { _source: { status: id === 'case-active' ? 'open' : 'closed' } } };
        if (index === retiring) {
          const hit = closedHits.find((item) => item._id === id);
          if (hit) return { body: { _source: hit._source } };
        }
        const e: any = new Error('not_found');
        e.meta = { statusCode: 404 };
        throw e;
      }),
      index: jest.fn(async () => ({ body: { _seq_no: 10, _primary_term: 2 } })),
      update: jest.fn(async () => ({})),
      delete: jest.fn(async () => ({})),
      ...overrides,
    } as any;
  }

  test('carries active alerts plus active-case closed alerts, archives the rest', async () => {
    const c = client();
    const copiedToCarry: any[] = [];
    c.bulk = jest.fn(async (args: any) => {
      for (let i = 0; i < args.body.length; i += 2) {
        copiedToCarry.push(args.body[i].index._id);
      }
      return { body: { errors: false, items: [] } };
    });
    const result = await executeAlertRetirement(c, retiring, 'analyst', noopLogger as any);
    // active 'a1' + closed case-linked 'c1' (active case). 'c2' is archived.
    expect(copiedToCarry.sort()).toEqual(['a1', 'c1']);
    expect(result.carriedDocuments).toBe(2);
    expect(result.carriedCaseLinkedDocuments).toBe(1);
    expect(result.archivedCaseLinkedDocuments).toBe(1);
    expect(c.index).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-write',
      id: evidenceId('case-closed', 'c2'),
      op_type: 'create',
      body: expect.objectContaining({ relationship_state: 'archived', archive_index: retiring }),
    }));
    expect(c.indices.putSettings).toHaveBeenCalledWith({ index: retiring, body: { 'index.blocks.write': true } });
    expect(c.indices.updateAliases).toHaveBeenCalledWith({ body: { actions: [
      { remove: { index: retiring, alias: ALERTS_READ_ALIAS } },
      { remove: { index: retiring, alias: ALERTS_WRITE_ALIAS } },
      { add: { index: expect.stringMatching(/^wazuh-alert-status-v2-carry-/), alias: ALERTS_READ_ALIAS } },
    ] } });
    const preparingCall = c.index.mock.calls.findIndex(([args]: any[]) => args.body?.status === 'preparing');
    const preparing = c.index.mock.calls[preparingCall][0];
    expect(preparing).toEqual(expect.objectContaining({
      index: META_INDEX,
      id: `retirement:${retiring}`,
      op_type: 'create',
      refresh: 'wait_for',
      body: expect.objectContaining({
        retiring_index: retiring,
        carry_index: expect.stringMatching(/^wazuh-alert-status-v2-carry-\d{17}$/),
        holder_id: expect.stringMatching(/^[a-f0-9]{32}$/),
        expires_at: expect.any(String),
        plan: expect.objectContaining({ retiringIndex: retiring }),
      }),
    }));
    expect(c.index.mock.invocationCallOrder[preparingCall]).toBeLessThan(c.indices.create.mock.invocationCallOrder[0]);
  });

  test('unblocks the source when carry-forward fails before cutover', async () => {
    const c = client();
    c.bulk = jest.fn(async () => {
      throw new Error('bulk boom');
    });
    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow('bulk boom');
    expect(c.indices.putSettings).toHaveBeenCalledWith({ index: retiring, body: { 'index.blocks.write': false } });
  });

  test('rolls back a created evidence link with the archive write OCC tokens', async () => {
    const c = client();
    c.indices.updateAliases = jest.fn(async () => { throw new Error('cutover boom'); });
    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow('cutover boom');
    expect(c.delete).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-write',
      id: evidenceId('case-closed', 'c2'),
      if_seq_no: 10,
      if_primary_term: 2,
    }));
  });

  test('restores an existing evidence document only if the archived version is unchanged', async () => {
    const previous = {
      case_id: 'case-closed', alert_id: 'c2', relationship_state: 'linked',
      linked_at: '2026-01-01T00:00:00Z', snapshot: { exact: ['original'] },
    };
    const c = client();
    const baseGet = c.get;
    c.get = jest.fn(async (args: any) => args.index === EVIDENCE_READ_ALIAS
      ? { body: {
          _index: 'wazuh-alert-manager-v2-evidence-000001', _seq_no: 6, _primary_term: 2, _source: previous,
        } }
      : baseGet(args));
    c.indices.updateAliases = jest.fn(async () => { throw new Error('cutover boom'); });
    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow('cutover boom');
    expect(c.index).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-000001',
      id: evidenceId('case-closed', 'c2'),
      body: previous,
      if_seq_no: 10,
      if_primary_term: 2,
    }));
  });

  test('does not overwrite a concurrent evidence change when rollback conflicts', async () => {
    const rollbackConflict: any = new Error('rollback conflict');
    rollbackConflict.meta = { statusCode: 409 };
    const c = client({ delete: jest.fn(async () => { throw rollbackConflict; }) });
    c.indices.updateAliases = jest.fn(async () => { throw new Error('cutover boom'); });
    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow('cutover boom');
    expect(c.delete).toHaveBeenCalledWith(expect.objectContaining({ if_seq_no: 10, if_primary_term: 2 }));
    expect(noopLogger.error).toHaveBeenCalledWith(expect.stringContaining('rollback conflict'));
    expect(c.indices.delete).not.toHaveBeenCalled();
    expect(c.delete).not.toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX }));
  });

  test('rejects an existing preparing transaction instead of replaying it', async () => {
    const c = client();
    c.get = jest.fn(async ({ index }: any) => index === META_INDEX
      ? { body: { _source: { status: 'preparing' } } }
      : Promise.reject(new Error('unexpected read')));

    await expect(executeAlertRetirement(c, retiring, 'other', noopLogger as any)).rejects.toThrow(
      /already in progress/
    );
    expect(c.count).not.toHaveBeenCalled();
    expect(c.indices.putSettings).not.toHaveBeenCalled();
  });

  test('rejects a create conflict instead of adopting the winning claim', async () => {
    const c = client();
    c.index = jest.fn(async (args: any) => {
      if (args.op_type === 'create') throw { meta: { statusCode: 409 } };
      return { body: {} };
    });
    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow(
      /already in progress/
    );
    expect(c.indices.putSettings).not.toHaveBeenCalled();
  });

  test('cleans an ordinary failed claim so a retry replans current state', async () => {
    const c = client();
    c.bulk = jest.fn().mockRejectedValueOnce(new Error('bulk boom')).mockResolvedValue({
      body: { errors: false, items: [] },
    });

    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow('bulk boom');
    expect(c.indices.delete).toHaveBeenCalledWith(expect.objectContaining({
      index: expect.stringMatching(/^wazuh-alert-status-v2-carry-\d{17}$/),
    }));
    expect(c.delete).toHaveBeenCalledWith(expect.objectContaining({
      index: META_INDEX,
      id: `retirement:${retiring}`,
      if_seq_no: 10,
      if_primary_term: 2,
    }));

    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).resolves.toEqual(
      expect.objectContaining({ carriedDocuments: 2 })
    );
    expect(c.count).toHaveBeenCalledTimes(6);
  });

  test('rejects when the retiring source becomes a write-alias member after planning', async () => {
    const c = client();
    let writeReads = 0;
    c.indices.getAlias = jest.fn(async ({ name, index }: any) => {
      if (index) return { body: { [index]: { aliases: {} } } };
      if (name === ALERTS_READ_ALIAS) return { body: { [retiring]: {}, [write]: {} } };
      writeReads += 1;
      return writeReads === 1
        ? { body: { [write]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } } } }
        : { body: { [retiring]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } } } };
    });

    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow(
      /planned writer|topology/
    );
    expect(c.indices.putSettings).not.toHaveBeenCalledWith({
      index: retiring,
      body: { 'index.blocks.write': true },
    });
    expect(c.indices.updateAliases).not.toHaveBeenCalled();
    expect(c.delete).toHaveBeenCalledWith(expect.objectContaining({
      index: META_INDEX,
      id: `retirement:${retiring}`,
    }));
  });

  test('startup recovery finalizes post-cutover after the numeric writer advances', async () => {
    const first = client();
    let transaction: any;
    first.index = jest.fn(async (args: any) => {
      if (args.body?.status === 'preparing') transaction = args.body;
      return { body: { _seq_no: 10, _primary_term: 2 } };
    });
    first.bulk = jest.fn(async () => { throw new Error('checkpoint'); });
    await expect(executeAlertRetirement(first, retiring, 'analyst', noopLogger as any)).rejects.toThrow('checkpoint');
    transaction.status = 'recovering';
    transaction.expires_at = '2000-01-01T00:00:00.000Z';

    const recovered = client();
    const advancedWrite = 'wazuh-alert-status-v2-000003';
    recovered.indices.getAlias = jest.fn(async ({ name, index }: any) => index
      ? { body: { [index]: { aliases: { [ALERTS_READ_ALIAS]: {} } } } }
      : {
          body: name === ALERTS_READ_ALIAS
            ? { [transaction.carry_index]: {}, [advancedWrite]: {} }
            : { [advancedWrite]: { aliases: { [ALERTS_WRITE_ALIAS]: { is_write_index: true } } } },
        });
    recovered.search = jest.fn(async () => ({
      body: {
        hits: {
          total: { value: 1 },
          hits: [{ _id: `retirement:${retiring}`, _seq_no: 10, _primary_term: 2, _source: transaction }],
        },
      },
    }));

    await expect(recoverPreparingAlertRetirements(recovered, noopLogger as any)).resolves.toBe(1);
    expect(recovered.indices.create).not.toHaveBeenCalled();
    expect(recovered.bulk).not.toHaveBeenCalled();
    expect(recovered.indices.putSettings).not.toHaveBeenCalled();
    expect(recovered.indices.updateAliases).not.toHaveBeenCalled();
    expect(recovered.index).toHaveBeenCalledWith(expect.objectContaining({
      id: `retirement:${retiring}`,
      refresh: 'wait_for',
      body: expect.objectContaining({ status: 'completed', carry_index: transaction.carry_index }),
    }));
  });

  test('startup recovery fails closed when the preparing scan exceeds its bound', async () => {
    const c: any = {
      search: jest.fn(async () => ({ body: { hits: { total: { value: 101 }, hits: [] } } })),
    };
    await expect(recoverPreparingAlertRetirements(c, noopLogger as any)).rejects.toThrow(/safe scan limit/);
  });

  test('startup recovery aborts pre-cutover work and conditionally clears archive fields', async () => {
    const first = client();
    let transaction: any;
    first.index = jest.fn(async (args: any) => {
      if (args.body?.status === 'preparing') transaction = args.body;
      return { body: { _seq_no: 10, _primary_term: 2 } };
    });
    first.bulk = jest.fn(async () => { throw new Error('capture transaction'); });
    await expect(executeAlertRetirement(first, retiring, 'analyst', noopLogger as any)).rejects.toThrow(
      'capture transaction'
    );
    transaction.status = 'recovering';
    transaction.expires_at = '2000-01-01T00:00:00.000Z';

    const recovering = client();
    const baseGet = recovering.get;
    recovering.get = jest.fn(async (args: any) => args.index === EVIDENCE_READ_ALIAS
      ? { body: {
          _index: 'wazuh-alert-manager-v2-evidence-000001',
          _seq_no: 7,
          _primary_term: 3,
          _source: {
            relationship_state: 'held', hold_reason: 'legal', snapshot: { stable: true },
            archive_index: retiring, archive_id: 'c2', archived_at: '2026-08-29T00:00:00Z',
          },
        } }
      : baseGet(args));
    recovering.search = jest.fn(async () => ({ body: { hits: {
      total: { value: 1 },
      hits: [{ _id: `retirement:${retiring}`, _seq_no: 10, _primary_term: 2, _source: transaction }],
    } } }));

    await expect(recoverPreparingAlertRetirements(recovering, noopLogger as any)).resolves.toBe(1);
    expect(recovering.index).toHaveBeenCalledWith(expect.objectContaining({
      if_seq_no: 10,
      if_primary_term: 2,
      body: expect.objectContaining({ status: 'recovering', holder_id: expect.any(String) }),
    }));
    expect(recovering.indices.putSettings).toHaveBeenCalledWith({
      index: retiring,
      body: { 'index.blocks.write': false },
    });
    expect(recovering.update).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-evidence-000001',
      if_seq_no: 7,
      if_primary_term: 3,
      body: { script: expect.objectContaining({ params: { archive_index: retiring, archive_id: 'c2' } }) },
    }));
    const cleanupScript = recovering.update.mock.calls[0][0].body.script.source;
    expect(cleanupScript).not.toContain('snapshot =');
    expect(cleanupScript).not.toContain('hold_reason =');
    expect(recovering.indices.create).not.toHaveBeenCalled();
    expect(recovering.bulk).not.toHaveBeenCalled();
    expect(recovering.indices.delete).toHaveBeenCalled();
    expect(recovering.delete).toHaveBeenCalledWith(expect.objectContaining({
      index: META_INDEX, id: `retirement:${retiring}`, if_seq_no: 10, if_primary_term: 2,
    }));
  });

  test('startup abort accepts evidence, carry, and claim 404 races idempotently', async () => {
    const seed = client();
    let transaction: any;
    seed.index = jest.fn(async (args: any) => {
      if (args.body?.status === 'preparing') transaction = args.body;
      return { body: { _seq_no: 10, _primary_term: 2 } };
    });
    seed.bulk = jest.fn(async () => { throw new Error('capture'); });
    await expect(executeAlertRetirement(seed, retiring, 'analyst', noopLogger as any)).rejects.toThrow('capture');
    transaction.status = 'recovering';
    transaction.expires_at = '2000-01-01T00:00:00.000Z';

    const missing: any = new Error('gone');
    missing.meta = { statusCode: 404 };
    const recovering = client();
    recovering.get = jest.fn(async ({ index }: any) => {
      if (index === EVIDENCE_READ_ALIAS) throw missing;
      throw missing;
    });
    recovering.indices.delete = jest.fn(async () => { throw missing; });
    recovering.delete = jest.fn(async () => { throw missing; });
    recovering.search = jest.fn(async () => ({ body: { hits: {
      total: { value: 1 },
      hits: [{ _id: `retirement:${retiring}`, _seq_no: 10, _primary_term: 2, _source: transaction }],
    } } }));

    await expect(recoverPreparingAlertRetirements(recovering, noopLogger as any)).resolves.toBe(1);
  });

  test('first expired preparing takeover only enters quiescence without operational mutations', async () => {
    const seed = client();
    let transaction: any;
    seed.index = jest.fn(async (args: any) => {
      if (args.op_type === 'create') transaction = args.body;
      return { body: { _seq_no: 10, _primary_term: 2 } };
    });
    seed.bulk = jest.fn(async () => { throw new Error('capture'); });
    await expect(executeAlertRetirement(seed, retiring, 'analyst', noopLogger as any)).rejects.toThrow('capture');
    transaction.expires_at = '2000-01-01T00:00:00.000Z';

    const recovering = client();
    recovering.search = jest.fn(async () => ({ body: { hits: {
      total: { value: 1 },
      hits: [{ _id: `retirement:${retiring}`, _seq_no: 10, _primary_term: 2, _source: transaction }],
    } } }));

    const takeoverStartedAt = Date.now();
    await expect(recoverPreparingAlertRetirements(recovering, noopLogger as any)).resolves.toBe(1);
    expect(recovering.index).toHaveBeenCalledTimes(1);
    expect(recovering.index).toHaveBeenCalledWith(expect.objectContaining({
      if_seq_no: 10,
      if_primary_term: 2,
      body: expect.objectContaining({
        status: 'recovering',
        holder_id: expect.any(String),
        expires_at: expect.any(String),
      }),
    }));
    const recoveringRecord = recovering.index.mock.calls[0][0].body;
    expect(recoveringRecord.holder_id).not.toBe(transaction.holder_id);
    expect(Date.parse(recoveringRecord.expires_at)).toBeGreaterThanOrEqual(takeoverStartedAt + 2 * 60 * 1000);
    expect(recovering.indices.getAlias).not.toHaveBeenCalled();
    expect(recovering.indices.putSettings).not.toHaveBeenCalled();
    expect(recovering.indices.delete).not.toHaveBeenCalled();
    expect(recovering.update).not.toHaveBeenCalled();
    expect(recovering.delete).not.toHaveBeenCalled();
  });

  test('startup recovery skips an active preparing lease without inspecting aliases', async () => {
    const seed = client();
    let transaction: any;
    seed.index = jest.fn(async (args: any) => {
      if (args.op_type === 'create') transaction = args.body;
      return { body: { _seq_no: 10, _primary_term: 2 } };
    });
    seed.bulk = jest.fn(async () => { throw new Error('capture'); });
    await expect(executeAlertRetirement(seed, retiring, 'analyst', noopLogger as any)).rejects.toThrow('capture');
    transaction.expires_at = '2999-01-01T00:00:00.000Z';

    const recovering = client();
    recovering.search = jest.fn(async () => ({ body: { hits: {
      total: { value: 1 },
      hits: [{ _id: `retirement:${retiring}`, _seq_no: 10, _primary_term: 2, _source: transaction }],
    } } }));

    await expect(recoverPreparingAlertRetirements(recovering, noopLogger as any)).resolves.toBe(0);
    expect(recovering.indices.getAlias).not.toHaveBeenCalled();
    expect(recovering.index).not.toHaveBeenCalled();
  });

  test('takes over a stale recovering lease and completes its pre-cutover abort', async () => {
    const seed = client();
    let transaction: any;
    seed.index = jest.fn(async (args: any) => {
      if (args.op_type === 'create') transaction = args.body;
      return { body: { _seq_no: 10, _primary_term: 2 } };
    });
    seed.bulk = jest.fn(async () => { throw new Error('capture'); });
    await expect(executeAlertRetirement(seed, retiring, 'analyst', noopLogger as any)).rejects.toThrow('capture');
    transaction = {
      ...transaction,
      status: 'recovering',
      holder_id: 'dead-recovery',
      expires_at: '2000-01-01T00:00:00.000Z',
    };

    const recovering = client();
    recovering.search = jest.fn(async () => ({ body: { hits: {
      total: { value: 1 },
      hits: [{ _id: `retirement:${retiring}`, _seq_no: 10, _primary_term: 2, _source: transaction }],
    } } }));

    await expect(recoverPreparingAlertRetirements(recovering, noopLogger as any)).resolves.toBe(1);
    expect(recovering.index).toHaveBeenCalledWith(expect.objectContaining({
      if_seq_no: 10,
      if_primary_term: 2,
      body: expect.objectContaining({
        status: 'recovering',
        holder_id: expect.not.stringMatching(/^dead-recovery$/),
        expires_at: expect.any(String),
      }),
    }));
  });

  test('stops mutating when the active worker loses its lease before alias cutover', async () => {
    const c = client();
    let evidenceRefreshed = false;
    let seqNo = 0;
    c.indices.refresh = jest.fn(async ({ index }: any) => {
      if (index === 'wazuh-alert-manager-v2-evidence-write') evidenceRefreshed = true;
      return {};
    });
    c.index = jest.fn(async (args: any) => {
      if (args.if_seq_no !== undefined && args.body?.status === 'preparing' && evidenceRefreshed) {
        throw { meta: { statusCode: 409 } };
      }
      seqNo += 1;
      return { body: { _seq_no: seqNo, _primary_term: 2 } };
    });

    await expect(executeAlertRetirement(c, retiring, 'analyst', noopLogger as any)).rejects.toThrow(
      /lease ownership/
    );
    expect(c.indices.updateAliases).not.toHaveBeenCalled();
    expect(c.delete).not.toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX }));
  });

  test('periodic recovery runs immediately and stops its minute timer', async () => {
    jest.useFakeTimers();
    const c: any = { search: jest.fn(async () => ({ body: { hits: { total: { value: 0 }, hits: [] } } })) };
    const stop = startRetirementRecoveryJob(c, noopLogger as any);
    expect(c.search).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(60 * 1000);
    expect(c.search).toHaveBeenCalledTimes(2);
    stop();
    jest.advanceTimersByTime(60 * 1000);
    expect(c.search).toHaveBeenCalledTimes(2);
    jest.useRealTimers();
  });
});

describe('restoreRetiredAlertIndex', () => {
  test('restores only missing IDs and treats 409 conflicts as already-live', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const archiveDocs = [
      { _id: 'a', _source: { status: 'closed' } },
      { _id: 'b', _source: { status: 'closed' } },
      { _id: 'c', _source: { status: 'closed' } },
    ];
    const client: any = {
      indices: { getAlias: jest.fn(async () => ({ body: {} })), refresh: jest.fn(async () => ({})) },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
      search: jest.fn(async (args: any) => {
        if (args.scroll) return { body: { _scroll_id: 's1', hits: { hits: archiveDocs } } };
        return { body: { hits: { hits: [{ _id: 'a' }] } } };
      }),
      scroll: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({
        body: { errors: false, items: [{ create: { status: 201 } }, { create: { status: 409 } }] },
      })),
      index: jest.fn(async () => ({})),
    };
    const result = await restoreRetiredAlertIndex(client, index, 'analyst');
    expect(result.restored).toBe(1);
    expect(result.alreadyLive).toBe(2);
    expect(result.archiveRetained).toBe(true);
  });

  test('is idempotent when every archive ID is already live', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const bulk = jest.fn(async () => ({ body: { errors: false, items: [] } }));
    const client: any = {
      indices: { getAlias: jest.fn(async () => ({ body: {} })), refresh: jest.fn(async () => ({})) },
      get: jest.fn(async () => ({ body: { _source: { status: 'restored', retiring_index: index } } })),
      search: jest.fn(async (args: any) => {
        if (args.scroll) return { body: { _scroll_id: 's1', hits: { hits: [{ _id: 'a', _source: {} }] } } };
        return { body: { hits: { hits: [{ _id: 'a' }] } } };
      }),
      scroll: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk,
      index: jest.fn(async () => ({})),
    };
    const result = await restoreRetiredAlertIndex(client, index, 'analyst');
    expect(result.restored).toBe(0);
    expect(result.alreadyLive).toBe(1);
    expect(bulk).not.toHaveBeenCalled();
  });

  test('fails cleanly when no completed retirement record exists', async () => {
    const client: any = {
      indices: { getAlias: jest.fn(async () => ({ body: {} })) },
      get: jest.fn(async () => {
        const e: any = new Error('not_found');
        e.meta = { statusCode: 404 };
        throw e;
      }),
    };
    await expect(restoreRetiredAlertIndex(client, 'wazuh-alert-status-v2-000001', 'analyst')).rejects.toThrow(
      /No completed retirement record/
    );
  });
});

describe('purgeRetiredAlertIndex', () => {
  test('refuses an index still attached to a live alias', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const client: any = {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => ({
          body: name === ALERTS_READ_ALIAS ? { [index]: {} } : {},
        })),
        getSettings: jest.fn(async () => ({ body: {} })),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
    };
    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).rejects.toThrow(/still attached/);
  });

  test('refuses an archive that is not write-blocked', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({ body: { [index]: { settings: { index: { blocks: {} } } } } })),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
    };
    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).rejects.toThrow(/not write-blocked/);
  });

  test('purges a write-blocked, detached, recorded archive', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const deleteFn = jest.fn(async () => ({ body: {} }));
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({
          body: {
            [index]: { settings: { index: { blocks: { write: 'true' } } } },
          },
        })),
        delete: deleteFn,
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
      search: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      index: jest.fn(async () => ({})),
    };
    const result = await purgeRetiredAlertIndex(client, index, 'analyst');
    expect(deleteFn).toHaveBeenCalledWith({ index });
    expect(result.purged).toBe(true);
  });

  test('creates and verifies every alert tombstone before deleting the archive', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const archiveHits = [{ _id: 'a1' }, { _id: 'a2' }];
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({
          body: { [index]: { settings: { index: { blocks: { write: 'true' } } } } },
        })),
        delete: jest.fn(async () => ({ body: {} })),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
      search: jest.fn(async (args: any) => args.index === index
        ? { body: { _scroll_id: 'archive-scroll', hits: { hits: archiveHits } } }
        : { body: { hits: { hits: [] } } }),
      scroll: jest.fn(async () => ({ body: { _scroll_id: 'archive-scroll', hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { items: [
        { create: { status: 201 } }, { create: { status: 201 } },
      ] } })),
      mget: jest.fn(async () => ({ body: { docs: archiveHits.map((hit) => ({
        _id: `retired-alert:${hit._id}`,
        found: true,
        _source: { document_type: 'retired_alert', alert_uid: hit._id, retiring_index: index },
      })) } })),
      index: jest.fn(async () => ({})),
    };

    await purgeRetiredAlertIndex(client, index, 'analyst');

    expect(client.bulk).toHaveBeenCalledWith(expect.objectContaining({
      refresh: 'wait_for',
      body: expect.arrayContaining([
        { create: { _index: META_INDEX, _id: 'retired-alert:a1' } },
        expect.objectContaining({ document_type: 'retired_alert', alert_uid: 'a1', retiring_index: index }),
      ]),
    }));
    expect(client.mget.mock.invocationCallOrder[0]).toBeLessThan(client.indices.delete.mock.invocationCallOrder[0]);
    expect(client.indices.delete).toHaveBeenCalledWith({ index });
  });

  test('retries partial tombstone progress idempotently through create conflicts', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({
          body: { [index]: { settings: { index: { blocks: { write: 'true' } } } } },
        })),
        delete: jest.fn(async () => ({})),
      },
      get: jest.fn(async () => ({ body: { _source: {
        status: 'purging', retiring_index: index, purge_started_at: '2026-08-28T10:00:00.000Z',
      } } })),
      search: jest.fn(async (args: any) => args.index === index
        ? { body: { _scroll_id: 'archive-scroll', hits: { hits: [{ _id: 'already-done' }, { _id: 'remaining' }] } } }
        : { body: { hits: { hits: [] } } }),
      scroll: jest.fn(async () => ({ body: { _scroll_id: 'archive-scroll', hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { errors: true, items: [
        { create: { status: 409, error: { type: 'version_conflict_engine_exception' } } },
        { create: { status: 201 } },
      ] } })),
      mget: jest.fn(async () => ({ body: { docs: [
        {
          _id: 'retired-alert:already-done', found: true,
          _source: { document_type: 'retired_alert', alert_uid: 'already-done', retiring_index: index },
        },
        {
          _id: 'retired-alert:remaining', found: true,
          _source: { document_type: 'retired_alert', alert_uid: 'remaining', retiring_index: index },
        },
      ] } })),
      index: jest.fn(async () => ({})),
    };

    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).resolves.toMatchObject({ purged: true });
    expect(client.indices.delete).toHaveBeenCalledWith({ index });
  });

  test('does not delete the archive when tombstone bulk evidence is incomplete', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({
          body: { [index]: { settings: { index: { blocks: { write: 'true' } } } } },
        })),
        delete: jest.fn(async () => ({})),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
      search: jest.fn(async (args: any) => args.index === index
        ? { body: { _scroll_id: 'archive-scroll', hits: { hits: [{ _id: 'a1' }, { _id: 'a2' }] } } }
        : { body: { hits: { hits: [] } } }),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { items: [{ create: { status: 201 } }] } })),
      index: jest.fn(async () => ({})),
    };

    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).rejects.toThrow(/incomplete item response/);
    expect(client.indices.delete).not.toHaveBeenCalled();
  });

  test('refuses purge while archived evidence is held', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({
          body: { [index]: { settings: { index: { blocks: { write: 'true' } } } } },
        })),
        delete: jest.fn(async () => ({})),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
      search: jest.fn(async () => ({ body: { hits: { hits: [{
        _id: 'e1', _index: 'wazuh-alert-manager-v2-evidence-000001', _source: { hold_reason: 'legal' },
      }] } } })),
    };
    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).rejects.toThrow(/evidence holds/);
    expect(client.indices.delete).not.toHaveBeenCalled();
  });

  test('finds a hold after the first 1000 archive references', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const hits = (offset: number, count: number) => Array.from({ length: count }, (_, i) => ({
      _id: `e${offset + i}`,
      _index: 'wazuh-alert-manager-v2-evidence-000001',
      _source: offset + i === 1000 ? { hold_reason: 'legal' } : {},
    }));
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => ({
          body: {
            [index]: { settings: { index: { blocks: { write: 'true' } } } },
          },
        })),
        delete: jest.fn(async () => ({})),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
      search: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: hits(0, 500) } } })),
      scroll: jest
        .fn()
        .mockResolvedValueOnce({ body: { _scroll_id: 's1', hits: { hits: hits(500, 500) } } })
        .mockResolvedValueOnce({ body: { _scroll_id: 's1', hits: { hits: hits(1000, 1) } } }),
      clearScroll: jest.fn(async () => ({})),
    };
    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).rejects.toThrow(/evidence holds/);
    expect(client.scroll).toHaveBeenCalledTimes(2);
    expect(client.indices.delete).not.toHaveBeenCalled();
  });

  test('refuses any write-alias member, even when it is not marked writer', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const client: any = {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => ({
          body: name === ALERTS_WRITE_ALIAS ? { [index]: { aliases: { [ALERTS_WRITE_ALIAS]: {} } } } : {},
        })),
      },
      get: jest.fn(async () => ({ body: { _source: { status: 'completed', retiring_index: index } } })),
    };
    await expect(purgeRetiredAlertIndex(client, index, 'analyst')).rejects.toThrow(/live alias/);
  });

  test('resumes evidence marking after the archive was already deleted and validates bulk items', async () => {
    const index = 'wazuh-alert-status-v2-000001';
    const evidenceIndex = 'wazuh-alert-manager-v2-evidence-000001';
    const notFound: any = new Error('not found');
    notFound.meta = { statusCode: 404 };
    const client: any = {
      indices: {
        getAlias: jest.fn(async () => ({ body: {} })),
        getSettings: jest.fn(async () => { throw notFound; }),
        delete: jest.fn(async () => ({})),
        refresh: jest.fn(async () => ({})),
      },
      get: jest.fn(async () => ({
        body: { _source: { status: 'purging', retiring_index: index, evidence_references: 1 } },
      })),
      search: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: [{
        _id: 'e1', _index: evidenceIndex, _source: { archive_index: index, relationship_state: 'archived' },
      }] } } })),
      scroll: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { items: [{ index: { status: 200 } }] } })),
      index: jest.fn(async () => ({})),
    };
    const result = await purgeRetiredAlertIndex(client, index, 'analyst');
    expect(client.indices.delete).not.toHaveBeenCalled();
    expect(client.bulk.mock.calls[0][0].body[0]).toEqual({ index: { _index: evidenceIndex, _id: 'e1' } });
    expect(result).toEqual({ index, purged: true, evidenceUpdated: 1 });
  });
});
