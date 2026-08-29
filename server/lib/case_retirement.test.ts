import {
  planCaseRetirement,
  executeCaseRetirement,
  listArchivedCaseGenerations,
  reopenArchivedCase,
} from './case_retirement';
import { CASES_READ_ALIAS, CASES_WRITE_ALIAS, META_INDEX } from '../../common';

const index = 'wazuh-alert-manager-v2-cases-000001';
const writeAlias = CASES_WRITE_ALIAS;

function caseHit(id: string, source: any) {
  return { _id: id, _source: source };
}

function scrollClient(hits: any[]) {
  return {
    search: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits } } })),
    scroll: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: [] } } })),
    clearScroll: jest.fn(async () => ({})),
  };
}

describe('case retirement planning', () => {
  test('carries active and recently-closed cases and archives expired closed ones', async () => {
    const recent = new Date(Date.now() - 10 * 86400000).toISOString();
    const expired = new Date(Date.now() - 400 * 86400000).toISOString();
    const client = scrollClient([
      caseHit('open-1', { status: 'open' }),
      caseHit('ip-1', { status: 'in_progress' }),
      caseHit('recent-closed', { status: 'closed', closed_at: recent }),
      caseHit('expired-closed', { status: 'closed', closed_at: expired }),
      caseHit('closed-no-date', { status: 'closed' }),
    ]);

    const plan = await planCaseRetirement(client, index, 365);

    expect(plan.active).toBe(2);
    expect(plan.recentClosed).toBe(1);
    expect(plan.expiredClosed).toBe(2);
    expect(plan.carryIds.sort()).toEqual(['ip-1', 'open-1', 'recent-closed'].sort());
    expect(plan.archiveIds.sort()).toEqual(['closed-no-date', 'expired-closed'].sort());
  });

  test('refuses a non-case index', async () => {
    const client = scrollClient([]);
    await expect(planCaseRetirement(client, 'wazuh-alert-status-v2-000001', 365)).rejects.toThrow('non-case index');
  });
});

describe('case retirement execution', () => {
  function executionClient(carryIds: string[]) {
    return {
      indices: {
        getAlias: jest.fn(async ({ name }: any) => ({
          body: name === CASES_READ_ALIAS ? { [index]: {} } : {
            [index]: { aliases: { [CASES_WRITE_ALIAS]: { is_write_index: false } } },
            'wazuh-alert-manager-v2-cases-000002': { aliases: { [CASES_WRITE_ALIAS]: { is_write_index: true } } },
          },
        })),
        putSettings: jest.fn(async () => ({})),
        updateAliases: jest.fn(async () => ({})),
      },
      search: jest.fn(async () => ({
        body: { _scroll_id: 's1', hits: { hits: carryIds.map((id) => ({ _id: id, _source: { status: 'open', case_uid: id } })) } },
      })),
      scroll: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { errors: false, items: carryIds.map(() => ({ update: { status: 201 } })) } })),
      index: jest.fn(async () => ({})),
    };
  }

  test('carries active cases into the writer, detaches, and records the retirement', async () => {
    const client: any = executionClient(['active-1']);
    const result = await executeCaseRetirement(client, index, 'admin', 365);

    expect(result).toEqual({ retiringIndex: index, carried: 1, archived: 0, failed: 0 });
    expect(client.bulk).toHaveBeenCalled();
    expect(client.bulk.mock.calls[0][0].body[0]).toEqual({ update: { _index: writeAlias, _id: 'active-1' } });
    expect(client.bulk.mock.calls[0][0].refresh).toBe('wait_for');
    expect(client.indices.updateAliases).toHaveBeenCalledWith({
      body: { actions: [
        { remove: { index, alias: CASES_READ_ALIAS } },
        { remove: { index, alias: CASES_WRITE_ALIAS } },
      ] },
    });
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      index: META_INDEX, id: `case-retirement:${index}`,
    }));
  });

  test('refuses to retire the current write generation', async () => {
    const client: any = {
      indices: {
        // `index` is a read member AND the sole write target.
        getAlias: jest.fn(async ({ name }: any) => ({ body: {
          [index]: { aliases: name === CASES_WRITE_ALIAS
            ? { [CASES_WRITE_ALIAS]: { is_write_index: true } } : {} },
        } })),
        updateAliases: jest.fn(),
      },
      search: jest.fn(),
      scroll: jest.fn(),
      clearScroll: jest.fn(),
      bulk: jest.fn(),
      index: jest.fn(),
    };
    await expect(executeCaseRetirement(client, index, 'admin', 365)).rejects.toThrow('Cannot retire');
  });
});

describe('archived cases and reopen', () => {
  test('reopens an archived case into the writer with status open', async () => {
    const archived = { _source: { case_uid: 'c1', title: 'old', status: 'closed', closed_at: '2026-01-01T00:00:00Z', history: [] } };
    const client: any = {
      search: jest.fn(async () => ({ body: { hits: { hits: [{ _id: `case-retirement:${index}`, _source: { retiring_index: index, status: 'retired' } }] } } })),
      count: jest.fn(async () => ({ body: { count: 1 } })),
      get: jest.fn(async () => ({ body: { found: true, _source: archived._source } })),
      create: jest.fn(async () => ({})),
      index: jest.fn(async () => ({})),
    };

    const reopened = await reopenArchivedCase(client, 'c1', 'admin');

    expect(reopened.status).toBe('open');
    expect(reopened.closed_at).toBeNull();
    expect(client.create).toHaveBeenCalledWith(expect.objectContaining({
      index: writeAlias, id: 'c1', body: expect.objectContaining({ status: 'open' }),
    }));
  });

  test('lists archived case generations', async () => {
    const client: any = {
      search: jest.fn(async () => ({
        body: { hits: { hits: [{ _id: `case-retirement:${index}`, _source: { retiring_index: index, status: 'retired', carried: 2, archived: 3 } }] } },
      })),
      count: jest.fn(async () => ({ body: { count: 3 } })),
    };

    const generations = await listArchivedCaseGenerations(client);
    expect(generations).toEqual([expect.objectContaining({ index, carried: 2, archived: 3, documents: 3 })]);
  });
});
