import { migrateCaseAliases } from './case_alias_migration';
import { CASES_WRITE_ALIAS, CASES_V2_SINGLETON_INDEX, META_INDEX } from '../../common';

const logger: any = { info: jest.fn(), error: jest.fn() };

describe('cases alias migration', () => {
  beforeEach(() => jest.clearAllMocks());

  test('is a no-op once the completion marker is present', async () => {
    const client = {
      get: jest.fn(async () => ({ body: { _source: { completed: true } } })),
      indices: { exists: jest.fn() },
      search: jest.fn(),
      scroll: jest.fn(),
      clearScroll: jest.fn(),
      bulk: jest.fn(),
      index: jest.fn(),
    };
    await expect(migrateCaseAliases(client, logger)).resolves.toBe(0);
    expect(client.search).not.toHaveBeenCalled();
    expect(client.indices.exists).not.toHaveBeenCalled();
  });

  test('copies singleton docs into the write alias and marks completion', async () => {
    const client = {
      get: jest.fn(async () => { const e: any = new Error('missing'); e.meta = { statusCode: 404 }; throw e; }),
      indices: { exists: jest.fn(async () => ({ body: true })) },
      search: jest.fn(async () => ({
        body: { _scroll_id: 's1', hits: { hits: [{ _id: 'c1', _source: { case_uid: 'c1' } }, { _id: 'c2', _source: { case_uid: 'c2' } }] } },
      })),
      scroll: jest.fn(async () => ({ body: { _scroll_id: 's1', hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { errors: false, items: [{ update: { status: 201 } }, { update: { status: 201 } }] } })),
      index: jest.fn(async () => ({})),
    };

    await expect(migrateCaseAliases(client, logger)).resolves.toBe(2);

    const bulk = client.bulk.mock.calls[0][0].body;
    expect(bulk[0]).toEqual({ update: { _index: CASES_WRITE_ALIAS, _id: 'c1' } });
    expect(bulk[2]).toEqual({ update: { _index: CASES_WRITE_ALIAS, _id: 'c2' } });
    expect(client.search.mock.calls[0][0].index).toBe(CASES_V2_SINGLETON_INDEX);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      index: META_INDEX, id: 'cases_alias_migration', body: expect.objectContaining({ completed: true, migrated: 2 }),
    }));
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 's1' });
  });

  test('fails closed when a bulk item errors', async () => {
    const client = {
      get: jest.fn(async () => { const e: any = new Error('missing'); e.meta = { statusCode: 404 }; throw e; }),
      indices: { exists: jest.fn(async () => ({ body: true })) },
      search: jest.fn(async () => ({
        body: { _scroll_id: 's1', hits: { hits: [{ _id: 'c1', _source: { case_uid: 'c1' } }] } },
      })),
      scroll: jest.fn(async () => ({ body: { hits: { hits: [] } } })),
      clearScroll: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { errors: true, items: [{ update: { status: 500, error: { reason: 'boom' } } }] } })),
      index: jest.fn(),
    };

    await expect(migrateCaseAliases(client, logger)).rejects.toThrow('failed to migrate');
    expect(client.index).not.toHaveBeenCalled();
  });
});
