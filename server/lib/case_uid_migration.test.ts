import { CASES_WRITE_ALIAS } from '../../common';
import { backfillCaseUids } from './case_uid_migration';

describe('case UID migration', () => {
  test('backfills the document ID into the stable mapped sort field', async () => {
    const updateByQuery = jest.fn().mockResolvedValue({
      body: { total: 2, updated: 2, version_conflicts: 0, failures: [], timed_out: false },
    });
    const count = jest.fn().mockResolvedValue({ body: { count: 0 } });

    await backfillCaseUids({ updateByQuery, count });

    expect(updateByQuery).toHaveBeenCalledWith(expect.objectContaining({
      index: CASES_WRITE_ALIAS,
      conflicts: 'proceed',
      refresh: true,
      body: expect.objectContaining({
        query: { bool: { must_not: [{ exists: { field: 'case_uid' } }] } },
        script: { lang: 'painless', source: 'ctx._source.case_uid = ctx._id' },
      }),
    }));
    expect(count).toHaveBeenCalledWith({
      index: CASES_WRITE_ALIAS,
      body: { query: { bool: { must_not: [{ exists: { field: 'case_uid' } }] } } },
    });
  });

  test('retries repeated equal verification counts until a later pass converges', async () => {
    const client = {
      updateByQuery: jest.fn().mockResolvedValue({
        body: { total: 1, updated: 0, version_conflicts: 1, failures: [], timed_out: false },
      }),
      count: jest.fn()
        .mockResolvedValueOnce({ body: { count: 1 } })
        .mockResolvedValueOnce({ body: { count: 1 } })
        .mockResolvedValueOnce({ body: { count: 1 } })
        .mockResolvedValueOnce({ body: { count: 0 } }),
    };

    await backfillCaseUids(client);

    expect(client.updateByQuery).toHaveBeenCalledTimes(4);
    expect(client.count).toHaveBeenCalledTimes(4);
  });

  test('fails persistent non-progress only after all bounded passes are exhausted', async () => {
    const client = {
      updateByQuery: jest.fn().mockResolvedValue({
        body: { total: 1, updated: 0, version_conflicts: 1, failures: [], timed_out: false },
      }),
      count: jest.fn().mockResolvedValue({ body: { count: 1 } }),
    };

    await expect(backfillCaseUids(client)).rejects.toThrow('exhausted 5 passes');
    expect(client.updateByQuery).toHaveBeenCalledTimes(5);
    expect(client.count).toHaveBeenCalledTimes(5);
  });

  test('fails closed when an update times out', async () => {
    const client = {
      updateByQuery: jest.fn().mockResolvedValue({ body: { timed_out: true, failures: [] } }),
      count: jest.fn(),
    };

    await expect(backfillCaseUids(client)).rejects.toThrow('timed out true');
    expect(client.count).not.toHaveBeenCalled();
  });

  test('fails closed when an update reports failures', async () => {
    const client = {
      updateByQuery: jest.fn().mockResolvedValue({
        body: { timed_out: false, failures: [{ cause: { reason: 'write failed' } }] },
      }),
      count: jest.fn(),
    };

    await expect(backfillCaseUids(client)).rejects.toThrow('failures 1');
    expect(client.count).not.toHaveBeenCalled();
  });

  test('fails closed when verification returns an invalid count', async () => {
    const client = {
      updateByQuery: jest.fn().mockResolvedValue({
        body: { timed_out: false, failures: [] },
      }),
      count: jest.fn().mockResolvedValue({ body: { count: 'invalid' } }),
    };

    await expect(backfillCaseUids(client)).rejects.toThrow('invalid count');
    expect(client.updateByQuery).toHaveBeenCalledTimes(1);
    expect(client.count).toHaveBeenCalledTimes(1);
  });

  test('fails closed when bounded passes are exhausted', async () => {
    const client = {
      updateByQuery: jest.fn().mockResolvedValue({
        body: { total: 1, updated: 1, version_conflicts: 0, failures: [], timed_out: false },
      }),
      count: jest.fn()
        .mockResolvedValueOnce({ body: { count: 5 } })
        .mockResolvedValueOnce({ body: { count: 4 } })
        .mockResolvedValueOnce({ body: { count: 3 } })
        .mockResolvedValueOnce({ body: { count: 2 } })
        .mockResolvedValueOnce({ body: { count: 1 } }),
    };

    await expect(backfillCaseUids(client)).rejects.toThrow('exhausted 5 passes');
    expect(client.updateByQuery).toHaveBeenCalledTimes(5);
  });
});
