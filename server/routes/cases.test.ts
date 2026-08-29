import { API_ROOT, CASES_INDEX } from '../../common';
import { bulkUpdateCases, closeCaseAndLinkedAlerts, defineCaseRoutes } from './cases';

const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';
const caseSearch = (docs: any[]) => jest.fn(async () => ({ body: { hits: { hits: docs
  .filter((doc) => doc.found !== false)
  .map((doc) => ({ _id: doc._id, _index: CASE_INDEX, _source: doc._source || {} })) } } }));

describe('bulk case update', () => {
  test('uses partial updates on the managed case target with actor attribution', async () => {
    const client = {
      search: caseSearch([
        { _id: 'c1', found: true, _source: { assigned_to: null } },
        { _id: 'c2', found: true, _source: { assigned_to: 'tier-1' } },
      ]),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }, { update: { status: 200 } }] } })),
      index: jest.fn(async () => ({})),
    };
    const result = await bulkUpdateCases(client, {
      ids: ['c1', 'c2'], actor: 'analyst', assignedTo: 'tier-2', timestamp: '2026-08-28T00:00:00Z',
    });

    expect(result).toEqual({
      requested: 2, updated: 2, failed: 0,
      results: [{ id: 'c1', ok: true }, { id: 'c2', ok: true }],
    });
    const request = client.bulk.mock.calls[0][0];
    expect(request.refresh).toBe('wait_for');
    expect(request.body[0]).toEqual({ update: { _index: CASE_INDEX, _id: 'c1' } });
    expect(request.body[2]).toEqual({ update: { _index: CASE_INDEX, _id: 'c2' } });
    expect(request.body[1].script.params).toEqual(expect.objectContaining({
      fields: { assigned_to: 'tier-2', updated_at: '2026-08-28T00:00:00Z', updated_by: 'analyst' },
      entry: expect.objectContaining({ user: 'analyst', action: 'assignment_change' }),
    }));
    expect(client.index).toHaveBeenCalledTimes(2);
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      body: expect.objectContaining({ target_type: 'case', target_id: 'c1', user: 'analyst', action: 'assignment_change', from: null, to: 'tier-2' }),
    }));
  });

  test('returns validated per-item partial outcomes', async () => {
    const client = {
      search: caseSearch([
        { _id: 'c1', found: true, _source: { status: 'open' } },
        { _id: 'missing', found: false },
        { _id: 'invalid', found: true, _source: { status: 'open' } },
      ]),
      bulk: jest.fn(async () => ({
        body: {
          items: [
            { update: { status: 200 } },
            { update: { status: 404, error: { reason: 'case not found' } } },
            { unexpected: { status: 200 } },
          ],
        },
      })),
      index: jest.fn(async () => ({})),
    };

    await expect(bulkUpdateCases(client, {
      ids: ['c1', 'missing', 'invalid'], actor: 'analyst', status: 'in_progress',
    })).resolves.toEqual({
      requested: 3, updated: 1, failed: 2,
      results: [
        { id: 'c1', ok: true },
        { id: 'missing', ok: false, error: 'case not found' },
        { id: 'invalid', ok: false, error: 'Bulk item returned unknown' },
      ],
    });
  });

  test('does not claim success for a malformed bulk response', async () => {
    const client = {
      search: caseSearch([]),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }] } })),
    };
    const result = await bulkUpdateCases(client, { ids: ['c1', 'c2'], actor: 'analyst', assignedTo: null });

    expect(result.updated).toBe(0);
    expect(result.results).toEqual([
      { id: 'c1', ok: false, error: 'Invalid bulk response item count.' },
      { id: 'c2', ok: false, error: 'Invalid bulk response item count.' },
    ]);
  });

  test('reports an audit failure without hiding the applied mutation', async () => {
    const client = {
      search: caseSearch([
        { _id: 'c1', found: true, _source: { status: 'open' } },
        { _id: 'c2', found: true, _source: { status: 'open' } },
      ]),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }, { update: { status: 200 } }] } })),
      index: jest.fn(async ({ body }: any) => {
        if (body.target_id === 'c2') throw new Error('activity index unavailable');
      }),
    };

    await expect(bulkUpdateCases(client, {
      ids: ['c1', 'c2'], actor: 'analyst', status: 'in_progress', timestamp: '2026-08-28T00:00:00Z',
    })).resolves.toEqual({
      requested: 2,
      updated: 1,
      failed: 1,
      results: [
        { id: 'c1', ok: true },
        { id: 'c2', ok: false, mutationApplied: true, error: 'Case updated, but activity audit failed: activity index unavailable' },
      ],
    });
  });
});

describe('coordinated case close', () => {
  test('closes the case and reports a partial live-alert failure while retaining archive-only evidence', async () => {
    const client = {
      get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }),
      search: jest.fn(async ({ index }: any) => {
        if (index === CASES_INDEX) {
          return { body: { hits: { hits: [{
            _id: 'c1', _index: CASE_INDEX, _source: { status: 'open', alert_ids: [] },
          }] } } };
        }
        if (index === 'wazuh-alert-manager-v2-evidence-read') {
          return {
            body: { hits: { total: { value: 3 }, hits: [
              { _id: 'e1', _source: { case_id: 'c1', alert_id: 'a1' }, sort: [1, 'e1'] },
              { _id: 'e2', _source: { case_id: 'c1', alert_id: 'a2' }, sort: [2, 'e2'] },
              { _id: 'e3', _source: { case_id: 'c1', alert_id: 'archived', archive_index: 'wazuh-alert-status-v2-000009', snapshot: { status: 'open' } }, sort: [3, 'e3'] },
            ] } },
          };
        }
        return { body: { hits: { hits: [
          { _id: 'a1', _index: 'wazuh-alert-status-v2-000001', _source: { status: 'open' } },
          { _id: 'a2', _index: 'wazuh-alert-status-v2-000001', _source: { status: 'open' } },
        ] } } };
      }),
      bulk: jest.fn(async () => ({ body: { items: [
        { update: { status: 200 } },
        { update: { status: 500, error: { reason: 'write rejected' } } },
      ] } })),
      index: jest.fn(async () => ({})),
      update: jest.fn(async () => ({})),
    };

    const result = await closeCaseAndLinkedAlerts(client, {
      caseId: 'c1', actor: 'analyst', timestamp: '2026-08-28T00:00:00Z',
    });
    expect(result).toEqual(expect.objectContaining({
      ok: false,
      caseClosed: false,
      closedAlerts: 1,
      failedAlertIds: ['a2'],
      evidenceOnlyAlertIds: ['archived'],
      archiveOnlyAlertIds: ['archived'],
    }));
    expect(result.stages).toContainEqual({ stage: 'close_alerts', attempted: 2, succeeded: 1, failed: 1 });
    expect(client.update).not.toHaveBeenCalled();
    expect(client.bulk.mock.calls[0][0].body[1].script.params.reporting).toEqual(
      expect.objectContaining({ closed_at: '2026-08-28T00:00:00Z', reporting_version: 1 })
    );
  });
});

describe('generic case update', () => {
  test('rejects closed status and directs clients to coordinated close', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router.put.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases/{id}`);
    expect(registration).toBeDefined();
    const handler = registration![1];
    const badRequest = jest.fn((value: any) => value);

    await handler(
      {},
      { params: { id: 'case-1' }, body: { status: 'closed', addAlertIds: [], removeAlertIds: [] } },
      { badRequest }
    );

    expect(badRequest).toHaveBeenCalledWith({
      body: { message: `Use POST ${API_ROOT}/cases/case-1/close to close a case and coordinate its linked alerts.` },
    });
  });
});

describe('case list pagination', () => {
  test('passes page and sort to OpenSearch and accepts a numeric total', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases`);
    expect(registration).toBeDefined();
    const search = jest.fn(async () => ({ body: {
      hits: { hits: [], total: 73 },
      aggregations: { summary_scope: { filtered: { doc_count: 80, by_status: { buckets: [
        { key: 'open', doc_count: 50 }, { key: 'in_progress', doc_count: 20 }, { key: 'closed', doc_count: 10 },
      ] } } } },
    } }));
    const ok = jest.fn((value: any) => value);

    await registration![1](
      { core: { opensearch: { client: { asCurrentUser: { search } } } } },
      { query: { from_offset: 40, size: 20, sortField: 'title', sortDirection: 'asc' } },
      { ok }
    );

    expect(search).toHaveBeenCalledWith(expect.objectContaining({
      index: CASES_INDEX,
      body: expect.objectContaining({
        from: 40,
        size: 20,
        track_total_hits: true,
        sort: [{ 'title.keyword': { order: 'asc' } }, { case_uid: { order: 'asc' } }],
      }),
    }));
    expect(search.mock.calls[0][0].body.sort.some(
      (entry: any) => Object.prototype.hasOwnProperty.call(entry, '_id')
    )).toBe(false);
    expect(ok).toHaveBeenCalledWith({ body: {
      cases: [], total: 73, summary: { open: 50, in_progress: 20, closed: 10, total: 80 },
    } });
  });

  test('combines severity and named or unassigned assignee filters', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases`);
    const search = jest.fn(async () => ({ body: {
      hits: { hits: [], total: { value: 0 } },
      aggregations: { summary_scope: { filtered: { doc_count: 0, by_status: { buckets: [] } } } },
    } }));
    const ok = jest.fn((value: any) => value);

    await registration![1](
      { core: { opensearch: { client: { asCurrentUser: { search } } } } },
      { query: { severity: 'critical,high', assignedTo: 'admin,__unassigned__' } },
      { ok }
    );

    const filters = search.mock.calls[0][0].body.query.bool.filter;
    expect(filters).toContainEqual({ terms: { severity: ['critical', 'high'] } });
    expect(filters).toContainEqual({ bool: {
      should: [
        { terms: { assigned_to: ['admin'] } },
        { bool: { must_not: [{ exists: { field: 'assigned_to' } }] } },
      ],
      minimum_should_match: 1,
    } });
  });

  test('rejects pages beyond the OpenSearch result window', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases`);
    const search = jest.fn();
    const badRequest = jest.fn((value: any) => value);

    await registration![1](
      { core: { opensearch: { client: { asCurrentUser: { search } } } } },
      { query: { from_offset: 9950, size: 100 } },
      { badRequest }
    );

    expect(search).not.toHaveBeenCalled();
    expect(badRequest).toHaveBeenCalledWith({
      body: { message: 'Case pagination is limited to the first 10000 results. Refine the filters to continue.' },
    });
  });
});
