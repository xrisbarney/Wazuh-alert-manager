import { API_ROOT, CASES_INDEX, CASES_WRITE_ALIAS } from '../../common';
import { bulkUpdateCases, closeCaseAndLinkedAlerts, defineCaseRoutes } from './cases';
import { invalidateSlaPolicyCache, primeSlaPolicyCache } from '../lib/sla/policy';

jest.mock('../lib/opensearch', () => ({
  ...jest.requireActual('../lib/opensearch'),
  getCurrentUsername: jest.fn(async () => 'analyst'),
}));

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

describe('case CSV export (step 5.1)', () => {
  const { CASE_EXPORT_COLUMNS, buildCaseExportSearchBody, buildCaseListQueries } = require('./cases');
  const { CSV_EXPORT_MAX_ROWS, CSV_EXPORT_PAGE_SIZE } = require('../lib/http_download');

  const readAll = async (stream: any): Promise<string> => {
    let text = '';
    for await (const chunk of stream) text += chunk.toString();
    return text;
  };

  const hit = (id: string, source: Record<string, any> = {}) => ({
    _id: id, _index: CASE_INDEX,
    _source: { title: `Case ${id}`, status: 'open', severity: 'high', created_at: '2026-11-20T10:00:00.000Z', alert_ids: ['a1', 'a2'], case_uid: `uid-${id}`, ...source },
    sort: [1763632800000, `uid-${id}`],
  });

  const registrationFor = (path: string) => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration!;
  };

  const runExport = async (query: Record<string, any>, pages: any[][], total?: any) => {
    const [, handler] = registrationFor('/cases/export.csv');
    let call = 0;
    const client = {
      search: jest.fn(async (_request: any) => {
        const hits = pages[call] || [];
        call += 1;
        return { body: { hits: { total: total ?? { value: pages.flat().length, relation: 'eq' }, hits } } };
      }),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);
    const result: any = await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } }, wazuhAlertManager: { logger: { warn: jest.fn(), error: jest.fn() } } },
      { query },
      { ok, customError }
    );
    expect(customError).not.toHaveBeenCalled();
    const text = await readAll(result.body);
    return { client, result, text, rows: text.split('\r\n').filter(Boolean) };
  };

  test('the column constant is the single ordered list of unique, named headers', () => {
    const headers = CASE_EXPORT_COLUMNS.map((column: any) => column.header);
    expect(headers).toEqual(['id', 'title', 'status', 'severity', 'assignee', 'created_by', 'created_at', 'updated_at', 'closed_at', 'alert_count', 'disposition', 'sla_due_at']);
    expect(new Set(headers).size).toBe(headers.length);
    const cells = (record: any) => Object.fromEntries(CASE_EXPORT_COLUMNS.map((column: any) => [column.header, column.value(record)]));
    expect(cells({ _id: 'c1', _source: { title: 'T', evidence_count: 7, alert_ids: ['a1'], assigned_to: 'bob', closed_at: null } })).toEqual(expect.objectContaining({ id: 'c1', title: 'T', assignee: 'bob', alert_count: 7, closed_at: '', disposition: '', sla_due_at: '' }));
    expect(cells({ _id: 'c2', _source: { alert_ids: ['a1', 'a2'] } }).alert_count).toBe(2);
  });


  test('sorting by severity orders by severity rank, not alphabetically (step 13.2)', () => {
    const { buildCaseListSort } = require('./cases');
    const [primary, tiebreak] = buildCaseListSort('severity', 'desc');
    expect(primary._script.type).toBe('number');
    expect(primary._script.order).toBe('desc');
    expect(primary._script.script.params.ranks).toEqual({ low: 0, medium: 1, high: 2, critical: 3 });
    expect(JSON.stringify(primary)).not.toContain('severity.keyword');
    expect(tiebreak).toEqual({ case_uid: { order: 'asc' } });
    // Every other field still sorts on itself; due dates keep missing last.
    expect(buildCaseListSort('title', 'asc')[0]).toEqual({ 'title.keyword': { order: 'asc' } });
    expect(buildCaseListSort('sla_due_at', undefined)[0]).toEqual({ sla_due_at: { order: 'desc', missing: '_last' } });
    expect(buildCaseListSort(undefined, undefined)[0]).toEqual({ updated_at: { order: 'desc' } });
  });

  test('the search box is plain text: a rule-created title with a colon and other Lucene characters is matched as typed (step 12.3)', () => {
    const { buildCaseListQueries, caseTextQuery } = require('./cases');
    const typed = 'Automation test: B burst case: automated incident';
    const { listQuery, summaryQuery } = buildCaseListQueries({ q: typed });
    expect(listQuery.bool.must).toEqual([caseTextQuery(typed)]);
    expect(summaryQuery.bool.must).toEqual([caseTextQuery(typed)]);
    expect(JSON.stringify(listQuery)).not.toContain('query_string');
    expect(caseTextQuery('  (phish) AND title:x*  ').multi_match).toEqual(expect.objectContaining({ query: '(phish) AND title:x*', type: 'phrase_prefix' }));
  });

  test('the list route and the export share one filter schema and query builder', async () => {
    const [listConfig] = registrationFor('/cases');
    const [exportConfig] = registrationFor('/cases/export.csv');
    const query = { status: 'open,in_progress', severity: 'high', assignedTo: 'bob,__unassigned__', q: 'phish', from: '2026-11-01', to: '2026-11-20' };
    expect(listConfig.validate.query.validate({ ...query, size: 10 })).toEqual(expect.objectContaining(query));
    expect(exportConfig.validate.query.validate(query)).toEqual(query);
    expect(() => exportConfig.validate.query.validate({ size: 10 })).toThrow();

    const { listQuery, summaryQuery } = buildCaseListQueries(query);
    expect(listQuery.bool.filter).toContainEqual({ terms: { status: ['open', 'in_progress'] } });
    expect(summaryQuery.bool.filter).not.toContainEqual({ terms: { status: ['open', 'in_progress'] } });
    expect(listQuery.bool.filter).toEqual(expect.arrayContaining([
      { terms: { severity: ['high'] } },
      { range: { created_at: { gte: '2026-11-01', lte: '2026-11-20' } } },
      { bool: { should: [{ terms: { assigned_to: ['bob'] } }, { bool: { must_not: [{ exists: { field: 'assigned_to' } }] } }], minimum_should_match: 1 } },
    ]));
    expect(listQuery.bool.must[0]).toEqual({ multi_match: { query: 'phish', type: 'phrase_prefix', fields: ['title^2', 'description'], max_expansions: 50 } });
    expect(buildCaseListQueries({}).listQuery).toEqual({ match_all: {} });


    const { client } = await runExport(query, [[hit('c1')]]);
    expect(client.search.mock.calls[0][0].index).toBe(CASES_INDEX);
    expect(client.search.mock.calls[0][0].body).toEqual(buildCaseExportSearchBody(query));
    expect(client.search.mock.calls[0][0].body.query).toEqual(listQuery);
    expect(client.search.mock.calls[0][0].body.sort).toEqual([{ created_at: { order: 'desc' } }, { case_uid: { order: 'asc' } }]);
  });

  test('pages with search_after across three pages and writes every row after the header', async () => {
    const page = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => hit(`${prefix}${i}`));
    const pages = [page('p1-', CSV_EXPORT_PAGE_SIZE), page('p2-', CSV_EXPORT_PAGE_SIZE), page('p3-', 3)];
    const { client, rows, result } = await runExport({}, pages);
    expect(result.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(result.headers['x-wam-truncated']).toBeUndefined();
    expect(client.search).toHaveBeenCalledTimes(3);
    expect(client.search.mock.calls[1][0].body.search_after).toEqual([1763632800000, `uid-p1-${CSV_EXPORT_PAGE_SIZE - 1}`]);
    expect(client.search.mock.calls[2][0].body.search_after).toEqual([1763632800000, `uid-p2-${CSV_EXPORT_PAGE_SIZE - 1}`]);
    expect(rows).toHaveLength(1 + 2 * CSV_EXPORT_PAGE_SIZE + 3);
    expect(rows[0]).toBe(CASE_EXPORT_COLUMNS.map((c: any) => c.header).join(','));
    expect(rows[1]).toBe('p1-0,Case p1-0,open,high,,,2026-11-20T10:00:00.000Z,,,2,,');
  });

  test('stops at the row cap and sends x-wam-truncated', async () => {
    const pageCount = CSV_EXPORT_MAX_ROWS / CSV_EXPORT_PAGE_SIZE;
    const pages = Array.from({ length: pageCount + 1 }, (_, p) => Array.from({ length: CSV_EXPORT_PAGE_SIZE }, (_, i) => hit(`p${p}-${i}`)));
    const { client, rows, result } = await runExport({}, pages, { value: CSV_EXPORT_MAX_ROWS + 1, relation: 'gte' });
    expect(result.headers['x-wam-truncated']).toBe('true');
    expect(rows).toHaveLength(1 + CSV_EXPORT_MAX_ROWS);
    expect(client.search).toHaveBeenCalledTimes(pageCount);
  });

  test('guards formula cells and names the attachment wam-cases-<date>.csv', async () => {
    const { result, rows } = await runExport({}, [[hit('c1', { title: '=cmd|"/C calc"!A0', assigned_to: '@ops' })]]);
    expect(result.headers['content-disposition']).toMatch(/^attachment; filename="wam-cases-\d{4}-\d{2}-\d{2}\.csv"$/);
    expect(rows[1]).toContain('"\'=cmd|""/C calc""!A0"');
    expect(rows[1]).toContain('"\'@ops"');
  });
});

describe('case report route (step 5.2)', () => {
  const { caseReportQuerySchema, caseReportCsp } = require('./cases');
  const { CASES_INDEX: casesIndex, ACTIVITY_READ_ALIAS, ATTACHMENTS_INDEX } = require('../../common');

  const registrationFor = (path: string) => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration!;
  };

  const reportClient = (found = true) => ({
    get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }),
    search: jest.fn(async (request: any) => {
      const index = String(request.index);
      if (index === casesIndex) {
        return { body: { hits: { total: { value: found ? 1 : 0 }, hits: found ? [{ _id: 'c1', _index: CASE_INDEX, _source: { title: 'Phishing <wave>', status: 'open', severity: 'high', alert_ids: [] } }] : [] } } };
      }
      if (index.startsWith('wazuh-alert-manager-v2-evidence')) return { body: { hits: { total: { value: 0 }, hits: [] } } };
      if (index === ACTIVITY_READ_ALIAS) return { body: { hits: { hits: [] } } };
      if (index === ATTACHMENTS_INDEX) throw { meta: { statusCode: 404 } };
      throw new Error(`unexpected index ${index}`);
    }),
  });

  const run = async (query: Record<string, any>, client = reportClient()) => {
    const [config, handler] = registrationFor('/cases/{id}/report');
    const validated = config.validate.query.validate(query);
    const ok = jest.fn((value: any) => value);
    const notFound = jest.fn((value: any) => ({ status: 404, ...value }));
    const customError = jest.fn((value: any) => value);
    const result: any = await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { params: { id: 'c1' }, query: validated },
      { ok, notFound, customError }
    );
    return { result, ok, notFound, customError, client };
  };

  test('validates the format and the flags', () => {
    expect(caseReportQuerySchema.validate({})).toEqual({ format: 'html' });
    expect(caseReportQuerySchema.validate({ format: 'markdown' })).toEqual({ format: 'markdown' });
    expect(caseReportQuerySchema.validate({ format: 'html', inline: '1', print: 'true' })).toEqual({ format: 'html', inline: '1', print: 'true' });
    expect(() => caseReportQuerySchema.validate({ format: 'pdf' })).toThrow();
    expect(() => caseReportQuerySchema.validate({ format: 'html', inline: 'x'.repeat(9) })).toThrow();
    const [config] = registrationFor('/cases/{id}/report');
    expect(() => config.validate.params.validate({ id: '' })).toThrow();
  });

  test('serves Markdown as an attachment with the wam-case filename', async () => {
    const { result, customError } = await run({ format: 'markdown' });
    expect(customError).not.toHaveBeenCalled();
    expect(result.headers['content-type']).toBe('text/markdown; charset=utf-8');
    expect(result.headers['content-disposition']).toMatch(/^attachment; filename="wam-case-c1-\d{4}-\d{2}-\d{2}\.md"$/);
    expect(result.headers['cache-control']).toBe('no-store');
    expect(result.headers['x-content-type-options']).toBe('nosniff');
    expect(result.body).toContain('# Case report: Phishing &lt;wave&gt;');
  });

  test('serves HTML as an attachment by default and inline (with the print trigger) on request', async () => {
    const download = await run({});
    expect(download.result.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(download.result.headers['content-disposition']).toMatch(/^attachment; filename="wam-case-c1-\d{4}-\d{2}-\d{2}\.html"$/);
    expect(download.result.body).not.toContain('<script');
    expect(download.result.headers['content-security-policy']).toMatch(/^default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'nonce-[A-Za-z0-9+/=]{20,}'; base-uri 'none'; form-action 'none'$/);

    // `print` without `inline` is ignored: a saved file must never print itself.
    const printedAttachment = await run({ format: 'html', print: '1' });
    expect(printedAttachment.result.headers['content-disposition']).toMatch(/^attachment;/);
    expect(printedAttachment.result.body).not.toContain('window.print()');
    expect(printedAttachment.result.body).not.toContain('<script');

    const inline = await run({ format: 'html', inline: '1', print: '1' });
    expect(inline.result.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(inline.result.headers['content-disposition']).toMatch(/^inline; filename="wam-case-c1-\d{4}-\d{2}-\d{2}\.html"$/);
    expect(inline.result.headers['cache-control']).toBe('no-store');
    expect(inline.result.body).toContain('window.print()');
    expect(inline.result.body).toContain('Phishing &lt;wave&gt;');
    // The nonce in the CSP is the one stamped on the only script, and differs per response.
    const nonce = inline.result.headers['content-security-policy'].match(/'nonce-([^']+)'/)[1];
    expect(inline.result.headers['content-security-policy']).toBe(caseReportCsp(nonce));
    expect(inline.result.body).toContain(`<script nonce="${nonce}">`);
    expect((inline.result.body.match(/<script/g) || []).length).toBe(1);
    expect(download.result.headers['content-security-policy']).not.toBe(inline.result.headers['content-security-policy']);

    // Markdown is never inlined, whatever the flags say.
    const md = await run({ format: 'markdown', inline: '1', print: '1' });
    expect(md.result.headers['content-disposition']).toMatch(/^attachment;/);
    expect(md.result.body).not.toContain('window.print()');
  });

  test('reads as the current user and returns 404 for an unknown case', async () => {
    const { notFound, ok, client } = await run({ format: 'html' }, reportClient(false));
    expect(ok).not.toHaveBeenCalled();
    expect(notFound).toHaveBeenCalledWith({ body: { message: 'Case c1 was not found.' } });
    expect(client.search.mock.calls[0][0].index).toBe(casesIndex);
  });

  test('maps other failures to their status code', async () => {
    const client = reportClient();
    client.search.mockImplementation(async () => { throw { meta: { statusCode: 403 }, message: 'forbidden' }; });
    const { customError } = await run({ format: 'html' }, client);
    expect(customError).toHaveBeenCalledWith({ statusCode: 403, body: { message: 'forbidden' } });
  });
});

describe('case due date (step 3.2)', () => {
  const policy = {
    targets: {
      critical: { resolveMinutes: 30, assignMinutes: 5 },
      high: { resolveMinutes: 120, assignMinutes: 20 },
      medium: { resolveMinutes: 600, assignMinutes: 60 },
      low: { resolveMinutes: 2880, assignMinutes: 240 },
    },
    escalations: [],
  };
  const plus = (ts: string, minutes: number) => new Date(Date.parse(ts) + minutes * 60000).toISOString();
  const handlerFor = (method: 'get' | 'post' | 'put', path: string) => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration![1];
  };
  const context = (client: any) => ({ core: { opensearch: { client: { asCurrentUser: client } } } });
  const responses = () => ({ ok: jest.fn((v: any) => ({ kind: 'ok', ...v })), customError: jest.fn((v: any) => ({ kind: 'customError', ...v })), badRequest: jest.fn((v: any) => ({ kind: 'badRequest', ...v })) });

  beforeEach(() => {
    invalidateSlaPolicyCache();
    primeSlaPolicyCache(policy);
  });
  afterAll(() => invalidateSlaPolicyCache());

  test('create stamps sla_due_at = created_at + the resolve target of the severity', async () => {
    const handler = handlerFor('post', '/cases');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const evidence = require('../lib/case_evidence_service');
    const reconcile = jest.spyOn(evidence, 'reconcileCaseEvidence').mockResolvedValue({ ok: true, requested: 0, linkedAlertIds: [] } as any);
    let created: any = null;
    const client = {
      create: jest.fn(async (req: any) => { created = req; return {}; }),
      search: jest.fn(async () => ({ body: { hits: { hits: created ? [{ _id: created.id, _index: CASE_INDEX, _source: created.body }] : [] } } })),
      index: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { items: [] } })),
    };
    const out = await handler(context(client), { body: { title: 'T', severity: 'high', alertIds: [], assignedTo: null } }, responses());
    expect(out.kind).toBe('ok');
    expect(created.index).toBe(CASES_WRITE_ALIAS);
    expect(created.body.sla_due_at).toBe(plus(created.body.created_at, 120));
    expect(created.body.closed_at).toBeNull();
    expect(out.body.sla_due_at).toBe(created.body.sla_due_at);
    reconcile.mockRestore();
  });

  test('update recomputes sla_due_at from created_at when the severity changes and leaves it alone otherwise', async () => {
    const handler = handlerFor('put', '/cases/{id}');
    const createdAt = '2026-11-21T10:00:00.000Z';
    const stored = { title: 'T', severity: 'high', status: 'open', assigned_to: null, created_at: createdAt, sla_due_at: plus(createdAt, 120), closed_at: null };
    const client = {
      search: jest.fn(async () => ({ body: { hits: { hits: [{ _id: 'case-1', _index: CASE_INDEX, _source: stored }] } } })),
      update: jest.fn(async () => ({})),
      index: jest.fn(async () => ({})),
    };
    const raised = await handler(context(client), { params: { id: 'case-1' }, body: { severity: 'critical', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(raised.kind).toBe('ok');
    expect(client.update.mock.calls[0][0].body.script.params.fields).toMatchObject({ severity: 'critical', sla_due_at: plus(createdAt, 30) });
    expect(client.update.mock.calls[0][0].body.script.params.fields.closed_at).toBeUndefined();

    const same = await handler(context(client), { params: { id: 'case-1' }, body: { severity: 'high', title: 'T2', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(same.kind).toBe('ok');
    const fields = client.update.mock.calls[1][0].body.script.params.fields;
    expect(fields.severity).toBe('high');
    expect(fields).not.toHaveProperty('sla_due_at');
  });

  test('the list accepts slaState and the sla_due_at sort', async () => {
    const handler = handlerFor('get', '/cases');
    const search = jest.fn(async () => ({ body: { hits: { hits: [], total: { value: 0 } }, aggregations: { summary_scope: { filtered: { doc_count: 0, by_status: { buckets: [] } } } } } }));
    const out = await handler(context({ search }), { query: { slaState: 'breached', sortField: 'sla_due_at', sortDirection: 'asc' } }, responses());
    expect(out.kind).toBe('ok');
    const body = (search.mock.calls[0] as any)[0].body;
    expect(body.sort[0]).toEqual({ sla_due_at: { order: 'asc', missing: '_last' } });
    const clause = body.query.bool.filter.find((f: any) => f.bool?.filter?.some((inner: any) => inner.range?.sla_due_at));
    expect(clause.bool.filter[0].range.sla_due_at).toHaveProperty('lt');
    expect(clause.bool.filter[1]).toEqual({ terms: { status: ['open', 'in_progress'] } });
    // The status summary leaves the status filter out but keeps the SLA state.
    expect(body.aggs.summary_scope.aggs.filtered.filter.bool.filter).toContainEqual(clause);
  });
});

jest.mock('../lib/task_lists', () => ({ getTaskList: jest.fn(), applyTaskListToCase: jest.fn() }));

describe('POST /cases with taskListId (step 2.2)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const taskLists = require('../lib/task_lists');
  const registration = () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    return router.post.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases`)!;
  };
  const context = (client: any) => ({ core: { opensearch: { client: { asCurrentUser: client } } } });
  const responses = () => ({ ok: jest.fn((v: any) => ({ kind: 'ok', ...v })), customError: jest.fn((v: any) => ({ kind: 'customError', ...v })), badRequest: jest.fn((v: any) => ({ kind: 'badRequest', ...v })) });
  const clientFor = () => {
    let created: any = null;
    return {
      create: jest.fn(async (req: any) => { created = req; return {}; }),
      search: jest.fn(async () => ({ body: { hits: { hits: created ? [{ _id: created.id, _index: CASE_INDEX, _source: created.body }] : [] } } })),
      index: jest.fn(async () => ({})),
      bulk: jest.fn(async () => ({ body: { items: [] } })),
    };
  };
  let reconcile: jest.SpyInstance;

  beforeEach(() => {
    invalidateSlaPolicyCache();
    primeSlaPolicyCache({ targets: { critical: { resolveMinutes: 30, assignMinutes: 5 }, high: { resolveMinutes: 120, assignMinutes: 20 }, medium: { resolveMinutes: 600, assignMinutes: 60 }, low: { resolveMinutes: 2880, assignMinutes: 240 } }, escalations: [] } as any);
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    reconcile = jest.spyOn(require('../lib/case_evidence_service'), 'reconcileCaseEvidence').mockResolvedValue({ ok: true, requested: 0, linkedAlertIds: [] } as any);
    taskLists.getTaskList.mockReset();
    taskLists.applyTaskListToCase.mockReset();
  });
  afterEach(() => reconcile.mockRestore());
  afterAll(() => invalidateSlaPolicyCache());

  test('the body schema accepts an optional taskListId', () => {
    const [config] = registration();
    expect(config.validate.body.validate({ title: 'T', severity: 'high', taskListId: 'pb-1' }).taskListId).toBe('pb-1');
    expect(config.validate.body.validate({ title: 'T', severity: 'high' }).taskListId).toBeUndefined();
    expect(() => config.validate.body.validate({ title: 'T', severity: 'high', taskListId: '' })).toThrow();
  });

  test('applies the task list after creation, as the creator, and reports it on the response', async () => {
    taskLists.getTaskList.mockResolvedValue({ id: 'pb-1', name: 'Triage', enabled: true, tasks: [] });
    taskLists.applyTaskListToCase.mockResolvedValue({ applied: true, task_list_id: 'pb-1', tasks_added: 3, counts: { open: 3, done: 0 } });
    const client = clientFor();
    const out = await registration()[1](context(client), { body: { title: 'T', severity: 'high', alertIds: [], assignedTo: null, taskListId: 'pb-1' } }, responses());
    expect(out.kind).toBe('ok');
    expect(out.body.taskList).toEqual({ applied: true, tasks_added: 3 });
    expect(taskLists.getTaskList).toHaveBeenCalledWith(client, 'pb-1');
    const [, caseId, taskList, actor] = taskLists.applyTaskListToCase.mock.calls[0];
    expect(caseId).toBe(out.body.id);
    expect(taskList.id).toBe('pb-1');
    expect(actor).toBe('analyst');
    expect(client.create.mock.invocationCallOrder[0]).toBeLessThan(taskLists.applyTaskListToCase.mock.invocationCallOrder[0]);
  });

  test('a task list failure (unknown, disabled) leaves the case created and is reported, never rolled back', async () => {
    taskLists.getTaskList.mockRejectedValue(Object.assign(new Error('Task list not found.'), { statusCode: 404 }));
    const client = clientFor();
    const out = await registration()[1](context(client), { body: { title: 'T', severity: 'high', alertIds: [], taskListId: 'pb-x' } }, responses());
    expect(out.kind).toBe('ok');
    expect(out.body.id).toMatch(/^case-/);
    expect(out.body.taskList).toEqual({ applied: false, error: 'Task list not found.' });
    expect(client.create).toHaveBeenCalledTimes(1);

    const without = await registration()[1](context(clientFor()), { body: { title: 'T', severity: 'high', alertIds: [] } }, responses());
    expect(without.kind).toBe('ok');
    expect(without.body).not.toHaveProperty('task list');
    expect(taskLists.applyTaskListToCase).not.toHaveBeenCalled();
  });
});

describe('case timeline route (step 2.3)', () => {
  const { caseTimelineQuerySchema } = require('./cases');
  const { CASES_INDEX: casesIndex, ACTIVITY_READ_ALIAS, CASE_TIMELINE_PAGE } = require('../../common');
  const { CASE_TIMELINE_LIMIT_MAX, encodeTimelineCursor } = require('../lib/case_timeline');

  const registration = () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const found = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases/{id}/timeline`);
    expect(found).toBeDefined();
    return found!;
  };

  const timelineClient = (found = true) => ({
    get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }),
    search: jest.fn(async (request: any) => {
      const index = String(request.index);
      if (index === casesIndex) {
        return { body: { hits: { total: { value: found ? 1 : 0 }, hits: found ? [{ _id: 'c1', _index: CASE_INDEX, _source: { title: 'Case', status: 'open', severity: 'high', alert_ids: [], tasks: [{ id: 't1', title: 'Follow up', due_at: '2026-11-21T09:00:00.000Z', done: false }] } }] : [] } } };
      }
      if (index.startsWith('wazuh-alert-manager-v2-evidence')) return { body: { hits: { total: { value: 0 }, hits: [] } } };
      if (index === ACTIVITY_READ_ALIAS) {
        return { body: { hits: { hits: [{ _id: 'au1', _source: { event_type: 'audit', case_id: 'c1', user: 'alice', action: 'case_created', to: 'Case', timestamp: '2026-11-20T10:00:00.000Z' }, sort: [1, 'au1'] }] } } };
      }
      throw new Error(`unexpected index ${index}`);
    }),
  });

  const run = async (query: Record<string, any>, client = timelineClient()) => {
    const [config, handler] = registration();
    const validated = config.validate.query.validate(query);
    const ok = jest.fn((value: any) => value);
    const notFound = jest.fn((value: any) => ({ status: 404, ...value }));
    const badRequest = jest.fn((value: any) => ({ status: 400, ...value }));
    const customError = jest.fn((value: any) => value);
    const result: any = await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { params: { id: 'c1' }, query: validated },
      { ok, notFound, badRequest, customError }
    );
    return { result, ok, notFound, badRequest, customError, client };
  };

  test('validates the cursor and the limit', () => {
    expect(caseTimelineQuerySchema.validate({})).toEqual({ limit: CASE_TIMELINE_PAGE });
    expect(caseTimelineQuerySchema.validate({ cursor: 'abc', limit: 5 })).toEqual({ cursor: 'abc', limit: 5 });
    expect(() => caseTimelineQuerySchema.validate({ limit: 0 })).toThrow();
    expect(() => caseTimelineQuerySchema.validate({ limit: CASE_TIMELINE_LIMIT_MAX + 1 })).toThrow();
    expect(() => caseTimelineQuerySchema.validate({ cursor: '' })).toThrow();
    expect(() => caseTimelineQuerySchema.validate({ cursor: 'x'.repeat(4097) })).toThrow();
    const [config] = registration();
    expect(() => config.validate.params.validate({ id: '' })).toThrow();
  });

  test('answers the merged page as the current user', async () => {
    const { result, ok, client } = await run({});
    expect(ok).toHaveBeenCalledTimes(1);
    expect(client.search.mock.calls[0][0].index).toBe(casesIndex);
    expect(result.body.entries.map((entry: any) => [entry.kind, entry.id])).toEqual([
      ['audit', 'activity:au1'],
      ['task_due', 'task_due:t1'],
    ]);
    expect(result.body.entries[0]).toEqual(expect.objectContaining({ title: 'case created: Case', actor: 'alice', action: 'case_created', ref: { activity_id: 'au1' } }));
    expect(result.body.next_cursor).toBeNull();
    expect(result.body.truncated_alerts).toBe(false);
    const activityCall = client.search.mock.calls.find(([request]: any[]) => request.index === ACTIVITY_READ_ALIAS);
    expect(activityCall[0].body.size).toBe(CASE_TIMELINE_PAGE + 1);
  });

  test('404 for an unknown case, 400 for a cursor of another case', async () => {
    const missing = await run({}, timelineClient(false));
    expect(missing.ok).not.toHaveBeenCalled();
    expect(missing.notFound).toHaveBeenCalledWith({ body: { message: 'Case c1 was not found.' } });

    const foreign = encodeTimelineCursor({ case: 'c2', at: '2026-11-20T10:00:00.000Z', id: 'activity:au1', sources: {} });
    const rejected = await run({ cursor: foreign });
    expect(rejected.ok).not.toHaveBeenCalled();
    expect(rejected.badRequest).toHaveBeenCalledWith({ body: { message: 'Invalid or mismatched timeline cursor.' } });
    // A foreign cursor is refused before any read beyond the case itself.
    expect(rejected.client.search.mock.calls.map(([request]: any[]) => request.index)).toEqual([]);
  });

  test('maps other failures to their status code', async () => {
    const client = timelineClient();
    client.search.mockImplementation(async () => { throw { meta: { statusCode: 403 }, message: 'forbidden' }; });
    const { customError } = await run({}, client);
    expect(customError).toHaveBeenCalledWith({ statusCode: 403, body: { message: 'forbidden' } });
  });
});

describe('disposition on case close (step 2.4)', () => {
  const { closeCaseBodySchema } = require('./cases');
  const { dispositionFilterValues } = require('../lib/disposition');
  const { DISPOSITIONS, CLOSURE_REASON_MAX_LENGTH } = require('../../common');

  const closeClient = (caseStatus = 'open', caseExtra: Record<string, any> = {}) => ({
    get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }),
    search: jest.fn(async ({ index }: any) => {
      if (index === CASES_INDEX) {
        return { body: { hits: { hits: [{ _id: 'c1', _index: CASE_INDEX, _source: { status: caseStatus, alert_ids: [], ...caseExtra } }] } } };
      }
      if (index === 'wazuh-alert-manager-v2-evidence-read') {
        return { body: { hits: { total: { value: 2 }, hits: [
          { _id: 'e1', _source: { case_id: 'c1', alert_id: 'a1' }, sort: [1, 'e1'] },
          { _id: 'e2', _source: { case_id: 'c1', alert_id: 'a2' }, sort: [2, 'e2'] },
        ] } } };
      }
      return { body: { hits: { hits: [
        { _id: 'a1', _index: 'wazuh-alert-status-v2-000001', _source: { status: 'open' } },
        { _id: 'a2', _index: 'wazuh-alert-status-v2-000001', _source: { status: 'closed', disposition: 'benign' } },
      ] } } };
    }),
    bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }] } })),
    index: jest.fn(async () => ({})),
    update: jest.fn(async () => ({})),
  });

  test('the close body accepts the taxonomy and bounds the reason; disposition stays optional for older clients', () => {
    expect(closeCaseBodySchema.validate({})).toEqual({ excludeAlertIds: [] });
    expect(closeCaseBodySchema.validate({ disposition: 'false_positive', closureReason: 'Scanner noise' })).toEqual({
      excludeAlertIds: [], disposition: 'false_positive', closureReason: 'Scanner noise',
    });
    for (const value of DISPOSITIONS) expect(closeCaseBodySchema.validate({ disposition: value }).disposition).toBe(value);
    expect(() => closeCaseBodySchema.validate({ disposition: 'resolved' })).toThrow();
    expect(() => closeCaseBodySchema.validate({ closureReason: 'x'.repeat(CLOSURE_REASON_MAX_LENGTH + 1) })).toThrow();
    expect(closeCaseBodySchema.validate({ closureReason: null }).closureReason).toBeNull();
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const [config] = router.post.mock.calls.find(([c]: any[]) => c.path === `${API_ROOT}/cases/{id}/close`)!;
    expect(config.validate.body).toBe(closeCaseBodySchema);
  });

  test('propagates the disposition and reason onto every alert it closes, in the same scripted update, and stores both on the case', async () => {
    const client = closeClient();
    const result = await closeCaseAndLinkedAlerts(client, {
      caseId: 'c1', actor: 'analyst', timestamp: '2026-11-21T10:00:00.000Z',
      disposition: 'false_positive', closureReason: '  Vulnerability scanner from the <ops> team  ',
    });
    expect(result).toEqual(expect.objectContaining({ ok: true, caseClosed: true, closedAlerts: 1, alreadyClosedAlerts: 1 }));

    // Only the open alert is closed; the already-closed one keeps its own disposition.
    const bulk = (client.bulk.mock.calls as any[])[0][0];
    expect(bulk.body).toHaveLength(2);
    expect(bulk.body[0]).toEqual({ update: { _index: 'wazuh-alert-status-v2-000001', _id: 'a1' } });
    const script = bulk.body[1].script;
    expect(script.source).toContain("if (ctx._source.status != 'closed')");
    expect(script.source).toContain('ctx._source.disposition = params.disposition');
    expect(script.source).toContain('ctx._source.closure_reason = params.closure_reason');
    expect(script.params).toEqual(expect.objectContaining({
      disposition: 'false_positive',
      closure_reason: 'Vulnerability scanner from the <ops> team',
      entry: expect.objectContaining({ action: 'status_change', to: 'closed', disposition: 'false_positive' }),
    }));
    expect(script.params.reporting).toEqual(expect.objectContaining({ closed_at: '2026-11-21T10:00:00.000Z' }));

    // The alert audit event carries the outcome as unindexed details.
    const alertAudit = (client.index.mock.calls as any[]).find(([call]: any[]) => call.id === 'case-close:c1:a1')?.[0];
    expect(alertAudit.body).toEqual(expect.objectContaining({ action: 'status_change', to: 'closed', details: { disposition: 'false_positive', closure_reason: 'Vulnerability scanner from the <ops> team' } }));
    // The already-closed alert was not stamped, so its audit names the outcome it keeps, not this close's.
    const retainedAudit = (client.index.mock.calls as any[]).find(([call]: any[]) => call.id === 'case-close:c1:a2')?.[0];
    expect(retainedAudit.body).toEqual(expect.objectContaining({ action: 'status_change', details: { disposition: 'benign', closure_reason: null, retained: true } }));
    expect(result).toEqual(expect.objectContaining({ disposition: 'false_positive', closureReason: 'Vulnerability scanner from the <ops> team' }));

    // The case document stores the same outcome.
    const caseUpdate = (client.update.mock.calls as any[])[0][0];
    expect(caseUpdate).toEqual(expect.objectContaining({ index: CASE_INDEX, id: 'c1', refresh: 'wait_for' }));
    expect(caseUpdate.body.script.source).toContain('ctx._source.disposition = params.disposition; ctx._source.closure_reason = params.closure_reason;');
    expect(caseUpdate.body.script.params).toEqual(expect.objectContaining({
      disposition: 'false_positive',
      closure_reason: 'Vulnerability scanner from the <ops> team',
      entry: expect.objectContaining({ to: 'closed', disposition: 'false_positive' }),
    }));
  });

  test('a close without a disposition stores undetermined and a null reason (backward compatibility)', async () => {
    const client = closeClient();
    await closeCaseAndLinkedAlerts(client, { caseId: 'c1', actor: 'analyst' });
    expect((client.bulk.mock.calls as any[])[0][0].body[1].script.params).toEqual(expect.objectContaining({ disposition: 'undetermined', closure_reason: null }));
    expect((client.update.mock.calls as any[])[0][0].body.script.params).toEqual(expect.objectContaining({ disposition: 'undetermined', closure_reason: null }));
    const unknown = closeClient();
    await closeCaseAndLinkedAlerts(unknown, { caseId: 'c1', actor: 'analyst', disposition: 'resolved' as any, closureReason: '   ' });
    expect((unknown.update.mock.calls as any[])[0][0].body.script.params).toEqual(expect.objectContaining({ disposition: 'undetermined', closure_reason: null }));
  });

  test('a re-close of an already-closed case keeps the stored outcome: still-open linked alerts and the audit carry it, not the body', async () => {
    const client = closeClient('closed', { disposition: 'benign', closure_reason: 'Known scanner' });
    const result = await closeCaseAndLinkedAlerts(client, {
      caseId: 'c1', actor: 'analyst', timestamp: '2026-11-21T10:00:00.000Z',
      disposition: 'true_positive', closureReason: 'Second thoughts',
    });
    expect(result).toEqual(expect.objectContaining({ caseClosed: true, closedAlerts: 1, disposition: 'benign', closureReason: 'Known scanner' }));
    // The case document is never re-written on a re-close.
    expect(client.update).not.toHaveBeenCalled();
    const script = (client.bulk.mock.calls as any[])[0][0].body[1].script;
    expect(script.params).toEqual(expect.objectContaining({
      disposition: 'benign', closure_reason: 'Known scanner',
      entry: expect.objectContaining({ to: 'closed', disposition: 'benign' }),
    }));
    const alertAudit = (client.index.mock.calls as any[]).find(([call]: any[]) => call.id === 'case-close:c1:a1')?.[0];
    expect(alertAudit.body.details).toEqual({ disposition: 'benign', closure_reason: 'Known scanner' });

    // Through the route the case audit names the stored outcome too.
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const [config, handler] = router.post.mock.calls.find(([c]: any[]) => c.path === `${API_ROOT}/cases/{id}/close`)!;
    const routed = closeClient('closed', { disposition: 'benign', closure_reason: 'Known scanner' });
    const ok = jest.fn((value: any) => value);
    await handler(
      { core: { opensearch: { client: { asCurrentUser: routed } } } },
      { params: { id: 'c1' }, body: config.validate.body.validate({ disposition: 'true_positive', closureReason: 'Second thoughts' }) },
      { ok, customError: jest.fn() }
    );
    const caseAudit = (routed.index.mock.calls as any[]).map(([call]: any[]) => call.body).find((body: any) => body.action === 'case_closed');
    // `already_closed` keeps the notification hook (step 1.3) from emitting case.closed again.
    expect(caseAudit).toEqual(expect.objectContaining({ target_id: 'c1', details: { disposition: 'benign', closure_reason: 'Known scanner', already_closed: true } }));
  });

  test('the route passes the body through and audits the outcome on the case', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    const [config, handler] = router.post.mock.calls.find(([c]: any[]) => c.path === `${API_ROOT}/cases/{id}/close`)!;
    const client = closeClient();
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);
    await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { params: { id: 'c1' }, body: config.validate.body.validate({ disposition: 'duplicate', closureReason: 'Same as case 7' }) },
      { ok, customError }
    );
    expect(customError).not.toHaveBeenCalled();
    expect(ok).toHaveBeenCalledTimes(1);
    expect((client.update.mock.calls as any[])[0][0].body.script.params).toEqual(expect.objectContaining({ disposition: 'duplicate', closure_reason: 'Same as case 7' }));
    const caseAudit = (client.index.mock.calls as any[]).map(([call]: any[]) => call.body).find((body: any) => body.action === 'case_closed');
    expect(caseAudit).toEqual(expect.objectContaining({ target_type: 'case', target_id: 'c1', details: { disposition: 'duplicate', closure_reason: 'Same as case 7' } }));
  });

  test('the case list filters on disposition with a terms clause, ignoring unknown values; the export shares it', async () => {
    const { buildCaseListQueries, buildCaseExportSearchBody } = require('./cases');
    expect(dispositionFilterValues('false_positive,bogus,benign')).toEqual(['false_positive', 'benign']);
    const { listQuery, summaryQuery } = buildCaseListQueries({ status: 'closed', disposition: 'false_positive,bogus' });
    expect(listQuery.bool.filter).toContainEqual({ terms: { disposition: ['false_positive'] } });
    expect(summaryQuery.bool.filter).toContainEqual({ terms: { disposition: ['false_positive'] } });
    expect(buildCaseListQueries({ disposition: 'bogus' })).toEqual({ listQuery: { match_all: {} }, summaryQuery: { match_all: {} } });
    expect(buildCaseExportSearchBody({ disposition: 'duplicate' }).query.bool.filter).toContainEqual({ terms: { disposition: ['duplicate'] } });
    const { caseFilterQuerySchema } = require('./cases');
    expect(caseFilterQuerySchema.validate({ disposition: 'benign' })).toEqual({ disposition: 'benign' });
  });
});

describe('case notifications (step 1.3)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { registerNotificationEmitter } = require('../lib/notifications/emitters');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { registerActivityEmitter } = require('../lib/activity');
  const registration = () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineCaseRoutes(router);
    return router.put.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases/{id}`)!;
  };
  const context = (client: any) => ({ core: { opensearch: { client: { asCurrentUser: client } } } });
  const responses = () => ({ ok: jest.fn((v: any) => ({ kind: 'ok', ...v })), customError: jest.fn((v: any) => ({ kind: 'customError', ...v })), badRequest: jest.fn((v: any) => ({ kind: 'badRequest', ...v })) });
  const stored = (overrides: any = {}) => ({ case_uid: 'case-1', title: 'T', severity: 'medium', status: 'open', assigned_to: null, created_at: '2026-11-21T00:00:00.000Z', ...overrides });
  const clientFor = (source: any) => ({
    search: caseSearch([{ _id: 'case-1', found: true, _source: source }]),
    update: jest.fn(async () => ({ body: { result: 'updated' } })),
    index: jest.fn(async () => ({})),
  });
  const emitterMock = () => ({ emitCaseEvent: jest.fn(async () => ({})), emitSlaEvent: jest.fn(), emitReportEvent: jest.fn(), activityHook: jest.fn() });

  beforeEach(() => {
    invalidateSlaPolicyCache();
    primeSlaPolicyCache({ targets: { critical: { resolveMinutes: 30, assignMinutes: 5 }, high: { resolveMinutes: 120, assignMinutes: 20 }, medium: { resolveMinutes: 600, assignMinutes: 60 }, low: { resolveMinutes: 2880, assignMinutes: 240 } }, escalations: [] } as any);
  });
  afterEach(() => {
    registerNotificationEmitter(null);
    registerActivityEmitter(null);
    invalidateSlaPolicyCache();
  });

  test('PUT with a changed severity calls the emitter with the fresh document and both values, after the activity write; the same severity does not', async () => {
    const emitter = emitterMock();
    registerNotificationEmitter(emitter);
    const client = clientFor(stored());
    const out = await registration()[1](context(client), { params: { id: 'case-1' }, body: { severity: 'high', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(out.kind).toBe('ok');
    expect(emitter.emitCaseEvent).toHaveBeenCalledTimes(1);
    const [event, doc, options] = emitter.emitCaseEvent.mock.calls[0] as any[];
    expect(event).toBe('case.severity_raised');
    expect(doc).toEqual(expect.objectContaining({ id: 'case-1', severity: 'high', updated_by: 'analyst', sla_due_at: expect.any(String) }));
    expect(options).toEqual({ actor: 'analyst', changes: { from: 'medium', to: 'high' } });
    expect(client.index.mock.invocationCallOrder[0]).toBeLessThan(emitter.emitCaseEvent.mock.invocationCallOrder[0]);

    emitter.emitCaseEvent.mockClear();
    const same = await registration()[1](context(clientFor(stored({ severity: 'high' }))), { params: { id: 'case-1' }, body: { severity: 'high', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(same.kind).toBe('ok');
    expect(emitter.emitCaseEvent).not.toHaveBeenCalled();

    // A lowered severity is still handed over: the emitter decides (only a higher band fires).
    const lower = await registration()[1](context(clientFor(stored({ severity: 'high' }))), { params: { id: 'case-1' }, body: { severity: 'low', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(lower.kind).toBe('ok');
    expect(emitter.emitCaseEvent).toHaveBeenCalledWith('case.severity_raised', expect.anything(), { actor: 'analyst', changes: { from: 'high', to: 'low' } });
  });

  test('without a registered emitter the route is unchanged', async () => {
    const client = clientFor(stored());
    const out = await registration()[1](context(client), { params: { id: 'case-1' }, body: { severity: 'critical', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(out.kind).toBe('ok');
    expect(client.update).toHaveBeenCalledTimes(1);
  });

  test('assignment goes through the activity hook (assignment_change with from / to), for PUT and the bulk assign alike', async () => {
    const seen: any[] = [];
    registerActivityEmitter(async (event: any) => { seen.push(event); });
    const client = clientFor(stored({ assigned_to: null }));
    const out = await registration()[1](context(client), { params: { id: 'case-1' }, body: { assignedTo: 'bob', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(out.kind).toBe('ok');
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual(expect.objectContaining({ target_type: 'case', case_id: 'case-1', action: 'assignment_change', from: null, to: 'bob', user: 'analyst' }));

    seen.length = 0;
    const bulkClient = {
      search: caseSearch([{ _id: 'c1', found: true, _source: { assigned_to: null } }]),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }] } })),
      index: jest.fn(async () => ({})),
    };
    await bulkUpdateCases(bulkClient, { ids: ['c1'], actor: 'analyst', assignedTo: 'tier-2' });
    expect(seen.map((e) => [e.case_id, e.action, e.to])).toEqual([['c1', 'assignment_change', 'tier-2']]);
  });

  test('status and assignee in one request (PUT and bulk): the single status_change row is audited and case.assigned is emitted directly, keyed on it', async () => {
    const emitter = emitterMock();
    registerNotificationEmitter(emitter);
    const client = clientFor(stored({ assigned_to: 'alice' }));
    const out = await registration()[1](context(client), { params: { id: 'case-1' }, body: { status: 'in_progress', assignedTo: 'bob', addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(out.kind).toBe('ok');
    const audits = (client.index.mock.calls as any[]).map(([call]: any[]) => call.body);
    expect(audits.map((a) => a.action)).toEqual(['status_change']);
    expect(emitter.emitCaseEvent).toHaveBeenCalledTimes(1);
    expect(emitter.emitCaseEvent).toHaveBeenCalledWith('case.assigned', expect.objectContaining({ id: 'case-1', status: 'in_progress', assigned_to: 'bob', updated_by: 'analyst' }), {
      actor: 'analyst', changes: { from: 'alice', to: 'bob' }, activityId: audits[0].event_uid, now: expect.any(Date),
    });

    // The same assignee, or an unassignment, with a status change: nothing.
    emitter.emitCaseEvent.mockClear();
    await registration()[1](context(clientFor(stored({ assigned_to: 'bob' }))), { params: { id: 'case-1' }, body: { status: 'in_progress', assignedTo: 'bob', addAlertIds: [], removeAlertIds: [] } }, responses());
    await registration()[1](context(clientFor(stored({ assigned_to: 'bob' }))), { params: { id: 'case-1' }, body: { status: 'open', assignedTo: null, addAlertIds: [], removeAlertIds: [] } }, responses());
    expect(emitter.emitCaseEvent).not.toHaveBeenCalled();

    const bulkClient = {
      search: caseSearch([{ _id: 'c1', found: true, _source: { assigned_to: null, status: 'open' } }, { _id: 'c2', found: true, _source: { assigned_to: 'tier-2', status: 'open' } }]),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }, { update: { status: 200 } }] } })),
      index: jest.fn(async () => ({})),
    };
    const result = await bulkUpdateCases(bulkClient, { ids: ['c1', 'c2'], actor: 'analyst', status: 'in_progress', assignedTo: 'tier-2', timestamp: '2026-11-21T12:00:00.000Z' });
    expect(result.updated).toBe(2);
    const bulkAudits = (bulkClient.index.mock.calls as any[]).map(([call]: any[]) => call.body);
    expect(bulkAudits.map((a) => [a.case_id, a.action])).toEqual([['c1', 'status_change'], ['c2', 'status_change']]);
    // Only c1 changed assignee; c2 already carried tier-2.
    expect(emitter.emitCaseEvent).toHaveBeenCalledTimes(1);
    expect(emitter.emitCaseEvent).toHaveBeenCalledWith('case.assigned', expect.objectContaining({ id: 'c1', status: 'in_progress', assigned_to: 'tier-2' }), {
      actor: 'analyst', changes: { from: null, to: 'tier-2' }, activityId: bulkAudits[0].event_uid, now: new Date('2026-11-21T12:00:00.000Z'),
    });
  });
});
