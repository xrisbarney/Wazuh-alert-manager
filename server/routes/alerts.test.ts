import { API_ROOT } from '../../common';
import { buildAlertCountSearchBody, buildAlertListSearchBody, buildBoolQuery, defineAlertRoutes, filterQuerySchema, resolveAlertSortField } from './alerts';

jest.mock('../lib/opensearch', () => ({
  ...jest.requireActual('../lib/opensearch'),
  getCurrentUsername: jest.fn(async () => 'analyst'),
}));

describe('alert route exact totals', () => {
  test('requests exact total hits for the paged Workbench queue', () => {
    const body = buildAlertListSearchBody({
      from_offset: 20, size: 20, sortField: '@timestamp', sortDirection: 'desc',
      statuses: 'open',
    });

    expect(body.track_total_hits).toBe(true);
    expect(body.from).toBe(20);
    expect(body.size).toBe(20);
  });

  test('requests exact total hits for summary counts', () => {
    const body = buildAlertCountSearchBody({ from: '2026-08-29T00:00:00.000Z' });

    expect(body.track_total_hits).toBe(true);
    expect(body.size).toBe(0);
    expect(body.aggs.status_counts.terms.field).toBe('status');
  });
});

const ALERT_INDEX = 'wazuh-alert-status-v2-000001';
const alertSearch = (ids: string[]) => jest.fn(async () => ({
  body: { hits: { hits: ids.map((id) => ({ _id: id, _index: ALERT_INDEX, _source: { status: 'open' } })) } },
}));
const handlerFor = (method: 'get' | 'post' | 'put', path: string) => {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineAlertRoutes(router);
  const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
  expect(registration).toBeDefined();
  return registration![1];
};

describe('alert bulk update', () => {
  test('waits for status and assignment changes to be searchable before responding', async () => {
    const handler = handlerFor('post', '/alerts/bulk-update');
    const client = {
      search: alertSearch(['a1', 'a2']),
      // Per alert: the alert update plus its activity-log entry.
      bulk: jest.fn(async () => ({ body: { items: Array.from({ length: 4 }, () => ({ update: { status: 200 } })) } })),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);

    await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { body: { ids: ['a1', 'a2'], status: 'in_progress', assignedTo: 'tier-2' } },
      { ok, customError, badRequest: jest.fn() }
    );

    expect(customError).not.toHaveBeenCalled();
    expect(ok).toHaveBeenCalledWith({ body: { requested: 2, updated: 2 } });
    const request = client.bulk.mock.calls[0][0] as any;
    expect(request.refresh).toBe('wait_for');
    expect(request.body[0]).toEqual({ update: { _index: ALERT_INDEX, _id: 'a1' } });
    expect(request.body[1].script.params.fields).toEqual(expect.objectContaining({ status: 'in_progress', assigned_to: 'tier-2', updated_by: 'analyst' }));
  });
});

describe('related alert linking', () => {

  test('waits for the link to be searchable so the panel re-read shows it (issue #11)', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineAlertRoutes(router);
    const registration = router.post.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/alerts/{id}/related`);
    expect(registration).toBeDefined();
    const handler = registration![1];

    const client = {
      search: jest.fn(async () => ({
        body: { hits: { hits: ['a1', 'a2'].map((id) => ({ _id: id, _index: ALERT_INDEX, _source: {} })) } },
      })),
      bulk: jest.fn(async () => ({ body: { items: [{ update: { status: 200 } }, { update: { status: 200 } }, { update: { status: 200 } }] } })),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);

    await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { params: { id: 'a1' }, body: { relatedIds: ['a2'], mode: 'add' } },
      { ok, customError, badRequest: jest.fn(), notFound: jest.fn() }
    );

    expect(customError).not.toHaveBeenCalled();
    expect(ok).toHaveBeenCalledWith({ body: { updated: true, alertsUpdated: 2 } });
    const request = client.bulk.mock.calls[0][0] as any;
    expect(request.refresh).toBe('wait_for');
    expect(request.body[0]).toEqual({ update: { _index: ALERT_INDEX, _id: 'a1' } });
    expect(request.body[4]).toEqual({ update: { _index: ALERT_INDEX, _id: 'a2' } });
  });
});

describe('alert hydration is guarded by the stored index family', () => {
  const hydrate = async (stored: any, raw: Record<string, any>) => {
    const handler = handlerFor('get', '/alerts/{id}');
    const client = {
      search: jest.fn(async () => ({ body: { hits: { hits: [{ _id: 'a1', _index: ALERT_INDEX, _source: stored }] } } })),
      get: jest.fn(async ({ index, id }: any) => {
        const key = `${index}/${id}`;
        if (raw[key]) return { body: { _source: raw[key] } };
        const error: any = new Error('not found'); error.meta = { statusCode: 404 }; throw error;
      }),
    };
    const ok = jest.fn((value: any) => value);
    const response = await handler(
      { core: { opensearch: { client: { asCurrentUser: client } } } },
      { params: { id: 'a1' } },
      { ok, customError: jest.fn((v: any) => v), notFound: jest.fn((v: any) => v) }
    );
    return { client, body: ok.mock.calls[0]?.[0]?.body, response };
  };

  test('a 4.x alert hydrates from its exact wazuh-alerts-* index and takes no second hop', async () => {
    const { client, body } = await hydrate(
      { source_resolved: true, source_index: 'wazuh-alerts-4.x-2026.10.31', source_id: 'x1' },
      { 'wazuh-alerts-4.x-2026.10.31/x1': { full_log: 'raw' } }
    );
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(body._raw_source).toEqual({ full_log: 'raw' });
    expect(body._source_available).toBe(true);
    expect(body._raw_event).toBeNull();
    expect(body._source_family).toBe('wazuh4_alerts');
  });

  test('a 5.0 finding hydrates the finding, then its event only through the events matcher', async () => {
    const { client, body } = await hydrate(
      { source_resolved: true, source_index: '.ds-wazuh-findings-v5-security-000001', source_id: 'f1' },
      {
        '.ds-wazuh-findings-v5-security-000001/f1': { message: 'finding', event: { index: '.ds-wazuh-events-v5-security-000001', doc_id: 'e1' } },
        '.ds-wazuh-events-v5-security-000001/e1': { event: { original: 'raw line' } },
      }
    );
    expect(client.get).toHaveBeenCalledTimes(2);
    expect(client.get).toHaveBeenLastCalledWith({ index: '.ds-wazuh-events-v5-security-000001', id: 'e1' });
    expect(body._raw_event).toEqual({ event: { original: 'raw line' } });
    expect(body._event_available).toBe(true);
    expect(body._source_family).toBe('wazuh5_findings');
  });

  test('an event reference outside the events family is never followed', async () => {
    const { client, body } = await hydrate(
      { source_resolved: true, source_index: '.ds-wazuh-findings-v5-security-000001', source_id: 'f1' },
      { '.ds-wazuh-findings-v5-security-000001/f1': { event: { index: '.kibana_1', doc_id: 'config:1' } } }
    );
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(body._raw_event).toBeNull();
    expect(body._event_available).toBe(false);
  });

  test('a stored index outside both families is never read, even if marked resolved', async () => {
    for (const index of ['.kibana_1', 'wazuh-alert-status-v2-000001', 'wazuh-events-v5-security', '.ds-wazuh-events-v5-security-000001', 'wazuh-alerts-*']) {
      const { client, body } = await hydrate(
        { source_resolved: true, source_index: index, source_id: 'x' },
        { [`${index}/x`]: { leaked: true } }
      );
      expect(client.get).not.toHaveBeenCalled();
      expect(body._raw_source).toBeNull();
      expect(body._source_available).toBe(false);
      expect(body._source_family).toBeNull();
    }
  });
});

describe('enrichment verdict filter (step 6.3)', () => {
  const listSchema = () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineAlertRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/alerts`);
    return registration![0].validate.query;
  };

  test('the list query schema accepts only the stored verdict values', () => {
    const query = listSchema();
    expect(query.validate({ enrichmentVerdict: 'malicious' }).enrichmentVerdict).toBe('malicious');
    expect(query.validate({ enrichmentVerdict: 'suspicious' }).enrichmentVerdict).toBe('suspicious');
    expect(query.validate({ enrichmentVerdict: 'clean' }).enrichmentVerdict).toBe('clean');
    expect(() => query.validate({ enrichmentVerdict: 'any' })).toThrow();
    expect(() => query.validate({ enrichmentVerdict: 'unknown' })).toThrow();
    expect(query.validate({}).enrichmentVerdict).toBeUndefined();
  });

  test('adds a term filter on enrichment.worst_verdict to both the list and the count bodies', () => {
    const list = buildAlertListSearchBody({ enrichmentVerdict: 'malicious', statuses: 'open' });
    expect(list.query.bool.filter).toContainEqual({ term: { 'enrichment.worst_verdict': 'malicious' } });
    const counts = buildAlertCountSearchBody({ enrichmentVerdict: 'suspicious' });
    expect(counts.query.bool.filter).toEqual([{ term: { 'enrichment.worst_verdict': 'suspicious' } }]);
    expect(buildAlertCountSearchBody({}).query).toEqual({ match_all: {} });
  });
});

describe('asset criticality filter (step 6.4a)', () => {
  test('filters on the stamped asset.criticality and ignores unknown values', () => {
    const body: any = buildAlertListSearchBody({ assetCriticality: 'high,critical,bogus' });
    expect(body.query.bool.filter).toContainEqual({ terms: { 'asset.criticality': ['high', 'critical'] } });
    expect(buildAlertListSearchBody({ assetCriticality: 'bogus' }).query).toEqual({ match_all: {} });
  });
});

describe('alert CSV export (step 5.1)', () => {
  const { ALERT_EXPORT_COLUMNS, buildAlertExportSearchBody } = require('./alerts');
  const { CSV_EXPORT_MAX_ROWS, CSV_EXPORT_PAGE_SIZE } = require('../lib/http_download');

  const readAll = async (stream: any): Promise<string> => {
    let text = '';
    for await (const chunk of stream) text += chunk.toString();
    return text;
  };

  const hit = (id: string, source: Record<string, any> = {}) => ({
    _id: id, _index: ALERT_INDEX, _source: { '@timestamp': '2026-11-20T10:00:00.000Z', status: 'open', alert_uid: `uid-${id}`, ...source },
    sort: [1763632800000, `uid-${id}`],
  });

  const runExport = async (query: Record<string, any>, pages: any[][], total?: any) => {
    const handler = handlerFor('get', '/alerts/export.csv');
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
    const headers = ALERT_EXPORT_COLUMNS.map((column: any) => column.header);
    expect(headers).toEqual([
      'id', 'timestamp', 'status', 'assignee', 'severity', 'rule.level', 'severity_label', 'rule.id', 'rule.description',
      'agent.id', 'agent.name', 'data.srcip', 'data.dstip', 'asset.criticality', 'enrichment.worst_verdict',
      'reporting.sla_due_at', 'case_id', 'disposition', 'last_updated',
    ]);
    expect(new Set(headers).size).toBe(headers.length);
    for (const column of ALERT_EXPORT_COLUMNS) expect(typeof column.value).toBe('function');
    const record = { _id: 'a1', _source: { rule: { level: 12, id: '5710', description: 'brute force' }, severity_label: null, case_id: 'c1', updated_at: '2026-11-20T11:00:00.000Z', reporting: { sla_due_at: '2026-11-21T00:00:00.000Z' } } };
    const cells = Object.fromEntries(ALERT_EXPORT_COLUMNS.map((column: any) => [column.header, column.value(record)]));
    expect(cells).toEqual(expect.objectContaining({ id: 'a1', severity: 'critical', 'rule.level': 12, severity_label: '', 'rule.id': '5710', case_id: 'c1', disposition: '', last_updated: '2026-11-20T11:00:00.000Z', 'reporting.sla_due_at': '2026-11-21T00:00:00.000Z' }));
    expect(ALERT_EXPORT_COLUMNS.find((c: any) => c.header === 'disposition').value({ _id: 'a2', _source: { status: 'closed', disposition: 'false_positive' } })).toBe('false_positive');
    expect(ALERT_EXPORT_COLUMNS.find((c: any) => c.header === 'severity').value({ _id: 'f1', _source: { rule: { level: null }, severity_label: 'High' } })).toBe('high');
  });

  test('the export route accepts exactly the list filters and forwards them to the bool query', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineAlertRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/alerts/export.csv`);
    expect(registration).toBeDefined();
    const schema = registration![0].validate.query;
    expect(schema.validate({ statuses: 'open', levelMin: 7, enrichmentVerdict: 'malicious' })).toEqual(expect.objectContaining({ statuses: 'open', levelMin: 7 }));
    expect(() => schema.validate({ size: 10 })).toThrow();
    expect(() => schema.validate({ enrichmentVerdict: 'any' })).toThrow();

    const query = { statuses: 'open,in_progress', ruleIds: '5710', agentNames: 'web-1', assignedTo: 'tier-2', from: '2026-11-01', to: '2026-11-20', q: 'ssh' };
    const { client } = await runExport(query, [[hit('a1')]]);
    const body = client.search.mock.calls[0][0].body;
    expect(client.search.mock.calls[0][0].index).toBe('wazuh-alert-status-v2-read');
    expect(body).toEqual(buildAlertExportSearchBody(query));
    expect(body.query.bool.filter).toEqual(expect.arrayContaining([
      { terms: { status: ['open', 'in_progress'] } },
      { terms: { 'rule.id': ['5710'] } },
      { terms: { 'agent.name': ['web-1'] } },
      { terms: { assigned_to: ['tier-2'] } },
      { range: { '@timestamp': { gte: '2026-11-01', lte: '2026-11-20' } } },
    ]));
    expect(body.query.bool.must[0].query_string.query).toBe('ssh');
    expect(body.sort).toEqual([{ '@timestamp': { order: 'desc' } }, { alert_uid: { order: 'asc' } }]);
    expect(body.size).toBe(CSV_EXPORT_PAGE_SIZE);
    expect(body.search_after).toBeUndefined();
  });

  test('pages with search_after across three pages and writes every row after the header', async () => {
    const page = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => hit(`${prefix}${i}`));
    const pages = [page('p1-', CSV_EXPORT_PAGE_SIZE), page('p2-', CSV_EXPORT_PAGE_SIZE), page('p3-', 5)];
    const { client, rows, result } = await runExport({}, pages);
    expect(result.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(result.headers['x-wam-truncated']).toBeUndefined();
    expect(client.search).toHaveBeenCalledTimes(3);
    expect(client.search.mock.calls[0][0].body.search_after).toBeUndefined();
    expect(client.search.mock.calls[1][0].body.search_after).toEqual([1763632800000, `uid-p1-${CSV_EXPORT_PAGE_SIZE - 1}`]);
    expect(client.search.mock.calls[2][0].body.search_after).toEqual([1763632800000, `uid-p2-${CSV_EXPORT_PAGE_SIZE - 1}`]);
    expect(rows).toHaveLength(1 + 2 * CSV_EXPORT_PAGE_SIZE + 5);
    expect(rows[0]).toBe(ALERT_EXPORT_COLUMNS.map((c: any) => c.header).join(','));
    expect(rows[1].startsWith('p1-0,2026-11-20T10:00:00.000Z,open,')).toBe(true);
    expect(rows[rows.length - 1].startsWith('p3-4,')).toBe(true);
  });

  test('stops at the row cap, sends x-wam-truncated and fetches nothing beyond it', async () => {
    const pageCount = CSV_EXPORT_MAX_ROWS / CSV_EXPORT_PAGE_SIZE;
    const pages = Array.from({ length: pageCount + 2 }, (_, p) => Array.from({ length: CSV_EXPORT_PAGE_SIZE }, (_, i) => hit(`p${p}-${i}`)));
    const { client, rows, result } = await runExport({}, pages, { value: CSV_EXPORT_MAX_ROWS + 1, relation: 'eq' });
    expect(result.headers['x-wam-truncated']).toBe('true');
    expect(rows).toHaveLength(1 + CSV_EXPORT_MAX_ROWS);
    expect(client.search).toHaveBeenCalledTimes(pageCount);
    expect(client.search.mock.calls[0][0].body.track_total_hits).toBe(CSV_EXPORT_MAX_ROWS + 1);
  });

  test('guards formula cells and names the attachment wam-alerts-<date>.csv', async () => {
    const { result, rows } = await runExport({}, [[
      hit('a1', { rule: { id: '1', description: '=HYPERLINK("http://evil")' }, agent: { name: 'web,1' }, assigned_to: '-bob' }),
    ]]);
    expect(result.headers['content-disposition']).toMatch(/^attachment; filename="wam-alerts-\d{4}-\d{2}-\d{2}\.csv"$/);
    expect(result.headers['cache-control']).toBe('no-store');
    expect(rows[1]).toContain('"\'=HYPERLINK(""http://evil"")"');
    expect(rows[1]).toContain('"web,1"');
    expect(rows[1]).toContain('"\'-bob"');
  });

  test('a failing first search is reported as an error response, not an empty file', async () => {
    const handler = handlerFor('get', '/alerts/export.csv');
    const error: any = new Error('forbidden'); error.meta = { statusCode: 403 };
    const client = { search: jest.fn(async (_request: any) => { throw error; }) };
    const ok = jest.fn();
    const customError = jest.fn((value: any) => value);
    await handler({ core: { opensearch: { client: { asCurrentUser: client } } } }, { query: {} }, { ok, customError });
    expect(ok).not.toHaveBeenCalled();
    expect(customError).toHaveBeenCalledWith({ statusCode: 403, body: { message: 'forbidden' } });
  });
});

describe('SLA due-date filters and sort (step 3.2)', () => {
  const now = '2026-11-21T10:00:00.000Z';
  const soon = '2026-11-21T11:00:00.000Z';
  const statuses = { terms: { status: ['open', 'in_progress'] } };

  test('the list query schema accepts only the three SLA states', () => {
    expect(filterQuerySchema.validate({ slaState: 'breached' }).slaState).toBe('breached');
    expect(filterQuerySchema.validate({ slaState: 'due_soon' }).slaState).toBe('due_soon');
    expect(filterQuerySchema.validate({ slaState: 'on_track' }).slaState).toBe('on_track');
    expect(() => filterQuerySchema.validate({ slaState: 'late' })).toThrow();
  });

  test('slaState produces the expected bool clauses over reporting.sla_due_at and combines with the other filters', () => {
    const breached: any = buildBoolQuery({ slaState: 'breached', statuses: 'open', assignedTo: 'alice' }, true, now);
    expect(breached.bool.filter).toContainEqual({ terms: { status: ['open'] } });
    expect(breached.bool.filter).toContainEqual({ terms: { assigned_to: ['alice'] } });
    expect(breached.bool.filter).toContainEqual({ bool: { filter: [{ range: { 'reporting.sla_due_at': { lt: now } } }, statuses] } });
    const dueSoon: any = buildBoolQuery({ slaState: 'due_soon' }, true, now);
    expect(dueSoon.bool.filter).toEqual([{ bool: { filter: [{ range: { 'reporting.sla_due_at': { gte: now, lte: soon } } }, statuses] } }]);
    const onTrack: any = buildBoolQuery({ slaState: 'on_track' }, false, now);
    expect(onTrack.bool.filter).toEqual([{ bool: { filter: [{ range: { 'reporting.sla_due_at': { gt: soon } } }, statuses] } }]);
    // The counts body carries the same clause.
    expect(buildAlertCountSearchBody({ slaState: 'breached' }).query.bool.filter[0].bool.filter[1]).toEqual(statuses);
  });

  test('sort by due round-trips: the alias and the stored path both sort on reporting.sla_due_at, undated last', () => {
    expect(resolveAlertSortField('sla_due_at')).toBe('reporting.sla_due_at');
    expect(resolveAlertSortField('reporting.sla_due_at')).toBe('reporting.sla_due_at');
    expect(resolveAlertSortField(undefined)).toBe('@timestamp');
    expect(resolveAlertSortField('rule.level')).toBe('rule.level');
    // Own-property lookup only: an inherited member of the alias map must not
    // leak out as a sort field.
    expect(resolveAlertSortField('toString')).toBe('toString');
    expect(resolveAlertSortField('constructor')).toBe('constructor');
    const body = buildAlertListSearchBody({ sortField: 'sla_due_at', sortDirection: 'asc' });
    expect(body.sort).toEqual([{ 'reporting.sla_due_at': { order: 'asc', missing: '_last' } }]);
    expect(buildAlertListSearchBody({}).sort).toEqual([{ '@timestamp': { order: 'desc', missing: '_last' } }]);
  });
});

describe('disposition on alert close (step 2.4)', () => {
  const run = async (body: Record<string, any>, sources: Record<string, any> = {}) => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineAlertRoutes(router);
    const [config, handler] = router.post.mock.calls.find(([c]: any[]) => c.path === `${API_ROOT}/alerts/bulk-update`)!;
    const validated = config.validate.body.validate(body);
    const ids: string[] = validated.ids;
    const client = {
      search: jest.fn(async () => ({ body: { hits: { hits: ids.map((id) => ({ _id: id, _index: ALERT_INDEX, _source: { status: 'open', ...(sources[id] || {}) } })) } } })),
      bulk: jest.fn(async () => ({ body: { items: Array.from({ length: ids.length * 2 }, () => ({ update: { status: 200 } })) } })),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);
    const badRequest = jest.fn((value: any) => value);
    await handler({ core: { opensearch: { client: { asCurrentUser: client } } } }, { body: validated }, { ok, customError, badRequest });
    expect(customError).not.toHaveBeenCalled();
    expect(badRequest).not.toHaveBeenCalled();
    const request = (client.bulk.mock.calls as any[])[0][0];
    return { client, ok, fields: request.body[1].script.params.fields, entry: request.body[1].script.params.entry, activity: request.body[3] };
  };

  test('the body accepts an optional disposition and a bounded reason', () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineAlertRoutes(router);
    const [config] = router.post.mock.calls.find(([c]: any[]) => c.path === `${API_ROOT}/alerts/bulk-update`)!;
    expect(config.validate.body.validate({ ids: ['a1'], status: 'closed', disposition: 'benign', closureReason: 'Expected' })).toEqual(
      { ids: ['a1'], status: 'closed', disposition: 'benign', closureReason: 'Expected' }
    );
    expect(() => config.validate.body.validate({ ids: ['a1'], status: 'closed', disposition: 'resolved' })).toThrow();
    expect(() => config.validate.body.validate({ ids: ['a1'], status: 'closed', closureReason: 'x'.repeat(2001) })).toThrow();
  });

  test('a close writes the disposition and the trimmed reason with the status, in one scripted update, and audits them', async () => {
    const { fields, entry, activity } = await run({ ids: ['a1', 'a2'], status: 'closed', disposition: 'false_positive', closureReason: '  Known scanner  ' });
    expect(fields).toEqual(expect.objectContaining({ status: 'closed', disposition: 'false_positive', closure_reason: 'Known scanner' }));
    expect(entry).toEqual(expect.objectContaining({ action: 'status_change', to: 'closed', disposition: 'false_positive' }));
    expect(activity).toEqual(expect.objectContaining({ action: 'status_change', to: 'closed', details: { disposition: 'false_positive', closure_reason: 'Known scanner' } }));
  });

  test('a close without a disposition leaves the field alone; any other status change never touches it (reopen keeps it for audit)', async () => {
    const plain = await run({ ids: ['a1'], status: 'closed' });
    expect(plain.fields).not.toHaveProperty('disposition');
    expect(plain.fields).not.toHaveProperty('closure_reason');
    expect(plain.entry).not.toHaveProperty('disposition');
    expect(plain.activity).not.toHaveProperty('details');

    const reopen = await run({ ids: ['a1'], status: 'open', disposition: 'benign', closureReason: 'stale' }, { a1: { status: 'closed', disposition: 'false_positive' } });
    expect(reopen.fields).toEqual({ updated_at: expect.any(String), updated_by: 'analyst', status: 'open' });
    expect(reopen.entry).not.toHaveProperty('disposition');

    const assign = await run({ ids: ['a1'], assignedTo: 'bob', disposition: 'benign' });
    expect(assign.fields).toEqual({ updated_at: expect.any(String), updated_by: 'analyst', assigned_to: 'bob' });
  });

  test('the list, count and export filters accept a csv disposition and produce one terms clause (unknown values ignored)', () => {
    expect(filterQuerySchema.validate({ disposition: 'false_positive,benign' })).toEqual({ disposition: 'false_positive,benign' });
    const query = buildBoolQuery({ statuses: 'closed', disposition: 'false_positive,bogus,benign' }, true);
    expect(query.bool.filter).toContainEqual({ terms: { disposition: ['false_positive', 'benign'] } });
    expect(buildBoolQuery({ disposition: 'bogus' }, true)).toEqual({ match_all: {} });
    expect(buildAlertCountSearchBody({ disposition: 'duplicate' }).query.bool.filter).toContainEqual({ terms: { disposition: ['duplicate'] } });
    const { buildAlertExportSearchBody } = require('./alerts');
    expect(buildAlertExportSearchBody({ disposition: 'duplicate' }).query.bool.filter).toContainEqual({ terms: { disposition: ['duplicate'] } });
  });
});
