import { ACTIVITY_WRITE_ALIAS, API_ROOT, META_INDEX, REPORT_SCHEDULES_DOC_ID } from '../../common';
import { defineReportRoutes, reportRunFilename } from './reports';

jest.mock('../lib/authorization', () => ({ requirePluginAdmin: jest.fn() }));
jest.mock('../lib/identity', () => ({ trustedIdentity: jest.fn() }));
jest.mock('../lib/report_schedules/metrics', () => ({
  collectReportMetrics: jest.fn(),
  collectReportSummary: jest.fn(),
}));

/* eslint-disable @typescript-eslint/no-var-requires */
const requirePluginAdmin: jest.Mock = require('../lib/authorization').requirePluginAdmin;
const trustedIdentity: jest.Mock = require('../lib/identity').trustedIdentity;
const collectReportMetrics: jest.Mock = require('../lib/report_schedules/metrics').collectReportMetrics;
const collectReportSummary: jest.Mock = require('../lib/report_schedules/metrics').collectReportSummary;
/* eslint-enable @typescript-eslint/no-var-requires */

const summaryFixture = {
  metrics: {
    from: '', to: '', totalAlerts: 1, exact: true, alertBasis: 'exact_cohort', timingBasis: 'exact_cohort', caseBasis: 'exact_cohort',
    coverage: { closedMissingReporting: 0, assignedMissingReporting: 0 }, statusBreakdown: { open: 1, in_progress: 0, closed: 0 },
    resolvedCount: 0, assignedCount: 0, meanTimeToResolveMinutes: null, meanTimeToAssignMinutes: null, slaCompliancePct: null,
    slaBreakdown: [], slaPolicy: [], analysts: [], caseAnalysts: [],
    cases: { totalCases: 0, statusBreakdown: { open: 0, in_progress: 0, closed: 0 }, severityBreakdown: {}, meanTimeToCloseMinutes: null, closedCount: 0 },
  },
  extras: { severityBands: {}, topRules: [], topAgents: [], openCasesBySeverity: {}, breachedCount: null },
};

function forbidden() {
  const error: any = new Error('Administrator permission is required for this operation.');
  error.statusCode = 403;
  throw error;
}

/** Meta index in memory (settings doc + run docs) and an activity sink. */
function clientWith(initial: Record<string, any> = {}) {
  const docs = new Map<string, any>(Object.entries(initial));
  const activity: any[] = [];
  const notFound = () => Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
  return {
    docs,
    activity,
    get: jest.fn(async ({ index, id }: any) => {
      if (index !== META_INDEX || !docs.has(id)) throw notFound();
      return { body: { _id: id, _source: docs.get(id), _seq_no: 1, _primary_term: 1 } };
    }),
    index: jest.fn(async ({ index, id, body }: any) => {
      if (index === ACTIVITY_WRITE_ALIAS) activity.push(body);
      else if (index === META_INDEX) docs.set(id, body);
      else throw new Error(`unexpected index ${index}`);
      return { body: { result: 'created' } };
    }),
    update: jest.fn(async ({ index, id, body }: any) => {
      if (index !== META_INDEX) throw new Error(`unexpected index ${index}`);
      if (!docs.has(id) && !body.doc_as_upsert) throw notFound();
      docs.set(id, { ...(docs.get(id) || {}), ...body.doc });
      return { body: { result: 'updated' } };
    }),
    delete: jest.fn(async ({ index, id }: any) => {
      if (index !== META_INDEX) throw new Error(`unexpected index ${index}`);
      if (!docs.has(id)) throw notFound();
      docs.delete(id);
      return { body: { result: 'deleted' } };
    }),
    mget: jest.fn(async ({ body }: any) => ({
      body: { docs: body.ids.map((id: string) => (docs.has(id) ? { _id: id, found: true, _source: docs.get(id) } : { _id: id, found: false })) },
    })),
  };
}

function response() {
  return {
    ok: jest.fn((r: any) => ({ kind: 'ok', ...r })),
    badRequest: jest.fn((r: any) => ({ kind: 'badRequest', ...r })),
    forbidden: jest.fn((r: any) => ({ kind: 'forbidden', ...r })),
    notFound: jest.fn((r: any) => ({ kind: 'notFound', ...r })),
    customError: jest.fn((r: any) => ({ kind: 'customError', ...r })),
  };
}

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineReportRoutes(router);
  const find = (method: 'get' | 'post' | 'put', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration as [any, any];
  };
  return {
    metrics: find('get', '/reports/metrics'),
    exportRoute: find('get', '/reports/export'),
    getSchedules: find('get', '/reports/schedules'),
    putSchedules: find('put', '/reports/schedules'),
    lastRun: find('get', '/reports/schedules/{id}/last-run'),
    lastRunMd: find('get', '/reports/schedules/{id}/last-run.md'),
    runNow: find('post', '/reports/schedules/{id}/run-now'),
  };
}

function contextWith(client: any) {
  return { core: { opensearch: { client: { asCurrentUser: client } } } } as any;
}

const daily = { id: 'daily-8', name: 'Daily 08:00', cadence: 'daily', dayOfWeek: 1, hourUtc: 8, rangeDays: 1, channelIds: [], enabled: true };

describe('report routes', () => {
  beforeEach(() => {
    requirePluginAdmin.mockReset();
    requirePluginAdmin.mockResolvedValue({ name: 'admin', source: 'security_plugin', securityRoles: ['all_access'] });
    collectReportMetrics.mockReset();
    collectReportSummary.mockReset();
    collectReportSummary.mockResolvedValue(summaryFixture);
  });

  test('registers the routes with schema validation on every input-taking route', () => {
    const r = routes();
    expect(r.metrics[0].validate.query).toBeDefined();
    expect(r.exportRoute[0].validate.query).toBeDefined();
    expect(r.getSchedules[0].validate).toBe(false);
    expect(r.putSchedules[0].validate.body).toBeDefined();
    expect(r.lastRun[0].validate.params).toBeDefined();
    expect(r.lastRunMd[0].validate.params).toBeDefined();
    expect(r.runNow[0].validate.params).toBeDefined();
  });

  test('PUT body schema: shape, cadence literal, range bounds, cap, unknown keys', () => {
    const { body } = routes().putSchedules[0].validate;
    expect(body.validate({ schedules: [daily] }).schedules[0]).toMatchObject({ id: 'daily-8', enabled: true });
    expect(body.validate({ schedules: [{ ...daily, enabled: undefined, channelIds: undefined, dayOfWeek: undefined }] }).schedules[0].enabled).toBe(true);
    expect(() => body.validate({ schedules: [{ ...daily, cadence: 'monthly' }] })).toThrow();
    expect(() => body.validate({ schedules: [{ ...daily, rangeDays: 91 }] })).toThrow();
    expect(() => body.validate({ schedules: [{ ...daily, extra: 1 }] })).toThrow();
    expect(() => body.validate({ schedules: [{ ...daily, id: '' }] })).toThrow();
    expect(() => body.validate({ schedules: Array.from({ length: 21 }, (_, i) => ({ ...daily, id: `s${i}` })) })).toThrow();
    expect(() => body.validate({})).toThrow();
  });

  test('GET /reports/metrics returns the collector result for the current user', async () => {
    collectReportMetrics.mockResolvedValue({ totalAlerts: 5 });
    const client = clientWith();
    const res = await routes().metrics[1](contextWith(client), { query: { from: '2026-11-01', to: '2026-11-02' } }, response());
    expect(collectReportMetrics).toHaveBeenCalledWith(client, { from: '2026-11-01', to: '2026-11-02' }, expect.anything());
    expect(res).toMatchObject({ kind: 'ok', body: { totalAlerts: 5 } });
  });

  test('GET /reports/metrics carries the SLA enforcement figures of the collector unchanged', async () => {
    const enforcement = {
      slaCurrentlyBreached: { asOf: '2026-11-02T00:00:00.000Z', alerts: 2, cases: 1, byBand: { critical: 1, high: 2, medium: 0, low: 0 } },
      slaBreachesInPeriod: { total: 3, alerts: 2, cases: 1 },
      slaEscalationsInPeriod: { total: 1, byEscalation: [{ id: 'crit', name: 'Critical unassigned', count: 1 }] },
    };
    collectReportMetrics.mockResolvedValue({ ...summaryFixture.metrics, ...enforcement });
    const client = clientWith();
    const res: any = await routes().metrics[1](contextWith(client), { query: { from: '2026-11-01', to: '2026-11-02' } }, response());
    expect(res.kind).toBe('ok');
    expect(res.body.slaCurrentlyBreached).toEqual(enforcement.slaCurrentlyBreached);
    expect(res.body.slaBreachesInPeriod).toEqual(enforcement.slaBreachesInPeriod);
    expect(res.body.slaEscalationsInPeriod).toEqual(enforcement.slaEscalationsInPeriod);
    expect(Object.keys(res.body.slaEscalationsInPeriod.byEscalation[0]).sort()).toEqual(['count', 'id', 'name']);
  });

  test('GET /reports/metrics carries the dispositions and the false-positive rate by rule (step 2.4) unchanged', async () => {
    const dispositions = {
      dispositions: { true_positive: 1, false_positive: 4, benign: 0, duplicate: 0, undetermined: 1 },
      falsePositiveByRule: [{ rule_id: '5710', description: 'sshd', closed: 5, false_positive: 4, rate: 0.8 }],
    };
    collectReportMetrics.mockResolvedValue({ ...summaryFixture.metrics, ...dispositions });
    const client = clientWith();
    const res: any = await routes().metrics[1](contextWith(client), { query: { from: '2026-11-01', to: '2026-11-02' } }, response());
    expect(res.kind).toBe('ok');
    expect(res.body.dispositions).toEqual(dispositions.dispositions);
    expect(res.body.falsePositiveByRule).toEqual(dispositions.falsePositiveByRule);
    expect(Object.keys(res.body.falsePositiveByRule[0]).sort()).toEqual(['closed', 'description', 'false_positive', 'rate', 'rule_id']);
  });

  test('GET/PUT /reports/schedules and run-now require the plugin administrator', async () => {
    requirePluginAdmin.mockImplementation(forbidden);
    const r = routes();
    const client = clientWith();
    expect((await r.getSchedules[1](contextWith(client), {}, response())).kind).toBe('forbidden');
    expect((await r.putSchedules[1](contextWith(client), { body: { schedules: [daily] } }, response())).kind).toBe('forbidden');
    expect((await r.runNow[1](contextWith(client), { params: { id: 'daily-8' } }, response())).kind).toBe('forbidden');
    expect(client.index).not.toHaveBeenCalled();
    expect(collectReportSummary).not.toHaveBeenCalled();
  });

  test('PUT stores the normalised list, audits it and returns next slots; a semantic error is a 400', async () => {
    const r = routes();
    const client = clientWith();
    const res: any = await r.putSchedules[1](contextWith(client), { body: { schedules: [{ ...daily, hourUtc: 8 }] } }, response());
    expect(res.kind).toBe('ok');
    expect(res.body.schedules).toEqual([daily]);
    expect(res.body.lastRuns).toEqual({});
    expect(res.body.nextSlots['daily-8']).toMatch(/T08:00:00\.000Z$/);
    expect(res.body.updated_by).toBe('admin');
    expect(client.docs.get(REPORT_SCHEDULES_DOC_ID)).toMatchObject({ schedules: [daily], updated_by: 'admin', source: 'workbench' });
    expect(client.activity).toEqual([expect.objectContaining({ action: 'report_schedules_updated', target_id: REPORT_SCHEDULES_DOC_ID, to: '1', user: 'admin' })]);

    const bad: any = await r.putSchedules[1](contextWith(client), { body: { schedules: [{ ...daily, cadence: 'weekly', dayOfWeek: 9 }] } }, response());
    expect(bad.kind).toBe('badRequest');
    expect(bad.body.message).toMatch(/dayOfWeek/);
    expect(client.docs.get(REPORT_SCHEDULES_DOC_ID).schedules).toEqual([daily]);
  });

  test('run-now renders with the caller client, stores the run and GET lists it; last-run is open to any user', async () => {
    const r = routes();
    const client = clientWith({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] } });
    const run: any = await r.runNow[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(run.kind).toBe('ok');
    expect(collectReportSummary).toHaveBeenCalledWith(client, expect.objectContaining({ to: expect.stringMatching(/T08:00:00\.000Z$/) }));
    expect(run.body.run).toMatchObject({ schedule_id: 'daily-8', triggered_by: 'admin', error: null, truncated: false });
    expect(run.body.run.markdown).toBeUndefined();
    expect(run.body.run.markdown_bytes).toBeGreaterThan(0);
    expect(client.docs.get('report_run:daily-8')).toMatchObject({ document_type: 'report_run', triggered_by: 'admin' });
    expect(client.activity.map((a) => a.action)).toEqual(['report_schedule_run']);

    const list: any = await r.getSchedules[1](contextWith(client), {}, response());
    expect(list.body.lastRuns['daily-8']).toMatchObject({ slot: run.body.run.slot, triggered_by: 'admin' });

    requirePluginAdmin.mockImplementation(forbidden);
    const last: any = await r.lastRun[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(last.kind).toBe('ok');
    expect(last.body.run.slot).toBe(run.body.run.slot);
    client.docs.set(REPORT_SCHEDULES_DOC_ID, { schedules: [daily, { ...daily, id: 'never-ran' }] });
    const none: any = await r.lastRun[1](contextWith(client), { params: { id: 'never-ran' } }, response());
    expect(none).toMatchObject({ kind: 'ok', body: { run: null } });
  });

  test('last-run and last-run.md answer 404 for an id no schedule owns, even when a run doc exists', async () => {
    const r = routes();
    const client = clientWith({
      [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] },
      'report_run:gone': { document_type: 'report_run', schedule_id: 'gone', slot: '2026-11-20T08:00:00.000Z', markdown: '# Gone\n', error: null },
    });
    requirePluginAdmin.mockImplementation(forbidden);
    const last: any = await r.lastRun[1](contextWith(client), { params: { id: 'gone' } }, response());
    expect(last.kind).toBe('notFound');
    const md: any = await r.lastRunMd[1](contextWith(client), { params: { id: 'gone' } }, response());
    expect(md.kind).toBe('notFound');
    expect(client.get).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'report_run:gone' }));
  });

  test('PUT deletes the run docs of removed (or renamed) schedules and keeps the others', async () => {
    const r = routes();
    const client = clientWith({
      [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily, { ...daily, id: 'b' }] },
      'report_run:daily-8': { document_type: 'report_run', schedule_id: 'daily-8', slot: '2026-11-20T08:00:00.000Z', markdown: '# a\n', error: null },
      'report_run:b': { document_type: 'report_run', schedule_id: 'b', slot: '2026-11-20T08:00:00.000Z', markdown: '# b\n', error: null },
    });
    const res: any = await r.putSchedules[1](contextWith(client), { body: { schedules: [daily] } }, response());
    expect(res.kind).toBe('ok');
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: 'report_run:b' }));
    expect(client.docs.has('report_run:b')).toBe(false);
    expect(client.docs.has('report_run:daily-8')).toBe(true);
    expect(res.body.lastRuns).toEqual({ 'daily-8': expect.objectContaining({ slot: '2026-11-20T08:00:00.000Z' }) });

    // Removing a schedule that never ran is fine (404 on the run doc ignored).
    client.docs.set(REPORT_SCHEDULES_DOC_ID, { schedules: [daily, { ...daily, id: 'never' }] });
    const again: any = await r.putSchedules[1](contextWith(client), { body: { schedules: [daily] } }, response());
    expect(again.kind).toBe('ok');
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ id: 'report_run:never' }));
    // A rejected list deletes nothing.
    client.delete.mockClear();
    const bad: any = await r.putSchedules[1](contextWith(client), { body: { schedules: [{ ...daily, cadence: 'weekly', dayOfWeek: 9 }] } }, response());
    expect(bad.kind).toBe('badRequest');
    expect(client.delete).not.toHaveBeenCalled();
  });

  test('a failed run-now after a stored report keeps the Markdown downloadable', async () => {
    const r = routes();
    const client = clientWith({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] } });
    const ok: any = await r.runNow[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(ok.body.run.error).toBeNull();
    collectReportSummary.mockRejectedValue(new Error('timeout'));
    const failed: any = await r.runNow[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(failed.kind).toBe('ok');
    expect(failed.body.run).toMatchObject({ error: 'timeout', attempts: 1, slot: ok.body.run.slot, markdown_bytes: ok.body.run.markdown_bytes });
    const md: any = await r.lastRunMd[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(md.kind).toBe('ok');
    expect(md.body).toContain('# Daily 08:00');
    const list: any = await r.getSchedules[1](contextWith(client), {}, response());
    expect(list.body.lastRuns['daily-8']).toMatchObject({ error: 'timeout', failed_slot: ok.body.run.slot, markdown_bytes: ok.body.run.markdown_bytes });
  });

  test('run-now on an unknown or malformed id is a 404 and renders nothing', async () => {
    const r = routes();
    const client = clientWith({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] } });
    expect((await r.runNow[1](contextWith(client), { params: { id: 'missing' } }, response())).kind).toBe('notFound');
    expect((await r.runNow[1](contextWith(client), { params: { id: '../x' } }, response())).kind).toBe('notFound');
    expect(collectReportSummary).not.toHaveBeenCalled();
    expect(client.get).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'report_run:../x' }));
  });

  test('run-now stores a failed render as an error run (200) and the .md download then answers 404', async () => {
    collectReportSummary.mockRejectedValue(new Error('index_not_found_exception'));
    const r = routes();
    const client = clientWith({ [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] } });
    const run: any = await r.runNow[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(run.kind).toBe('ok');
    expect(run.body.run).toMatchObject({ error: 'index_not_found_exception', markdown_bytes: 0, attempts: 1, slot: '' });
    expect(client.docs.get('report_run:daily-8')).toMatchObject({ document_type: 'report_run', schedule_id: 'daily-8', error: 'index_not_found_exception' });
    const md: any = await r.lastRunMd[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(md.kind).toBe('notFound');
    expect(md.body.message).toMatch(/index_not_found_exception/);
  });

  test('last-run.md downloads the stored Markdown as an attachment', async () => {
    const r = routes();
    const client = clientWith({
      [REPORT_SCHEDULES_DOC_ID]: { schedules: [daily] },
      'report_run:daily-8': { document_type: 'report_run', schedule_id: 'daily-8', slot: '2026-11-20T08:00:00.000Z', generated_at: '2026-11-20T08:00:05.000Z', range_from: '2026-11-19T08:00:00.000Z', range_to: '2026-11-20T08:00:00.000Z', triggered_by: 'scheduler', markdown: '# Daily 08:00\n', error: null },
    });
    const res: any = await r.lastRunMd[1](contextWith(client), { params: { id: 'daily-8' } }, response());
    expect(res.kind).toBe('ok');
    expect(res.body).toBe('# Daily 08:00\n');
    expect(res.headers['content-type']).toBe('text/markdown; charset=utf-8');
    expect(res.headers['content-disposition']).toBe('attachment; filename="wam-report-daily-8-2026-11-20.md"');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect((await r.lastRunMd[1](contextWith(client), { params: { id: 'never' } }, response())).kind).toBe('notFound');
  });

  test('reportRunFilename uses the slot day', () => {
    expect(reportRunFilename('weekly', '2026-11-16T06:00:00.000Z')).toBe('wam-report-weekly-2026-11-16.md');
    expect(reportRunFilename('weekly', '')).toBe('wam-report-weekly-latest.md');
  });
});

describe('GET /reports/export (step 10.3)', () => {
  const window = { from: '2026-11-14T00:00:00.000Z', to: '2026-11-21T00:00:00.000Z' };

  beforeEach(() => {
    trustedIdentity.mockReset();
    trustedIdentity.mockResolvedValue({ name: 'analyst', source: 'security_plugin', roles: [], securityRoles: [], backendRoles: [] });
  });

  test('is registered with a query schema: window strings, format literal (default html), inline/print flags', () => {
    const { query } = routes().exportRoute[0].validate;
    expect(query.validate({ ...window })).toMatchObject({ ...window, format: 'html' });
    for (const format of ['html', 'markdown', 'csv', 'json']) expect(query.validate({ ...window, format }).format).toBe(format);
    expect(() => query.validate({ ...window, format: 'pdf' })).toThrow();
    expect(() => query.validate({ ...window, format: 'xlsx' })).toThrow();
    expect(() => query.validate({ from: 'now-7d' })).toThrow();
    expect(() => query.validate({ ...window, print: '1'.repeat(9) })).toThrow();
    expect(query.validate({ ...window, inline: '1', print: 'true' })).toMatchObject({ inline: '1', print: 'true' });
  });

  test('renders the summary for the current user as an attachment with the content type of the format', async () => {
    const r = routes();
    const client = clientWith();
    const expectations: Array<[string, string, string, (body: string) => void]> = [
      ['html', 'text/html; charset=utf-8', '.html', (body) => { expect(body.startsWith('<!DOCTYPE html>')).toBe(true); expect(body).not.toContain('<script'); expect(body).toContain('by analyst.'); }],
      ['markdown', 'text/markdown; charset=utf-8', '.md', (body) => { expect(body.startsWith('# SOC report\n')).toBe(true); expect(body).toContain('SOC report over the alerts and cases of the selected window from **2026-11-14T00:00:00.000Z**'); }],
      ['csv', 'text/csv; charset=utf-8', '.csv', (body) => { expect(body.startsWith('﻿SOC report\r\n')).toBe(true); expect(body).toContain('# Alert volume'); }],
      ['json', 'application/json; charset=utf-8', '.json', (body) => { expect(JSON.parse(body)).toMatchObject({ generated_by: 'analyst', window, metrics: { totalAlerts: 1 } }); }],
    ];
    for (const [format, contentType, extension, check] of expectations) {
      const res: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format } }, response());
      expect(res.kind).toBe('ok');
      expect(res.headers['content-type']).toBe(contentType);
      expect(res.headers['content-disposition']).toBe(`attachment; filename="wam-report-${new Date().toISOString().slice(0, 10)}-2026-11-14_2026-11-21${extension}"`);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['content-security-policy']).toContain("default-src 'none'");
      check(res.body);
    }
    expect(collectReportSummary).toHaveBeenCalledWith(client, window, expect.anything());
    expect(collectReportSummary).toHaveBeenCalledTimes(4);
    expect(client.index).not.toHaveBeenCalled();
    expect(client.update).not.toHaveBeenCalled();
  });

  test('passes the window through untouched (date math stays date math) and names the file after it', async () => {
    const r = routes();
    const client = clientWith();
    const res: any = await r.exportRoute[1](contextWith(client), { query: { from: 'now-7d', to: 'now', format: 'csv' } }, response());
    expect(collectReportSummary).toHaveBeenCalledWith(client, { from: 'now-7d', to: 'now' }, expect.anything());
    expect(res.headers['content-disposition']).toMatch(/^attachment; filename="wam-report-\d{4}-\d{2}-\d{2}-now-7d_now\.csv"$/);
  });

  test('inline HTML is shown in a tab with a nonce CSP; print=1 embeds the trigger only inline and only for html', async () => {
    const r = routes();
    const client = clientWith();
    const inline: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format: 'html', inline: '1' } }, response());
    expect(inline.headers['content-disposition']).toMatch(/^inline; filename="wam-report-.*\.html"$/);
    expect(inline.headers['referrer-policy']).toBe('no-referrer');
    expect(inline.headers['content-security-policy']).toMatch(/^default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-[A-Za-z0-9+/=]+'; base-uri 'none'; form-action 'none'$/);
    expect(inline.body).not.toContain('<script');

    const print: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format: 'html', inline: 'true', print: '1' } }, response());
    const nonce = /script-src 'nonce-([^']+)'/.exec(print.headers['content-security-policy'])![1];
    expect(print.body).toContain(`<script nonce="${nonce}">window.addEventListener("load",function(){window.print();});</script>`);

    const saved: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format: 'html', print: '1' } }, response());
    expect(saved.headers['content-disposition']).toMatch(/^attachment/);
    expect(saved.body).not.toContain('<script');

    const md: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format: 'markdown', inline: '1', print: '1' } }, response());
    expect(md.headers['content-disposition']).toMatch(/^attachment/);
    expect(md.body).not.toContain('<script');
  });

  test('an anonymous identity leaves the generating user out; a collector failure is reported with its status', async () => {
    trustedIdentity.mockResolvedValue({ name: 'anonymous', source: 'anonymous', roles: [], securityRoles: [], backendRoles: [] });
    const r = routes();
    const client = clientWith();
    const res: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format: 'json' } }, response());
    expect(JSON.parse(res.body).generated_by).toBeNull();

    collectReportSummary.mockRejectedValueOnce(Object.assign(new Error('index_not_found_exception'), { meta: { statusCode: 404 } }));
    const failed: any = await r.exportRoute[1](contextWith(client), { query: { ...window, format: 'html' } }, response());
    expect(failed.kind).toBe('notFound');
    expect(failed.body.message).toMatch(/index_not_found_exception/);
  });
});
