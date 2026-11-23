// These assertions describe the Wazuh 4.x behaviour of this module (native
// alert indices, numeric rule levels, the 4.x channel/source set). The build
// target is a build-time constant and CI runs this suite once per matrix
// entry, including the 5.0 one, so pin it rather than assert whichever
// target happens to be checked in.
jest.mock('../../common/build_info', () => ({ ...(jest.requireActual('../../common/build_info') as object), TARGET_WAZUH_MAJOR: 4, TARGET_WAZUH_VERSION: '4.14.10' }));

import { API_ROOT, ENRICHMENT_CACHE_INDEX, META_INDEX, ACTIVITY_WRITE_ALIAS } from '../../common';
import { ENCRYPTION_KEY_ENV_VAR } from '../lib/secrets_config';
import { ENRICHMENT_WRITE_ATTEMPTS, defineEnrichmentRoutes } from './enrichment';

jest.mock('../lib/authorization', () => ({ requirePluginAdmin: jest.fn() }));
jest.mock('../lib/enrichment/abuseipdb', () => ({ abuseIpDbProvider: { kind: 'abuseipdb', lookup: jest.fn() } }));

/* eslint-disable @typescript-eslint/no-var-requires */
const requirePluginAdmin: jest.Mock = require('../lib/authorization').requirePluginAdmin;
const abuseLookup: jest.Mock = require('../lib/enrichment/abuseipdb').abuseIpDbProvider.lookup;
/* eslint-enable @typescript-eslint/no-var-requires */

const KEY = 'unit-test-encryption-key-with-32-plus-characters';

function forbidden() {
  const error: any = new Error('Administrator permission is required for this operation.');
  error.statusCode = 403;
  throw error;
}

function clientWith(settings: any | null) {
  const client = {
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && settings !== null) return { body: { _source: settings } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    index: jest.fn(async (req: any) => {
      if (req.index === META_INDEX) settings = req.body;
      return { body: { result: 'created' } };
    }),
  };
  return client;
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
  defineEnrichmentRoutes(router);
  const find = (method: 'get' | 'post' | 'put', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration as [any, any];
  };
  return {
    getSettings: find('get', '/enrichment/settings'),
    putSettings: find('put', '/enrichment/settings'),
    lookup: find('post', '/enrichment/lookup'),
    test: find('post', '/enrichment/test/{sourceId}'),
  };
}

function contextWith(client: any) {
  return { core: { opensearch: { client: { asCurrentUser: client } } } } as any;
}

const misp = { id: 'misp-1', name: 'Corp MISP', kind: 'misp', enabled: true, baseUrl: 'https://misp.example.org', apiKey: 'k3y' };

describe('enrichment routes', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    requirePluginAdmin.mockReset();
    requirePluginAdmin.mockResolvedValue({ name: 'admin', source: 'security_plugin', securityRoles: ['all_access'] });
    abuseLookup.mockReset();
  });
  afterAll(() => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
  });

  test('registers the four routes with schema validation on every input-taking route', () => {
    const r = routes();
    expect(r.getSettings[0].validate).toBe(false);
    expect(r.putSettings[0].validate.body).toBeDefined();
    expect(r.lookup[0].validate.body).toBeDefined();
    expect(r.lookup[0].validate.query).toBeDefined();
    expect(r.test[0].validate.params).toBeDefined();
  });

  test('PUT body schema accepts a full source and forbids unknown keys / bad enums', () => {
    const { putSettings } = routes();
    const body = putSettings[0].validate.body;
    const ok = body.validate({
      sources: [{ ...misp, supports: ['ip', 'hash'], cacheTtlSeconds: 600, timeoutMs: 5000, apiKeyConfigured: true, builtIn: false, apiKey: null }],
    });
    expect(ok.sources[0].enabled).toBe(true);
    expect(() => body.validate({ sources: [{ ...misp, kind: 'virustotal' }] })).toThrow();
    expect(() => body.validate({ sources: [{ ...misp, supports: ['email'] }] })).toThrow();
    expect(() => body.validate({ sources: [{ ...misp, extra: 1 }] })).toThrow();
    expect(() => body.validate({ sources: [{ ...misp, verdictMap: { bad: 'evil' } }] })).toThrow();
    const lookup = routes().lookup[0].validate.body;
    expect(() => lookup.validate({ type: 'email', value: 'x' })).toThrow();
    expect(() => lookup.validate({ type: 'ip', value: '' })).toThrow();
    expect(lookup.validate({ type: 'ip', value: '8.8.8.8', sourceIds: ['a'] })).toEqual({ type: 'ip', value: '8.8.8.8', sourceIds: ['a'] });
  });

  test('settings and test routes are admin-only; lookup is open to every user', async () => {
    requirePluginAdmin.mockImplementation(async () => forbidden());
    const r = routes();
    const client = clientWith(null);
    const res = response();
    expect((await r.getSettings[1](contextWith(client), {}, res)).kind).toBe('forbidden');
    expect((await r.putSettings[1](contextWith(client), { body: { sources: [] } }, res)).kind).toBe('forbidden');
    expect((await r.test[1](contextWith(client), { params: { sourceId: 'x' } }, res)).kind).toBe('forbidden');
    expect(client.index).not.toHaveBeenCalled();

    const open = await r.lookup[1](contextWith(client), { body: { type: 'ip', value: '8.8.8.8' }, query: {} }, res);
    expect(open.kind).toBe('ok');
    expect(open.body.value).toBe('8.8.8.8');
    expect(Array.isArray(open.body.results)).toBe(true);
  });

  test('PUT rejects a bad base URL with 400 and stores a good one with the key encrypted and an audit event', async () => {
    const r = routes();
    const client = clientWith(null);
    const res = response();
    const bad = await r.putSettings[1](contextWith(client), { body: { sources: [{ ...misp, baseUrl: 'https://misp.local' }] } }, res);
    expect(bad.kind).toBe('badRequest');
    expect(bad.body.message).toMatch(/local/);
    expect(client.index).not.toHaveBeenCalled();

    const good = await r.putSettings[1](contextWith(client), { body: { sources: [misp] } }, res);
    expect(good.kind).toBe('ok');
    // The checked-in build targets Wazuh 4.x, so the 5.0-only local CTI source is not listed.
    expect(good.body.sources.map((s: any) => s.id)).toEqual(['misp-1']);
    expect(good.body.sources[0]).toMatchObject({ apiKeyConfigured: true });
    expect(good.body.sources[0].apiKey).toBeUndefined();
    expect(good.body.encryptionConfigured).toBe(true);
    const writes = client.index.mock.calls.map((c: any[]) => c[0]);
    expect(writes[0].index).toBe(META_INDEX);
    expect(writes[0].body.sources[0].apiKey).not.toBe('k3y');
    expect(writes[1].index).toBe(ACTIVITY_WRITE_ALIAS);
    expect(writes[1].body).toMatchObject({ target_type: 'system', target_id: 'enrichment_settings', action: 'enrichment_settings_updated', user: 'admin' });

    const read = await r.getSettings[1](contextWith(client), {}, res);
    expect(read.body.sources[0]).toMatchObject({ id: 'misp-1', apiKeyConfigured: true });
  });

  test('lookup runs the configured sources through the cache and reports per-source failures', async () => {
    const r = routes();
    const client = clientWith(null);
    const res = response();
    await r.putSettings[1](contextWith(client), { body: { sources: [{ id: 'abuse', name: 'AbuseIPDB', kind: 'abuseipdb', enabled: true, apiKey: 'k3y' }] } }, res);
    abuseLookup.mockRejectedValueOnce(new Error('HTTP 429'));
    const failed = await r.lookup[1](contextWith(client), { body: { type: 'ip', value: '203.0.113.7', sourceIds: ['abuse'] }, query: {} }, res);
    expect(failed.body.results).toEqual([{ sourceId: 'abuse', sourceName: 'AbuseIPDB', kind: 'abuseipdb', status: 'error', cached: false, error: 'HTTP 429' }]);

    abuseLookup.mockResolvedValueOnce({ source: 'abuse', verdict: 'malicious', score: 99, tags: [], link: null, summary: 'bad', checkedAt: 'x' });
    const ok = await r.lookup[1](contextWith(client), { body: { type: 'ip', value: '203.0.113.7', sourceIds: ['abuse'] }, query: { refresh: true } }, res);
    expect(ok.body.results[0]).toMatchObject({ status: 'ok', cached: false, result: { verdict: 'malicious' } });
    expect(client.index.mock.calls.some((c: any[]) => c[0].index === ENRICHMENT_CACHE_INDEX)).toBe(true);

    const invalid = await r.lookup[1](contextWith(client), { body: { type: 'ip', value: 'nope' }, query: {} }, res);
    expect(invalid.kind).toBe('badRequest');
  });

  test('test route looks up the benign value and 404s an unknown source', async () => {
    const r = routes();
    const client = clientWith(null);
    const res = response();
    await r.putSettings[1](contextWith(client), { body: { sources: [{ id: 'abuse', name: 'AbuseIPDB', kind: 'abuseipdb', enabled: false, apiKey: 'k3y' }] } }, res);
    abuseLookup.mockResolvedValueOnce({ source: 'abuse', verdict: 'clean', score: 0, tags: [], link: null, summary: 'fine', checkedAt: 'x' });
    const ok = await r.test[1](contextWith(client), { params: { sourceId: 'abuse' } }, res);
    expect(ok.body).toMatchObject({ sourceId: 'abuse', status: 'ok', type: 'ip', value: '8.8.8.8', result: { verdict: 'clean' } });
    expect(abuseLookup.mock.calls[0][0].source.apiKey).toBe('k3y');
    const missing = await r.test[1](contextWith(client), { params: { sourceId: 'ghost' } }, res);
    expect(missing.kind).toBe('notFound');
    expect(missing.body.message).toMatch(/ghost/);
  });
});

// ---------------------------------------------------------------------------
// Step 6.3: per-alert lookup that stores a bounded `enrichment` object
// ---------------------------------------------------------------------------

jest.mock('../lib/opensearch', () => ({
  ...(jest.requireActual('../lib/opensearch') as object),
  getCurrentUsername: jest.fn(async () => 'analyst'),
}));

/* eslint-disable @typescript-eslint/no-var-requires */
const { PLUGIN_OWNED_FIELDS } = require('../lib/sync_job');
const { alertStatusMapping } = require('../lib/mappings');
const { MAX_ALERT_ENRICHMENT_ITEMS, MAX_ALERT_ENRICHMENT_TAGS } = require('../../common');
/* eslint-enable @typescript-eslint/no-var-requires */

const ALERT_INDEX = 'wazuh-alert-status-v2-000007';

/**
 * Client whose alert record behaves like a real document: the ids search
 * reports `_seq_no` / `_primary_term`, and an update guarded by a stale
 * `if_seq_no` answers 409 instead of applying; a successful update applies
 * the partial doc and bumps the sequence number.
 */
function alertClient(alertSource: any, settings: any | null = null) {
  const base: any = clientWith(settings);
  const doc = { source: { ...alertSource }, seqNo: 1, primaryTerm: 1 };
  base.doc = doc;
  base.search = jest.fn(async (req: any) => {
    if (req.body?.query?.ids) {
      return {
        body: {
          hits: {
            hits: [{ _id: 'alert-1', _index: ALERT_INDEX, _source: { ...doc.source }, _seq_no: doc.seqNo, _primary_term: doc.primaryTerm }],
          },
        },
      };
    }
    // Sibling verdict search (term threat.sibling_of): none in these tests.
    return { body: { hits: { hits: [] } } };
  });
  base.update = jest.fn(async (req: any) => {
    if (req.if_seq_no !== undefined && (req.if_seq_no !== doc.seqNo || req.if_primary_term !== doc.primaryTerm)) {
      throw Object.assign(new Error('version conflict'), { meta: { statusCode: 409 } });
    }
    doc.source = { ...doc.source, ...req.body.doc };
    doc.seqNo += 1;
    return { body: { result: 'updated' } };
  });
  return base;
}

function alertRoute() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineEnrichmentRoutes(router);
  const registration = router.post.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/enrichment/alerts/{alertId}/lookup`);
  expect(registration).toBeDefined();
  return registration as [any, any];
}

async function enableAbuse(client: any) {
  await routes().putSettings[1](contextWith(client), { body: { sources: [{ id: 'abuse', name: 'AbuseIPDB', kind: 'abuseipdb', enabled: true, apiKey: 'k3y' }] } }, response());
}

describe('per-alert enrichment lookup (stored on the alert)', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    requirePluginAdmin.mockResolvedValue({ name: 'admin', source: 'security_plugin', securityRoles: ['all_access'] });
  });

  test('validates params, query and body like the plain lookup route', () => {
    const [config] = alertRoute();
    expect(() => config.validate.params.validate({ alertId: '' })).toThrow();
    expect(() => config.validate.body.validate({ type: 'email', value: 'x' })).toThrow();
    expect(() => config.validate.body.validate({ type: 'ip', value: '1.1.1.1', extra: true })).toThrow();
    expect(config.validate.body.validate({ type: 'ip', value: '1.1.1.1' })).toEqual({ type: 'ip', value: '1.1.1.1' });
    expect(config.validate.query.validate({ refresh: true })).toEqual({ refresh: true });
  });

  test('enrichment is a plugin-owned, mapped top-level field with keyword verdict / float score / date checked_at', () => {
    expect(PLUGIN_OWNED_FIELDS).toContain('enrichment');
    const mapping = alertStatusMapping.properties.enrichment;
    expect(mapping.properties.worst_verdict.type).toBe('keyword');
    expect(mapping.properties.updated_at.type).toBe('date');
    const item = mapping.properties.items.properties;
    expect(item.type.type).toBe('keyword');
    expect(item.value.type).toBe('keyword');
    expect(item.source.type).toBe('keyword');
    expect(item.verdict.type).toBe('keyword');
    expect(item.score.type).toBe('float');
    expect(item.checked_at.type).toBe('date');
  });

  test('stores the merged verdicts on the resolved managed index with a partial update that waits for refresh, and audits it', async () => {
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' } });
    await enableAbuse(client);
    abuseLookup.mockResolvedValueOnce({
      source: 'abuse', verdict: 'malicious', score: 99, link: 'https://www.abuseipdb.com/check/203.0.113.7', summary: 'bad',
      checkedAt: '2026-11-20T10:00:00.000Z', tags: Array.from({ length: 25 }, (_, i) => `tag-${i}`),
    });
    const [, handler] = alertRoute();
    const res = response();
    const out = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, res);
    expect(out.kind).toBe('ok');
    expect(out.body.alertId).toBe('alert-1');
    expect(out.body.results[0]).toMatchObject({ sourceId: 'abuse', status: 'ok' });
    expect(out.body.enrichment.worst_verdict).toBe('malicious');
    expect(out.body.enrichment.items).toHaveLength(1);
    expect(out.body.enrichment.items[0]).toMatchObject({ type: 'ip', value: '203.0.113.7', source: 'abuse', verdict: 'malicious', score: 99, checked_at: '2026-11-20T10:00:00.000Z' });
    expect(out.body.enrichment.items[0].tags).toHaveLength(MAX_ALERT_ENRICHMENT_TAGS);

    expect(client.update).toHaveBeenCalledTimes(1);
    const write = client.update.mock.calls[0][0];
    expect(write.index).toBe(ALERT_INDEX);
    expect(write.id).toBe('alert-1');
    expect(write.refresh).toBe('wait_for');
    expect(write).toMatchObject({ if_seq_no: 1, if_primary_term: 1 });
    expect(client.search.mock.calls[0][0].body.seq_no_primary_term).toBe(true);
    expect(Object.keys(write.body)).toEqual(['doc']);
    expect(Object.keys(write.body.doc)).toEqual(['enrichment']);
    expect(write.body.doc.enrichment).toEqual(out.body.enrichment);

    const audit = client.index.mock.calls.map((c: any[]) => c[0]).find((c: any) => c.index === ACTIVITY_WRITE_ALIAS && c.body.action === 'enrichment_lookup');
    expect(audit.body).toMatchObject({ target_type: 'alert', target_id: 'alert-1', user: 'analyst', to: 'ip:203.0.113.7' });
  });

  test('keeps earlier items for other indicators, replaces the same (source, type, value), and caps the list', async () => {
    const stale = Array.from({ length: MAX_ALERT_ENRICHMENT_ITEMS }, (_, i) => ({
      type: 'hash', value: `h${i}`, source: 'abuse', verdict: 'clean', score: 0, tags: [], link: null,
      checked_at: `2026-11-01T00:00:${String(i % 60).padStart(2, '0')}.000Z`,
    }));
    stale[0] = { ...stale[0], type: 'ip', value: '203.0.113.7', verdict: 'suspicious' };
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' }, enrichment: { updated_at: 'x', worst_verdict: 'suspicious', items: stale } });
    await enableAbuse(client);
    abuseLookup.mockResolvedValueOnce({ source: 'abuse', verdict: 'clean', score: 1, tags: [], link: null, summary: 'ok', checkedAt: '2026-11-20T10:00:00.000Z' });
    const [, handler] = alertRoute();
    const out = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, response());
    expect(out.kind).toBe('ok');
    const { items, worst_verdict: worst } = out.body.enrichment;
    expect(items).toHaveLength(MAX_ALERT_ENRICHMENT_ITEMS);
    expect(items[0]).toMatchObject({ type: 'ip', value: '203.0.113.7', verdict: 'clean' });
    expect(items.filter((i: any) => i.value === '203.0.113.7')).toHaveLength(1);
    expect(worst).toBe('clean');
  });

  test('a failed source keeps the previous stored item and never writes an error entry', async () => {
    const previous = { type: 'ip', value: '203.0.113.7', source: 'abuse', verdict: 'malicious', score: 90, tags: [], link: null, checked_at: '2026-11-01T00:00:00.000Z' };
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' }, enrichment: { updated_at: 'x', worst_verdict: 'malicious', items: [previous] } });
    await enableAbuse(client);
    abuseLookup.mockRejectedValueOnce(new Error('HTTP 429'));
    const [, handler] = alertRoute();
    const out = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.results[0].status).toBe('error');
    expect(out.body.enrichment.items).toEqual([previous]);
    expect(out.body.enrichment.worst_verdict).toBe('malicious');
  });

  test('two interleaved lookups for different indicators both survive: the stale writer gets 409, re-reads and re-merges', async () => {
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7', dstip: '198.51.100.9' } });
    await enableAbuse(client);
    abuseLookup.mockImplementation(async ({ value }: any) => ({
      source: 'abuse', verdict: value === '203.0.113.7' ? 'malicious' : 'suspicious', score: 50, tags: [], link: null, summary: 'x',
      checkedAt: '2026-11-20T10:00:00.000Z',
    }));
    const [, handler] = alertRoute();
    const [a, b] = await Promise.all([
      handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, response()),
      handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '198.51.100.9' }, query: {} }, response()),
    ]);
    expect(a.kind).toBe('ok');
    expect(b.kind).toBe('ok');
    // Both read seq_no 1; one write landed, the other conflicted and retried.
    expect(client.update).toHaveBeenCalledTimes(3);
    const stored = client.doc.source.enrichment;
    expect(stored.items.map((i: any) => i.value).sort()).toEqual(['198.51.100.9', '203.0.113.7']);
    expect(stored.worst_verdict).toBe('malicious');
    // The retried response reflects the merged record, not its stale first read.
    const last = [a, b].find((r) => r.body.enrichment.items.length === 2);
    expect(last).toBeDefined();
    expect(abuseLookup).toHaveBeenCalledTimes(2);
    const audits = client.index.mock.calls.map((c: any[]) => c[0]).filter((c: any) => c.index === ACTIVITY_WRITE_ALIAS && c.body.action === 'enrichment_lookup');
    expect(audits).toHaveLength(2);
  });

  test('gives up after bounded conflicts with the 409 instead of overwriting', async () => {
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' } });
    await enableAbuse(client);
    abuseLookup.mockResolvedValueOnce({ source: 'abuse', verdict: 'clean', score: 0, tags: [], link: null, summary: 'x', checkedAt: 'x' });
    client.update.mockImplementation(async () => {
      throw Object.assign(new Error('version conflict'), { meta: { statusCode: 409 } });
    });
    const [, handler] = alertRoute();
    const out = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, response());
    expect(out.kind).toBe('customError');
    expect(out.statusCode).toBe(409);
    expect(client.update).toHaveBeenCalledTimes(ENRICHMENT_WRITE_ATTEMPTS);
  });

  test('when no enabled source supports the type nothing is written or audited and the stored object is returned as is', async () => {
    const previous = { updated_at: '2026-11-01T00:00:00.000Z', worst_verdict: 'malicious', items: [{ type: 'ip', value: '203.0.113.7', source: 'abuse', verdict: 'malicious', score: 90, tags: [], link: null, checked_at: '2026-11-01T00:00:00.000Z' }] };
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' }, syscheck: { md5_after: 'd41d8cd98f00b204e9800998ecf8427e' }, enrichment: previous });
    await enableAbuse(client); // AbuseIPDB supports ip only
    const [, handler] = alertRoute();
    const out = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e' }, query: {} }, response());
    expect(out.kind).toBe('ok');
    expect(out.body.results).toEqual([]);
    expect(out.body.enrichment).toEqual(previous);
    expect(client.update).not.toHaveBeenCalled();
    expect(client.index.mock.calls.map((c: any[]) => c[0]).some((c: any) => c.index === ACTIVITY_WRITE_ALIAS && c.body.action === 'enrichment_lookup')).toBe(false);

    const bare = alertClient({ status: 'open', syscheck: { md5_after: 'd41d8cd98f00b204e9800998ecf8427e' } });
    await enableAbuse(bare);
    const none = await handler(contextWith(bare), { params: { alertId: 'alert-1' }, body: { type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e' }, query: {} }, response());
    expect(none.body.enrichment).toBeNull();
    expect(bare.update).not.toHaveBeenCalled();
  });

  test('404s an unknown alert and 400s a value the alert does not carry, without writing', async () => {
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' } });
    client.search.mockImplementationOnce(async () => ({ body: { hits: { hits: [] } } }));
    const [, handler] = alertRoute();
    const missing = await handler(contextWith(client), { params: { alertId: 'ghost' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, response());
    expect(missing.kind).toBe('notFound');

    const foreign = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '198.51.100.9' }, query: {} }, response());
    expect(foreign.kind).toBe('badRequest');
    expect(foreign.body.message).toMatch(/not a ip indicator/);
    expect(client.update).not.toHaveBeenCalled();
  });

  test('refuses to write when the alias resolves outside the managed family', async () => {
    const client = alertClient({ status: 'open', data: { srcip: '203.0.113.7' } });
    client.search.mockImplementation(async (req: any) =>
      req.body?.query?.ids
        ? { body: { hits: { hits: [{ _id: 'alert-1', _index: 'wazuh-alerts-4.x-2026.11.20', _source: { data: { srcip: '203.0.113.7' } } }] } } }
        : { body: { hits: { hits: [] } } }
    );
    const [, handler] = alertRoute();
    const out = await handler(contextWith(client), { params: { alertId: 'alert-1' }, body: { type: 'ip', value: '203.0.113.7' }, query: {} }, response());
    expect(out.kind).toBe('customError');
    expect(out.body.message).toMatch(/managed family/);
    expect(client.update).not.toHaveBeenCalled();
  });
});
