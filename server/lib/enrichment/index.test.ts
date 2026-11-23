import { ENRICHMENT_CACHE_INDEX, META_INDEX, WAZUH_CTI_LOCAL_SOURCE_ID } from '../../../common';
import { ENCRYPTION_KEY_ENV_VAR } from '../secrets_config';
import { encryptSecret } from '../crypto';
import { cacheDocId, sourceConfigFingerprint } from './cache';
import { canonicalLookupValue, runEnrichmentLookup, testEnrichmentSource, TEST_VALUES } from './index';

const ABUSE_FP = sourceConfigFingerprint({ kind: 'abuseipdb' });

jest.mock('./abuseipdb', () => ({ abuseIpDbProvider: { kind: 'abuseipdb', lookup: jest.fn() } }));
jest.mock('./misp', () => ({ mispProvider: { kind: 'misp', lookup: jest.fn() } }));
jest.mock('./generic_http', () => ({ genericHttpProvider: { kind: 'generic_http', lookup: jest.fn() } }));
jest.mock('./wazuh_cti_local', () => ({ wazuhCtiLocalProvider: { kind: 'wazuh_cti_local', lookup: jest.fn() } }));
// These lookups exercise the built-in local CTI source, which only exists on a
// Wazuh 5.0 build; run the suite as one regardless of the checked-in target.
jest.mock('../../../common/build_info', () => ({ ...jest.requireActual('../../../common/build_info'), TARGET_WAZUH_MAJOR: 5 }));

/* eslint-disable @typescript-eslint/no-var-requires */
const abuse: jest.Mock = require('./abuseipdb').abuseIpDbProvider.lookup;
const misp: jest.Mock = require('./misp').mispProvider.lookup;
const cti: jest.Mock = require('./wazuh_cti_local').wazuhCtiLocalProvider.lookup;
/* eslint-enable @typescript-eslint/no-var-requires */

const KEY = 'unit-test-encryption-key-with-32-plus-characters';
const NOW = new Date('2026-11-20T12:00:00.000Z');

function verdict(source: string, v: 'malicious' | 'clean' | 'unknown' = 'clean') {
  return { source, verdict: v, score: v === 'malicious' ? 90 : 0, tags: [], link: null, summary: `${source} says ${v}`, checkedAt: NOW.toISOString() };
}

interface Fixture {
  settings?: any;
  cache?: Record<string, any>;
}

function clientWith({ settings = null, cache = {} }: Fixture) {
  return {
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX) {
        if (settings === null) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
        return { body: { _source: settings } };
      }
      if (req.index === ENRICHMENT_CACHE_INDEX) {
        if (!cache[req.id]) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
        return { body: { _source: cache[req.id] } };
      }
      throw new Error(`unexpected get ${req.index}`);
    }),
    index: jest.fn(async () => ({ body: { result: 'created' } })),
  };
}

const stored = (key = encryptSecret('k3y', KEY)) => ({
  sources: [
    { id: 'abuse', name: 'AbuseIPDB', kind: 'abuseipdb', enabled: true, supports: ['ip'], cacheTtlSeconds: 600, timeoutMs: 8000, apiKey: key },
    { id: 'misp', name: 'MISP', kind: 'misp', enabled: true, supports: ['ip', 'domain'], cacheTtlSeconds: 600, timeoutMs: 8000, baseUrl: 'https://misp.example.org', apiKey: key },
    { id: 'off', name: 'Disabled', kind: 'misp', enabled: false, supports: ['ip'], cacheTtlSeconds: 600, timeoutMs: 8000, baseUrl: 'https://misp2.example.org', apiKey: '' },
    { id: WAZUH_CTI_LOCAL_SOURCE_ID, name: 'CTI', kind: 'wazuh_cti_local', enabled: true, supports: ['ip', 'domain', 'url', 'hash'], cacheTtlSeconds: 600, timeoutMs: 8000 },
  ],
});

describe('runEnrichmentLookup', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    abuse.mockReset();
    misp.mockReset();
    cti.mockReset();
  });
  afterAll(() => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
  });

  test('runs every enabled source supporting the type in parallel, decrypts keys, caches each result', async () => {
    abuse.mockResolvedValue(verdict('abuse', 'malicious'));
    misp.mockResolvedValue(verdict('misp'));
    cti.mockResolvedValue(verdict('wazuh_cti_local', 'unknown'));
    const client = clientWith({ settings: stored() });
    const res = await runEnrichmentLookup(client, { type: 'ip', value: ' 203.0.113.007 ' }, { now: NOW });
    expect(res.value).toBe('203.0.113.7');
    expect(res.results.map((r) => [r.sourceId, r.status, r.cached])).toEqual([
      ['abuse', 'ok', false],
      ['misp', 'ok', false],
      ['wazuh_cti_local', 'ok', false],
    ]);
    expect(abuse.mock.calls[0][0].source.apiKey).toBe('k3y');
    expect(abuse.mock.calls[0][0]).toMatchObject({ type: 'ip', value: '203.0.113.7', client, now: NOW });
    expect(client.index).toHaveBeenCalledTimes(3);
    const written = client.index.mock.calls.map((c: any[]) => c[0]);
    expect(written.every((w: any) => w.index === ENRICHMENT_CACHE_INDEX)).toBe(true);
    expect(written.find((w: any) => w.body.source_id === 'abuse')).toMatchObject({ id: cacheDocId('abuse', 'ip', '203.0.113.7', ABUSE_FP), body: { expires_at: '2026-11-20T12:10:00.000Z' } });
  });

  test('a cache write failure never discards a fetched verdict', async () => {
    abuse.mockResolvedValue(verdict('abuse', 'malicious'));
    const client = clientWith({ settings: stored() });
    client.index.mockRejectedValue(Object.assign(new Error('index_not_found_exception'), { meta: { statusCode: 404 } }));
    const logger = { warn: jest.fn() };
    const res = await runEnrichmentLookup(client, { type: 'ip', value: '203.0.113.7', sourceIds: ['abuse'] }, { now: NOW, logger });
    expect(res.results[0]).toMatchObject({ sourceId: 'abuse', status: 'ok', cached: false, result: { verdict: 'malicious' } });
    expect(res.results[0].error).toBeUndefined();
    expect(client.index).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('index_not_found_exception'));
  });

  test('the cache id changes with the lookup-relevant configuration of a source', async () => {
    // A hit stored under an older configuration of the same id is not served.
    const staleId = cacheDocId('misp', 'ip', '203.0.113.7', sourceConfigFingerprint({ kind: 'misp', baseUrl: 'https://old.example.org' }));
    const cached = { source_id: 'misp', type: 'ip', value: '203.0.113.7', checked_at: NOW.toISOString(), expires_at: '2999-01-01T00:00:00.000Z', result: verdict('misp', 'malicious') };
    misp.mockResolvedValue(verdict('misp', 'clean'));
    const res = await runEnrichmentLookup(clientWith({ settings: stored(), cache: { [staleId]: cached } }), { type: 'ip', value: '203.0.113.7', sourceIds: ['misp'] }, { now: NOW });
    expect(res.results[0]).toMatchObject({ cached: false, result: { verdict: 'clean' } });
    expect(misp).toHaveBeenCalledTimes(1);
    // The current configuration's id is served.
    const liveId = cacheDocId('misp', 'ip', '203.0.113.7', sourceConfigFingerprint({ kind: 'misp', baseUrl: 'https://misp.example.org' }));
    const hit = await runEnrichmentLookup(clientWith({ settings: stored(), cache: { [liveId]: cached } }), { type: 'ip', value: '203.0.113.7', sourceIds: ['misp'] }, { now: NOW });
    expect(hit.results[0]).toMatchObject({ cached: true, result: { verdict: 'malicious' } });
    expect(misp).toHaveBeenCalledTimes(1);
  });

  test('a failing source is reported per entry and never fails the others', async () => {
    abuse.mockRejectedValue(new Error('AbuseIPDB answered HTTP 429'));
    misp.mockResolvedValue(verdict('misp'));
    cti.mockResolvedValue(verdict('wazuh_cti_local', 'unknown'));
    const res = await runEnrichmentLookup(clientWith({ settings: stored() }), { type: 'ip', value: '203.0.113.7' });
    const byId = Object.fromEntries(res.results.map((r) => [r.sourceId, r]));
    expect(byId.abuse).toMatchObject({ status: 'error', error: 'AbuseIPDB answered HTTP 429' });
    expect(byId.abuse.result).toBeUndefined();
    expect(byId.misp).toMatchObject({ status: 'ok', result: { verdict: 'clean' } });
  });

  test('serves unexpired cache entries without calling the source; refresh bypasses them', async () => {
    const cached = { source_id: 'abuse', type: 'ip', value: '203.0.113.7', checked_at: NOW.toISOString(), expires_at: '2026-11-20T12:30:00.000Z', result: verdict('abuse', 'malicious') };
    const client = clientWith({ settings: stored(), cache: { [cacheDocId('abuse', 'ip', '203.0.113.7', ABUSE_FP)]: cached } });
    misp.mockResolvedValue(verdict('misp'));
    cti.mockResolvedValue(verdict('wazuh_cti_local', 'unknown'));
    const res = await runEnrichmentLookup(client, { type: 'ip', value: '203.0.113.7', sourceIds: ['abuse', 'misp'] }, { now: NOW });
    expect(res.results.map((r) => r.sourceId)).toEqual(['abuse', 'misp']);
    expect(res.results[0]).toMatchObject({ status: 'ok', cached: true, result: { verdict: 'malicious' } });
    expect(abuse).not.toHaveBeenCalled();

    abuse.mockResolvedValue(verdict('abuse', 'clean'));
    const refreshed = await runEnrichmentLookup(client, { type: 'ip', value: '203.0.113.7', sourceIds: ['abuse'], refresh: true }, { now: NOW });
    expect(refreshed.results[0]).toMatchObject({ cached: false, result: { verdict: 'clean' } });
    expect(abuse).toHaveBeenCalledTimes(1);

    const expired = await runEnrichmentLookup(client, { type: 'ip', value: '203.0.113.7', sourceIds: ['abuse'] }, { now: new Date('2026-11-20T13:00:00.000Z') });
    expect(expired.results[0].cached).toBe(false);
    expect(abuse).toHaveBeenCalledTimes(2);
  });

  test('skips sources that do not support the type and unknown sourceIds', async () => {
    misp.mockResolvedValue(verdict('misp'));
    cti.mockResolvedValue(verdict('wazuh_cti_local', 'unknown'));
    const res = await runEnrichmentLookup(clientWith({ settings: stored() }), { type: 'domain', value: 'Evil.Example.' });
    expect(res.value).toBe('evil.example');
    expect(res.results.map((r) => r.sourceId)).toEqual(['misp', 'wazuh_cti_local']);
    expect(abuse).not.toHaveBeenCalled();
    const none = await runEnrichmentLookup(clientWith({ settings: stored() }), { type: 'domain', value: 'evil.example', sourceIds: ['nope'] });
    expect(none.results).toEqual([]);
  });

  test('rejects an invalid value with a 400', async () => {
    await expect(runEnrichmentLookup(clientWith({ settings: stored() }), { type: 'ip', value: 'not-an-ip' })).rejects.toMatchObject({ statusCode: 400 });
    expect(canonicalLookupValue('hash', 'D41D8CD98F00B204E9800998ECF8427E')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(() => canonicalLookupValue('hash', 'zz')).toThrow(/not a valid hash/);
  });

  test('without the encryption key, keyed sources fail individually and the built-in source still runs', async () => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
    cti.mockResolvedValue(verdict('wazuh_cti_local', 'malicious'));
    const res = await runEnrichmentLookup(clientWith({ settings: stored() }), { type: 'ip', value: '203.0.113.7' });
    const byId = Object.fromEntries(res.results.map((r) => [r.sourceId, r]));
    expect(byId.abuse).toMatchObject({ status: 'error', error: expect.stringContaining(ENCRYPTION_KEY_ENV_VAR) });
    expect(byId.misp.status).toBe('error');
    expect(byId.wazuh_cti_local).toMatchObject({ status: 'ok', result: { verdict: 'malicious' } });
    expect(abuse).not.toHaveBeenCalled();
  });

  test('with no settings stored, only the built-in source exists on a 5.0 build', async () => {
    cti.mockResolvedValue(verdict('wazuh_cti_local', 'unknown'));
    const res = await runEnrichmentLookup(clientWith({ settings: null }), { type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e' });
    expect(res.results.map((r) => r.sourceId)).toEqual([WAZUH_CTI_LOCAL_SOURCE_ID]);
  });
});

describe('testEnrichmentSource', () => {
  beforeEach(() => {
    process.env[ENCRYPTION_KEY_ENV_VAR] = KEY;
    abuse.mockReset();
    misp.mockReset();
  });
  afterAll(() => {
    delete process.env[ENCRYPTION_KEY_ENV_VAR];
  });

  test('looks up the fixed benign value for the first supported type, bypassing the cache, even when disabled', async () => {
    misp.mockResolvedValue(verdict('off', 'unknown'));
    const offFp = sourceConfigFingerprint({ kind: 'misp', baseUrl: 'https://misp2.example.org' });
    const client = clientWith({ settings: stored(), cache: { [cacheDocId('off', 'ip', TEST_VALUES.ip, offFp)]: { expires_at: '2999-01-01T00:00:00.000Z', result: verdict('off', 'malicious') } } });
    const res = await testEnrichmentSource(client, 'off');
    expect(res).toMatchObject({ sourceId: 'off', status: 'ok', cached: false, type: 'ip', value: '8.8.8.8', result: { verdict: 'unknown' } });
    expect(misp.mock.calls[0][0].value).toBe('8.8.8.8');
    expect(client.index).not.toHaveBeenCalled();
  });

  test('reports a provider failure as an error entry and an unknown id as 404', async () => {
    abuse.mockRejectedValue(new Error('nope'));
    expect(await testEnrichmentSource(clientWith({ settings: stored() }), 'abuse')).toMatchObject({ status: 'error', error: 'nope' });
    await expect(testEnrichmentSource(clientWith({ settings: stored() }), 'missing')).rejects.toMatchObject({ statusCode: 404 });
  });
});
