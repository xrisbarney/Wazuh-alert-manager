import { ReadableStream } from 'stream/web';

import { EGRESS_ALLOWED_HOSTS_ENV_VAR } from '../egress/url_policy';
import { abuseIpDbProvider, ABUSEIPDB_ENDPOINT } from './abuseipdb';
import { genericHttpProvider, jsonPointer, mapVerdict, renderUrlTemplate } from './generic_http';
import { mispProvider } from './misp';
import { EnrichmentSourceError, ResolvedEnrichmentSource } from './provider';
import { buildCtiLocalQuery, confidenceScore, wazuhCtiLocalProvider, CTI_CATALOG_NOT_AVAILABLE } from './wazuh_cti_local';

jest.mock('dns', () => ({ promises: { lookup: jest.fn() } }));
// eslint-disable-next-line @typescript-eslint/no-var-requires
const dnsLookup: jest.Mock = require('dns').promises.lookup;

function fakeHeaders(values: Record<string, string>) {
  const lower: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) lower[key.toLowerCase()] = value;
  return {
    get: (name: string) => (name.toLowerCase() in lower ? lower[name.toLowerCase()] : null),
    forEach: (cb: (value: string, key: string) => void) => {
      for (const [key, value] of Object.entries(lower)) cb(value, key);
    },
  };
}

function jsonResponse(status: number, body: unknown) {
  const bytes = new Uint8Array(Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8'));
  let sent = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (!sent) {
        sent = true;
        controller.enqueue(bytes);
      } else controller.close();
    },
  });
  return { status, headers: fakeHeaders({ 'content-type': 'application/json' }), body: stream };
}

const NOW = new Date('2026-11-20T12:00:00.000Z');

function source(overrides: Partial<ResolvedEnrichmentSource>): ResolvedEnrichmentSource {
  return {
    id: 'src',
    name: 'Source',
    kind: 'abuseipdb',
    enabled: true,
    supports: ['ip'],
    cacheTtlSeconds: 3600,
    timeoutMs: 8000,
    apiKey: 'k3y',
    ...overrides,
  };
}

describe('remote providers', () => {
  const realFetch = (global as any).fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    delete process.env[EGRESS_ALLOWED_HOSTS_ENV_VAR];
    fetchMock = jest.fn();
    (global as any).fetch = fetchMock;
    dnsLookup.mockReset();
    dnsLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  });
  afterAll(() => {
    (global as any).fetch = realFetch;
  });

  describe('abuseipdb', () => {
    test('GETs the check endpoint with the Key header and maps the confidence score', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse(200, {
          data: { ipAddress: '203.0.113.7', abuseConfidenceScore: 92, totalReports: 14, countryCode: 'NL', usageType: 'Data Center/Web Hosting/Transit', isp: 'Example ISP', isTor: false, lastReportedAt: '2026-11-19T00:00:00+00:00' },
        })
      );
      const result = await abuseIpDbProvider.lookup({ source: source({}), type: 'ip', value: '203.0.113.7', client: {}, now: NOW });
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe(`${ABUSEIPDB_ENDPOINT}?ipAddress=203.0.113.7&maxAgeInDays=90`);
      expect(init.method).toBe('GET');
      expect(init.headers.Key).toBe('k3y');
      expect(result).toEqual({
        source: 'src',
        verdict: 'malicious',
        score: 92,
        tags: ['country:NL', 'Data Center/Web Hosting/Transit', 'isp:Example ISP'],
        link: 'https://www.abuseipdb.com/check/203.0.113.7',
        summary: 'Abuse confidence 92% (14 reports in 90 days, last 2026-11-19T00:00:00+00:00)',
        checkedAt: NOW.toISOString(),
      });
    });

    test('scores 30 as suspicious and 0 as clean', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: { abuseConfidenceScore: 30, totalReports: 1 } }));
      expect((await abuseIpDbProvider.lookup({ source: source({}), type: 'ip', value: '203.0.113.7', client: {}, now: NOW })).verdict).toBe('suspicious');
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: { abuseConfidenceScore: 0, totalReports: 0, isWhitelisted: true } }));
      const clean = await abuseIpDbProvider.lookup({ source: source({}), type: 'ip', value: '8.8.8.8', client: {}, now: NOW });
      expect(clean.verdict).toBe('clean');
      expect(clean.tags).toEqual(['whitelisted']);
    });

    test('surfaces HTTP errors, API error bodies and a missing key as source errors', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(401, { errors: [{ detail: 'Authentication failed.' }] }));
      await expect(abuseIpDbProvider.lookup({ source: source({}), type: 'ip', value: '8.8.8.8', client: {}, now: NOW })).rejects.toThrow(/HTTP 401/);
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { errors: [{ detail: 'Bad request.' }] }));
      await expect(abuseIpDbProvider.lookup({ source: source({}), type: 'ip', value: '8.8.8.8', client: {}, now: NOW })).rejects.toThrow(/Bad request/);
      await expect(abuseIpDbProvider.lookup({ source: source({ apiKey: '' }), type: 'ip', value: '8.8.8.8', client: {}, now: NOW })).rejects.toBeInstanceOf(EnrichmentSourceError);
      await expect(abuseIpDbProvider.lookup({ source: source({}), type: 'domain', value: 'example.com', client: {}, now: NOW })).rejects.toThrow(/only looks up IP/);
    });

    test('propagates egress policy errors from boundedFetch (private resolution)', async () => {
      dnsLookup.mockResolvedValue([{ address: '10.0.0.9', family: 4 }]);
      await expect(abuseIpDbProvider.lookup({ source: source({}), type: 'ip', value: '8.8.8.8', client: {}, now: NOW })).rejects.toMatchObject({ code: 'policy' });
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe('misp', () => {
    const misp = source({ id: 'misp', name: 'MISP', kind: 'misp', supports: ['ip', 'domain', 'url', 'hash'], baseUrl: 'https://misp.example.org' });

    test('POSTs restSearch with the Authorization header; to_ids makes it malicious', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse(200, {
          response: {
            Attribute: [
              { event_id: '42', to_ids: true, Tag: [{ name: 'tlp:amber' }, { name: 'malware:emotet' }], Event: { info: 'Emotet wave' } },
              { event_id: '42', to_ids: false, Tag: [{ name: 'tlp:amber' }] },
            ],
          },
        })
      );
      const result = await mispProvider.lookup({ source: misp, type: 'domain', value: 'evil.example', client: {}, now: NOW });
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://misp.example.org/attributes/restSearch');
      expect(init.method).toBe('POST');
      expect(init.headers.Authorization).toBe('k3y');
      expect(JSON.parse(init.body)).toEqual({ value: 'evil.example', returnFormat: 'json', limit: 20 });
      expect(result).toMatchObject({
        verdict: 'malicious',
        score: null,
        tags: ['tlp:amber', 'malware:emotet'],
        link: 'https://misp.example.org/events/view/42',
        summary: '2 attributes in 1 event, 1 flagged for IDS - "Emotet wave"',
      });
    });

    test('attributes without to_ids are suspicious; none is unknown', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { response: { Attribute: [{ event_id: 7, to_ids: 0 }] } }));
      expect((await mispProvider.lookup({ source: misp, type: 'ip', value: '203.0.113.7', client: {}, now: NOW })).verdict).toBe('suspicious');
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { response: { Attribute: [] } }));
      const miss = await mispProvider.lookup({ source: misp, type: 'ip', value: '203.0.113.7', client: {}, now: NOW });
      expect(miss).toMatchObject({ verdict: 'unknown', link: null, summary: 'No matching attribute in MISP' });
    });

    test('requires a base URL and a key', async () => {
      await expect(mispProvider.lookup({ source: { ...misp, baseUrl: undefined }, type: 'ip', value: '1.1.1.1', client: {}, now: NOW })).rejects.toThrow(/base URL/);
      await expect(mispProvider.lookup({ source: { ...misp, apiKey: '' }, type: 'ip', value: '1.1.1.1', client: {}, now: NOW })).rejects.toThrow(/API key/);
    });
  });

  describe('generic_http', () => {
    const generic = source({
      id: 'gen',
      name: 'Intel',
      kind: 'generic_http',
      supports: ['ip', 'domain', 'url', 'hash'],
      urlTemplate: 'https://intel.example.com/v1/{type}?q={value}',
      headers: { Authorization: 'Bearer {apiKey}', 'X-Client': 'wam' },
      verdictPath: '/data/classification',
      scorePath: '/data/risk',
      tagsPath: '/data/labels',
      linkPath: '/data/permalink',
      verdictMap: { bad: 'malicious', dodgy: 'suspicious', ok: 'clean' },
    });

    test('renders the template, substitutes {apiKey} in headers and reads pointers', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse(200, { data: { classification: 'dodgy', risk: '55', labels: ['scanner', 'scanner', 7], permalink: 'https://intel.example.com/r/1' } })
      );
      const result = await genericHttpProvider.lookup({ source: generic, type: 'url', value: 'https://x.example/a b?c=1', client: {}, now: NOW });
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://intel.example.com/v1/url?q=https%3A%2F%2Fx.example%2Fa%20b%3Fc%3D1');
      expect(init.headers).toEqual({ Accept: 'application/json', Authorization: 'Bearer k3y', 'X-Client': 'wam' });
      expect(result).toMatchObject({
        verdict: 'suspicious',
        score: 55,
        tags: ['scanner', '7'],
        link: 'https://intel.example.com/r/1',
        summary: 'intel.example.com: verdict "dodgy", score 55',
      });
    });

    test('falls back to the score thresholds when the verdict is unmapped, and refuses non-http links', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: { classification: 'weird', risk: 80, permalink: 'javascript:alert(1)' } }));
      const result = await genericHttpProvider.lookup({ source: generic, type: 'ip', value: '203.0.113.7', client: {}, now: NOW });
      expect(result).toMatchObject({ verdict: 'malicious', score: 80, link: null });
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: {} }));
      const empty = await genericHttpProvider.lookup({ source: { ...generic, scorePath: undefined }, type: 'ip', value: '203.0.113.7', client: {}, now: NOW });
      expect(empty).toMatchObject({ verdict: 'unknown', score: null, summary: 'intel.example.com: no verdict field in the response' });
    });

    test('fails clearly on non-JSON, HTTP errors and a missing key referenced by a header', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse(200, '<html>'));
      await expect(genericHttpProvider.lookup({ source: generic, type: 'ip', value: '1.1.1.1', client: {}, now: NOW })).rejects.toThrow(/did not return JSON/);
      fetchMock.mockResolvedValueOnce(jsonResponse(503, 'down'));
      await expect(genericHttpProvider.lookup({ source: generic, type: 'ip', value: '1.1.1.1', client: {}, now: NOW })).rejects.toThrow(/HTTP 503: down/);
      await expect(genericHttpProvider.lookup({ source: { ...generic, apiKey: '' }, type: 'ip', value: '1.1.1.1', client: {}, now: NOW })).rejects.toThrow(/API key/);
    });

    test('jsonPointer follows RFC 6901 incl. escapes and array indices', () => {
      const doc = { a: { 'b/c': [10, { '~x': 'deep' }] }, '': 'empty-key' };
      expect(jsonPointer(doc, '')).toBe(doc);
      expect(jsonPointer(doc, '/a/b~1c/0')).toBe(10);
      expect(jsonPointer(doc, '/a/b~1c/1/~0x')).toBe('deep');
      expect(jsonPointer(doc, '/')).toBe('empty-key');
      expect(jsonPointer(doc, '/a/b~1c/01')).toBeUndefined();
      expect(jsonPointer(doc, '/a/missing')).toBeUndefined();
      expect(jsonPointer(doc, 'a/b')).toBeUndefined();
      expect(jsonPointer({ constructor: 1 }, '/toString')).toBeUndefined();
    });

    test('mapVerdict and renderUrlTemplate helpers', () => {
      expect(mapVerdict('Malicious', undefined)).toBe('malicious');
      expect(mapVerdict(1, { '1': 'suspicious' })).toBe('suspicious');
      expect(mapVerdict(true, undefined)).toBeNull();
      expect(mapVerdict({ x: 1 }, undefined)).toBeNull();
      expect(renderUrlTemplate('https://h/{type}/{value}/{value}', 'a/b', 'ip')).toBe('https://h/ip/a%2Fb/a%2Fb');
    });
  });
});

describe('wazuh_cti_local', () => {
  const cti = source({ id: 'wazuh_cti_local', name: 'CTI', kind: 'wazuh_cti_local', supports: ['ip', 'domain', 'url', 'hash'], apiKey: '' });

  function clientAnswering(impl: (req: any) => any, catalogDocs = 1234) {
    return {
      search: jest.fn(async (req: any) => impl(req)),
      count: jest.fn(async (_req: any) => ({ body: { count: catalogDocs } })),
    };
  }

  test('queries the catalog with the CTI Explorer shape (exact term + ip:port prefix, checksum doc excluded); a miss is unknown with no link', async () => {
    const client = clientAnswering(() => ({ body: { hits: { total: { value: 0 }, hits: [] } } }));
    const result = await wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '203.0.113.7', client, now: NOW });
    const req = client.search.mock.calls[0][0];
    expect(req.index).toBe('wazuh-threatintel-enrichments*');
    expect(req.body).toEqual(buildCtiLocalQuery('ip', '203.0.113.7'));
    expect(req.body.query.bool.filter).toEqual([{ exists: { field: 'document.type' } }]);
    expect(req.body.query.bool.should).toEqual([
      { term: { 'document.name': { value: '203.0.113.7', case_insensitive: true } } },
      { bool: { filter: [{ term: { 'document.type': 'connection' } }, { prefix: { 'document.name': { value: '203.0.113.7:', case_insensitive: true } } }] } },
    ]);
    expect(buildCtiLocalQuery('hash', 'abc').query).toMatchObject({ bool: { should: [{ term: { 'document.name': { value: 'abc', case_insensitive: true } } }] } });
    expect(result).toMatchObject({ verdict: 'unknown', score: null, link: null, summary: 'Not in the local Wazuh CTI catalog' });
    // The miss was confirmed against a populated catalog (presence count on the same pattern).
    expect(client.count).toHaveBeenCalledTimes(1);
    expect(client.count.mock.calls[0]![0]).toMatchObject({ index: 'wazuh-threatintel-enrichments*', body: { query: { exists: { field: 'document.type' } } } });
  });

  test('an empty wildcard (4.x, or 5.0 before the catalog is synced) is an error, never a cached "unknown"', async () => {
    // OpenSearch answers a wildcard matching no index with 200 and zero hits.
    const noIndex = clientAnswering(() => ({ body: { hits: { total: { value: 0 }, hits: [] } } }), 0);
    await expect(wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '1.1.1.1', client: noIndex, now: NOW })).rejects.toThrow(CTI_CATALOG_NOT_AVAILABLE);
    const countMissing = {
      search: jest.fn(async () => ({ body: { hits: { total: { value: 0 }, hits: [] } } })),
      count: jest.fn(async () => {
        throw Object.assign(new Error('missing'), { meta: { statusCode: 404, body: { error: { type: 'index_not_found_exception' } } } });
      }),
    };
    await expect(wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '1.1.1.1', client: countMissing, now: NOW })).rejects.toThrow(/not available/);
    // A real hit never pays for the presence count.
    const hit = clientAnswering(() => ({ body: { hits: { total: { value: 1 }, hits: [{ _id: '1', _index: 'x', _source: { document: { name: '1.1.1.1', type: 'ip' } } }] } } }), 0);
    await expect(wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '1.1.1.1', client: hit, now: NOW })).resolves.toMatchObject({ verdict: 'malicious' });
    expect(hit.count).not.toHaveBeenCalled();
  });

  test('a catalog hit is malicious with the highest confidence, provider, feed and software tags', async () => {
    const client = clientAnswering(() => ({
      body: {
        hits: {
          total: { value: 2 },
          hits: [
            { _id: '1', _index: 'wazuh-threatintel-enrichments-a', _source: { document: { name: '203.0.113.7:443', type: 'connection', confidence: '75', provider: 'threat-fox', feed: { name: 'abuse_ch' }, tags: ['botnet'], software: { name: 'Emotet' } } } },
            { _id: '2', _index: 'wazuh-threatintel-enrichments-a', _source: { document: { name: '203.0.113.7:80', type: 'connection', confidence: 'high', provider: 'threat-fox' } } },
          ],
        },
      },
    }));
    const result = await wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '203.0.113.7', client, now: NOW });
    expect(result).toMatchObject({
      verdict: 'malicious',
      score: 90,
      tags: ['feed:abuse_ch', 'botnet', 'software:Emotet'],
      link: null,
      summary: '2 CTI catalog records (connection) from threat-fox, confidence 90',
    });
    expect(confidenceScore('medium')).toBe(60);
    expect(confidenceScore(undefined)).toBeNull();
  });

  test('maps 403 to a role-grant error and 404 to "not available"', async () => {
    const forbidden = clientAnswering(() => {
      throw Object.assign(new Error('forbidden'), { meta: { statusCode: 403 } });
    });
    await expect(wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '1.1.1.1', client: forbidden, now: NOW })).rejects.toThrow(/native_read/);
    const missing = clientAnswering(() => {
      throw Object.assign(new Error('missing'), { meta: { statusCode: 404, body: { error: { type: 'index_not_found_exception' } } } });
    });
    await expect(wazuhCtiLocalProvider.lookup({ source: cti, type: 'ip', value: '1.1.1.1', client: missing, now: NOW })).rejects.toThrow(/not available/);
  });
});
