import { createHash } from 'crypto';

import { ENRICHMENT_CACHE_INDEX } from '../../../common';
import { cacheDocId, readCachedResult, sourceConfigFingerprint, writeCachedResult } from './cache';

const NOW = new Date('2026-11-20T12:00:00.000Z');
const result = { source: 'src', verdict: 'malicious' as const, score: 90, tags: ['x'], link: null, summary: 's', checkedAt: NOW.toISOString() };

function clientWith(doc: any | null) {
  return {
    get: jest.fn(async (_req: any) => {
      if (doc === null) throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
      return { body: { _source: doc } };
    }),
    index: jest.fn(async (_req: any) => ({ body: { result: 'created' } })),
  };
}

describe('enrichment cache', () => {
  test('doc id is sha256(source:type:value)', () => {
    expect(cacheDocId('src', 'ip', '203.0.113.7')).toBe(createHash('sha256').update('src:ip:203.0.113.7').digest('hex'));
    expect(cacheDocId('src', 'ip', '203.0.113.7')).not.toBe(cacheDocId('other', 'ip', '203.0.113.7'));
  });

  test('the config fingerprint covers what a lookup depends on and changes the doc id', () => {
    const base = { kind: 'generic_http', urlTemplate: 'https://a.example.com/{value}', headers: { Authorization: 'Bearer x' }, verdictPath: '/v', verdictMap: { bad: 'malicious' } };
    const fp = sourceConfigFingerprint(base);
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
    expect(sourceConfigFingerprint({ ...base })).toBe(fp);
    // Header values (the secret-bearing part) do not matter; names, URLs, pointers and the map do.
    expect(sourceConfigFingerprint({ ...base, headers: { Authorization: 'Bearer other' } })).toBe(fp);
    expect(sourceConfigFingerprint({ ...base, headers: { 'X-Key': 'Bearer x' } })).not.toBe(fp);
    expect(sourceConfigFingerprint({ ...base, urlTemplate: 'https://b.example.com/{value}' })).not.toBe(fp);
    expect(sourceConfigFingerprint({ ...base, verdictPath: '/verdict' })).not.toBe(fp);
    expect(sourceConfigFingerprint({ ...base, verdictMap: { bad: 'suspicious' } })).not.toBe(fp);
    expect(sourceConfigFingerprint({ kind: 'misp', baseUrl: 'https://a' })).not.toBe(sourceConfigFingerprint({ kind: 'misp', baseUrl: 'https://b' }));
    expect(cacheDocId('src', 'ip', '1.1.1.1', fp)).not.toBe(cacheDocId('src', 'ip', '1.1.1.1'));
    expect(cacheDocId('src', 'ip', '1.1.1.1', fp)).toBe(createHash('sha256').update(`src:${fp}:ip:1.1.1.1`).digest('hex'));
  });

  test('read and write use the fingerprinted id when one is given', async () => {
    const client = clientWith(null);
    const fp = sourceConfigFingerprint({ kind: 'abuseipdb' });
    await writeCachedResult(client, { sourceId: 'src', kind: 'abuseipdb', type: 'ip', value: '1.1.1.1', result, ttlSeconds: 60, now: NOW, configFingerprint: fp });
    expect(client.index.mock.calls[0]![0].id).toBe(cacheDocId('src', 'ip', '1.1.1.1', fp));
    await readCachedResult(client, 'src', 'ip', '1.1.1.1', NOW, fp);
    expect(client.get.mock.calls[0]![0].id).toBe(cacheDocId('src', 'ip', '1.1.1.1', fp));
  });

  test('write stores the entry in the cache index with expires_at = now + ttl', async () => {
    const client = clientWith(null);
    const doc = await writeCachedResult(client, { sourceId: 'src', kind: 'abuseipdb', type: 'ip', value: '203.0.113.7', result, ttlSeconds: 3600, now: NOW });
    const call = client.index.mock.calls[0]![0];
    expect(call.index).toBe(ENRICHMENT_CACHE_INDEX);
    expect(call.id).toBe(cacheDocId('src', 'ip', '203.0.113.7'));
    expect(call.body).toEqual(doc);
    expect(doc).toEqual({
      source_id: 'src',
      kind: 'abuseipdb',
      type: 'ip',
      value: '203.0.113.7',
      checked_at: NOW.toISOString(),
      expires_at: '2026-11-20T13:00:00.000Z',
      result,
    });
  });

  test('miss: 404 and a missing index both read as null', async () => {
    expect(await readCachedResult(clientWith(null), 'src', 'ip', '1.1.1.1', NOW)).toBeNull();
    const noIndex = { get: jest.fn(async () => { throw Object.assign(new Error('index_not_found'), { meta: { statusCode: 404, body: { error: { type: 'index_not_found_exception' } } } }); }) };
    expect(await readCachedResult(noIndex, 'src', 'ip', '1.1.1.1', NOW)).toBeNull();
    const broken = { get: jest.fn(async () => { throw Object.assign(new Error('boom'), { meta: { statusCode: 500 } }); }) };
    await expect(readCachedResult(broken, 'src', 'ip', '1.1.1.1', NOW)).rejects.toThrow('boom');
  });

  test('hit: an unexpired entry is returned, an expired one is not', async () => {
    const fresh = { source_id: 'src', type: 'ip', value: '1.1.1.1', checked_at: NOW.toISOString(), expires_at: '2026-11-20T13:00:00.000Z', result };
    const client = clientWith(fresh);
    expect(await readCachedResult(client, 'src', 'ip', '1.1.1.1', NOW)).toEqual(fresh);
    expect(client.get.mock.calls[0]![0]).toEqual({ index: ENRICHMENT_CACHE_INDEX, id: cacheDocId('src', 'ip', '1.1.1.1') });
    expect(await readCachedResult(client, 'src', 'ip', '1.1.1.1', new Date('2026-11-20T13:00:00.000Z'))).toBeNull();
    expect(await readCachedResult(clientWith({ ...fresh, expires_at: 'garbage' }), 'src', 'ip', '1.1.1.1', NOW)).toBeNull();
    expect(await readCachedResult(clientWith({ ...fresh, result: undefined }), 'src', 'ip', '1.1.1.1', NOW)).toBeNull();
  });
});
