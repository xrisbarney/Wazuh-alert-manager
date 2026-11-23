import { MAX_ALERT_ENRICHMENT_ITEMS, MAX_ALERT_ENRICHMENT_TAGS } from './constants';
import { enrichmentItemsFor, mergeAlertEnrichment, worstEnrichmentVerdict } from './enrichment';
import { aggregateIndicators } from './indicators';

const NOW = new Date('2026-11-20T12:00:00.000Z');

function ok(source: string, verdict: any, checkedAt = '2026-11-20T11:00:00.000Z', extra: any = {}) {
  return {
    sourceId: source, sourceName: source, kind: 'generic_http' as const, status: 'ok' as const, cached: false,
    result: { source, verdict, score: 10, tags: ['a'], link: null, summary: '', checkedAt, ...extra },
  };
}

describe('worstEnrichmentVerdict', () => {
  test('ranks malicious > suspicious > clean > unknown and ignores junk', () => {
    expect(worstEnrichmentVerdict([])).toBeNull();
    expect(worstEnrichmentVerdict([{ verdict: 'unknown' }, { verdict: 'clean' }])).toBe('clean');
    expect(worstEnrichmentVerdict([{ verdict: 'clean' }, { verdict: 'suspicious' }])).toBe('suspicious');
    expect(worstEnrichmentVerdict([{ verdict: 'suspicious' }, { verdict: 'malicious' }, { verdict: 'nope' } as any])).toBe('malicious');
  });
});

describe('mergeAlertEnrichment', () => {
  test('builds the stored object from successful results only, newest first, tags capped', () => {
    const merged = mergeAlertEnrichment(null, {
      type: 'ip', value: '203.0.113.7',
      results: [
        ok('old', 'clean', '2026-11-20T09:00:00.000Z'),
        { sourceId: 'down', sourceName: 'down', kind: 'misp', status: 'error', cached: false, error: 'HTTP 500' },
        ok('new', 'suspicious', '2026-11-20T11:00:00.000Z', { tags: Array.from({ length: 30 }, (_, i) => `t${i}`), score: null }),
      ],
    }, NOW);
    expect(merged.updated_at).toBe(NOW.toISOString());
    expect(merged.worst_verdict).toBe('suspicious');
    expect(merged.items.map((i) => i.source)).toEqual(['new', 'old']);
    expect(merged.items[0].tags).toHaveLength(MAX_ALERT_ENRICHMENT_TAGS);
    expect(merged.items[0].score).toBeNull();
    expect(merged.items[0]).toMatchObject({ type: 'ip', value: '203.0.113.7', checked_at: '2026-11-20T11:00:00.000Z', link: null });
  });

  test('replaces the same (source, type, value), keeps other items, drops malformed ones and caps the list', () => {
    const existing = {
      updated_at: 'x', worst_verdict: 'malicious' as const,
      items: [
        { type: 'ip', value: '203.0.113.7', source: 'src', verdict: 'malicious', score: 99, tags: [], link: null, checked_at: '2026-11-01T00:00:00.000Z' },
        { type: 'hash', value: 'abc', source: 'src', verdict: 'clean', score: 0, tags: [], link: null, checked_at: '2026-11-02T00:00:00.000Z' },
        { type: 'hash', value: '', source: 'src', verdict: 'clean', score: 0, tags: [], link: null, checked_at: '2026-11-02T00:00:00.000Z' },
        ...Array.from({ length: MAX_ALERT_ENRICHMENT_ITEMS }, (_, i) => ({
          type: 'domain', value: `d${i}.example`, source: 'src', verdict: 'unknown', score: null, tags: [], link: null, checked_at: '2026-10-01T00:00:00.000Z',
        })),
      ] as any,
    };
    const merged = mergeAlertEnrichment(existing, { type: 'ip', value: '203.0.113.7', results: [ok('src', 'clean', '2026-11-20T11:00:00.000Z')] }, NOW);
    expect(merged.items).toHaveLength(MAX_ALERT_ENRICHMENT_ITEMS);
    expect(merged.items[0]).toMatchObject({ type: 'ip', value: '203.0.113.7', source: 'src', verdict: 'clean' });
    expect(merged.items[1]).toMatchObject({ type: 'hash', value: 'abc' });
    expect(merged.items.filter((i) => i.value === '203.0.113.7')).toHaveLength(1);
    expect(merged.items.some((i) => i.value === '')).toBe(false);
    expect(merged.worst_verdict).toBe('clean');
    expect(enrichmentItemsFor(merged, 'hash', 'abc')).toHaveLength(1);
    expect(enrichmentItemsFor(merged, 'hash', 'zzz')).toEqual([]);
  });

  test('a lookup with no successful result keeps the previous items and refreshes updated_at only', () => {
    const existing = { updated_at: 'x', worst_verdict: 'malicious' as const, items: [{ type: 'ip', value: '203.0.113.7', source: 'src', verdict: 'malicious', score: 99, tags: [], link: null, checked_at: '2026-11-01T00:00:00.000Z' }] } as any;
    const merged = mergeAlertEnrichment(existing, { type: 'ip', value: '203.0.113.7', results: [{ sourceId: 'src', sourceName: 's', kind: 'misp', status: 'error', cached: false, error: 'x' }] }, NOW);
    expect(merged.items).toEqual(existing.items);
    expect(merged.worst_verdict).toBe('malicious');
  });
});

describe('aggregateIndicators carries stored enrichment of member alerts', () => {
  test('one item per source per indicator, newest checked_at wins, malformed entries ignored', () => {
    const a1 = { _id: 'a1', _source: { '@timestamp': '2026-11-20T10:00:00.000Z', data: { srcip: '203.0.113.7' }, enrichment: { items: [
      { type: 'ip', value: '203.0.113.7', source: 'abuse', verdict: 'clean', score: 0, tags: [], link: null, checked_at: '2026-11-19T00:00:00.000Z' },
      { type: 'ip', value: '203.0.113.7', source: 'misp', verdict: 'suspicious', score: null, tags: [], link: null, checked_at: '2026-11-19T00:00:00.000Z' },
      { type: 'ip', value: '203.0.113.7', source: '', verdict: 'malicious', checked_at: '2026-11-19T00:00:00.000Z' },
    ] } } };
    const a2 = { _id: 'a2', _source: { '@timestamp': '2026-11-20T11:00:00.000Z', data: { srcip: '203.0.113.7' }, enrichment: { items: [
      { type: 'ip', value: '203.0.113.7', source: 'abuse', verdict: 'malicious', score: 100, tags: ['tor'], link: null, checked_at: '2026-11-20T00:00:00.000Z' },
    ] } } };
    const a3 = { _id: 'a3', _source: { '@timestamp': '2026-11-20T12:00:00.000Z', data: { srcip: '203.0.113.8' }, enrichment: 'junk' } };
    const rows = aggregateIndicators([a1, a2, a3]);
    const row = rows.find((r) => r.value === '203.0.113.7')!;
    expect(row.count).toBe(2);
    expect(row.enrichment.map((i) => [i.source, i.verdict])).toEqual([['abuse', 'malicious'], ['misp', 'suspicious']]);
    expect(rows.find((r) => r.value === '203.0.113.8')!.enrichment).toEqual([]);
  });
});
