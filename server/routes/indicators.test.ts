import { API_ROOT } from '../../common';
import { buildCaseIndicators, defineIndicatorRoutes } from './indicators';

const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';
const ALERT_INDEX = 'wazuh-alert-status-v2-000001';

interface Fixture {
  alerts?: Record<string, any>;
  evidence?: any[];
  caseDoc?: any;
}

/**
 * Client double: the case read alias, the evidence read alias (cursor paged
 * through the real encode/decode helpers, `sort` = [position, alert_id]), the
 * alert read alias (ids query) and a meta index whose backfill marker is
 * complete so no legacy fallback search runs. Archive GETs are offline.
 */
function clientWith({ alerts = {}, evidence = [], caseDoc = { alert_ids: [] } }: Fixture) {
  return {
    search: jest.fn(async (req: any) => {
      const index = String(req.index);
      if (index.startsWith('wazuh-alert-manager-v2-cases')) {
        return { body: { hits: { hits: [{ _id: 'case-1', _index: CASE_INDEX, _source: caseDoc, _seq_no: 1, _primary_term: 1 }] } } };
      }
      if (index.startsWith('wazuh-alert-manager-v2-evidence')) {
        const after = Array.isArray(req.body?.search_after) ? Number(req.body.search_after[0]) : -1;
        const hits = evidence
          .map((item, position) => ({ _id: `ev-${position}`, _source: item, sort: [position, item.alert_id] }))
          .filter((hit) => hit.sort[0] > after)
          .slice(0, req.body.size);
        return { body: { hits: { hits, total: { value: evidence.length } } } };
      }
      const ids: string[] = req.body?.query?.ids?.values || [];
      return { body: { hits: { hits: ids.filter((id) => alerts[id]).map((id) => ({ _id: id, _index: ALERT_INDEX, _source: alerts[id] })) } } };
    }),
    get: jest.fn(async (req: any) => {
      if (String(req.index) === 'wazuh-alert-manager-v2-meta') return { body: { _source: { completed: true } } };
      throw Object.assign(new Error('offline'), { meta: { statusCode: 404 } });
    }),
  };
}

function handlerFor() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
  defineIndicatorRoutes(router);
  const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/cases/{id}/indicators`);
  expect(registration).toBeDefined();
  return registration;
}

describe('GET /cases/{id}/indicators', () => {
  test('is registered with the API root and params validation', () => {
    const [config] = handlerFor();
    expect(config.validate.params).toBeDefined();
  });

  test('pages all evidence, resolves alerts and aggregates with counts, first/last seen and hints', async () => {
    const client = clientWith({
      evidence: [
        { alert_id: 'fim', relationship_state: 'linked' },
        { alert_id: 'vt', relationship_state: 'linked' },
        {
          alert_id: 'snap', relationship_state: 'archived', archive_index: 'wazuh-alert-status-v2-000000',
          snapshot: { '@timestamp': '2026-11-20T09:00:00.000Z', data: { srcip: '203.0.113.7' }, agent: { name: 'web-01' } },
        },
      ],
      alerts: {
        fim: {
          '@timestamp': '2026-11-20T10:00:00.000Z',
          data: { srcip: '203.0.113.7', srcuser: 'root' },
          syscheck: { md5_after: 'D41D8CD98F00B204E9800998ECF8427E' },
          agent: { name: 'web-01', ip: '10.0.0.2' },
        },
        vt: {
          '@timestamp': '2026-11-20T10:00:05.000Z',
          threat: { matches: [{ source: 'virustotal', verdict: 'malicious', detail: 'VirusTotal 7/70 engines flagged', matched_field: 'data.virustotal.source.md5', indicator: { name: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5' } }] },
        },
      },
    });

    const body = await buildCaseIndicators(client, 'case-1');

    expect(body.includedAlerts).toBe(3);
    expect(body.totalRelationships).toBe(3);
    expect(body.truncated).toBe(false);
    expect(body.limit).toBe(5000);
    const srcip = body.indicators.find((i) => i.type === 'ip' && i.value === '203.0.113.7')!;
    expect(srcip).toMatchObject({ count: 2, first_seen: '2026-11-20T09:00:00.000Z', last_seen: '2026-11-20T10:00:00.000Z', alert_ids: ['snap', 'fim'] });
    const md5 = body.indicators.find((i) => i.type === 'hash')!;
    expect(md5).toMatchObject({ value: 'd41d8cd98f00b204e9800998ecf8427e', count: 2, alert_ids: ['fim', 'vt'] });
    expect(md5.verdictHints).toEqual([expect.objectContaining({ source: 'virustotal', verdict: 'malicious' })]);
    expect(body.indicators.find((i) => i.type === 'host')).toMatchObject({ value: 'web-01', count: 2 });
    expect(body.indicators.find((i) => i.type === 'ip' && i.value === '10.0.0.2')!.tags).toEqual(['private']);
    // The archived record was looked up through its managed archive index, never a caller-supplied one.
    expect(client.get).toHaveBeenCalledWith({ index: 'wazuh-alert-status-v2-000000', id: 'snap' });
  });

  test('walks every evidence page with the scoped cursor', async () => {
    const evidence = Array.from({ length: 2500 }, (_, i) => ({ alert_id: `a${i}`, relationship_state: 'linked' }));
    const alerts: Record<string, any> = {};
    for (let i = 0; i < 2500; i += 1) alerts[`a${i}`] = { '@timestamp': '2026-11-20T10:00:00.000Z', data: { srcip: `203.0.113.${i % 5}` } };
    const client = clientWith({ evidence, alerts });
    const body = await buildCaseIndicators(client, 'case-1');
    expect(body.totalRelationships).toBe(2500);
    expect(body.includedAlerts).toBe(2500);
    expect(body.truncated).toBe(false);
    expect(body.indicators).toHaveLength(5);
    expect(body.indicators.map((i) => i.count)).toEqual([500, 500, 500, 500, 500]);
    expect(body.indicators[0].alert_ids).toHaveLength(20);
    const evidenceSearches = client.search.mock.calls.filter(([req]: any[]) => String(req.index).startsWith('wazuh-alert-manager-v2-evidence'));
    expect(evidenceSearches).toHaveLength(3);
    expect(evidenceSearches[1][0].body.search_after).toEqual([999, 'a999']);
  });

  test('stops at the 5000-relationship cap and reports truncation', async () => {
    const evidence = Array.from({ length: 5200 }, (_, i) => ({ alert_id: `a${i}`, relationship_state: 'linked' }));
    const body = await buildCaseIndicators(clientWith({ evidence }), 'case-1');
    expect(body.truncated).toBe(true);
    expect(body.totalRelationships).toBe(5000);
    expect(body.includedAlerts).toBe(0);
    expect(body.indicators).toEqual([]);
  });

  test('returns an empty aggregation for a case without evidence', async () => {
    const body = await buildCaseIndicators(clientWith({}), 'case-1');
    expect(body).toEqual({ indicators: [], includedAlerts: 0, totalRelationships: 0, truncated: false, limit: 5000 });
  });

  test('GET /alerts/{id}/sibling-verdicts merges the sibling records\' threat.matches, bounded', async () => {
    const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn() };
    defineIndicatorRoutes(router);
    const registration = router.get.mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}/alerts/{id}/sibling-verdicts`);
    expect(registration).toBeDefined();
    expect(registration[0].validate.params).toBeDefined();
    const vtMatch = { source: 'virustotal', verdict: 'malicious', indicator: { name: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5' } };
    const client = {
      search: jest.fn(async () => ({
        body: { hits: { hits: [
          { _id: 'vt', _source: { threat: { sibling_of: 'fim', matches: [vtMatch] } } },
          { _id: 'mv', _source: { threat: { sibling_of: 'fim', matches: Array.from({ length: 25 }, (_, i) => ({ source: 'maltiverse', verdict: 'suspicious', indicator: { name: `203.0.113.${i}`, type: 'ip' } })) } } },
          { _id: 'odd', _source: { threat: { sibling_of: 'fim', matches: 'nope' } } },
        ] } },
      })),
    };
    const ok = jest.fn((value: any) => value);
    const customError = jest.fn((value: any) => value);
    const result = await registration[1]({ core: { opensearch: { client: { asCurrentUser: client } } } }, { params: { id: 'fim' } }, { ok, customError });
    expect(customError).not.toHaveBeenCalled();
    expect(result.body.siblings).toBe(3);
    expect(result.body.matches).toHaveLength(20);
    expect(result.body.matches[0]).toEqual(vtMatch);
    const [req] = client.search.mock.calls[0] as any[];
    expect(req.index).toBe('wazuh-alert-status-v2-read');
    expect(req.body.query).toEqual({ term: { 'threat.sibling_of': 'fim' } });
    expect(req.body._source).toEqual(['threat']);
  });

  test('maps a missing case to its status code through the handler', async () => {
    const [, handler] = handlerFor();
    const client = { search: jest.fn(async () => ({ body: { hits: { hits: [] } } })) };
    const customError = jest.fn((value: any) => value);
    const ok = jest.fn((value: any) => value);
    await handler({ core: { opensearch: { client: { asCurrentUser: client } } } }, { params: { id: 'missing' } }, { ok, customError });
    expect(ok).not.toHaveBeenCalled();
    expect(customError).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 404 }));
  });
});
