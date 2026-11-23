import {
  ASSET_CONTEXT_CACHE_TTL_MS,
  FIELD_MAPS,
  assetContextLinks,
  cacheKey,
  clearAssetContextCache,
  fieldMapForLine,
  getAssetContext,
  hasErrorFamily,
  identityCandidates,
  itHygieneAvailable,
  readAssetContextFamilies,
} from './asset_context';

/**
 * Fixture documents shaped like the two lines' states indices:
 *  - 4.14: `wazuh-states-<family>-<cluster>` with root `agent.id` (mappings
 *    captured from the 4.14.10 Docker stack)
 *  - 5.0:  bare `wazuh-states-<family>` with `wazuh.agent.id` (rc2 index
 *    templates in runtime-evidence/phase1-5.0-rc2)
 * The data fields are WCS on both lines.
 */
const SYSTEM_4 = {
  agent: { id: '001', name: 'web-01' },
  host: { hostname: 'web-01', os: { name: 'Ubuntu', version: '22.04.4 LTS', platform: 'ubuntu' } },
  wazuh: { cluster: { name: 'wazuh' } },
};
const SYSTEM_5 = {
  wazuh: { agent: { id: '0191a2b3', name: 'web-01', groups: ['default'] }, cluster: { name: 'wazuh' } },
  host: { hostname: 'web-01', os: { name: 'Debian GNU/Linux', version: '12', platform: 'debian' } },
  state: { modified_at: '2026-11-20T10:00:00Z' },
};
const VULN_4 = [
  { agent: { id: '001' }, vulnerability: { id: 'CVE-2024-3094', severity: 'Critical', score: { base: 10 }, under_evaluation: false } },
  { agent: { id: '001' }, vulnerability: { id: 'CVE-2023-4863', severity: 'High', score: { base: 8.8 }, under_evaluation: false } },
];
const VULN_5 = [
  { wazuh: { agent: { id: '0191a2b3' } }, vulnerability: { id: 'CVE-2024-6387', severity: 'High', score: { base: 8.1 } } },
];

type Agg = Record<string, unknown>;

function fakeClient(opts: {
  identityField: string;
  agentId: string;
  system?: any;
  ips?: string[];
  ports?: { open: number; listening: number };
  vulns?: any[];
  vulnBuckets?: Array<{ key: string; doc_count: number }>;
  sca?: { failed: number; passed: number };
  throwFor?: Record<string, any>;
  delayFor?: Record<string, number>;
}) {
  const calls: any[] = [];
  const search = jest.fn(async (req: any) => {
    calls.push(req);
    const family = String(req.index).replace(/^wazuh-states-(inventory-)?/, '').replace(/\*$/, '');
    if (opts.throwFor?.[family]) throw opts.throwFor[family];
    if (opts.delayFor?.[family]) await new Promise((r) => setTimeout(r, opts.delayFor![family]));
    const filter = req.body?.query?.bool?.filter || [];
    const term = filter[0]?.term || {};
    const [field, value] = Object.entries(term)[0] as [string, string];
    const matches = field === opts.identityField && value === opts.agentId;
    const ok = (hits: any[], total: number, aggregations?: Agg) => ({
      body: { hits: { total: { value: total, relation: 'eq' }, hits: hits.map((s, i) => ({ _id: String(i), _index: req.index, _source: s })) }, ...(aggregations ? { aggregations } : {}) },
    });
    if (!matches) return ok([], 0, { ips: { buckets: [] }, listening: { doc_count: 0 }, severity: { buckets: [] }, result: { buckets: [] } });
    switch (family) {
      case 'system':
        return ok(opts.system ? [opts.system] : [], opts.system ? 1 : 0);
      case 'networks':
        return ok([], (opts.ips || []).length, { ips: { buckets: (opts.ips || []).map((ip) => ({ key: ip, doc_count: 1 })) } });
      case 'ports':
        return ok([], opts.ports?.open || 0, { listening: { doc_count: opts.ports?.listening || 0 } });
      case 'vulnerabilities':
        return ok(opts.vulns || [], (opts.vulns || []).length, { severity: { buckets: opts.vulnBuckets || [] } });
      case 'sca':
        return ok([], (opts.sca?.failed || 0) + (opts.sca?.passed || 0), {
          result: { buckets: [{ key: 'failed', doc_count: opts.sca?.failed || 0 }, { key: 'passed', doc_count: opts.sca?.passed || 0 }] },
        });
      default:
        throw new Error(`unexpected family ${family}`);
    }
  });
  return { search, count: jest.fn(), index: jest.fn(), update: jest.fn(), bulk: jest.fn(), delete: jest.fn(), calls };
}

const httpError = (statusCode: number, type?: string) =>
  Object.assign(new Error(`http ${statusCode}`), { meta: { statusCode, body: type ? { error: { type } } : undefined } });

describe('asset context field maps', () => {
  test('select by target Wazuh major with the other line as fallback identity', () => {
    expect(fieldMapForLine(4)).toBe(FIELD_MAPS[4]);
    expect(fieldMapForLine(5)).toBe(FIELD_MAPS[5]);
    expect(fieldMapForLine('garbage')).toBe(FIELD_MAPS[4]);
    expect(FIELD_MAPS[4].identityFields).toEqual(['agent.id', 'wazuh.agent.id']);
    expect(FIELD_MAPS[5].identityFields).toEqual(['wazuh.agent.id', 'agent.id']);
    expect(FIELD_MAPS[4].patterns.sca).toBeNull();
    expect(FIELD_MAPS[5].patterns.sca).toBe('wazuh-states-sca*');
    // 4.14 index names carry -<cluster.name>, 5.0 names are bare: both lines need trailing wildcards.
    for (const map of [FIELD_MAPS[4], FIELD_MAPS[5]]) {
      for (const pattern of Object.values(map.patterns)) if (pattern) expect(pattern.endsWith('*')).toBe(true);
    }
  });

  test('identity candidates prefer the agent id and fall back to the name', () => {
    expect(identityCandidates(FIELD_MAPS[4], { agentId: '001', agentName: 'web-01' })).toEqual([
      ['agent.id', '001'],
      ['wazuh.agent.id', '001'],
    ]);
    expect(identityCandidates(FIELD_MAPS[5], { agentId: null, agentName: 'web-01' })).toEqual([
      ['wazuh.agent.name', 'web-01'],
      ['agent.name', 'web-01'],
    ]);
    expect(identityCandidates(FIELD_MAPS[5], { agentId: null, agentName: null })).toEqual([]);
  });

  test('deep links target IT Hygiene and Vulnerability Detection with the agent id', () => {
    // Explicit target: the default is the BUILD target, so a 4.12 or 5.0 build
    // legitimately withholds itHygiene / configurationAssessment (see the two
    // tests below). This one is about the link shape, not the build.
    const target = { major: 4, version: '4.14.10' };
    expect(assetContextLinks('001', target)).toEqual({
      itHygiene: '/app/it-hygiene#/overview/?tab=it-hygiene&tabView=dashboard&agentId=001',
      vulnerabilityDetection: '/app/vulnerability-detection#/overview/?tab=vuls&tabView=dashboard&agentId=001',
      configurationAssessment: '/app/configuration-assessment#/overview/?tab=sca&tabView=inventory&agentId=001',
    });
    expect(assetContextLinks('a b', target).itHygiene).toContain('agentId=a%20b');
    expect(assetContextLinks(null, target).itHygiene).not.toContain('agentId');
  });

  test('the IT Hygiene link is withheld on builds before Wazuh 4.13, where the app does not exist', () => {
    expect(itHygieneAvailable({ major: 4, version: '4.12.0' })).toBe(false);
    expect(itHygieneAvailable({ major: 4, version: '4.13.1' })).toBe(true);
    expect(itHygieneAvailable({ major: 4, version: '4.14.7' })).toBe(true);
    expect(itHygieneAvailable({ major: 5, version: '5.0.0' })).toBe(true);
    expect(itHygieneAvailable({ major: 4, version: 'unknown' })).toBe(true);
    const links = assetContextLinks('001', { major: 4, version: '4.12.0' });
    expect(links.itHygiene).toBeNull();
    expect(links.vulnerabilityDetection).toContain('agentId=001');
  });

  test('the Configuration Assessment link is emitted on the 4.x line only (SCA results are not indexed there)', () => {
    expect(assetContextLinks('001', { major: 4, version: '4.14.10' }).configurationAssessment).toBe('/app/configuration-assessment#/overview/?tab=sca&tabView=inventory&agentId=001');
    expect(assetContextLinks('001', { major: 4, version: '4.12.0' }).configurationAssessment).toContain('agentId=001');
    expect(assetContextLinks('001', { major: 5, version: '5.0.0' }).configurationAssessment).toBeNull();
    expect(assetContextLinks(null, { major: 4, version: '4.14.10' }).configurationAssessment).not.toContain('agentId');
  });
});

describe('readAssetContextFamilies', () => {
  test('4.14 fixtures: root agent.id, every family read in parallel, SCA not available', async () => {
    const client = fakeClient({
      identityField: 'agent.id',
      agentId: '001',
      system: SYSTEM_4,
      ips: ['10.0.0.5', 'fe80::1'],
      ports: { open: 12, listening: 7 },
      vulns: VULN_4,
      vulnBuckets: [{ key: 'Critical', doc_count: 1 }, { key: 'High', doc_count: 1 }],
    });
    const families = await readAssetContextFamilies(client, { agentId: '001', agentName: 'web-01' }, { map: FIELD_MAPS[4] });
    expect(families.system).toEqual({ status: 'ok', os: { name: 'Ubuntu', version: '22.04.4 LTS', platform: 'ubuntu' }, hostname: 'web-01' });
    expect(families.networks).toEqual({ status: 'ok', ips: ['10.0.0.5', 'fe80::1'], total: 2 });
    expect(families.ports).toEqual({ status: 'ok', open: 12, listening: 7 });
    expect(families.vulnerabilities).toEqual({
      status: 'ok',
      total: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      topCves: [
        { id: 'CVE-2024-3094', severity: 'Critical', score: 10 },
        { id: 'CVE-2023-4863', severity: 'High', score: 8.8 },
      ],
    });
    expect(families.sca.status).toBe('not_available');
    expect(families.sca.reason).toMatch(/4\.x/);
    // Four families, one search each, primary identity field on the first try.
    expect(client.search).toHaveBeenCalledTimes(4);
    for (const call of client.calls) expect(call.body.query.bool.filter[0]).toEqual({ term: { 'agent.id': '001' } });
    const vuln = client.calls.find((c) => c.index === 'wazuh-states-vulnerabilities*');
    expect(vuln.body.query.bool.must_not).toEqual([{ term: { 'vulnerability.under_evaluation': true } }]);
    expect(vuln.body.sort[0]['vulnerability.score.base'].order).toBe('desc');
    expect(client.calls.find((c) => c.index === 'wazuh-states-inventory-ports*').body.aggs.listening).toEqual({ filter: { term: { 'interface.state': 'listening' } } });
  });

  test('5.0 fixtures: wazuh.agent.id identity and the SCA family', async () => {
    const client = fakeClient({
      identityField: 'wazuh.agent.id',
      agentId: '0191a2b3',
      system: SYSTEM_5,
      ips: ['192.168.1.20'],
      ports: { open: 3, listening: 3 },
      vulns: VULN_5,
      vulnBuckets: [{ key: 'High', doc_count: 1 }],
      sca: { failed: 14, passed: 60 },
    });
    const families = await readAssetContextFamilies(client, { agentId: '0191a2b3', agentName: null }, { map: FIELD_MAPS[5] });
    expect(families.system.os).toEqual({ name: 'Debian GNU/Linux', version: '12', platform: 'debian' });
    expect(families.vulnerabilities).toMatchObject({ status: 'ok', critical: 0, high: 1, topCves: [{ id: 'CVE-2024-6387', score: 8.1 }] });
    expect(families.sca).toEqual({ status: 'ok', total: 74, failed: 14, passed: 60 });
    expect(client.search).toHaveBeenCalledTimes(5);
    expect(client.calls.find((c) => c.index === 'wazuh-states-sca*').body.aggs.result.terms.field).toBe('check.result');
    for (const call of client.calls) expect(call.body.query.bool.filter[0]).toEqual({ term: { 'wazuh.agent.id': '0191a2b3' } });
  });

  test('falls back to the other line identity field when the primary finds nothing', async () => {
    // A 4.x build reading a 5.0 cluster: root agent.id matches nothing, wazuh.agent.id does.
    const client = fakeClient({ identityField: 'wazuh.agent.id', agentId: '0191a2b3', system: SYSTEM_5, ips: ['192.168.1.20'] });
    const families = await readAssetContextFamilies(client, { agentId: '0191a2b3', agentName: null }, { map: FIELD_MAPS[4] });
    expect(families.system.os?.name).toBe('Debian GNU/Linux');
    expect(families.networks.ips).toEqual(['192.168.1.20']);
    const systemCalls = client.calls.filter((c) => c.index === 'wazuh-states-inventory-system*');
    expect(systemCalls.map((c) => Object.keys(c.body.query.bool.filter[0].term)[0])).toEqual(['agent.id', 'wazuh.agent.id']);
  });

  test('an unknown agent is ok with no data after both identity fields were tried', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001' });
    const families = await readAssetContextFamilies(client, { agentId: '999', agentName: null }, { map: FIELD_MAPS[4] });
    expect(families.system).toEqual({ status: 'ok', os: null, hostname: null });
    expect(families.networks).toEqual({ status: 'ok', ips: [], total: 0 });
    expect(families.ports).toEqual({ status: 'ok', open: 0, listening: 0 });
    expect(families.vulnerabilities).toMatchObject({ status: 'ok', total: 0, critical: 0, high: 0, topCves: [] });
    expect(client.search).toHaveBeenCalledTimes(8);
  });

  test('matches by agent name when no id is known', async () => {
    const client = fakeClient({ identityField: 'agent.name', agentId: 'web-01', system: SYSTEM_4 });
    const families = await readAssetContextFamilies(client, { agentId: null, agentName: 'web-01' }, { map: FIELD_MAPS[4] });
    expect(families.system.os?.name).toBe('Ubuntu');
    expect(client.calls[0].body.query.bool.filter[0]).toEqual({ term: { 'agent.name': 'web-01' } });
  });

  test('refuses a target without any identity', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001' });
    await expect(readAssetContextFamilies(client, { agentId: null, agentName: null }, { map: FIELD_MAPS[4] })).rejects.toThrow(/agent id or agent name/);
    expect(client.search).not.toHaveBeenCalled();
  });

  test('maps 403 to no_access and 404 to not_available per family, without a second identity try', async () => {
    const client = fakeClient({
      identityField: 'wazuh.agent.id',
      agentId: '0191a2b3',
      system: SYSTEM_5,
      throwFor: { vulnerabilities: httpError(403, 'security_exception'), sca: httpError(404, 'index_not_found_exception'), ports: httpError(403) },
    });
    const families = await readAssetContextFamilies(client, { agentId: '0191a2b3', agentName: null }, { map: FIELD_MAPS[5] });
    expect(families.system.status).toBe('ok');
    expect(families.vulnerabilities).toEqual({ status: 'no_access' });
    expect(families.ports).toEqual({ status: 'no_access' });
    expect(families.sca).toEqual({ status: 'not_available' });
    expect(client.calls.filter((c) => c.index === 'wazuh-states-vulnerabilities*')).toHaveLength(1);
  });

  test('a real outage in one family is an error for that family only', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001', system: SYSTEM_4, throwFor: { networks: new Error('connection reset') } });
    const families = await readAssetContextFamilies(client, { agentId: '001', agentName: null }, { map: FIELD_MAPS[4] });
    expect(families.networks).toEqual({ status: 'error', reason: 'connection reset' });
    expect(families.system.status).toBe('ok');
  });

  test('a family slower than the budget times out while the others answer', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001', system: SYSTEM_4, delayFor: { vulnerabilities: 200 } });
    const started = Date.now();
    const families = await readAssetContextFamilies(client, { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], budgetMs: 40 });
    expect(Date.now() - started).toBeLessThan(190);
    expect(families.vulnerabilities).toEqual({ status: 'error', reason: 'timeout' });
    expect(families.system.status).toBe('ok');
    expect(families.networks.status).toBe('ok');
    await new Promise((r) => setTimeout(r, 220));
  });
});

describe('getAssetContext cache', () => {
  beforeEach(() => clearAssetContextCache());

  test('caches per user and agent for 60 s and marks served copies', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001', system: SYSTEM_4 });
    let clock = 1_000_000;
    const now = () => clock;
    const first = await getAssetContext(client, 'analyst', { agentId: '001', agentName: 'web-01' }, { map: FIELD_MAPS[4], now });
    expect(first).toMatchObject({ agentId: '001', agentName: 'web-01', line: 4, cached: false, fetchedAt: new Date(clock).toISOString() });
    // vulnerabilityDetection is emitted on every build target; itHygiene is not.
    expect(first.links.vulnerabilityDetection).toContain('agentId=001');
    const searches = client.search.mock.calls.length;

    clock += ASSET_CONTEXT_CACHE_TTL_MS - 1;
    const second = await getAssetContext(client, 'analyst', { agentId: '001', agentName: 'web-01' }, { map: FIELD_MAPS[4], now });
    expect(second.cached).toBe(true);
    expect(second.families).toEqual(first.families);
    expect(client.search.mock.calls.length).toBe(searches);

    // Another user never sees the first user's answer (their grants may differ).
    const other = await getAssetContext(client, 'admin', { agentId: '001', agentName: 'web-01' }, { map: FIELD_MAPS[4], now });
    expect(other.cached).toBe(false);
    expect(client.search.mock.calls.length).toBe(searches * 2);

    clock += 2;
    const expired = await getAssetContext(client, 'analyst', { agentId: '001', agentName: 'web-01' }, { map: FIELD_MAPS[4], now });
    expect(expired.cached).toBe(false);
    expect(client.search.mock.calls.length).toBe(searches * 3);
  });

  test('cache keys separate id and name targets and the two lines', () => {
    expect(cacheKey('u', FIELD_MAPS[4], { agentId: '001', agentName: 'x' })).toBe('u|4|id:001');
    expect(cacheKey('u', FIELD_MAPS[5], { agentId: null, agentName: 'web-01' })).toBe('u|5|name:web-01');
  });

  test('a response with an error family is not cached, so a timeout is re-queried on the next call', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001', system: SYSTEM_4, delayFor: { vulnerabilities: 200 } });
    const now = () => 1_700_000_000_000;
    const first = await getAssetContext(client, 'analyst', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now, budgetMs: 40 });
    expect(first.families.vulnerabilities).toEqual({ status: 'error', reason: 'timeout' });
    expect(hasErrorFamily(first.families)).toBe(true);
    const callsAfterFirst = client.search.mock.calls.length;
    const second = await getAssetContext(client, 'analyst', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now, budgetMs: 40 });
    expect(second.cached).toBe(false);
    expect(client.search.mock.calls.length).toBeGreaterThan(callsAfterFirst);
    // A clean answer is cached as before.
    const clean = fakeClient({ identityField: 'agent.id', agentId: '001', system: SYSTEM_4 });
    await getAssetContext(clean, 'analyst', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now });
    const again = await getAssetContext(clean, 'analyst', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now });
    expect(again.cached).toBe(true);
    expect(hasErrorFamily(again.families)).toBe(false);
  });

  test('cache: false neither reads nor writes the cache', async () => {
    const client = fakeClient({ identityField: 'agent.id', agentId: '001', system: SYSTEM_4 });
    const now = () => 1_700_000_000_000;
    await getAssetContext(client, 'dashboard_user', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now, cache: false });
    const second = await getAssetContext(client, 'dashboard_user', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now, cache: false });
    expect(second.cached).toBe(false);
    // Nothing was stored under that name either.
    const third = await getAssetContext(client, 'dashboard_user', { agentId: '001', agentName: null }, { map: FIELD_MAPS[4], now });
    expect(third.cached).toBe(false);
  });
});
