import { alertUid } from '../operational_projection';
import { WAZUH4_ALERT_ADAPTER } from './wazuh4_alert_adapter';
import { WAZUH5_FINDING_ADAPTER, projectFinding, projectNativeCase5 } from './wazuh5_finding_adapter';

// Live Wazuh 5.0.0 Beta 5 finding (redacted). Re-validated against rc2 in Phase 1.
const beta5Finding = {
  _index: '.ds-wazuh-findings-v5-system-activity-000001',
  _id: 'I8cUeKABID2WbzqznzaH',
  _source: {
    process: { name: 'apparmor_parser', pid: 81192, executable: 'unconfined' },
    '@timestamp': '2026-09-06T18:55:13.659Z',
    related: { hosts: ['wazuh-allinone'] },
    host: { hostname: 'wazuh-allinone' },
    wazuh: {
      cluster: { node: 'node01', name: 'wazuh' },
      protocol: { location: 'journald', queue: 49 },
      agent: {
        host: { hostname: 'wazuh-allinone', os: { name: 'Ubuntu', type: 'linux' }, architecture: 'x86_64' },
        name: 'wazuh-allinone',
        groups: ['default'],
        id: '001',
        version: 'v5.0.0',
      },
      integration: { name: 'linux', decoders: ['decoder/linux-apparmor/0'], category: 'system-activity' },
      rule: {
        sigma_id: '71156dc6-5833-5376-9426-e96f8485eec1',
        level: 'low',
        compliance: { pci_dss: ['10.6.1'] },
        id: '71156dc6-5833-5376-9426-e96f8485eec1',
        title: 'SELinux access vector cache denial',
        tags: ['low', 'auditd'],
        status: 'stable',
      },
      event: { id: 'edab1102-d2cd-4f32-b0e6-39cab79a0f4b' },
      space: { name: 'standard' },
    },
    event: {
      sequence: 435,
      original: 'Sep 06 18:55:10 wazuh-allinone kernel: audit: type=1400 ...',
      kind: 'event',
      index: '.ds-wazuh-events-v5-system-activity-000001',
      category: ['intrusion_detection'],
      type: ['info'],
      doc_id: 'GccTeKABID2WbzqzKzak',
    },
    message: 'audit: type=1400 audit(1788720910.947:435): apparmor="STATUS"',
  },
};

describe('Wazuh 5.0 finding adapter', () => {
  test('normalizes a Beta 5 finding into the canonical projection', () => {
    const doc = projectFinding(beta5Finding, '2026-10-31T00:00:00.000Z');
    expect(doc.alert_uid).toBe(alertUid('.ds-wazuh-findings-v5-system-activity-000001', 'I8cUeKABID2WbzqznzaH'));
    expect(doc.source_index).toBe('.ds-wazuh-findings-v5-system-activity-000001');
    expect(doc.source_id).toBe('I8cUeKABID2WbzqznzaH');
    expect(doc.source_resolved).toBe(true);
    expect(doc.source_family).toBe('wazuh5_findings');
    expect(doc.source_profile_version).toBe(1);
    expect(doc['@timestamp']).toBe('2026-09-06T18:55:13.659Z');
    expect(doc.ingested_at).toBe('2026-10-31T00:00:00.000Z');
    expect(doc.status).toBe('open');
    expect(doc.agent).toEqual({ id: '001', name: 'wazuh-allinone', ip: null });
    expect(doc.manager).toEqual({ name: 'node01' });
    expect(doc.rule).toEqual({
      id: '71156dc6-5833-5376-9426-e96f8485eec1',
      level: null,
      description: 'SELinux access vector cache denial',
      groups: ['low', 'auditd'],
      mitre: null,
    });
    expect(doc.severity_label).toBe('low');
    expect(doc.data).toEqual({
      srcip: null, dstip: null, srcport: null, dstport: null, srcuser: null, dstuser: null,
      process: { name: 'apparmor_parser' },
      url: null, hostname: null, win: null, audit: null,
    });
    expect(doc.decoder).toEqual({ name: 'linux' });
    expect(doc.location).toBe('journald');
    expect(doc.full_log_excerpt).toBe('Sep 06 18:55:10 wazuh-allinone kernel: audit: type=1400 ...');
    expect(doc.event_index).toBe('.ds-wazuh-events-v5-system-activity-000001');
    expect(doc.event_doc_id).toBe('GccTeKABID2WbzqzKzak');
    expect(doc.space).toBe('standard');
  });

  test('never coerces a severity label to a number and never invents zero', () => {
    for (const level of ['low', 'Medium', 'HIGH', 'critical', 'informational']) {
      const doc = projectFinding({ _index: 'x', _id: 'y', _source: { wazuh: { rule: { id: 'r', level } } } });
      expect(doc.rule.level).toBeNull();
      expect(doc.severity_label).toBe(level.toLowerCase());
    }
    const numeric = projectFinding({ _index: 'x', _id: 'y', _source: { wazuh: { rule: { id: 'r', level: 7 } } } });
    expect(numeric.rule.level).toBe(7);
    expect(numeric.severity_label).toBeNull();
    const absent = projectFinding({ _index: 'x', _id: 'y', _source: { wazuh: { rule: { id: 'r' } } } });
    expect(absent.rule.level).toBeNull();
    expect(absent.severity_label).toBeNull();
  });

  test('reads ECS entities and falls back to root agent/rule fields (rc2 template shape)', () => {
    const doc = projectFinding({
      _index: '.ds-wazuh-findings-v5-access-management-000003',
      _id: 'abc',
      _source: {
        '@timestamp': 1761900000000,
        agent: { id: '007', name: 'web-01', ip: '10.0.0.7' },
        rule: { id: 'rule-1', name: 'SSH brute force', level: 'high', mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
        source: { ip: '203.0.113.9', port: '51515', user: { name: 'root' } },
        destination: { ip: '10.0.0.7', port: 22, user: { name: 'svc' } },
        user: { name: 'ignored-because-source.user.name-wins' },
        process: { name: 'sshd' },
        event: { index: '.ds-wazuh-events-v5-access-management-000003', doc_id: 'evt-1', original: 'Failed password for root' },
        log: { file: { path: '/var/log/auth.log' } },
      },
    });
    expect(doc['@timestamp']).toBe(1761900000000);
    expect(doc.agent).toEqual({ id: '007', name: 'web-01', ip: '10.0.0.7' });
    expect(doc.rule.id).toBe('rule-1');
    expect(doc.rule.description).toBe('SSH brute force');
    expect(doc.rule.level).toBeNull();
    expect(doc.severity_label).toBe('high');
    expect(doc.rule.mitre).toEqual({ id: ['T1110'], technique: ['Brute Force'], tactic: ['Credential Access'] });
    expect(doc.data).toEqual({
      srcip: '203.0.113.9', dstip: '10.0.0.7', srcport: 51515, dstport: 22, srcuser: 'root', dstuser: 'svc',
      process: { name: 'sshd' },
      url: null, hostname: null, win: null, audit: null,
    });
    expect(doc.location).toBe('/var/log/auth.log');
    expect(doc.full_log_excerpt).toBe('Failed password for root');
  });

  test('bounds every free-text field and tolerates an empty document', () => {
    const long = 'x'.repeat(5000);
    const doc = projectFinding({
      _index: 'i', _id: 'd',
      _source: { wazuh: { rule: { id: 'r', title: long } }, event: { original: long, index: long, doc_id: long }, wazuh_space: {} },
    });
    expect(doc.rule.description.length).toBeLessThan(1100);
    expect(doc.full_log_excerpt.length).toBeLessThan(2100);
    expect(doc.event_index.length).toBeLessThan(600);
    expect(doc.event_doc_id.length).toBeLessThan(600);
    const empty = projectFinding({ _index: '', _id: '', _source: null });
    expect(empty.source_resolved).toBe(false);
    expect(empty.agent).toBeNull();
    expect(empty.rule).toBeNull();
    expect(empty.data.srcip).toBeNull();
    expect(empty.event_index).toBeNull();
  });

  test('query uses only the timestamp window and ignores the 4.x numeric floor', () => {
    const q = WAZUH5_FINDING_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minRuleLevel: 7 });
    expect(q).toEqual({ bool: { must: [{ range: { '@timestamp': { gte: 'a', lte: 'b' } } }] } });
    expect(WAZUH5_FINDING_ADAPTER.supportsNumericLevelFilter).toBe(false);
    // date_nanos sort keys must be cast to milliseconds (see sortSpec comment).
    expect(WAZUH5_FINDING_ADAPTER.sortSpec()).toEqual([
      { '@timestamp': { order: 'asc', numeric_type: 'date' } },
      { _doc: { order: 'asc' } },
    ]);
  });
});

describe('Wazuh 4.x alert adapter keeps v2 behaviour', () => {
  test('query, sort and projection match v2 plus additive provenance fields', () => {
    expect(WAZUH4_ALERT_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minRuleLevel: 7 })).toEqual({
      bool: { must: [{ range: { '@timestamp': { gte: 'a', lte: 'b' } } }, { range: { 'rule.level': { gte: 7 } } }] },
    });
    expect(WAZUH4_ALERT_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minRuleLevel: null })).toEqual({
      bool: { must: [{ range: { '@timestamp': { gte: 'a', lte: 'b' } } }] },
    });
    const doc = WAZUH4_ALERT_ADAPTER.project(
      {
        _index: 'wazuh-alerts-4.x-2026.10.31',
        _id: 'a1',
        _source: {
          '@timestamp': '2026-10-31T10:00:00.000Z',
          agent: { id: '001', name: 'h', ip: '10.0.0.1' },
          rule: { id: '5710', level: 5, description: 'sshd: attempt', groups: ['syslog', 'sshd'] },
          data: { srcip: '203.0.113.5', srcuser: 'root' },
          full_log: 'raw',
        },
      },
      '2026-10-31T10:00:01.000Z'
    );
    expect(doc.alert_uid).toBe(alertUid('wazuh-alerts-4.x-2026.10.31', 'a1'));
    expect(doc.rule).toEqual({ id: '5710', level: 5, description: 'sshd: attempt', groups: ['syslog', 'sshd'], mitre: null });
    expect(doc.data.srcip).toBe('203.0.113.5');
    expect(doc.source_family).toBe('wazuh4_alerts');
    expect(doc.source_profile_version).toBe(1);
    expect(doc.severity_label).toBeNull();
    expect(doc.event_index).toBeUndefined();
  });

  test('4.x and 5.x hits with equal meaning yield equal canonical entities', () => {
    const four = WAZUH4_ALERT_ADAPTER.project({
      _index: 'wazuh-alerts-4.x-2026.10.31', _id: '1',
      _source: { agent: { id: '001', name: 'h' }, data: { srcip: '203.0.113.5', srcport: '4444', dstip: '10.0.0.2', dstport: '22', srcuser: 'root', dstuser: 'svc', process: { name: 'sshd' } } },
    });
    const five = WAZUH5_FINDING_ADAPTER.project({
      _index: '.ds-wazuh-findings-v5-access-management-000001', _id: '1',
      _source: { wazuh: { agent: { id: '001', name: 'h' } }, source: { ip: '203.0.113.5', port: 4444, user: { name: 'root' } }, destination: { ip: '10.0.0.2', port: 22, user: { name: 'svc' } }, process: { name: 'sshd' } },
    });
    expect(five.agent).toEqual(four.agent);
    expect(five.data).toEqual(four.data);
  });
});

describe('Wazuh 5.0 rc2 live fixtures', () => {
  // Two genuine findings captured from a Wazuh 5.0.0-rc2 lab on 2026-10-31
  // (runtime-evidence/phase1-5.0-rc2); the adapter contract is locked to them.
  const fixtures: any[] = require('./__fixtures__/rc2_findings.json');

  test('every live finding normalizes with wazuh.* identity, a label severity and event provenance', () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(2);
    for (const hit of fixtures) {
      const doc = projectFinding(hit, '2026-10-31T17:00:00.000Z');
      expect(doc.source_index).toMatch(/^\.ds-wazuh-findings-v5-[a-z-]+-\d{6}$/);
      expect(doc.alert_uid).toBe(alertUid(hit._index, hit._id));
      expect(doc.agent).toEqual({ id: '001', name: 'wazuh-allinone', ip: null });
      expect(doc.manager).toEqual({ name: 'node01' });
      expect(typeof doc.rule.id).toBe('string');
      expect(doc.rule.description).toBe(hit._source.wazuh.rule.title);
      expect(doc.rule.level).toBeNull();
      expect(doc.severity_label).toBe(hit._source.wazuh.rule.level);
      expect(doc.rule.groups).toEqual(hit._source.wazuh.rule.tags);
      expect(doc.event_index).toMatch(/^\.ds-wazuh-events-v5-[a-z-]+-\d{6}$/);
      expect(typeof doc.event_doc_id).toBe('string');
      expect(doc.space).toBe('standard');
      expect(doc.decoder).toEqual({ name: 'system-auth' });
      expect(doc.location).toBe('journald');
      expect(doc['@timestamp']).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);
      expect(doc.full_log_excerpt).toBe(hit._source.event.original);
    }
  });

  test('the failed-authentication finding exposes the user entity for correlation', () => {
    const auth = fixtures.find((hit) => /Failed authentication/.test(hit._source.wazuh.rule.title));
    const doc = projectFinding(auth);
    expect(doc.data.srcuser).toBe('nobody');
    expect(doc.rule.mitre?.id).toEqual(expect.arrayContaining([expect.stringMatching(/^T\d{4}/)]));
  });
});

describe('Wazuh 5.0 source-side severity floor', () => {
  test('minSeverityLabel becomes a terms filter on wazuh.rule.level for that band and above', () => {
    const q = WAZUH5_FINDING_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minSeverityLabel: 'medium' });
    expect(q.bool.must[1]).toEqual({ terms: { 'wazuh.rule.level': ['medium', 'high', 'critical'] } });
    expect(WAZUH5_FINDING_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minSeverityLabel: 'HIGH ' }).bool.must[1]).toEqual({
      terms: { 'wazuh.rule.level': ['high', 'critical'] },
    });
  });

  test('an unknown or absent label floor adds no filter, and 4.x ignores the label floor', () => {
    expect(WAZUH5_FINDING_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minSeverityLabel: 'urgent' }).bool.must).toHaveLength(1);
    expect(WAZUH5_FINDING_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b' }).bool.must).toHaveLength(1);
    expect(WAZUH4_ALERT_ADAPTER.buildQuery({ windowFrom: 'a', windowTo: 'b', minSeverityLabel: 'high' }).bool.must).toHaveLength(1);
  });
});

describe('Wazuh 5.0 native context for indicators (step 6.1)', () => {
  // Shape from e2e/seed_findings_v5.py finding_doc() plus engine enrichments
  // (ECS threat.enrichments) and <entity>.geo/.as.
  const enriched = {
    _index: '.ds-wazuh-findings-v5-wam-e2e-000001',
    _id: 'f1',
    _source: {
      '@timestamp': '2026-11-20T11:00:00.000Z',
      host: { hostname: 'wam-e2e-agent' },
      source: { ip: '203.0.113.7', port: 4242, geo: { country_name: 'Germany', city_name: 'Berlin', location: { lat: 52.52, lon: 13.4 } }, as: { number: 64496, organization: { name: 'Example AS' } } },
      destination: { ip: '198.51.100.20', port: 22, domain: 'c2.example.net', as: { number: 64497 } },
      user: { name: 'alice' },
      process: { name: 'sshd' },
      file: { path: '/usr/bin/evil', hash: { md5: 'd41d8cd98f00b204e9800998ecf8427e', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } },
      url: { full: 'http://c2.example.net/beacon', domain: 'c2.example.net' },
      dns: { question: { name: 'c2.example.net' } },
      related: { ip: ['203.0.113.7', '198.51.100.20'], hosts: ['wam-e2e-agent'], hash: ['d41d8cd98f00b204e9800998ecf8427e'], user: ['alice'] },
      wazuh: {
        agent: { id: '901', name: 'wam-e2e-agent', groups: ['default'], host: { hostname: 'wam-e2e-agent', ip: '192.0.2.10' } },
        rule: { id: 'wam-e2e-rule', title: 'Failed authentication attempt - alice', level: 'high', tags: ['high'] },
        threat: {
          enrichments: Array.from({ length: 25 }, (_, i) => ({
            indicator: { id: `ioc-${i}`, name: i === 0 ? '198.51.100.20:22' : `198.51.100.${i}`, type: 'connection', provider: 'abuse.ch', feed: { name: 'feodotracker' }, confidence: 'High', tags: ['botnet'], software: { name: 'Emotet' } },
            matched: { field: 'destination.ip', atomic: '198.51.100.20' },
          })),
        },
      },
      event: { index: '.ds-wazuh-events-v5-wam-e2e-000001', doc_id: 'e1' },
    },
  };

  test('projects file hashes, url, hostname and related lists', () => {
    const doc = projectFinding(enriched, '2026-11-20T12:00:00.000Z');
    expect(doc.syscheck).toEqual({ path: '/usr/bin/evil', md5_after: 'd41d8cd98f00b204e9800998ecf8427e', sha1_after: null, sha256_after: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
    expect(doc.data.url).toBe('http://c2.example.net/beacon');
    expect(doc.data.hostname).toBe('c2.example.net');
    expect(doc.data.win).toBeNull();
    expect(doc.related).toEqual({ ip: ['203.0.113.7', '198.51.100.20'], hosts: ['wam-e2e-agent'], hash: ['d41d8cd98f00b204e9800998ecf8427e'], user: ['alice'] });
  });

  test('copies wazuh.threat.enrichments[] bounded to 20 entries with the matched field', () => {
    const doc = projectFinding(enriched, '2026-11-20T12:00:00.000Z');
    expect(doc.threat.total).toBe(25);
    expect(doc.threat.truncated).toBe(true);
    expect(doc.threat.matches).toHaveLength(20);
    expect(doc.threat.sibling_of).toBeNull();
    expect(doc.threat.matches[0]).toEqual({
      source: 'wazuh5_engine', verdict: 'malicious', matched_field: 'destination.ip', detail: null, link: null,
      indicator: { id: 'ioc-0', name: '198.51.100.20:22', type: 'connection', provider: 'abuse.ch', feed: 'feodotracker', confidence: 'High', tags: ['botnet'], software: 'Emotet' },
    });
  });

  test('projects <entity>.geo/.as per entity and nothing when absent', () => {
    const doc = projectFinding(enriched, '2026-11-20T12:00:00.000Z');
    expect(doc.geo).toEqual([
      { entity: 'source', ip: '203.0.113.7', country_name: 'Germany', region_name: null, city_name: 'Berlin', location: { lat: 52.52, lon: 13.4 }, as: { number: 64496, organization: 'Example AS' }, provider: 'wazuh5_engine' },
      { entity: 'destination', ip: '198.51.100.20', country_name: null, region_name: null, city_name: null, location: null, as: { number: 64497, organization: null }, provider: 'wazuh5_engine' },
    ]);
    const plain = projectFinding(beta5Finding, '2026-10-31T00:00:00.000Z');
    expect(plain.geo).toBeNull();
    expect(plain.threat).toBeNull();
    expect(plain.syscheck).toBeNull();
    expect(plain.related).toEqual({ ip: [], hosts: ['wazuh-allinone'], hash: [], user: [] });
  });

  test('projects client/server .geo/.as and host .geo, bounded to MAX_GEO_HINTS in entity order', () => {
    const doc = projectFinding({
      _index: '.ds-wazuh-findings-v5-wam-e2e-000001', _id: 'f2',
      _source: {
        '@timestamp': '2026-11-20T11:00:00.000Z',
        client: { ip: '203.0.113.8', geo: { country_name: 'France' }, as: { number: 64500, organization: { name: 'Client AS' } } },
        server: { ip: '198.51.100.30', geo: { city_name: 'Dublin', country_iso_code: 'IE' } },
        host: { hostname: 'wam-e2e-agent', geo: { country_name: 'Ireland', region_name: 'Leinster' } },
        wazuh: { agent: { id: '902', name: 'wam-e2e-agent' }, rule: { id: 'r', title: 't', level: 'low' } },
      },
    }, '2026-11-20T12:00:00.000Z');
    expect(doc.geo).toEqual([
      { entity: 'client', ip: '203.0.113.8', country_name: 'France', region_name: null, city_name: null, location: null, as: { number: 64500, organization: 'Client AS' }, provider: 'wazuh5_engine' },
      { entity: 'server', ip: '198.51.100.30', country_name: 'IE', region_name: null, city_name: 'Dublin', location: null, as: null, provider: 'wazuh5_engine' },
      { entity: 'host', ip: null, country_name: 'Ireland', region_name: 'Leinster', city_name: null, location: null, as: null, provider: 'wazuh5_engine' },
    ]);
    const all = projectFinding({
      _index: '.ds-wazuh-findings-v5-wam-e2e-000001', _id: 'f3',
      _source: {
        '@timestamp': '2026-11-20T11:00:00.000Z',
        source: { geo: { country_name: 'A' } }, destination: { geo: { country_name: 'B' } },
        client: { geo: { country_name: 'C' } }, server: { geo: { country_name: 'D' } }, host: { geo: { country_name: 'E' } },
        wazuh: { agent: { id: '902', name: 'x' }, rule: { id: 'r', title: 't', level: 'low' } },
      },
    }, '2026-11-20T12:00:00.000Z');
    expect(all.geo.map((g: any) => g.entity)).toEqual(['source', 'destination', 'client', 'server']);
  });
});

describe('Wazuh 5.0 asset stamping (step 6.4a)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { buildAssetMatcher } = require('../assets/matcher');
  const finding = (groups: any, extra: any = {}) => ({
    _index: '.ds-wazuh-findings-v5-wam-e2e-000001',
    _id: 'f-asset',
    _source: {
      '@timestamp': '2026-11-20T11:00:00.000Z',
      wazuh: { agent: { id: '901', name: 'wam-e2e-agent', groups, ...extra }, rule: { id: 'r', title: 't', level: 'high' } },
    },
  });
  const matcher = buildAssetMatcher([
    { id: 'pci', match: { kind: 'group', value: 'pci' }, criticality: 'critical', tags: ['pci-dss'] },
    { id: 'e2e', match: { kind: 'glob', value: 'wam-e2e-*' }, criticality: 'medium', tags: [] },
  ]);

  test('groups come from wazuh.agent.groups on the record; labels are null (removed in 5.0)', () => {
    const doc = projectFinding(finding(['default', 'pci']), '2026-11-20T12:00:00.000Z', { assets: matcher });
    expect(doc.asset).toEqual({ criticality: 'medium', tags: [], groups: ['default', 'pci'], labels: null, matched_id: 'e2e', matched_by: 'glob' });
    const byGroup = projectFinding(finding(['pci'], { name: 'other' }), undefined, { assets: matcher });
    expect(byGroup.asset).toMatchObject({ criticality: 'critical', tags: ['pci-dss'], matched_by: 'group' });
  });

  test('record groups win over any cached lookup and the field is present without a context', () => {
    const doc = projectFinding(finding('solo'), undefined, { assets: matcher, agentGroups: new Map([['901', ['cached']]]) });
    expect(doc.asset.groups).toEqual(['solo']);
    expect(WAZUH5_FINDING_ADAPTER.project(finding(undefined)).asset).toEqual({
      criticality: null, tags: [], groups: [], labels: null, matched_id: null, matched_by: null,
    });
  });
});

describe('due timestamps at first projection (step 3.2)', () => {
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

  test('the 5.0 adapter stamps both due fields from a label-only severity through the policy', () => {
    const doc = WAZUH5_FINDING_ADAPTER.project(beta5Finding, '2026-10-31T00:00:00.000Z', { slaPolicy: policy });
    expect(doc.rule.level).toBeNull();
    expect(doc.severity_label).toBe('low');
    expect(doc.reporting).toEqual({
      sla_due_at: plus('2026-09-06T18:55:13.659Z', 2880),
      assign_due_at: plus('2026-09-06T18:55:13.659Z', 240),
    });
    const high = WAZUH5_FINDING_ADAPTER.project(
      { _index: 'x', _id: 'y', _source: { '@timestamp': '2026-10-31T10:00:00.000Z', wazuh: { rule: { id: 'r', level: 'high' } } } },
      '2026-10-31T10:00:01.000Z',
      { slaPolicy: policy }
    );
    expect(high.reporting).toEqual({ sla_due_at: plus('2026-10-31T10:00:00.000Z', 120), assign_due_at: plus('2026-10-31T10:00:00.000Z', 20) });
    // No label at all: no due date (never guessed).
    const none = WAZUH5_FINDING_ADAPTER.project({ _index: 'x', _id: 'y', _source: { '@timestamp': '2026-10-31T10:00:00.000Z', wazuh: { rule: { id: 'r' } } } }, undefined, { slaPolicy: policy });
    expect(none.reporting).toEqual({ sla_due_at: null, assign_due_at: null });
  });

  test('the 4.x adapter stamps both due fields from the numeric level, with the built-in targets without a policy', () => {
    const hit = {
      _index: 'wazuh-alerts-4.x-2026.10.31',
      _id: 'a1',
      _source: { '@timestamp': '2026-10-31T10:00:00.000Z', rule: { id: '5710', level: 12, description: 'x' } },
    };
    expect(WAZUH4_ALERT_ADAPTER.project(hit, '2026-10-31T10:00:01.000Z', { slaPolicy: policy }).reporting).toEqual({
      sla_due_at: plus('2026-10-31T10:00:00.000Z', 30),
      assign_due_at: plus('2026-10-31T10:00:00.000Z', 5),
    });
    expect(WAZUH4_ALERT_ADAPTER.project(hit, '2026-10-31T10:00:01.000Z').reporting).toEqual({
      sla_due_at: plus('2026-10-31T10:00:00.000Z', 60),
      assign_due_at: plus('2026-10-31T10:00:00.000Z', 15),
    });
  });
});

describe('Wazuh 5.0 native case projection (step 2.6, Q6: read-only)', () => {
  const finding = (wazuhCase: any) => ({
    _index: '.ds-wazuh-findings-v5-access-management-000001',
    _id: 'f-case',
    _source: {
      '@timestamp': '2026-11-21T10:00:00.000Z',
      wazuh: {
        agent: { id: '001', name: 'web-01' },
        rule: { id: 'r1', title: 'Failed authentication', level: 'high' },
        ...(wazuhCase === undefined ? {} : { case: wazuhCase }),
      },
    },
  });

  test('copies the allowlisted wazuh.case.* fields verbatim and drops everything else', () => {
    // `id` is reserved: the bundled 5.0.0-rc2 sources write no wazuh.case.id
    // (a native case is the finding itself). The fixture exercises the slot
    // so a later Wazuh line that names cases flows through unchanged.
    const doc = projectFinding(finding({
      id: 'case-7',
      status: 'acknowledged',
      severity: 'high',
      priority: 'p2',
      tlp: 'amber',
      title: 'Brute force on web-01',
      tags: ['ssh', 'brute-force'],
      updated_at: '2026-11-21T09:30:00Z',
      description: 'long analyst text that must not be copied',
      comments: [{ user: 'a', text: 'secret' }],
      user: { name: 'analyst' },
      created_at: '2026-11-20T00:00:00Z',
    }));
    expect(doc.native_case).toEqual({
      id: 'case-7',
      status: 'acknowledged',
      severity: 'high',
      priority: 'p2',
      tlp: 'amber',
      title: 'Brute force on web-01',
      tags: ['ssh', 'brute-force'],
      updated_at: '2026-11-21T09:30:00.000Z',
    });
    expect(Object.keys(doc.native_case)).toEqual(['id', 'status', 'severity', 'priority', 'tlp', 'title', 'tags', 'updated_at']);
    // The canonical case link stays the plugin's own: a native case is never a WAM case.
    expect(doc.case_id).toBeNull();
  });

  test('is null when wazuh.case is absent, not an object, or empty', () => {
    expect(projectFinding(finding(undefined)).native_case).toBeNull();
    expect(projectFinding(finding(null)).native_case).toBeNull();
    expect(projectFinding(finding('active')).native_case).toBeNull();
    expect(projectFinding(finding(['active'])).native_case).toBeNull();
    expect(projectFinding(finding(42)).native_case).toBeNull();
    expect(projectFinding(finding({})).native_case).toBeNull();
    expect(projectFinding(finding({ description: 'only unknown keys' })).native_case).toBeNull();
    expect(projectNativeCase5({})).toBeNull();
  });

  test('coerces malformed values to strings, drops objects and bounds every field', () => {
    const doc = projectFinding(finding({
      id: 12345,
      status: ['active', 'ignored-second'],
      severity: { nested: 'object' },
      priority: true,
      tlp: '  red  ',
      title: 'x'.repeat(600),
      tags: 'single-tag',
      updated_at: 'not a date',
    }));
    expect(doc.native_case).toEqual({
      id: '12345',
      status: 'active',
      severity: null,
      priority: 'true',
      tlp: 'red',
      title: 'x'.repeat(512),
      tags: ['single-tag'],
      updated_at: null,
    });
    const longScalar = projectFinding(finding({ status: 's'.repeat(100) })).native_case;
    expect(longScalar.status).toHaveLength(64);
  });

  test('bounds tags to 20 entries of at most 128 characters and skips non-scalars and blanks', () => {
    const tags = Array.from({ length: 30 }, (_, i) => `tag-${i}`);
    const doc = projectFinding(finding({ status: 'active', tags: [...tags, { bad: true }, '', '   '] }));
    expect(doc.native_case.tags).toEqual(tags.slice(0, 20));
    const long = projectFinding(finding({ status: 'active', tags: ['y'.repeat(300), { obj: 1 }, 7] })).native_case;
    expect(long.tags).toEqual(['y'.repeat(128), '7']);
  });

  test('de-duplicates tags after trimming and truncation, before the cap', () => {
    expect(projectFinding(finding({ status: 'active', tags: ['a', 'a', ' a '] })).native_case.tags).toEqual(['a']);
    const collide = projectFinding(finding({ status: 'active', tags: ['z'.repeat(128) + '1', 'z'.repeat(128) + '2'] })).native_case;
    expect(collide.tags).toEqual(['z'.repeat(128)]);
    const repeated = projectFinding(finding({ status: 'active', tags: [...Array.from({ length: 25 }, () => 'dup'), 'last'] })).native_case;
    expect(repeated.tags).toEqual(['dup', 'last']);
  });

  test('the 4.x adapter always sets native_case to null, even when the source carries a wazuh.case object', () => {
    const doc = WAZUH4_ALERT_ADAPTER.project({
      _index: 'wazuh-alerts-4.x-2026.11.21',
      _id: 'a1',
      _source: { '@timestamp': '2026-11-21T10:00:00.000Z', rule: { id: '5710', level: 5 }, wazuh: { case: { status: 'active', title: 'ignored' } } },
    });
    expect(doc).toHaveProperty('native_case', null);
  });
});
