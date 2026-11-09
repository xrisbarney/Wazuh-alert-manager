import { alertUid } from '../operational_projection';
import { WAZUH4_ALERT_ADAPTER } from './wazuh4_alert_adapter';
import { WAZUH5_FINDING_ADAPTER, projectFinding } from './wazuh5_finding_adapter';

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
