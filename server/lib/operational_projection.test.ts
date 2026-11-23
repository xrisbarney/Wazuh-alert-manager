import { alertUid, legacyAlertUid, projectOperationalAlert } from './operational_projection';
import labAudit80730 from '../../lab/agent/samples/80730.json';
import labAudit80792 from '../../lab/agent/samples/80792.json';

describe('operational alert projection', () => {
  test('uses source index and id for stable collision-safe identity', () => {
    expect(alertUid('wazuh-alerts-a', 'same')).toBe(alertUid('wazuh-alerts-a', 'same'));
    expect(alertUid('wazuh-alerts-a', 'same')).not.toBe(alertUid('wazuh-alerts-b', 'same'));
    expect(legacyAlertUid('same')).not.toBe(alertUid('wazuh-alerts-a', 'same'));
  });

  test('allowlists operational fields and drops arbitrary source data', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.08.28',
      _id: 'abc',
      _source: {
        '@timestamp': '2026-08-28T00:00:00.000Z',
        agent: { id: '001', name: 'host', ip: '10.0.0.2' },
        rule: { id: '5502', level: 5, groups: 'syslog', description: 'test' },
        data: {
          srcip: '10.0.0.1', srcport: '443', dstport: 65535,
          password: 'must-not-copy', process: '/bin/sh',
        },
        secret: 'must-not-copy',
      },
    });
    expect(doc.data.srcip).toBe('10.0.0.1');
    expect(doc.data.process.name).toBe('/bin/sh');
    expect(doc.data.srcport).toBe(443);
    expect(doc.data.dstport).toBe(65535);
    expect(doc.data.password).toBeUndefined();
    expect(doc.secret).toBeUndefined();
    expect(doc.source_index).toBe('wazuh-alerts-4.x-2026.08.28');
  });

  test('drops invalid port values rather than indexing malformed integers', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-a', _id: '1',
      _source: { data: { srcport: 'not-a-port', dstport: 70000 } },
    });
    expect(doc.data.srcport).toBeNull();
    expect(doc.data.dstport).toBeNull();
  });
});

describe('native context ingested for indicators (step 6.1)', () => {
  test('projects FIM hashes, url/hostname/win ip and the GeoLocation hint', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.11.20', _id: 'fim',
      _source: {
        '@timestamp': '2026-11-20T10:00:00.000Z',
        rule: { id: '554', level: 5, description: 'File added to the system.' },
        syscheck: { path: '/tmp/payload.exe', md5_after: 'd41d8cd98f00b204e9800998ecf8427e', sha1_after: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', sha256_after: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', size_after: '0', uname_after: 'root' },
        data: { srcip: '203.0.113.7', url: 'http://evil.example.com/x', hostname: 'evil.example.com', win: { eventdata: { ipAddress: '198.51.100.9', targetUserName: 'x' }, system: { eventID: '4624' } } },
        GeoLocation: { country_name: 'Netherlands', city_name: 'Amsterdam', location: { lat: '52.37', lon: 4.9 }, continent_code: 'EU' },
      },
    });
    expect(doc.syscheck).toEqual({ path: '/tmp/payload.exe', md5_after: 'd41d8cd98f00b204e9800998ecf8427e', sha1_after: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', sha256_after: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' });
    expect(doc.data.url).toBe('http://evil.example.com/x');
    expect(doc.data.hostname).toBe('evil.example.com');
    expect(doc.data.win).toEqual({ eventdata: { ipAddress: '198.51.100.9' } });
    expect(doc.geo).toEqual([{ entity: 'unattributed', ip: null, country_name: 'Netherlands', region_name: null, city_name: 'Amsterdam', location: { lat: 52.37, lon: 4.9 }, as: null, provider: 'wazuh4_indexer_pipeline' }]);
    expect(doc.threat).toBeNull();
    expect(doc.related).toBeNull();
  });

  test('leaves the new fields null when the alert carries none of them', () => {
    const doc = projectOperationalAlert({ _index: 'wazuh-alerts-a', _id: '1', _source: { data: { srcip: '10.0.0.1' } } });
    expect(doc.syscheck).toBeNull();
    expect(doc.data.url).toBeNull();
    expect(doc.data.hostname).toBeNull();
    expect(doc.data.win).toBeNull();
    expect(doc.data.audit).toBeNull();
    expect(doc.geo).toBeNull();
    expect(doc.threat).toBeNull();
  });

  test('projects the auditd binary path of a real lab connect() alert (step 9.4)', () => {
    const doc = projectOperationalAlert({ ...labAudit80792, _id: 'lab-80792' });
    expect(doc.rule.id).toBe('80792');
    expect(doc.data.audit).toEqual({ exe: '/usr/bin/curl' });
    // Nothing else of data.audit (pid, auid, key, command) is projected.
    expect(Object.keys(doc.data.audit)).toEqual(['exe']);
    expect(doc.data.dstip).toBeNull();
  });

  test('stores the auditd AVC binary unquoted, equal to the indicator value (step 9.4)', () => {
    expect(labAudit80730._source.data.audit.exe).toBe('"/usr/sbin/apparmor_parser"');
    const doc = projectOperationalAlert({ ...labAudit80730, _id: 'lab-80730' });
    expect(doc.data.audit).toEqual({ exe: '/usr/sbin/apparmor_parser' });
    // A value that is not an absolute path (comm, a command line) is not stored.
    const other = projectOperationalAlert({ _index: 'wazuh-alerts-4.x-2026.11.21', _id: 'x', _source: { data: { audit: { exe: 'curl' } } } });
    expect(other.data.audit).toBeNull();
  });

  test('normalises a VirusTotal sibling alert into threat.matches with the source alert id', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.11.20', _id: 'vt',
      _source: {
        rule: { id: '87105', level: 12, description: 'VirusTotal: Alert - /tmp/payload.exe - 7 engines detected this file' },
        data: {
          integration: 'virustotal',
          virustotal: {
            found: 1, malicious: 1, positives: 7, total: 70, scan_date: '2026-11-20 10:00:03',
            sha1: 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709',
            source: { alert_id: '1763632800.1234', file: '/tmp/payload.exe', md5: 'd41d8cd98f00b204e9800998ecf8427e', sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
            permalink: 'https://www.virustotal.com/gui/file/x',
          },
        },
      },
    });
    expect(doc.threat.sibling_of).toBe('1763632800.1234');
    expect(doc.threat.integration).toBe('virustotal');
    expect(doc.threat.total).toBe(2);
    expect(doc.threat.truncated).toBe(false);
    expect(doc.threat.matches.map((m: any) => [m.indicator.type, m.indicator.name, m.verdict, m.matched_field])).toEqual([
      ['sha1', 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', 'malicious', 'data.virustotal.source.sha1'],
      ['md5', 'd41d8cd98f00b204e9800998ecf8427e', 'malicious', 'data.virustotal.source.md5'],
    ]);
    expect(doc.threat.matches[0].detail).toBe('VirusTotal 7/70 engines flagged /tmp/payload.exe');
    expect(doc.threat.matches[0].link).toBe('https://www.virustotal.com/gui/file/x');
    expect(doc.threat.matches[0].indicator.provider).toBe('VirusTotal');
    // The integration's scan metadata is not cloned.
    expect(doc.data.virustotal).toBeUndefined();
  });

  test('records a not-found VirusTotal lookup as unknown, and Maltiverse classifications', () => {
    const notFound = projectOperationalAlert({
      _index: 'a', _id: '1',
      _source: { data: { integration: 'virustotal', virustotal: { found: 0, source: { alert_id: 'x', md5: 'd41d8cd98f00b204e9800998ecf8427e' } } } },
    });
    expect(notFound.threat.matches[0]).toMatchObject({ verdict: 'unknown', detail: 'VirusTotal: hash not found' });

    // Real maltiverse.py output (4.14.10 manager, maltiverse_alert()): raw IoC
    // document under data.maltiverse.source, ECS data.threat.indicator.*,
    // data.alert_id; numbers stringified.
    const mv = projectOperationalAlert({
      _index: 'a', _id: '2',
      _source: {
        rule: { id: '99011', level: 10, description: 'Maltiverse: IP 203.0.113.9 classified as suspicious' },
        data: {
          integration: 'maltiverse', alert_id: '1763632800.99',
          maltiverse: {
            source: {
              type: 'ip', ip_addr: '203.0.113.9', classification: 'suspicious', tag: ['scanner', 'ssh'],
              blacklist: [{ description: 'Mass scanner', source: 'Maltiverse', first_seen: '2026-01-01 00:00:00', last_seen: '2026-11-19 00:00:00' }],
              creation_time: '2026-01-01 00:00:00', modification_time: '2026-11-19 00:00:00',
            },
          },
          threat: {
            indicator: {
              name: '203.0.113.9', type: 'ipv4-addr', ip: '203.0.113.9', description: 'Mass scanner', provider: 'Maltiverse',
              confidence: '80', reference: 'https://maltiverse.com/ip/203.0.113.9', sightings: '3',
              first_seen: '2026-01-01 00:00:00', last_seen: '2026-11-19 00:00:00', modified_at: '2026-11-19 00:00:00',
            },
            software: { name: 'Mirai' },
          },
        },
      },
    });
    expect(mv.threat.sibling_of).toBe('1763632800.99');
    expect(mv.threat.integration).toBe('maltiverse');
    expect(mv.threat.matches).toEqual([expect.objectContaining({
      source: 'maltiverse', verdict: 'suspicious', detail: 'Mass scanner', link: 'https://maltiverse.com/ip/203.0.113.9', matched_field: 'data.threat.indicator.name',
      indicator: expect.objectContaining({ name: '203.0.113.9', type: 'ip', provider: 'Maltiverse', confidence: '80', tags: ['scanner', 'ssh'], software: 'Mirai' }),
    })]);
    // The integration payload itself is not cloned onto the projection.
    expect(mv.data.maltiverse).toBeUndefined();
    expect(mv.data.threat).toBeUndefined();

    // ECS types for the other IoC kinds map onto the indicator types the
    // extractor classifies; a hostname IoC without the ECS block falls back
    // to the raw document.
    const url = projectOperationalAlert({ _index: 'a', _id: '3', _source: { data: { integration: 'maltiverse', alert_id: 'x', maltiverse: { source: { classification: 'malicious', url: 'http://evil.example/p' } }, threat: { indicator: { name: 'http://evil.example/p', type: 'url', provider: 'Maltiverse' } } } } });
    expect(url.threat.matches[0]).toMatchObject({ verdict: 'malicious', indicator: { type: 'url', name: 'http://evil.example/p' } });
    const file = projectOperationalAlert({ _index: 'a', _id: '4', _source: { data: { integration: 'maltiverse', alert_id: 'x', maltiverse: { source: { classification: 'malicious', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } }, threat: { indicator: { name: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type: 'file' } } } } });
    expect(file.threat.matches[0]).toMatchObject({ indicator: { type: 'hash', provider: 'Maltiverse' } });
    const raw = projectOperationalAlert({ _index: 'a', _id: '5', _source: { data: { integration: 'maltiverse', alert_id: 'x', maltiverse: { source: { classification: 'malicious', hostname: 'c2.example.net', tag: ['c2'] } } } } });
    expect(raw.threat.matches).toEqual([expect.objectContaining({ verdict: 'malicious', matched_field: 'data.maltiverse.source.hostname', indicator: expect.objectContaining({ name: 'c2.example.net', type: 'domain', tags: ['c2'] }) })]);
  });

  test('tags CDB IOC rule ids 99901-99920 as a verdict match', () => {
    const doc = projectOperationalAlert({ _index: 'a', _id: '1', _source: { rule: { id: '99901', level: 10, description: 'Malicious IP in IOC list' }, data: { srcip: '203.0.113.9' } } });
    expect(doc.threat.matches).toEqual([expect.objectContaining({ source: 'cdb_ioc', verdict: 'malicious', detail: 'CDB IOC list rule 99901: Malicious IP in IOC list', indicator: expect.objectContaining({ id: '99901', type: 'cdb_list' }) })]);
    expect(projectOperationalAlert({ _index: 'a', _id: '2', _source: { rule: { id: '99921', level: 10 } } }).threat).toBeNull();
    expect(projectOperationalAlert({ _index: 'a', _id: '3', _source: { rule: { id: '99900', level: 10 } } }).threat).toBeNull();
  });
});

describe('asset stamping at projection time (step 6.4a)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { buildAssetMatcher } = require('./assets/matcher');
  const hit = (agent: any) => ({
    _index: 'wazuh-alerts-4.x-2026.11.20',
    _id: 'a1',
    _source: { '@timestamp': '2026-11-20T00:00:00.000Z', agent, rule: { id: '1', level: 3 } },
  });
  const matcher = buildAssetMatcher([
    { id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'high', tags: ['pci'] },
    { id: 'dmz', match: { kind: 'group', value: 'dmz' }, criticality: 'critical', tags: [] },
    { id: 'prod', match: { kind: 'label', value: 'env=prod' }, criticality: 'medium', tags: ['prod'] },
  ]);

  test('always emits an asset object; without a context it is unstamped', () => {
    const doc = projectOperationalAlert(hit({ id: '001', name: 'web-01' }));
    expect(doc.asset).toEqual({ criticality: null, tags: [], groups: [], labels: null, matched_id: null, matched_by: null });
    expect(projectOperationalAlert({ _index: 'i', _id: 'x', _source: {} }).asset.criticality).toBeNull();
  });

  test('stamps criticality and tags from the matcher using the agent name', () => {
    const doc = projectOperationalAlert(hit({ id: '001', name: 'web-01' }), '2026-11-20T01:00:00.000Z', { assets: matcher });
    expect(doc.asset).toEqual({ criticality: 'high', tags: ['pci'], groups: [], labels: null, matched_id: 'web', matched_by: 'glob' });
  });

  test('4.x groups come from the cached Wazuh API lookup keyed by agent id, labels from agent.labels', () => {
    const agentGroups = new Map([['001', ['default', 'dmz']]]);
    const doc = projectOperationalAlert(hit({ id: '001', name: 'db-01', labels: { env: 'prod', 'tier': 'gold' } }), undefined, {
      assets: matcher,
      agentGroups,
    });
    expect(doc.asset.groups).toEqual(['default', 'dmz']);
    expect(doc.asset.labels).toEqual({ env: 'prod', tier: 'gold' });
    // group beats label
    expect(doc.asset).toMatchObject({ criticality: 'critical', matched_id: 'dmz', matched_by: 'group' });
    const unknownAgent = projectOperationalAlert(hit({ id: '002', name: 'db-02', labels: { env: 'prod' } }), undefined, {
      assets: matcher,
      agentGroups,
    });
    expect(unknownAgent.asset).toMatchObject({ groups: [], criticality: 'medium', matched_by: 'label', tags: ['prod'] });
  });

  test('a resync with changed settings re-stamps (asset is never plugin-owned)', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { PLUGIN_OWNED_FIELDS } = require('./sync_job');
    expect(PLUGIN_OWNED_FIELDS).not.toContain('asset');
    const changed = buildAssetMatcher([{ id: 'web', match: { kind: 'glob', value: 'web-*' }, criticality: 'low', tags: [] }]);
    expect(projectOperationalAlert(hit({ name: 'web-01' }), undefined, { assets: changed }).asset.criticality).toBe('low');
  });
});

describe('due timestamps on the projection (step 3.2)', () => {
  test('carries only the two due fields in `reporting`, from the context policy', () => {
    const policy: any = { targets: { critical: { resolveMinutes: 30, assignMinutes: 5 }, high: { resolveMinutes: 120, assignMinutes: 20 }, medium: { resolveMinutes: 600, assignMinutes: 60 }, low: { resolveMinutes: 2880, assignMinutes: 240 } }, escalations: [] };
    const doc = projectOperationalAlert(
      { _index: 'wazuh-alerts-4.x-2026.08.28', _id: 'abc', _source: { '@timestamp': '2026-08-28T00:00:00.000Z', rule: { id: '1', level: 5 } } },
      '2026-08-28T00:00:01.000Z',
      { slaPolicy: policy }
    );
    expect(doc.reporting).toEqual({ sla_due_at: '2026-08-28T10:00:00.000Z', assign_due_at: '2026-08-28T01:00:00.000Z' });
    expect(Object.keys(doc.reporting)).toEqual(['sla_due_at', 'assign_due_at']);
  });

  test('an alert without a rule has no due date', () => {
    const doc = projectOperationalAlert({ _index: 'i', _id: 'x', _source: { '@timestamp': '2026-08-28T00:00:00.000Z' } });
    expect(doc.reporting).toEqual({ sla_due_at: null, assign_due_at: null });
  });
});

describe('disposition survives a resync (step 2.4)', () => {
  test('disposition and closure_reason are plugin-owned, top-level, so the sync upsert never replays over them', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { PLUGIN_OWNED_FIELDS } = require('./sync_job');
    expect(PLUGIN_OWNED_FIELDS).toContain('disposition');
    expect(PLUGIN_OWNED_FIELDS).toContain('closure_reason');
    // Top-level only: the protection is by top-level key, nothing nested is listed.
    for (const field of PLUGIN_OWNED_FIELDS) expect(field).not.toContain('.');
    // The projection itself never emits either field: they are written by the close paths only.
    const projected: any = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.11.20',
      _id: 'a1',
      _source: { '@timestamp': '2026-11-20T00:00:00.000Z', agent: { name: 'web-01' }, rule: { id: '1', level: 3 } },
    });
    expect(projected).not.toHaveProperty('disposition');
    expect(projected).not.toHaveProperty('closure_reason');
  });
});

describe('native case projection (step 2.6)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { boundedNativeCase } = require('./operational_projection');

  test('native_case is not plugin-owned, so a later projection of the same finding replaces it', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { PLUGIN_OWNED_FIELDS } = require('./sync_job');
    expect(PLUGIN_OWNED_FIELDS).not.toContain('native_case');
    // The sync upsert script copies every non-protected key of the projected
    // document, so whenever the finding is projected again the stored value
    // is replaced and a removed native case clears the field. A case edited
    // after the finding left the sync window is carried by the reconciliation
    // pass instead (native_case_reconcile.test.ts).
    const first = boundedNativeCase({ status: 'active', severity: 'low' });
    const edited = boundedNativeCase({ status: 'completed', severity: 'high', title: 'Resolved' });
    expect(first).toMatchObject({ status: 'active', severity: 'low', title: null });
    expect(edited).toMatchObject({ status: 'completed', severity: 'high', title: 'Resolved' });
    expect(boundedNativeCase(undefined)).toBeNull();
  });

  test('the 4.x projection always carries native_case: null', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.11.21',
      _id: 'a1',
      _source: { '@timestamp': '2026-11-21T00:00:00.000Z', rule: { id: '1', level: 3 }, wazuh: { case: { status: 'active' } } },
    });
    expect(doc).toHaveProperty('native_case', null);
  });
});
