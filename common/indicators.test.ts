import {
  aggregateIndicators,
  canonicalDomain,
  canonicalExecutable,
  canonicalHash,
  canonicalIp,
  canonicalUrl,
  extractIndicators,
  groupIndicators,
  isPrivateIp,
  strongestVerdict,
  MAX_ALERT_IDS_PER_INDICATOR,
  ThreatMatch,
} from './indicators';
// Real alerts of the step 9.1 lab agent (`lab/agent/samples/<rule_id>.json`),
// every file one indexer hit (`_index` + `_source`).
import lab550 from '../lab/agent/samples/550.json';
import lab5301 from '../lab/agent/samples/5301.json';
import lab5402 from '../lab/agent/samples/5402.json';
import lab5501 from '../lab/agent/samples/5501.json';
import lab5502 from '../lab/agent/samples/5502.json';
import lab5710 from '../lab/agent/samples/5710.json';
import lab5712 from '../lab/agent/samples/5712.json';
import lab5715 from '../lab/agent/samples/5715.json';
import lab80730 from '../lab/agent/samples/80730.json';
import lab80781 from '../lab/agent/samples/80781.json';
import lab80792 from '../lab/agent/samples/80792.json';

// Canonical 4.x record as the sync job projects a benchmark/bench.py alert,
// extended with the step 6.1 fields (syscheck, data.url/hostname/win, threat, geo).
const fim4x = {
  '@timestamp': '2026-11-20T10:00:00.000Z',
  source_family: 'wazuh4_alerts',
  agent: { id: 'a1b', name: 'web-01', ip: '192.0.2.10' },
  rule: { id: '554', level: 5, description: 'File added to the system.', groups: ['syscheck'] },
  data: {
    srcip: '203.0.113.7', dstip: '10.0.0.5', srcport: 51234, dstport: 443,
    srcuser: 'root', dstuser: null, process: { name: 'curl' },
    url: 'HTTP://Evil.Example.COM:8080/payload.exe?x=1',
    hostname: 'Evil.Example.com.',
    win: { eventdata: { ipAddress: '198.51.100.9' } },
  },
  syscheck: {
    path: '/tmp/payload.exe',
    md5_after: 'D41D8CD98F00B204E9800998ECF8427E',
    sha1_after: 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709',
    sha256_after: 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
  },
  threat: null,
  geo: [{ entity: 'unattributed', ip: null, country_name: 'Netherlands', region_name: null, city_name: 'Amsterdam', location: { lat: 52.37, lon: 4.9 }, as: null, provider: 'wazuh4_indexer_pipeline' }],
};

// The VirusTotal integration writes a *sibling* alert for the FIM alert above.
const vtSibling4x = {
  '@timestamp': '2026-11-20T10:00:05.000Z',
  source_family: 'wazuh4_alerts',
  agent: { id: 'a1b', name: 'web-01', ip: '192.0.2.10' },
  rule: { id: '87105', level: 12, description: 'VirusTotal: Alert - /tmp/payload.exe - 7 engines detected this file', groups: ['virustotal'] },
  data: { srcip: null, dstip: null, srcport: null, dstport: null, srcuser: null, dstuser: null, process: null, url: null, hostname: null, win: null },
  syscheck: null,
  threat: {
    total: 2, truncated: false, sibling_of: '1763632800.1234', integration: 'virustotal',
    matches: [
      { source: 'virustotal', verdict: 'malicious', matched_field: 'data.virustotal.source.sha1', detail: 'VirusTotal 7/70 engines flagged /tmp/payload.exe', link: 'https://www.virustotal.com/gui/file/x',
        indicator: { id: null, name: 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', type: 'sha1', provider: 'VirusTotal', feed: null, confidence: null, tags: [], software: null } },
      { source: 'virustotal', verdict: 'malicious', matched_field: 'data.virustotal.source.md5', detail: 'VirusTotal 7/70 engines flagged /tmp/payload.exe', link: 'https://www.virustotal.com/gui/file/x',
        indicator: { id: null, name: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5', provider: 'VirusTotal', feed: null, confidence: null, tags: [], software: null } },
    ],
  },
  geo: null,
};

// Canonical 5.0 record as projected from an e2e/seed_findings_v5.py finding
// carrying engine enrichments and ECS geo.
const finding5 = {
  '@timestamp': '2026-11-20T11:00:00.000Z',
  source_family: 'wazuh5_findings',
  severity_label: 'high',
  agent: { id: '901', name: 'wam-e2e-agent', ip: '192.0.2.10' },
  rule: { id: 'wam-e2e-rule', level: null, description: 'Failed authentication attempt - alice', groups: ['high', 'wam_e2e'] },
  data: { srcip: '2001:DB8:0:0:0:0:0:1', dstip: '::ffff:198.51.100.20', srcport: 4242, dstport: 22, srcuser: 'alice', dstuser: null, process: { name: 'sshd' }, url: null, hostname: 'c2.example.net', win: null },
  syscheck: { path: '/usr/bin/evil', md5_after: null, sha1_after: null, sha256_after: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  related: { ip: ['2001:db8::1', '198.51.100.20'], hosts: ['wam-e2e-agent'], hash: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'], user: ['alice'] },
  threat: {
    total: 1, truncated: false, sibling_of: null, integration: null,
    matches: [
      { source: 'wazuh5_engine', verdict: 'malicious', matched_field: 'destination.ip', detail: null, link: null,
        indicator: { id: 'ioc-1', name: '198.51.100.20:22', type: 'connection', provider: 'abuse.ch', feed: 'feodotracker', confidence: 'High', tags: ['botnet'], software: 'Emotet' } },
    ],
  },
  geo: [{ entity: 'source', ip: '2001:db8::1', country_name: 'Germany', region_name: null, city_name: 'Berlin', location: null, as: { number: 64496, organization: 'Example AS' }, provider: 'wazuh5_engine' }],
};

describe('normalisation helpers', () => {
  test('canonicalises IPs: leading zeros, ports, brackets, zones, mapped IPv6', () => {
    expect(canonicalIp('010.000.001.002')).toBe('10.0.1.2');
    expect(canonicalIp('203.0.113.7:8443')).toBe('203.0.113.7');
    expect(canonicalIp('[2001:DB8::1]:443')).toBe('2001:db8::1');
    expect(canonicalIp('fe80::1%eth0')).toBe('fe80::1');
    expect(canonicalIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1');
    expect(canonicalIp('::ffff:198.51.100.20')).toBe('198.51.100.20');
    expect(canonicalIp('256.1.1.1')).toBeNull();
    expect(canonicalIp('evil.example.com')).toBeNull();
    expect(canonicalIp('1:2:3')).toBeNull();
  });

  test('tags private, loopback, link-local and ULA addresses', () => {
    for (const ip of ['10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '::1', 'fd00::1', 'fe80::1']) {
      expect(isPrivateIp(ip)).toBe(true);
    }
    for (const ip of ['172.32.0.1', '203.0.113.7', '8.8.8.8', '2001:db8::1']) expect(isPrivateIp(ip)).toBe(false);
  });

  test('canonicalises domains, urls and hashes', () => {
    expect(canonicalDomain('Evil.Example.com.')).toBe('evil.example.com');
    expect(canonicalDomain('Evil.Example.com:8080')).toBe('evil.example.com');
    expect(canonicalDomain('203.0.113.7')).toBeNull();
    expect(canonicalDomain('not a host')).toBeNull();
    expect(canonicalUrl('HTTP://Evil.Example.COM:8080/Payload.EXE?X=1')).toEqual({ url: 'http://evil.example.com:8080/Payload.EXE?X=1', host: 'evil.example.com' });
    expect(canonicalUrl('https://[2001:DB8::1]:8443/a')).toEqual({ url: 'https://[2001:db8::1]:8443/a', host: '2001:db8::1' });
    expect(canonicalUrl('/relative/path')).toBeNull();
    expect(canonicalHash('D41D8CD98F00B204E9800998ECF8427E')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(canonicalHash('not-a-hash')).toBeNull();
    expect(canonicalHash('d41d8cd98f00b204e9800998ecf8427')).toBeNull();
  });
});

describe('extractIndicators on a 4.x record', () => {
  test('extracts, normalises and deduplicates by (type, value)', () => {
    const items = extractIndicators(fim4x);
    const byKey = new Map(items.map((i) => [`${i.type}:${i.value}`, i]));
    expect(byKey.get('ip:203.0.113.7')).toMatchObject({ field: 'data.srcip', tags: [] });
    expect(byKey.get('ip:10.0.0.5')).toMatchObject({ field: 'data.dstip', tags: ['private'] });
    expect(byKey.get('ip:198.51.100.9')).toMatchObject({ field: 'data.win.eventdata.ipAddress' });
    expect(byKey.get('ip:192.0.2.10')).toMatchObject({ field: 'agent.ip' });
    // data.hostname and the URL host collapse into one domain with both fields recorded.
    expect(byKey.get('domain:evil.example.com')).toMatchObject({ field: 'data.hostname', fields: ['data.hostname', 'data.url'] });
    expect(byKey.get('url:http://evil.example.com:8080/payload.exe?x=1')).toMatchObject({ field: 'data.url' });
    expect(byKey.get('hash:d41d8cd98f00b204e9800998ecf8427e')).toMatchObject({ field: 'syscheck.md5_after' });
    expect(byKey.get('hash:da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBeDefined();
    expect(byKey.get('hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBeDefined();
    expect(byKey.get('user:root')).toMatchObject({ field: 'data.srcuser' });
    expect(byKey.get('process:curl')).toBeDefined();
    expect(byKey.get('host:web-01')).toMatchObject({ field: 'agent.name' });
    expect(items).toHaveLength(12);
  });

  test('attaches the unattributed 4.x GeoLocation hint to both addresses', () => {
    const items = extractIndicators(fim4x);
    const src = items.find((i) => i.value === '203.0.113.7')!;
    const dst = items.find((i) => i.value === '10.0.0.5')!;
    expect(src.verdictHints).toEqual([{ source: 'geoip:wazuh4_indexer_pipeline', verdict: 'info', detail: 'Amsterdam, Netherlands', confidence: null, link: null, matchedField: null }]);
    expect(dst.verdictHints).toHaveLength(1);
    expect(items.find((i) => i.value === '198.51.100.9')!.verdictHints).toEqual([]);
  });

  test('a VirusTotal sibling alert yields hash indicators carrying the verdict', () => {
    const items = extractIndicators(vtSibling4x);
    const hashes = items.filter((i) => i.type === 'hash');
    expect(hashes.map((i) => i.value)).toEqual(['d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709']);
    expect(hashes[0].field).toBe('threat.matches.indicator.name');
    expect(hashes[0].verdictHints).toEqual([
      { source: 'virustotal', verdict: 'malicious', detail: 'VirusTotal 7/70 engines flagged /tmp/payload.exe', confidence: null, link: 'https://www.virustotal.com/gui/file/x', matchedField: 'data.virustotal.source.md5' },
    ]);
  });

  test('a CDB IOC rule hints every public network/file indicator as malicious', () => {
    const items = extractIndicators({
      rule: { id: '99905', description: 'IP in IOC list' },
      data: { srcip: '203.0.113.9', srcuser: 'bob' },
      threat: { matches: [{ source: 'cdb_ioc', verdict: 'malicious', indicator: { id: '99905', type: 'cdb_list', provider: 'Wazuh CDB' } }] },
    });
    const ip = items.find((i) => i.type === 'ip')!;
    expect(ip.verdictHints).toEqual([{ source: 'cdb_ioc', verdict: 'malicious', detail: 'CDB IOC list rule 99905: IP in IOC list (matched field not reported; public values only)', confidence: null, link: null, matchedField: null }]);
    expect(items.find((i) => i.type === 'user')!.verdictHints).toEqual([]);
    // The cdb_list match itself names no indicator value and adds nothing.
    expect(items).toHaveLength(2);
  });

  test('a CDB IOC rule never flags the agent address or private addresses', () => {
    const items = extractIndicators({
      rule: { id: '99901', description: 'Malicious IP in IOC list' },
      agent: { name: 'web-01', ip: '10.0.0.7' },
      data: { srcip: '203.0.113.9', dstip: '10.0.0.5', hostname: 'evil.example.com' },
      syscheck: { sha256_after: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    });
    const flagged = items.filter((i) => i.verdictHints.some((h) => h.source === 'cdb_ioc')).map((i) => `${i.type}:${i.value}`);
    expect(flagged).toEqual(['ip:203.0.113.9', 'domain:evil.example.com', 'hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
    expect(items.find((i) => i.value === '10.0.0.7')!.verdictHints).toEqual([]);
    expect(items.find((i) => i.value === '10.0.0.5')!.verdictHints).toEqual([]);
    // A public agent address is still skipped when agent.ip is its only field.
    const publicAgent = extractIndicators({ rule: { id: '99901' }, agent: { ip: '198.51.100.9' }, data: { srcip: '203.0.113.9' } });
    expect(publicAgent.find((i) => i.value === '198.51.100.9')!.verdictHints).toEqual([]);
    // ...but not when the same address is also the source of the event.
    const shared = extractIndicators({ rule: { id: '99901' }, agent: { ip: '198.51.100.9' }, data: { srcip: '198.51.100.9' } });
    expect(shared.find((i) => i.value === '198.51.100.9')!.verdictHints).toHaveLength(1);
  });

  test('keeps a path-only 4.x data.url (web-access decoders) as a verbatim URL indicator', () => {
    const items = extractIndicators({ data: { url: '/wp-login.php?action=register', hostname: 'blog.example.com', srcip: '203.0.113.9' } });
    expect(items.find((i) => i.type === 'url')).toMatchObject({ value: '/wp-login.php?action=register', field: 'data.url', fields: ['data.url'] });
    expect(items.find((i) => i.type === 'domain')).toMatchObject({ value: 'blog.example.com', fields: ['data.hostname'] });
    // Anything that is neither a scheme URL nor a path is dropped.
    expect(extractIndicators({ data: { url: 'not a url' } })).toEqual([]);
  });

  test('attaches sibling VirusTotal/Maltiverse verdicts to the enriched alert', () => {
    const siblingMatches: ThreatMatch[] = [
      ...(vtSibling4x.threat.matches as ThreatMatch[]),
      { source: 'maltiverse', verdict: 'suspicious' as const, matched_field: 'data.threat.indicator.name', detail: 'Mass scanner', link: 'https://maltiverse.com/ip/203.0.113.7',
        indicator: { id: null, name: '203.0.113.7', type: 'ip', provider: 'Maltiverse', feed: null, confidence: '80', tags: ['scanner'], software: null } },
      { source: 'maltiverse', verdict: 'malicious' as const, matched_field: 'data.threat.indicator.name', detail: null, link: null,
        indicator: { id: null, name: 'other.example.net', type: 'domain', provider: 'Maltiverse', feed: null, confidence: null, tags: [], software: null } },
    ];
    const items = extractIndicators(fim4x, { siblingMatches });
    const md5 = items.find((i) => i.value === 'd41d8cd98f00b204e9800998ecf8427e')!;
    expect(md5.fields).toEqual(['syscheck.md5_after']);
    expect(md5.verdictHints).toEqual([expect.objectContaining({ source: 'virustotal', verdict: 'malicious', matchedField: 'data.virustotal.source.md5' })]);
    const src = items.find((i) => i.value === '203.0.113.7')!;
    expect(src.verdictHints.map((h) => h.source)).toEqual(['maltiverse', 'geoip:wazuh4_indexer_pipeline']);
    // A sibling naming a value this record lacks is still listed, attributed to the sibling.
    expect(items.find((i) => i.value === 'other.example.net')).toMatchObject({ type: 'domain', field: 'threat.sibling.indicator.name' });
    expect(extractIndicators(fim4x, { siblingMatches: null })).toEqual(extractIndicators(fim4x));
  });

  test('is deterministic and tolerant of malformed input', () => {
    expect(extractIndicators(fim4x)).toEqual(extractIndicators(JSON.parse(JSON.stringify(fim4x))));
    expect(extractIndicators(null)).toEqual([]);
    expect(extractIndicators({ data: 'string-data', threat: { matches: 'nope' }, geo: 'x' })).toEqual([]);
    expect(extractIndicators({ data: { srcip: ['1.1.1.1', '2.2.2.2'], srcuser: { nested: true } } }).map((i) => i.value)).toEqual(['1.1.1.1']);
  });
});

describe('extractIndicators on the lab agent fixtures (step 9.4 coverage)', () => {
  const keys = (record: any) => extractIndicators(record).map((i) => `${i.type}:${i.value}`);
  const field = (record: any, key: string) => extractIndicators(record).find((i) => `${i.type}:${i.value}` === key)?.fields;

  test('canonicalExecutable keeps a bare path and drops the decoder quotes of an AVC record', () => {
    expect(canonicalExecutable('/usr/bin/curl')).toBe('/usr/bin/curl');
    expect(canonicalExecutable('"/usr/sbin/apparmor_parser"')).toBe('/usr/sbin/apparmor_parser');
    expect(canonicalExecutable('  "/usr/bin/bash"  ')).toBe('/usr/bin/bash');
    expect(canonicalExecutable('curl')).toBeNull(); // comm, not a path
    expect(canonicalExecutable('/usr/bin/sudo -n true')).toBeNull(); // command line
    expect(canonicalExecutable('""')).toBeNull();
    expect(canonicalExecutable('')).toBeNull();
    expect(canonicalExecutable(null)).toBeNull();
  });

  test('80792 auditd connect(): the binary comes from data.audit.exe; the hex saddr is not decoded', () => {
    const items = extractIndicators(lab80792._source);
    expect(keys(lab80792._source)).toEqual(['ip:10.0.2.15', 'process:/usr/bin/curl', 'host:wam-lab-agent']);
    expect(field(lab80792._source, 'process:/usr/bin/curl')).toEqual(['data.audit.exe']);
    // The destination (118.25.6.39, printed by auditd inside full_log only) is
    // not an alert field, so no public ip is extracted.
    expect(items.filter((i) => i.type === 'ip' && !i.tags.includes('private'))).toEqual([]);
  });

  test('80781 auditd /etc write: binary extracted, the watched file path is not an indicator type', () => {
    expect(keys(lab80781._source)).toEqual(['ip:10.0.2.15', 'process:/usr/bin/bash', 'host:wam-lab-agent']);
  });

  test('80730 auditd AVC: the quoted exe value is unquoted', () => {
    expect(keys(lab80730._source)).toEqual(['ip:10.0.2.15', 'process:/usr/sbin/apparmor_parser', 'host:wam-lab-agent']);
  });

  test('5710 / 5712 sshd failures: data.srcip (second address, private) and data.srcuser', () => {
    expect(keys(lab5710._source)).toEqual(['ip:10.0.2.15', 'ip:10.0.2.77', 'user:baduser', 'host:wam-lab-agent']);
    expect(field(lab5710._source, 'ip:10.0.2.77')).toEqual(['data.srcip']);
    expect(field(lab5710._source, 'user:baduser')).toEqual(['data.srcuser']);
    expect(keys(lab5712._source)).toEqual(keys(lab5710._source));
  });

  test('5715 sshd success: data.srcip (the host) and data.dstuser', () => {
    expect(keys(lab5715._source)).toEqual(['ip:10.0.2.15', 'ip:10.0.2.2', 'user:vagrant', 'host:wam-lab-agent']);
    expect(field(lab5715._source, 'user:vagrant')).toEqual(['data.dstuser']);
  });

  test('5402 sudo: both users; data.command is a command line and stays out', () => {
    expect(keys(lab5402._source)).toEqual(['ip:10.0.2.15', 'user:root', 'user:vagrant', 'host:wam-lab-agent']);
    expect(field(lab5402._source, 'user:vagrant')).toEqual(['data.srcuser']);
    expect(field(lab5402._source, 'user:root')).toEqual(['data.dstuser']);
    expect(keys(lab5402._source).some((k) => k.startsWith('process:'))).toBe(false);
  });

  test('5501 / 5502 PAM session opened / closed: the user from data.srcuser + data.dstuser, then data.dstuser only', () => {
    expect(keys(lab5501._source)).toEqual(['ip:10.0.2.15', 'user:vagrant', 'host:wam-lab-agent']);
    expect(field(lab5501._source, 'user:vagrant')).toEqual(['data.srcuser', 'data.dstuser']);
    expect(keys(lab5502._source)).toEqual(['ip:10.0.2.15', 'user:vagrant', 'host:wam-lab-agent']);
    expect(field(lab5502._source, 'user:vagrant')).toEqual(['data.dstuser']);
  });

  test('5301 failed su: the stock decoder sets no data.* field, so only the agent is extracted', () => {
    expect(keys(lab5301._source)).toEqual(['ip:10.0.2.15', 'host:wam-lab-agent']);
  });

  test('550 syscheck change: the three *_after hashes, never the *_before ones', () => {
    expect(keys(lab550._source)).toEqual([
      'ip:10.0.2.15',
      'hash:1700ada2b315d52929ef67d3c1ba293a',
      'hash:2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376',
      'hash:ae5948bd09028c70956de5906bf946e6eae0d013',
      'host:wam-lab-agent',
    ]);
    expect(field(lab550._source, 'hash:2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376')).toEqual(['syscheck.sha256_after']);
  });

  test('aggregateIndicators over the lab alerts keeps one row per value with the auditd field recorded', () => {
    const rows = aggregateIndicators([
      { _id: 'a', _source: lab80792._source },
      { _id: 'b', _source: lab80781._source },
      { _id: 'c', _source: lab5710._source },
    ]);
    const agentIp = rows.find((r) => r.value === '10.0.2.15');
    expect(agentIp).toMatchObject({ type: 'ip', count: 3, alert_ids: ['c', 'a', 'b'], fields: ['agent.ip'], tags: ['private'] });
    expect(rows.find((r) => r.value === '/usr/bin/curl')).toMatchObject({ type: 'process', count: 1, fields: ['data.audit.exe'] });
    expect(rows.find((r) => r.value === '/usr/bin/bash')).toMatchObject({ type: 'process', count: 1, fields: ['data.audit.exe'] });
    expect(rows.map((r) => r.type)).toEqual(['ip', 'ip', 'user', 'process', 'process', 'host']);
  });
});

describe('extractIndicators on a 5.0 record', () => {
  test('canonicalises IPv6, strips the connection port and keeps the engine verdict', () => {
    const items = extractIndicators(finding5);
    const byKey = new Map(items.map((i) => [`${i.type}:${i.value}`, i]));
    expect(byKey.get('ip:2001:db8::1')).toMatchObject({ fields: ['data.srcip', 'related.ip'] });
    const dst = byKey.get('ip:198.51.100.20')!;
    expect(dst.fields).toEqual(['data.dstip', 'related.ip', 'threat.matches.indicator.name']);
    expect(dst.verdictHints).toEqual([
      { source: 'wazuh5_engine', verdict: 'malicious', detail: 'abuse.ch / feodotracker / Emotet / botnet', confidence: 'High', link: null, matchedField: 'destination.ip' },
    ]);
    expect(byKey.get('domain:c2.example.net')).toBeDefined();
    expect(byKey.get('hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')!.fields).toEqual(['syscheck.sha256_after', 'related.hash']);
    expect(byKey.get('user:alice')!.fields).toEqual(['data.srcuser', 'related.user']);
    expect(byKey.get('host:wam-e2e-agent')!.fields).toEqual(['agent.name', 'related.hosts']);
    expect(byKey.get('ip:2001:db8::1')!.verdictHints).toEqual([
      { source: 'geoip:wazuh5_engine', verdict: 'info', detail: 'Berlin, Germany (AS64496 Example AS)', confidence: null, link: null, matchedField: null },
    ]);
  });

  test('groups by type in canonical order', () => {
    expect(groupIndicators(extractIndicators(finding5)).map((g) => g.type)).toEqual(['ip', 'domain', 'hash', 'user', 'process', 'host']);
  });

  test('strongest verdict ranks malicious over info', () => {
    expect(strongestVerdict([{ source: 'a', verdict: 'info' }, { source: 'b', verdict: 'suspicious' }])).toBe('suspicious');
    expect(strongestVerdict([])).toBeNull();
  });
});

describe('aggregateIndicators', () => {
  test('counts distinct alerts, tracks first/last seen and merges hints across siblings', () => {
    const rows = aggregateIndicators([
      { _id: 'vt', _source: vtSibling4x },
      { _id: 'fim', _source: fim4x },
      { _id: 'f5', _source: finding5 },
    ]);
    const md5 = rows.find((r) => r.type === 'hash' && r.value === 'd41d8cd98f00b204e9800998ecf8427e')!;
    expect(md5).toMatchObject({ count: 2, first_seen: '2026-11-20T10:00:00.000Z', last_seen: '2026-11-20T10:00:05.000Z', alert_ids: ['fim', 'vt'] });
    expect(md5.fields).toEqual(['syscheck.md5_after', 'threat.matches.indicator.name']);
    expect(md5.verdictHints.map((h) => h.source)).toEqual(['virustotal']);
    const sha256 = rows.find((r) => r.type === 'hash' && r.value.startsWith('e3b0'))!;
    expect(sha256).toMatchObject({ count: 2, alert_ids: ['fim', 'f5'], last_seen: '2026-11-20T11:00:00.000Z' });
    const agentIp = rows.find((r) => r.type === 'ip' && r.value === '192.0.2.10')!;
    expect(agentIp.count).toBe(3);
    expect(agentIp.tags).toEqual([]);
    expect(rows.map((r) => r.type)).toEqual([...rows.map((r) => r.type)].sort((a, b) => ['ip', 'domain', 'url', 'hash', 'user', 'process', 'host'].indexOf(a) - ['ip', 'domain', 'url', 'hash', 'user', 'process', 'host'].indexOf(b)));
  });

  test('caps alert ids per indicator and ignores alerts without a record', () => {
    const alerts = Array.from({ length: MAX_ALERT_IDS_PER_INDICATOR + 5 }, (_, i) => ({
      _id: `a${String(i).padStart(2, '0')}`,
      _source: { '@timestamp': `2026-11-20T10:${String(i).padStart(2, '0')}:00.000Z`, data: { srcip: '203.0.113.1' } },
    }));
    const rows = aggregateIndicators([...alerts, { _id: 'none', _source: null }]);
    expect(rows).toHaveLength(1);
    expect(rows[0].count).toBe(MAX_ALERT_IDS_PER_INDICATOR + 5);
    expect(rows[0].alert_ids).toHaveLength(MAX_ALERT_IDS_PER_INDICATOR);
    expect(rows[0].alert_ids[0]).toBe('a00');
  });
});
