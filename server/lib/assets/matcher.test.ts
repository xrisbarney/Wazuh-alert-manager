import {
  boundedGroups,
  boundedLabels,
  buildAssetMatcher,
  criticalitiesAtOrAbove,
  globMatch,
  meetsMinAssetCriticality,
  parseLabelMatch,
} from './matcher';

const entry = (id: string, kind: any, value: string, criticality: any = 'high', tags: string[] = []) => ({
  id,
  match: { kind, value },
  criticality,
  tags,
});

describe('globMatch (no regular expressions from user input)', () => {
  test('* matches any run including empty, ? exactly one character', () => {
    expect(globMatch('web-*', 'web-')).toBe(true);
    expect(globMatch('web-*', 'web-01')).toBe(true);
    expect(globMatch('web-??', 'web-01')).toBe(true);
    expect(globMatch('web-??', 'web-001')).toBe(false);
    expect(globMatch('*db*', 'prod-db-3')).toBe(true);
    expect(globMatch('*', '')).toBe(true);
    expect(globMatch('', 'x')).toBe(false);
  });

  test('regex metacharacters are literal', () => {
    expect(globMatch('host.(1|2)', 'host.(1|2)')).toBe(true);
    expect(globMatch('host.(1|2)', 'host.1')).toBe(false);
    expect(globMatch('a+b', 'aab')).toBe(false);
    expect(globMatch('a+b', 'a+b')).toBe(true);
    expect(globMatch('[a-z]', 'b')).toBe(false);
    expect(globMatch('^x$', 'x')).toBe(false);
  });

  test('pathological patterns stay linear', () => {
    const pattern = `${'*a'.repeat(30)}*b`;
    const input = 'a'.repeat(5000);
    const started = Date.now();
    expect(globMatch(pattern, input)).toBe(false);
    expect(Date.now() - started).toBeLessThan(500);
  });
});

describe('buildAssetMatcher precedence', () => {
  const matcher = buildAssetMatcher([
    entry('lbl', 'label', 'env=prod', 'low', ['label-tag']),
    entry('grp', 'group', 'dmz', 'medium', ['group-tag']),
    entry('glob', 'glob', 'web-*', 'high', ['glob-tag']),
    entry('name', 'name', 'web-01', 'critical', ['name-tag']),
  ]);

  test('exact name beats glob beats group beats label, regardless of list order', () => {
    const all = { agentName: 'web-01', groups: ['dmz'], labels: { env: 'prod' } };
    expect(matcher.resolve(all)).toEqual({ criticality: 'critical', tags: ['name-tag'], matchedId: 'name', matchedBy: 'name' });
    expect(matcher.resolve({ ...all, agentName: 'web-02' })).toMatchObject({ criticality: 'high', matchedId: 'glob', matchedBy: 'glob' });
    expect(matcher.resolve({ ...all, agentName: 'db-02' })).toMatchObject({ criticality: 'medium', matchedId: 'grp', matchedBy: 'group' });
    expect(matcher.resolve({ agentName: 'db-02', groups: ['default'], labels: { env: 'prod' } })).toMatchObject({
      criticality: 'low',
      matchedId: 'lbl',
      matchedBy: 'label',
    });
    expect(matcher.resolve({ agentName: 'db-02', groups: ['default'], labels: { env: 'dev' } })).toEqual({
      criticality: null,
      tags: [],
      matchedId: null,
      matchedBy: null,
    });
  });

  test('first entry in list order wins inside a kind', () => {
    const m = buildAssetMatcher([
      entry('first', 'glob', 'web-*', 'low'),
      entry('second', 'glob', 'web-0?', 'critical'),
      entry('g1', 'group', 'linux', 'low'),
      entry('g2', 'group', 'pci', 'critical'),
    ]);
    expect(m.resolve({ agentName: 'web-01' })).toMatchObject({ matchedId: 'first', criticality: 'low' });
    // Agent group order does not matter; configured order does.
    expect(m.resolve({ agentName: 'db', groups: ['pci', 'linux'] })).toMatchObject({ matchedId: 'g1' });
  });

  test('names and globs are case-insensitive; groups and labels are exact', () => {
    const m = buildAssetMatcher([
      entry('n', 'name', 'Web-01', 'high'),
      entry('g', 'group', 'DMZ', 'medium'),
      entry('l', 'label', 'tier=Gold', 'low'),
    ]);
    expect(m.resolve({ agentName: 'WEB-01' })).toMatchObject({ matchedId: 'n' });
    expect(m.resolve({ agentName: 'x', groups: ['dmz'] })).toMatchObject({ matchedId: null });
    expect(m.resolve({ agentName: 'x', groups: ['DMZ'] })).toMatchObject({ matchedId: 'g' });
    expect(m.resolve({ agentName: 'x', labels: { tier: 'gold' } })).toMatchObject({ matchedId: null });
    expect(m.resolve({ agentName: 'x', labels: { tier: 'Gold' } })).toMatchObject({ matchedId: 'l' });
  });

  test('ignores malformed entries instead of throwing, and an empty list resolves nothing', () => {
    const m = buildAssetMatcher([
      null as any,
      entry('bad-kind', 'regex', '.*', 'high'),
      entry('bad-crit', 'name', 'x', 'urgent'),
      entry('empty', 'name', '   ', 'high'),
      entry('bad-label', 'label', 'novalue', 'high'),
      entry('ok', 'name', 'x', 'high'),
    ]);
    expect(m.size).toBe(1);
    expect(m.resolve({ agentName: 'x' })).toMatchObject({ matchedId: 'ok' });
    expect(buildAssetMatcher([]).resolve({ agentName: 'x' })).toMatchObject({ criticality: null });
    expect(buildAssetMatcher(undefined).size).toBe(0);
  });
});

describe('criticality helpers', () => {
  test('criticalitiesAtOrAbove and meetsMinAssetCriticality share minLevel semantics', () => {
    expect(criticalitiesAtOrAbove('low')).toEqual(['low', 'medium', 'high', 'critical']);
    expect(criticalitiesAtOrAbove('high')).toEqual(['high', 'critical']);
    expect(meetsMinAssetCriticality({ asset: { criticality: 'critical' } }, 'high')).toBe(true);
    expect(meetsMinAssetCriticality({ asset: { criticality: 'high' } }, 'high')).toBe(true);
    expect(meetsMinAssetCriticality({ asset: { criticality: 'medium' } }, 'high')).toBe(false);
    // Unstamped or unknown never meets a floor (like a record without a level).
    expect(meetsMinAssetCriticality({}, 'low')).toBe(false);
    expect(meetsMinAssetCriticality({ asset: { criticality: null } }, 'low')).toBe(false);
    expect(meetsMinAssetCriticality({ asset: { criticality: 'urgent' } }, 'low')).toBe(false);
  });

  test('parseLabelMatch needs a key', () => {
    expect(parseLabelMatch('env=prod')).toEqual({ key: 'env', value: 'prod' });
    expect(parseLabelMatch('env=')).toEqual({ key: 'env', value: '' });
    expect(parseLabelMatch('=prod')).toBeNull();
    expect(parseLabelMatch('noequals')).toBeNull();
  });

  test('boundedGroups and boundedLabels bound and flatten', () => {
    expect(boundedGroups(['default', ' dmz ', 'default', '', null])).toEqual(['default', 'dmz']);
    expect(boundedGroups('single')).toEqual(['single']);
    expect(boundedGroups(Array.from({ length: 80 }, (_, i) => `g${i}`)).length).toBe(50);
    expect(boundedLabels({ env: 'prod', nested: { tier: 'gold' }, list: ['a', 'b'], empty: null })).toEqual({
      env: 'prod',
      'nested.tier': 'gold',
      list: 'a,b',
    });
    expect(boundedLabels(null)).toBeNull();
    expect(boundedLabels('x')).toBeNull();
    expect(boundedLabels({})).toBeNull();
  });
});
