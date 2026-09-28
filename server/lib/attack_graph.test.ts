import { buildAttackGraph } from './attack_graph';

const ts = (h: number) => `2026-08-28T${String(h).padStart(2, '0')}:00:00.000Z`;

describe('buildAttackGraph', () => {
  test('tolerates scalar and array forms of multi-valued MITRE/user fields', () => {
    const graph = buildAttackGraph([
      {
        _id: 'a1',
        _source: {
          '@timestamp': ts(1),
          agent: { name: 'host-1' },
          rule: { level: 7, mitre: { id: 'T1110', technique: 'Brute Force', tactic: 'Credential Access' } },
          data: { srcuser: 'bob' },
        },
      },
      {
        _id: 'a2',
        _source: {
          '@timestamp': ts(2),
          agent: { name: 'host-1' },
          rule: { level: 5, mitre: { id: ['T1003', 'T1021'], technique: ['Credential Dumping', 'Remote Services'], tactic: ['Credential Access', 'Lateral Movement'] } },
          data: { srcuser: ['alice', 'carol'] },
        },
      },
    ]);

    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    expect(byId.get('host:host-1')?.alertCount).toBe(2);
    expect(byId.get('user:bob')?.alertCount).toBe(1);
    expect(byId.get('user:alice')?.alertCount).toBe(1);
    expect(byId.get('user:carol')?.alertCount).toBe(1);
    expect(byId.get('technique:T1110')?.label).toBe('Brute Force');
    expect(byId.get('technique:T1003')?.label).toBe('Credential Dumping');
    expect(byId.get('technique:T1021')?.label).toBe('Remote Services');
  });

  test('deduplicates entities and counts how many alerts mention them', () => {
    const graph = buildAttackGraph([
      { _id: 'a1', _source: { '@timestamp': ts(1), agent: { name: 'host-1' } } },
      { _id: 'a2', _source: { '@timestamp': ts(2), agent: { name: 'host-1' } } },
      { _id: 'a3', _source: { '@timestamp': ts(3), agent: { name: 'host-2' } } },
    ]);
    const hosts = graph.nodes.filter((n) => n.type === 'host');
    expect(hosts).toHaveLength(2);
    expect(hosts.find((n) => n.id === 'host:host-1')?.alertCount).toBe(2);
  });

  test('counts an entity once per alert and never emits duplicate or self edges', () => {
    const graph = buildAttackGraph([
      {
        _id: 'a1',
        _source: {
          '@timestamp': ts(1),
          agent: { name: 'host-1' },
          data: { srcuser: ['root', 'root'], dstuser: 'root' },
          rule: {
            level: 8,
            mitre: {
              id: ['T1548', 'T1548'],
              technique: ['Abuse Elevation Control Mechanism', 'Duplicate label'],
              tactic: ['Privilege Escalation', 'Privilege Escalation'],
            },
          },
        },
      },
    ]);
    expect(graph.nodes.find((n) => n.id === 'user:root')?.alertCount).toBe(1);
    expect(graph.nodes.find((n) => n.id === 'technique:T1548')?.alertCount).toBe(1);
    expect(graph.edges).toHaveLength(3);
    expect(graph.edges.every((edge) => edge.source !== edge.target)).toBe(true);
    expect(graph.killChain).toHaveLength(1);
    expect(graph.killChain[0].alertCount).toBe(1);
  });

  test('orders kill-chain phases by ATT&CK tactic order, unknown tactics last', () => {
    const graph = buildAttackGraph([
      { _id: 'a', _source: { '@timestamp': ts(1), rule: { mitre: { tactic: 'Impact' } } } },
      { _id: 'b', _source: { '@timestamp': ts(2), rule: { mitre: { tactic: 'Initial Access' } } } },
      { _id: 'c', _source: { '@timestamp': ts(3), rule: { mitre: { tactic: 'Something Custom' } } } },
    ]);
    expect(graph.killChain.map((p) => p.tactic)).toEqual(['Initial Access', 'Impact', 'Something Custom']);
  });

  test('sorts hops chronologically regardless of input order', () => {
    const graph = buildAttackGraph([
      { _id: 'later', _source: { '@timestamp': ts(10) } },
      { _id: 'earlier', _source: { '@timestamp': ts(1) } },
      { _id: 'middle', _source: { '@timestamp': ts(5) } },
    ]);
    expect(graph.hops.map((h) => h.alertId)).toEqual(['earlier', 'middle', 'later']);
  });

  test('produces a co-occurrence star per alert (edges between every entity present)', () => {
    const graph = buildAttackGraph([
      {
        _id: 'a1',
        _source: {
          '@timestamp': ts(1),
          agent: { name: 'h' },
          rule: { level: 9, mitre: { id: 'T1003', technique: 'Credential Dumping' } },
          data: { srcuser: 'u' },
        },
      },
    ]);
    // host, user, technique -> 3 choose 2 = 3 undirected edges.
    expect(graph.edges).toHaveLength(3);
    expect(graph.edges.every((e) => e.alertId === 'a1')).toBe(true);
    expect(graph.edges.every((e) => e.level === 9)).toBe(true);
  });

  test('records source addresses and technique ids on each hop', () => {
    const graph = buildAttackGraph([
      {
        _id: 'a1',
        _source: {
          '@timestamp': ts(1),
          agent: { name: 'h' },
          rule: { level: 5, mitre: { id: ['T1110.001', 'T1021.004'], technique: ['Password Guessing', 'SSH'] } },
          data: { srcip: ['203.0.113.7', '203.0.113.7'], srcuser: 'root' },
        },
      },
      { _id: 'a2', _source: { '@timestamp': ts(2), agent: { name: 'h' }, data: { srcip: '198.51.100.2' } } },
      { _id: 'a3', _source: { '@timestamp': ts(3), agent: { name: 'h' } } },
    ]);
    expect(graph.hops.map((h) => h.sources)).toEqual([['203.0.113.7'], ['198.51.100.2'], []]);
    expect(graph.hops[0].techniqueIds).toEqual(['T1110.001', 'T1021.004']);
    expect(graph.hops[0].techniques).toEqual(['Password Guessing', 'SSH']);
  });
});
