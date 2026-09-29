import { buildAttackGraph } from '../server/lib/attack_graph';
import { buildAttackStory, storyPathOf } from './attack_story';

const ts = (m: number) => `2026-09-24T11:${String(m).padStart(2, '0')}:00.000Z`;
const alert = (id: string, m: number, src: any) => ({ _id: id, _source: { '@timestamp': ts(m), ...src } });

describe('buildAttackStory', () => {
  test('starts at hosts with directed adjacent-layer edges when no srcip is recorded', () => {
    const story = buildAttackStory(buildAttackGraph([
      alert('a1', 1, { agent: { name: 'web' }, data: { srcuser: 'root' }, rule: { level: 10, mitre: { id: 'T1110.001', technique: 'Password Guessing' } } }),
      alert('a2', 2, { agent: { name: 'web' }, data: { srcuser: 'root' }, rule: { level: 5 } }),
      alert('a3', 3, { agent: { name: 'db' }, rule: { level: 3, mitre: { id: 'T1078', technique: 'Valid Accounts' } } }),
    ]));
    expect(story.columns).toEqual(['host', 'user', 'technique']);
    expect(story.nodes.some((n) => n.column === 'source')).toBe(false);
    const edge = (s: string, t: string) => story.edges.find((e) => e.source === s && e.target === t);
    expect(edge('host:web', 'user:root')).toMatchObject({ alertCount: 2, maxLevel: 10 });
    expect(edge('user:root', 'technique:T1110.001')?.alertCount).toBe(1);
    // No account on a3: the host links straight to the technique rather than dropping it.
    expect(edge('host:db', 'technique:T1078')?.alertCount).toBe(1);
    expect(story.edges.some((e) => e.source === 'host:web' && e.target.startsWith('technique:'))).toBe(false);
    expect(story.totalAlerts).toBe(3);
    expect(story.firstSeen).toBe(ts(1));
    expect(story.lastSeen).toBe(ts(3));
  });

  test('uses source addresses when present and labels the rest as unknown', () => {
    const story = buildAttackStory(buildAttackGraph([
      alert('a1', 1, { agent: { name: 'h' }, data: { srcip: '203.0.113.7' } }),
      alert('a2', 2, { agent: { name: 'h' } }),
    ]));
    expect(story.nodes.filter((n) => n.column === 'source').map((n) => n.label).sort()).toEqual(['203.0.113.7', 'Unknown source']);
  });

  test('folds the long tail of a column into one "+N more" node without losing alerts', () => {
    const alerts = Array.from({ length: 6 }, (_, i) => alert(`a${i}`, i, { agent: { name: `host-${i}` }, rule: { level: 3 } }));
    alerts.push(alert('extra', 9, { agent: { name: 'host-0' }, rule: { level: 3 } }));
    const story = buildAttackStory(buildAttackGraph(alerts), { maxPerColumn: 3 });
    const hosts = story.nodes.filter((n) => n.column === 'host');
    expect(hosts).toHaveLength(3);
    const other = hosts.find((n) => n.groupedCount != null)!;
    expect(other.label).toBe('4 more hosts');
    expect(other.alertCount).toBe(4);
    expect(hosts.find((n) => n.id === 'host:host-0')?.rank).toBe(0);
    expect(story.distinct.host).toBe(6);
  });

  test('path selection walks both upstream and downstream only', () => {
    const story = buildAttackStory(buildAttackGraph([
      alert('a1', 1, { agent: { name: 'a' }, data: { srcuser: 'x' } }),
      alert('a2', 2, { agent: { name: 'b' }, data: { srcuser: 'y' } }),
    ]));
    const path = storyPathOf(story, 'host:a');
    expect(Array.from(path).sort()).toEqual(['host:a', 'user:x']);
  });

  test('carries the highest rule level onto kill-chain phases', () => {
    const story = buildAttackStory(buildAttackGraph([
      alert('a1', 1, { rule: { level: 4, mitre: { tactic: 'Persistence' } } }),
      alert('a2', 2, { rule: { level: 11, mitre: { tactic: 'Persistence' } } }),
    ]));
    expect(story.phases[0]).toMatchObject({ tactic: 'Persistence', maxLevel: 11, alertCount: 2 });
  });
});
