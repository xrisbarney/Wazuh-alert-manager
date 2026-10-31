import { AttackGraph, AttackGraphHop, KillChainPhase } from './types';

/**
 * Turns the raw attack-graph payload into a left-to-right "story": which
 * hosts were hit, which accounts were involved, and which MITRE techniques were
 * used - led by a source-address column only when the alerts record data.srcip. Unlike the co-occurrence edges on the
 * payload, story edges are directed and only join adjacent layers, so the graph
 * reads like a sentence instead of a hairball. Pure and DOM-free so it can be
 * unit tested alongside the server code.
 */

export type StoryColumn = 'source' | 'host' | 'user' | 'technique';
export const STORY_COLUMNS: StoryColumn[] = ['source', 'host', 'user', 'technique'];

export interface StoryNode {
  id: string;
  column: StoryColumn;
  label: string;
  /** MITRE id for technique nodes. */
  techniqueId?: string;
  alertCount: number;
  maxLevel: number;
  alertIds: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  /** Set on a "+N more" node that stands in for the long tail of a column. */
  groupedCount?: number;
  /** Rank within its column by alert count (0 = busiest). */
  rank: number;
}

export interface StoryEdge {
  id: string;
  source: string;
  target: string;
  alertCount: number;
  maxLevel: number;
  alertIds: string[];
}

export interface StoryPhase extends KillChainPhase {
  maxLevel: number;
}

export interface AttackStory {
  columns: StoryColumn[];
  nodes: StoryNode[];
  edges: StoryEdge[];
  /** Every technique seen, busiest first - not collapsed, for the technique cards. */
  techniques: Array<{ id: string; label: string; alertCount: number; maxLevel: number; nodeId: string }>;
  phases: StoryPhase[];
  totalAlerts: number;
  firstSeen: string | null;
  lastSeen: string | null;
  /** Distinct entity counts before collapsing, per column. */
  distinct: Record<StoryColumn, number>;
}

const OTHER = '__other';

interface Acc {
  id: string;
  column: StoryColumn;
  label: string;
  techniqueId?: string;
  alertIds: Set<string>;
  maxLevel: number;
  firstSeen: string | null;
  lastSeen: string | null;
}

const earlier = (a: string | null, b: string | null) => (!a ? b : !b ? a : a < b ? a : b);
const later = (a: string | null, b: string | null) => (!a ? b : !b ? a : a > b ? a : b);

function hopLayers(hop: AttackGraphHop, anySource: boolean) {
  // The source column only exists when some alert records a source address;
  // within it, alerts without one are grouped under "Unknown source".
  const sources = !anySource
    ? []
    : hop.sources && hop.sources.length
      ? hop.sources.map((ip) => ({ id: `source:${ip}`, label: ip }))
      : [{ id: 'source:unknown', label: 'Unknown source' }];
  const hosts = hop.host ? [{ id: `host:${hop.host}`, label: hop.host }] : [];
  const users = (hop.users || []).map((u) => ({ id: `user:${u}`, label: u }));
  const techniques = (hop.techniques || []).map((label, i) => {
    const techniqueId = hop.techniqueIds?.[i] || label;
    return { id: `technique:${techniqueId}`, label, techniqueId };
  });
  return { source: sources, host: hosts, user: users, technique: techniques } as Record<
    StoryColumn,
    Array<{ id: string; label: string; techniqueId?: string }>
  >;
}

export function buildAttackStory(graph: AttackGraph, opts: { maxPerColumn?: number } = {}): AttackStory {
  const maxPerColumn = Math.max(2, opts.maxPerColumn || 8);
  const hops = graph.hops || [];
  const anySource = hops.some((hop) => hop.sources && hop.sources.length > 0);

  // Pass 1: count every entity so each column's long tail can be folded into
  // a single "+N more" node before edges are built.
  const raw = new Map<string, Acc>();
  const touch = (column: StoryColumn, e: { id: string; label: string; techniqueId?: string }, hop: AttackGraphHop) => {
    const acc = raw.get(e.id) || {
      id: e.id, column, label: e.label, techniqueId: e.techniqueId, alertIds: new Set<string>(),
      maxLevel: 0, firstSeen: null, lastSeen: null,
    };
    acc.alertIds.add(hop.alertId);
    acc.maxLevel = Math.max(acc.maxLevel, Number(hop.level) || 0);
    acc.firstSeen = earlier(acc.firstSeen, hop.timestamp || null);
    acc.lastSeen = later(acc.lastSeen, hop.timestamp || null);
    raw.set(e.id, acc);
  };
  const layersByHop = hops.map((hop) => hopLayers(hop, anySource));
  hops.forEach((hop, i) => STORY_COLUMNS.forEach((column) => layersByHop[i][column].forEach((e) => touch(column, e, hop))));

  const byCount = (a: Acc, b: Acc) => b.alertIds.size - a.alertIds.size || a.label.localeCompare(b.label);
  const distinct = { source: 0, host: 0, user: 0, technique: 0 } as Record<StoryColumn, number>;
  const remap = new Map<string, string>();
  for (const column of STORY_COLUMNS) {
    const list = Array.from(raw.values()).filter((n) => n.column === column).sort(byCount);
    distinct[column] = list.length;
    const keep = list.length > maxPerColumn ? list.slice(0, maxPerColumn - 1) : list;
    list.forEach((n) => remap.set(n.id, keep.includes(n) ? n.id : `${column}:${OTHER}`));
  }

  // Pass 2: aggregate collapsed nodes and directed edges between adjacent,
  // present layers (an alert with no user links its host straight to its
  // techniques, so nothing is dropped).
  const nodes = new Map<string, Acc & { groupedCount?: number }>();
  const edges = new Map<string, { source: string; target: string; alertIds: Set<string>; maxLevel: number }>();
  hops.forEach((hop, i) => {
    const layers = layersByHop[i];
    const present: string[][] = [];
    for (const column of STORY_COLUMNS) {
      const ids = Array.from(new Set(layers[column].map((e) => remap.get(e.id)!)));
      ids.forEach((id) => {
        let acc = nodes.get(id);
        if (!acc) {
          const src = raw.get(id);
          acc = src
            ? { ...src, alertIds: new Set<string>(), maxLevel: 0, firstSeen: null, lastSeen: null }
            : { id, column, label: '', alertIds: new Set<string>(), maxLevel: 0, firstSeen: null, lastSeen: null, groupedCount: 0 };
          nodes.set(id, acc);
        }
        acc.alertIds.add(hop.alertId);
        acc.maxLevel = Math.max(acc.maxLevel, Number(hop.level) || 0);
        acc.firstSeen = earlier(acc.firstSeen, hop.timestamp || null);
        acc.lastSeen = later(acc.lastSeen, hop.timestamp || null);
      });
      if (ids.length) present.push(ids);
    }
    for (let l = 0; l + 1 < present.length; l++) {
      for (const source of present[l]) {
        for (const target of present[l + 1]) {
          const key = `${source}→${target}`;
          const edge = edges.get(key) || { source, target, alertIds: new Set<string>(), maxLevel: 0 };
          edge.alertIds.add(hop.alertId);
          edge.maxLevel = Math.max(edge.maxLevel, Number(hop.level) || 0);
          edges.set(key, edge);
        }
      }
    }
  });

  const plural: Record<StoryColumn, string> = { source: 'sources', host: 'hosts', user: 'accounts', technique: 'techniques' };
  for (const column of STORY_COLUMNS) {
    const other = nodes.get(`${column}:${OTHER}`);
    if (other) {
      other.groupedCount = distinct[column] - (maxPerColumn - 1);
      other.label = `${other.groupedCount} more ${plural[column]}`;
    }
  }

  const rankIn = new Map<string, number>();
  for (const column of STORY_COLUMNS) {
    Array.from(nodes.values())
      .filter((n) => n.column === column)
      .sort((a, b) => (a.groupedCount != null ? 1 : 0) - (b.groupedCount != null ? 1 : 0) || byCount(a, b))
      .forEach((n, i) => rankIn.set(n.id, i));
  }

  const storyNodes: StoryNode[] = Array.from(nodes.values()).map((n) => ({
    id: n.id,
    column: n.column,
    label: n.label,
    techniqueId: n.techniqueId,
    alertCount: n.alertIds.size,
    maxLevel: n.maxLevel,
    alertIds: Array.from(n.alertIds),
    firstSeen: n.firstSeen,
    lastSeen: n.lastSeen,
    groupedCount: n.groupedCount,
    rank: rankIn.get(n.id) || 0,
  }));

  const storyEdges: StoryEdge[] = Array.from(edges.entries()).map(([id, e]) => ({
    id, source: e.source, target: e.target, alertCount: e.alertIds.size, maxLevel: e.maxLevel, alertIds: Array.from(e.alertIds),
  }));

  const techniques = Array.from(raw.values())
    .filter((n) => n.column === 'technique')
    .sort(byCount)
    .map((n) => ({
      id: n.techniqueId || n.label,
      label: n.label,
      alertCount: n.alertIds.size,
      maxLevel: n.maxLevel,
      nodeId: remap.get(n.id) || n.id,
    }));

  const tacticLevel = new Map<string, number>();
  hops.forEach((hop) => (hop.tactics || []).forEach((t) => tacticLevel.set(t, Math.max(tacticLevel.get(t) || 0, Number(hop.level) || 0))));
  const phases = (graph.killChain || []).map((p) => ({ ...p, maxLevel: tacticLevel.get(p.tactic) || 0 }));

  let firstSeen: string | null = null;
  let lastSeen: string | null = null;
  hops.forEach((hop) => {
    firstSeen = earlier(firstSeen, hop.timestamp || null);
    lastSeen = later(lastSeen, hop.timestamp || null);
  });

  return {
    columns: STORY_COLUMNS.filter((c) => storyNodes.some((n) => n.column === c)),
    nodes: storyNodes,
    edges: storyEdges,
    techniques,
    phases,
    totalAlerts: new Set(hops.map((h) => h.alertId)).size,
    firstSeen,
    lastSeen,
    distinct,
  };
}

/**
 * Upstream + downstream closure of a node: everything that led to it and
 * everything it led to. Used to light up one attack path on selection.
 */
export function storyPathOf(story: Pick<AttackStory, 'edges'>, id: string): Set<string> {
  const keep = new Set([id]);
  const walk = (dir: 'up' | 'down') => {
    const stack = [id];
    const seen = new Set([id]);
    while (stack.length) {
      const x = stack.pop()!;
      for (const e of story.edges) {
        const [from, to] = dir === 'up' ? [e.target, e.source] : [e.source, e.target];
        if (from === x && !seen.has(to)) {
          seen.add(to);
          keep.add(to);
          stack.push(to);
        }
      }
    }
  };
  walk('up');
  walk('down');
  return keep;
}

// Plain-language one-liners for the MITRE techniques Wazuh's default rules emit
// most, so an analyst new to ATT&CK can read the graph without a lookup. Keyed
// by technique id; unknown ids simply show no description.
export const TECHNIQUE_PLAIN: Record<string, string> = {
  T1110: 'Fast, automated login attempts',
  'T1110.001': 'Trying common passwords one after another',
  'T1110.003': 'One password tried against many accounts',
  'T1110.004': 'Replaying leaked username/password pairs',
  T1021: 'Logging in to machines remotely',
  'T1021.001': 'Remote login over RDP',
  'T1021.004': 'Remote login over SSH, being abused',
  T1078: 'Using real credentials to blend in',
  'T1078.001': 'Using built-in default accounts',
  'T1078.003': 'Using local machine accounts',
  T1548: 'Bypassing controls to gain higher rights',
  'T1548.003': 'Escalating to admin rights via sudo',
  T1098: 'Changing an account to keep access',
  T1136: 'Creating a new account to keep access',
  T1543: 'Installing a service to keep running',
  T1053: 'Scheduling tasks to run code later',
  T1059: 'Running commands through a shell or interpreter',
  T1070: 'Deleting logs or traces to hide activity',
  'T1070.004': 'Deleting files to hide activity',
  T1105: 'Downloading tools onto the machine',
  T1190: 'Exploiting a public-facing application',
  T1203: 'Exploiting software on the user side',
  T1484: 'Changing domain policy to gain control',
  T1485: 'Destroying data',
  T1486: 'Encrypting data for ransom',
  T1489: 'Stopping services to cause disruption',
  T1499: 'Flooding a service to knock it over',
  T1562: 'Turning off security defences',
  'T1562.001': 'Disabling or changing security tools',
  T1565: 'Tampering with stored data',
  T1003: 'Dumping stored passwords and hashes',
  T1087: 'Listing accounts to find targets',
  T1082: 'Collecting details about the system',
  T1046: 'Scanning the network for open services',
  T1071: 'Talking to a command server over normal protocols',
  T1036: 'Disguising malicious files as legitimate ones',
  T1112: 'Changing the registry',
  T1068: 'Exploiting a bug to gain admin rights',
  T1133: 'Coming in through VPN or other remote services',
  T1204: 'Tricking a user into running something',
  T1566: 'Phishing messages',
};

export const TACTIC_PLAIN: Record<string, string> = {
  Reconnaissance: 'Scouted the target',
  'Resource Development': 'Prepared infrastructure',
  'Initial Access': 'Got in the door',
  Execution: 'Ran their own code',
  Persistence: 'Set up to stay',
  'Privilege Escalation': 'Reached for admin rights',
  'Defense Evasion': 'Tried to avoid detection',
  'Credential Access': 'Went after passwords',
  Discovery: 'Looked around',
  'Lateral Movement': 'Moved to other machines',
  Collection: 'Gathered data',
  'Command and Control': 'Phoned home',
  Exfiltration: 'Took data out',
  Impact: 'Caused damage',
};
