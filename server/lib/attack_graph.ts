// MITRE ATT&CK tactic kill-chain order, used to sequence a case's alerts
// into a narrative even when their raw timestamps don't line up with the
// conceptual attack phase (e.g. discovery noise logged after the initial
// access alert that actually started the intrusion).
const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export type AttackGraphNodeType = 'host' | 'user' | 'technique';

export interface AttackGraphNode {
  id: string;
  type: AttackGraphNodeType;
  label: string;
  alertCount: number;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  alertId: string;
  timestamp: string;
  level: number;
}

export interface KillChainPhase {
  tactic: string;
  order: number;
  alertCount: number;
  techniques: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface AttackGraphHop {
  timestamp: string;
  alertId: string;
  host: string | null;
  sources: string[];
  users: string[];
  techniqueIds: string[];
  techniques: string[];
  tactics: string[];
  ruleDescription: string;
  level: number;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  killChain: KillChainPhase[];
  hops: AttackGraphHop[];
}

/**
 * Derives an entity graph, MITRE kill-chain phase breakdown, and a
 * chronological hop list from a set of alerts - typically the alerts
 * linked to one case. This is intentionally graph-data-only: no rendering,
 * no path-finding search yet (see README "Coming soon" for that). The
 * value today is turning a pile of alerts into "who/what was involved and
 * in what order," which is most of the analytical work of tracing an
 * incident by hand.
 */
// Wazuh fields that are logically multi-valued (MITRE ids, techniques, tactics)
// are emitted as an array by most decoders but as a bare scalar by some. Calling
// .map/.forEach on the scalar form throws and 500s the whole graph route, so
// every opportunistic multi-valued field is coerced through this first.
function asArray<T>(v: T | T[] | null | undefined): T[] {
  if (v == null) return [];
  return Array.isArray(v) ? v.filter((x) => x != null) : [v];
}

export function buildAttackGraph(alerts: Array<{ _id: string; _source: any }>): AttackGraph {
  const nodes = new Map<string, AttackGraphNode>();
  const edges: AttackGraphEdge[] = [];
  const phases = new Map<string, KillChainPhase>();
  const hops: AttackGraphHop[] = [];

  const touch = (id: string, type: AttackGraphNodeType, label: string) => {
    const existing = nodes.get(id);
    if (existing) {
      existing.alertCount += 1;
    } else {
      nodes.set(id, { id, type, label, alertCount: 1 });
    }
  };

  for (const alert of alerts) {
    const src = alert._source || {};
    const timestamp = src['@timestamp'];
    const level = src.rule?.level || 0;

    // src.data can be an object OR (for some decoders) a plain string; reading
    // .srcuser off a string is safely undefined, and asArray tolerates scalars.
    const data = src.data && typeof src.data === 'object' ? src.data : {};
    const hostId = src.agent?.name ? `host:${src.agent.name}` : null;
    const userNames: string[] = Array.from(
      new Set([...asArray<string>(data.srcuser), ...asArray<string>(data.dstuser)].filter(Boolean))
    );
    const sources: string[] = Array.from(new Set(asArray<string>(data.srcip).map(String).filter(Boolean)));
    const userIds = userNames.map((u) => `user:${u}`);
    const rawTechniqueIds: string[] = asArray<string>(src.rule?.mitre?.id);
    const rawTechniqueLabels: string[] = asArray<string>(src.rule?.mitre?.technique);
    const techniques = Array.from(
      new Map(rawTechniqueIds.filter(Boolean).map((id, i) => [id, rawTechniqueLabels[i] || id])).entries()
    );
    const techniqueIds = techniques.map(([id]) => id);
    const techniqueLabels = techniques.map(([, label]) => label);
    const tactics: string[] = Array.from(new Set(asArray<string>(src.rule?.mitre?.tactic).filter(Boolean)));

    if (hostId) touch(hostId, 'host', src.agent.name);
    userIds.forEach((id, i) => touch(id, 'user', userNames[i]));
    techniqueIds.forEach((id, i) => touch(`technique:${id}`, 'technique', techniqueLabels[i] || id));

    const entitiesInAlert = [hostId, ...userIds, ...techniqueIds.map((id) => `technique:${id}`)].filter(
      Boolean
    ) as string[];
    for (let i = 0; i < entitiesInAlert.length; i++) {
      for (let j = i + 1; j < entitiesInAlert.length; j++) {
        edges.push({ source: entitiesInAlert[i], target: entitiesInAlert[j], alertId: alert._id, timestamp, level });
      }
    }

    for (const tactic of tactics) {
      const phase = phases.get(tactic) || {
        tactic,
        order: TACTIC_ORDER.indexOf(tactic),
        alertCount: 0,
        techniques: [],
        firstSeen: timestamp,
        lastSeen: timestamp,
      };
      phase.alertCount += 1;
      for (const t of techniqueLabels) {
        if (!phase.techniques.includes(t)) phase.techniques.push(t);
      }
      if (timestamp < phase.firstSeen) phase.firstSeen = timestamp;
      if (timestamp > phase.lastSeen) phase.lastSeen = timestamp;
      phases.set(tactic, phase);
    }

    hops.push({
      timestamp,
      alertId: alert._id,
      host: src.agent?.name || null,
      sources,
      users: userNames,
      techniqueIds,
      techniques: techniqueLabels,
      tactics,
      ruleDescription: src.rule?.description || '',
      level,
    });
  }

  hops.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  const killChain = Array.from(phases.values()).sort((a, b) => {
    const orderA = a.order === -1 ? TACTIC_ORDER.length : a.order;
    const orderB = b.order === -1 ? TACTIC_ORDER.length : b.order;
    return orderA - orderB;
  });

  return { nodes: Array.from(nodes.values()), edges, killChain, hops };
}
