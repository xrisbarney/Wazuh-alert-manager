import { AttackGraph, AttackGraphNode, AttackGraphNodeType } from './attack_graph';

/**
 * Deterministic, dependency-free SVG rendering of an attack graph (step
 * 5.2). Three layers, one per entity type (hosts, users, techniques), nodes
 * stacked top to bottom in a stable order, parallel edges merged into one
 * line whose width grows with the number of alerts that produced them. The
 * output is a plain `<svg>` string with no scripts, no external references
 * and every label escaped, so it can be inlined in the HTML report or saved
 * next to the Markdown one.
 */

export interface AttackGraphSvgOptions {
  /** Width of one node box. */
  nodeWidth?: number;
  nodeHeight?: number;
  /** Horizontal gap between layers and vertical gap between nodes. */
  columnGap?: number;
  rowGap?: number;
  /** Labels longer than this are cut with an ellipsis. */
  maxLabelLength?: number;
  /** Text shown when the graph has no nodes. */
  emptyText?: string;
  /**
   * Nodes drawn per layer (the top-N by alert count); the rest collapse into
   * one overflow box per layer so a 5,000-alert case stays a bounded drawing.
   */
  maxNodesPerLayer?: number;
}

export interface AttackGraphLayoutDropped {
  type: AttackGraphNodeType;
  /** Nodes of this layer left out of the drawing. */
  count: number;
}

export interface AttackGraphLayoutOverflow {
  type: AttackGraphNodeType;
  count: number;
  layer: number;
  x: number;
  y: number;
  label: string;
}

export interface AttackGraphLayoutNode extends AttackGraphNode {
  layer: number;
  row: number;
  x: number;
  y: number;
}

export interface AttackGraphLayoutEdge {
  source: string;
  target: string;
  /** Number of merged (source, target) alert edges. */
  count: number;
  /** Highest `rule.level` among the merged edges. */
  maxLevel: number;
}

export interface AttackGraphLayout {
  width: number;
  height: number;
  nodes: AttackGraphLayoutNode[];
  edges: AttackGraphLayoutEdge[];
  layers: Array<{ type: AttackGraphNodeType; title: string; x: number }>;
  /** One entry per layer that exceeded `maxNodesPerLayer`. */
  dropped: AttackGraphLayoutDropped[];
  /** The "+N more" box drawn under each cut layer. */
  overflow: AttackGraphLayoutOverflow[];
}

const LAYER_ORDER: AttackGraphNodeType[] = ['host', 'user', 'technique'];
const LAYER_TITLES: Record<AttackGraphNodeType, string> = {
  host: 'Hosts',
  user: 'Users',
  technique: 'Techniques',
};
const NODE_FILL: Record<AttackGraphNodeType, string> = {
  host: '#e6f1fa',
  user: '#fff1e6',
  technique: '#fbe9ef',
};
const NODE_STROKE: Record<AttackGraphNodeType, string> = {
  host: '#1a6fb4',
  user: '#c96a16',
  technique: '#b4295b',
};

const DEFAULTS: Required<AttackGraphSvgOptions> = {
  nodeWidth: 180,
  nodeHeight: 36,
  columnGap: 120,
  rowGap: 16,
  maxLabelLength: 26,
  emptyText: 'No attack graph: the linked alerts carry no host, user or MITRE technique.',
  maxNodesPerLayer: 60,
};

const PADDING = 24;
const TITLE_HEIGHT = 28;

/** Escape text for an SVG/XML attribute or text node. */
export function escapeSvgText(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layerIndex(type: AttackGraphNodeType): number {
  const index = LAYER_ORDER.indexOf(type);
  return index === -1 ? LAYER_ORDER.length : index;
}

function truncateLabel(label: string, max: number): string {
  const text = String(label ?? '');
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(1, max - 1))}…`;
}

function overflowLabel(type: AttackGraphNodeType, count: number): string {
  const noun = type === 'technique' ? 'technique' : type;
  return `+${count} more ${noun}${count === 1 ? '' : 's'}`;
}

/**
 * Place the nodes of the graph in a layered grid: one column per entity
 * type in `host, user, technique` order, nodes sorted by alert count
 * (descending) then label then id so the same graph always yields the same
 * picture. Each layer keeps at most `maxNodesPerLayer` nodes; the rest are
 * reported in `dropped` and drawn as one overflow box, and edges touching a
 * dropped node are left out. Edges are merged by (source, target) regardless
 * of direction.
 */
export function layoutAttackGraph(graph: AttackGraph, options: AttackGraphSvgOptions = {}): AttackGraphLayout {
  const opts = { ...DEFAULTS, ...options };
  const perLayer = Math.max(1, Math.floor(opts.maxNodesPerLayer));
  const byLayer = new Map<number, AttackGraphNode[]>();
  for (const node of graph.nodes || []) {
    if (!node || typeof node.id !== 'string') continue;
    const layer = layerIndex(node.type);
    const list = byLayer.get(layer) || [];
    list.push(node);
    byLayer.set(layer, list);
  }
  const presentLayers = Array.from(byLayer.keys()).sort((a, b) => a - b);
  const nodes: AttackGraphLayoutNode[] = [];
  const layers: AttackGraphLayout['layers'] = [];
  const dropped: AttackGraphLayoutDropped[] = [];
  const overflow: AttackGraphLayoutOverflow[] = [];
  let maxRows = 0;
  presentLayers.forEach((layer, column) => {
    const sorted = (byLayer.get(layer) || []).slice().sort((a, b) => {
      if (b.alertCount !== a.alertCount) return b.alertCount - a.alertCount;
      const label = String(a.label ?? '').localeCompare(String(b.label ?? ''));
      return label !== 0 ? label : a.id.localeCompare(b.id);
    });
    const list = sorted.slice(0, perLayer);
    const cut = sorted.length - list.length;
    const x = PADDING + column * (opts.nodeWidth + opts.columnGap);
    const type = list[0]?.type ?? 'technique';
    layers.push({ type, title: LAYER_TITLES[type] || String(type), x });
    const rowY = (row: number) => PADDING + TITLE_HEIGHT + row * (opts.nodeHeight + opts.rowGap);
    list.forEach((node, row) => {
      nodes.push({ ...node, layer: column, row, x, y: rowY(row) });
    });
    let rows = list.length;
    if (cut > 0) {
      dropped.push({ type, count: cut });
      overflow.push({ type, count: cut, layer: column, x, y: rowY(rows), label: overflowLabel(type, cut) });
      rows += 1;
    }
    maxRows = Math.max(maxRows, rows);
  });

  const known = new Set(nodes.map((node) => node.id));
  const merged = new Map<string, AttackGraphLayoutEdge>();
  for (const edge of graph.edges || []) {
    if (!edge || !known.has(edge.source) || !known.has(edge.target) || edge.source === edge.target) continue;
    const [a, b] = edge.source < edge.target ? [edge.source, edge.target] : [edge.target, edge.source];
    const key = `${a}\u0000${b}`;
    const level = typeof edge.level === 'number' && Number.isFinite(edge.level) ? edge.level : 0;
    const existing = merged.get(key);
    if (existing) {
      existing.count += 1;
      existing.maxLevel = Math.max(existing.maxLevel, level);
    } else {
      merged.set(key, { source: a, target: b, count: 1, maxLevel: level });
    }
  }
  const edges = Array.from(merged.values()).sort((x, y) =>
    x.source === y.source ? x.target.localeCompare(y.target) : x.source.localeCompare(y.source)
  );

  const columns = presentLayers.length;
  const width = columns
    ? PADDING * 2 + columns * opts.nodeWidth + (columns - 1) * opts.columnGap
    : PADDING * 2 + opts.nodeWidth * 2;
  const height = maxRows
    ? PADDING * 2 + TITLE_HEIGHT + maxRows * opts.nodeHeight + (maxRows - 1) * opts.rowGap
    : PADDING * 2 + opts.nodeHeight * 2;
  return { width, height, nodes, edges, layers, dropped, overflow };
}

function strokeWidth(count: number): number {
  return Math.min(6, 1 + Math.log2(Math.max(1, count)));
}

/**
 * Render the graph as an inline SVG string: layer titles, merged edges drawn
 * behind the nodes (thicker when more alerts share the pair, darker when a
 * higher-level alert produced it) and one labelled box per node with its
 * alert count. The picture is deterministic for the same graph, carries no
 * script, style sheet reference or external resource, and escapes every
 * label, so analyst-controlled text can never break out of the markup.
 */
export function renderAttackGraphSvg(graph: AttackGraph, options: AttackGraphSvgOptions = {}): string {
  const opts = { ...DEFAULTS, ...options };
  const layout = layoutAttackGraph(graph, opts);
  const header =
    `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Attack graph" ` +
    `viewBox="0 0 ${layout.width} ${layout.height}" width="${layout.width}" height="${layout.height}" ` +
    `font-family="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif" font-size="12" class="wam-attack-graph">`;
  if (!layout.nodes.length) {
    return (
      `${header}<text x="${PADDING}" y="${PADDING + 16}" fill="#555" class="wam-attack-graph-empty">` +
      `${escapeSvgText(opts.emptyText)}</text></svg>`
    );
  }
  const byId = new Map(layout.nodes.map((node) => [node.id, node]));
  const parts: string[] = [header];
  parts.push('<g class="wam-attack-graph-layers">');
  for (const layer of layout.layers) {
    parts.push(
      `<text x="${layer.x}" y="${PADDING + 14}" font-weight="600" fill="#333" class="wam-attack-graph-layer">` +
        `${escapeSvgText(layer.title)}</text>`
    );
  }
  parts.push('</g><g class="wam-attack-graph-edges">');
  for (const edge of layout.edges) {
    const a = byId.get(edge.source)!;
    const b = byId.get(edge.target)!;
    // Leave the box on the side facing the other node so lines never cross a label.
    const ax = a.layer <= b.layer ? a.x + opts.nodeWidth : a.x;
    const bx = b.layer < a.layer ? b.x + opts.nodeWidth : b.x;
    const ay = a.y + opts.nodeHeight / 2;
    const by = b.y + opts.nodeHeight / 2;
    const stroke = edge.maxLevel >= 12 ? '#8a1c1c' : edge.maxLevel >= 7 ? '#b4295b' : '#7a8794';
    parts.push(
      `<line x1="${ax}" y1="${ay}" x2="${bx}" y2="${by}" stroke="${stroke}" stroke-opacity="0.75" ` +
        `stroke-width="${strokeWidth(edge.count).toFixed(1)}" data-source="${escapeSvgText(edge.source)}" ` +
        `data-target="${escapeSvgText(edge.target)}" data-count="${edge.count}">` +
        `<title>${escapeSvgText(`${a.label} ↔ ${b.label}: ${edge.count} alert${edge.count === 1 ? '' : 's'}`)}</title></line>`
    );
  }
  parts.push('</g><g class="wam-attack-graph-nodes">');
  for (const node of layout.nodes) {
    const label = truncateLabel(String(node.label ?? node.id), opts.maxLabelLength);
    const countText = `${node.alertCount} alert${node.alertCount === 1 ? '' : 's'}`;
    parts.push(
      `<g class="wam-attack-graph-node wam-attack-graph-node--${escapeSvgText(node.type)}" data-node-id="${escapeSvgText(node.id)}">` +
        `<title>${escapeSvgText(`${node.label} (${countText})`)}</title>` +
        `<rect x="${node.x}" y="${node.y}" width="${opts.nodeWidth}" height="${opts.nodeHeight}" rx="6" ry="6" ` +
        `fill="${NODE_FILL[node.type] || '#eee'}" stroke="${NODE_STROKE[node.type] || '#666'}" stroke-width="1.5"/>` +
        `<text x="${node.x + 10}" y="${node.y + 15}" fill="#1a1a1a" font-weight="600">${escapeSvgText(label)}</text>` +
        `<text x="${node.x + 10}" y="${node.y + 29}" fill="#555" font-size="10">${escapeSvgText(countText)}</text>` +
        `</g>`
    );
  }
  parts.push('</g><g class="wam-attack-graph-overflow">');
  for (const box of layout.overflow) {
    parts.push(
      `<g class="wam-attack-graph-overflow-box wam-attack-graph-overflow-box--${escapeSvgText(box.type)}" data-dropped="${box.count}">` +
        `<title>${escapeSvgText(`${box.count} more ${box.type} entit${box.count === 1 ? 'y' : 'ies'} with fewer alerts are not drawn`)}</title>` +
        `<rect x="${box.x}" y="${box.y}" width="${opts.nodeWidth}" height="${opts.nodeHeight}" rx="6" ry="6" ` +
        `fill="#f3f4f6" stroke="#9aa3ad" stroke-width="1" stroke-dasharray="4 3"/>` +
        `<text x="${box.x + 10}" y="${box.y + 22}" fill="#555" font-style="italic">${escapeSvgText(box.label)}</text>` +
        `</g>`
    );
  }
  parts.push('</g></svg>');
  return parts.join('');
}
