import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { AttackGraphHop, AttackStory, StoryColumn, StoryEdge, StoryNode, storyPathOf, TECHNIQUE_PLAIN } from '../../common';
import { formatAbsolute, formatDuration } from '../design';
import { EDGE_HEX, storyTone, StoryTone, TONE_HEX, TONE_LABEL } from './attack_story_tone';

// Fixed logical stage, fitted to the container width and then zoomed/panned on
// top of that - the same model as the design, so node spacing and edge labels
// keep their proportions at any flyout size.
const STAGE_W = 1200;
// Sized so a ~21-character name fits in the dashboard's code font at 12px.
const NODE_W = 224;
const SOURCE_W = 190;
const NODE_H = 54;
const TOP = 112;
const BOTTOM_PAD = 52;
const ROW_GAP = 104;
const MIN_ZOOM = 0.4;
const MAX_ZOOM = 3;

export type StorySelection = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null;

const COLUMN_TITLE: Record<StoryColumn, string> = {
  source: 'Source IPs',
  host: 'Hosts',
  user: 'Accounts',
  technique: 'Techniques',
};

// Pills between adjacent columns, read left to right. Kept generic (the design's
// "login attempts as" only fits authentication cases).
const verbFor = (from: StoryColumn, to: StoryColumn) => {
  if (to === 'host') return 'targeted';
  if (to === 'user') return 'as account';
  return 'targeted using';
};

// The same relationships as full sentences, for the info panel.
const sentenceVerb = (from: StoryColumn, to: StoryColumn) => {
  if (to === 'host') return 'targeted';
  if (to === 'user') return from === 'host' ? 'saw activity as' : 'acted as';
  return from === 'user' ? 'was targeted using' : 'was hit using';
};

const ICON: Record<string, React.ReactNode> = {
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18" /></>,
  server: <><rect x="4" y="4" width="16" height="7" rx="1.5" /><rect x="4" y="13" width="16" height="7" rx="1.5" /><path d="M8 7.5h.01M8 16.5h.01" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 4-6 8-6s8 2 8 6" /></>,
  crown: <path d="M3 8l4 4 5-7 5 7 4-4-2 11H5z" />,
  key: <><circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M17 6l3 3" /></>,
  door: <path d="M5 21V4h11v17M3 21h18M13 12h.01" />,
  id: <><rect x="3" y="5" width="18" height="14" rx="2" /><circle cx="9" cy="12" r="2.5" /><path d="M14 10h4M14 14h3" /></>,
  hammer: <path d="M14 4l6 6-3 3-6-6zM11 7l-8 8 3 3 8-8" />,
  stairs: <path d="M3 20h5v-5h5v-5h5V5h3" />,
  target: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><path d="M12 12h.01" /></>,
  more: <path d="M6 12h.01M12 12h.01M18 12h.01" />,
};

const ADMIN_ACCOUNTS = new Set(['root', 'administrator', 'admin']);

const iconFor = (node: StoryNode) => {
  if (node.groupedCount != null) return 'more';
  if (node.column === 'source') return 'globe';
  if (node.column === 'host') return 'server';
  if (node.column === 'user') return ADMIN_ACCOUNTS.has(node.label.toLowerCase()) ? 'crown' : 'user';
  const id = node.techniqueId || '';
  if (id === 'T1110.001') return 'key';
  if (id.startsWith('T1110')) return 'hammer';
  if (id.startsWith('T1021')) return 'door';
  if (id.startsWith('T1078')) return 'id';
  if (id.startsWith('T1548') || id === 'T1068') return 'stairs';
  return 'target';
};

const alertsText = (n: number) => `${n.toLocaleString()} alert${n === 1 ? '' : 's'}`;

const spanOf = (first: string | null, last: string | null) => {
  if (!first || !last) return null;
  const minutes = (Date.parse(last) - Date.parse(first)) / 60000;
  return Number.isFinite(minutes) && minutes >= 1 ? formatDuration(minutes) : null;
};

const subtitleFor = (node: StoryNode, story: AttackStory) => {
  const count = alertsText(node.alertCount);
  const columnSize = story.nodes.filter((n) => n.column === node.column).length;
  if (node.groupedCount != null) return `${count} · grouped`;
  if (node.column === 'technique') return `${node.techniqueId && node.techniqueId !== node.label ? `${node.techniqueId} · ` : ''}${count}`;
  if (node.column === 'user' && ADMIN_ACCOUNTS.has(node.label.toLowerCase())) return `${count} · admin account`;
  if (node.rank === 0 && columnSize > 1 && (node.column === 'host' || node.column === 'user')) {
    return `${count} · ${node.column === 'host' ? 'main target' : 'most targeted'}`;
  }
  return count;
};

const B: React.FC = ({ children }) => <b>{children}</b>;
const joinNames = (names: string[]) => names.map((name, i) => (
  <React.Fragment key={name}>{i > 0 && (i === names.length - 1 ? ' and ' : ', ')}<B>{name}</B></React.Fragment>
));

function describeNode(node: StoryNode, story: AttackStory): React.ReactNode {
  const count = <B>{alertsText(node.alertCount)}</B>;
  const columnSize = story.nodes.filter((n) => n.column === node.column).length;
  const top = node.rank === 0 && columnSize > 1;
  let lead: React.ReactNode;
  if (node.groupedCount != null) {
    lead = <>{node.groupedCount} less active {node.column === 'user' ? 'accounts' : `${node.column}s`} are grouped here to keep the graph readable. Together they account for {count}.</>;
  } else if (node.column === 'source') {
    lead = node.id === 'source:unknown'
      ? <>{count} had no recorded source address.</>
      : <><B>{node.label}</B> is recorded as the source of {count}.</>;
  } else if (node.column === 'host') {
    lead = top ? <><B>{node.label}</B> was the main target, with {count}.</> : <><B>{node.label}</B> saw {count}.</>;
  } else if (node.column === 'user') {
    lead = ADMIN_ACCOUNTS.has(node.label.toLowerCase())
      ? <><B>{node.label}</B> is the all-powerful admin account. It appeared in {count}.</>
      : top
        ? <><B>{node.label}</B> was the most targeted account ({count}).</>
        : <>The account <B>{node.label}</B> appeared in {count}.</>;
  } else {
    const plain = node.techniqueId ? TECHNIQUE_PLAIN[node.techniqueId] : undefined;
    lead = <><B>{node.label}</B>{plain ? <>: {plain.charAt(0).toLowerCase() + plain.slice(1)}</> : null}. Seen in {count}.</>;
  }
  const byId = new Map(story.nodes.map((n) => [n.id, n]));
  const ins = story.edges.filter((e) => e.target === node.id).map((e) => byId.get(e.source)!.label);
  const outs = story.edges.filter((e) => e.source === node.id).map((e) => byId.get(e.target)!);
  return (
    <>
      {lead}
      {ins.length > 0 && <> Linked from {joinNames(ins)}.</>}
      {outs.length > 0 && <> It {sentenceVerb(node.column, outs[0].column)} {joinNames(outs.map((n) => n.label))}.</>}
    </>
  );
}

function describeEdge(edge: StoryEdge, a: StoryNode, b: StoryNode): React.ReactNode {
  return (
    <>
      <B>{a.label}</B> {sentenceVerb(a.column, b.column)} <B>{b.label}</B> in <B>{alertsText(edge.alertCount)}</B>. {TONE_LABEL[storyTone(edge.maxLevel)]} severity.
    </>
  );
}

function summaryOf(story: AttackStory): React.ReactNode {
  const hostNode = story.nodes.find((n) => n.column === 'host' && n.rank === 0 && n.groupedCount == null);
  const userNode = story.nodes.find((n) => n.column === 'user' && n.rank === 0 && n.groupedCount == null);
  const span = spanOf(story.firstSeen, story.lastSeen);
  const scope = [
    story.distinct.host ? `${story.distinct.host} host${story.distinct.host === 1 ? '' : 's'}` : null,
    story.distinct.user ? `${story.distinct.user} account${story.distinct.user === 1 ? '' : 's'}` : null,
  ].filter(Boolean).join(' and ');
  const pair = hostNode && userNode ? story.edges.find((e) => e.source === hostNode.id && e.target === userNode.id) : undefined;
  return (
    <>
      <B>{alertsText(story.totalAlerts)}</B>{scope ? ` across ${scope}` : ''}{span ? ` over about ${span}` : ''}.
      {pair && story.distinct.host > 1
        ? <> One host, <B>{hostNode!.label}</B>, and one account, <B>{userNode!.label}</B>, account for {pair.alertCount} of the {story.totalAlerts} alerts.</>
        : hostNode && story.distinct.host > 1
          ? <> <B>{hostNode.label}</B> took the most activity ({hostNode.alertCount} of {story.totalAlerts}).</>
          : null}
      {' '}Click any box for details.
    </>
  );
}

interface Point { x: number; y: number }

const bezier = (p0: Point, p1: Point, p2: Point, p3: Point, t: number): Point => {
  const u = 1 - t;
  return {
    x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
    y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y,
  };
};

const clamp = (v: number, min: number, max: number) => Math.min(max, Math.max(min, v));
const widthOf = (node: StoryNode) => (node.column === 'source' ? SOURCE_W : NODE_W);

let markerSeq = 0;

// Edge-count pills are sized to their text. The label font is the dashboard
// theme's code font (it differs between theme versions), so measure it rather
// than assume a fixed character width.
let measureCtx: CanvasRenderingContext2D | null | undefined;
const measureLabel = (text: string, family: string) => {
  if (measureCtx === undefined) {
    try { measureCtx = document.createElement('canvas').getContext('2d'); } catch (e) { measureCtx = null; }
  }
  if (!measureCtx || !family) return text.length * 7.4;
  measureCtx.font = `700 12px ${family}`;
  return measureCtx.measureText(text).width;
};

const readSaved = (key: string): Record<string, Point> => {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(key) || '{}');
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (e) {
    return {};
  }
};

interface Props {
  story: AttackStory;
  storageKey: string;
  selection: StorySelection;
  onSelectionChange: (selection: StorySelection) => void;
  /** Every hop of the graph, so a selection can preview its linked alerts. */
  hops: AttackGraphHop[];
  /** Opens the Linked Alerts tab filtered to these alerts. */
  onOpenLinked?: (alertIds: string[], label: string) => void;
  headerActions?: React.ReactNode;
}

export const AttackGraphCanvas: React.FC<Props> = ({ story, storageKey, selection, onSelectionChange, hops, onOpenLinked, headerActions }) => {
  const wrapRef = useRef<HTMLDivElement>(null);
  // The resolved code-font stack, and a tick that re-measures labels once web fonts finish loading.
  const [labelFont, setLabelFont] = useState({ family: '', loaded: 0 });
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return undefined;
    let live = true;
    const read = () => {
      if (live) setLabelFont((f) => ({ family: getComputedStyle(el).getPropertyValue('--ag-mono').trim(), loaded: f.loaded + 1 }));
    };
    read();
    (document as any).fonts?.ready?.then(read);
    return () => { live = false; };
  }, []);
  const markerId = useMemo(() => `wamAg${++markerSeq}`, []);
  // base fits the stage to the container; zoom and pan are the viewer's own.
  const [base, setBase] = useState(1);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState<Point>({ x: 0, y: 0 });
  const scale = base * zoom;
  const view = useRef({ base, zoom, pan });
  view.current = { base, zoom, pan };
  const panDrag = useRef<{ pointerId: number; sx: number; sy: number; px: number; py: number; moved: boolean } | null>(null);
  const [panning, setPanning] = useState(false);
  const [overrides, setOverrides] = useState<Record<string, Point>>(() => readSaved(storageKey));
  const overridesRef = useRef(overrides);
  overridesRef.current = overrides;
  const drag = useRef<{ id: string; pointerId: number; sx: number; sy: number; ox: number; oy: number; moved: boolean } | null>(null);

  useEffect(() => setOverrides(readSaved(storageKey)), [storageKey]);

  const layout = useMemo(() => {
    const cols = story.columns;
    const [left, right] = cols.length >= 4 ? [110, 132] : [170, 190];
    const colX = (i: number) => (cols.length > 1 ? left + i * ((STAGE_W - left - right) / (cols.length - 1)) : STAGE_W / 2);
    const perCol = cols.map((c) => story.nodes.filter((n) => n.column === c));
    const maxRows = Math.max(1, ...perCol.map((list) => list.length));
    const height = Math.max(420, TOP + (maxRows - 1) * ROW_GAP + NODE_H + BOTTOM_PAD);
    const pos = new Map<string, Point>();
    perCol.forEach((list, ci) => {
      // Order by the average height of the nodes feeding each one so edges
      // cross as little as possible; the first column is ordered by volume.
      const weight = (n: StoryNode) => {
        const ins = story.edges.filter((e) => e.target === n.id && pos.has(e.source));
        const total = ins.reduce((s, e) => s + e.alertCount, 0);
        return total ? ins.reduce((s, e) => s + pos.get(e.source)!.y * e.alertCount, 0) / total : Number.POSITIVE_INFINITY;
      };
      const ordered = ci === 0
        ? [...list].sort((a, b) => a.rank - b.rank)
        : [...list].map((n) => ({ n, w: weight(n) })).sort((a, b) => (a.n.groupedCount != null ? 1 : 0) - (b.n.groupedCount != null ? 1 : 0) || a.w - b.w || a.n.rank - b.n.rank).map((x) => x.n);
      const bottom = height - BOTTOM_PAD - NODE_H / 2;
      const top = TOP;
      const gap = ordered.length > 1 ? Math.min(128, (bottom - top) / (ordered.length - 1)) : 0;
      const start = (top + bottom) / 2 - (gap * (ordered.length - 1)) / 2;
      ordered.forEach((n, i) => pos.set(n.id, { x: colX(ci), y: start + i * gap }));
    });
    return { height, colX, pos };
  }, [story]);

  const nodePos = useCallback((id: string): Point => {
    const saved = overrides[id];
    const base = layout.pos.get(id)!;
    if (!saved || !Number.isFinite(saved.x) || !Number.isFinite(saved.y)) return base;
    return { x: clamp(saved.x, 100, STAGE_W - 100), y: clamp(saved.y, 40, layout.height - 30) };
  }, [overrides, layout]);

  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return undefined;
    const fit = () => { if (el.clientWidth) setBase(Math.min(1.15, el.clientWidth / STAGE_W)); };
    fit();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', fit);
      return () => window.removeEventListener('resize', fit);
    }
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Zoom about a point in wrap coordinates (defaults to the centre), keeping
  // that point fixed on screen.
  const zoomAt = useCallback((nextZoom: number, cx?: number, cy?: number) => {
    const el = wrapRef.current;
    const { base: b, zoom: z, pan: p } = view.current;
    const target = clamp(nextZoom, MIN_ZOOM, MAX_ZOOM);
    const x = cx ?? (el ? el.clientWidth / 2 : 0);
    const y = cy ?? (el ? el.clientHeight / 2 : 0);
    const k = (b * target) / (b * z);
    setPan({ x: x - (x - p.x) * k, y: y - (y - p.y) * k });
    setZoom(target);
  }, []);
  const resetView = useCallback(() => { setZoom(1); setPan({ x: 0, y: 0 }); }, []);

  const onWrapPointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    try { event.currentTarget.setPointerCapture(event.pointerId); } catch (e) { /* pointer already gone */ }
    panDrag.current = { pointerId: event.pointerId, sx: event.clientX, sy: event.clientY, px: pan.x, py: pan.y, moved: false };
  };
  const onWrapPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    const d = panDrag.current;
    if (!d || d.pointerId !== event.pointerId) return;
    const dx = event.clientX - d.sx;
    const dy = event.clientY - d.sy;
    if (!d.moved && Math.abs(dx) + Math.abs(dy) > 3) { d.moved = true; setPanning(true); }
    if (d.moved) setPan({ x: d.px + dx, y: d.py + dy });
  };
  const onWrapPointerUp = (event: React.PointerEvent<HTMLDivElement>) => {
    const d = panDrag.current;
    if (!d || d.pointerId !== event.pointerId) return;
    panDrag.current = null;
    setPanning(false);
    if (!d.moved) onSelectionChange(null);
  };

  const byId = useMemo(() => new Map(story.nodes.map((n) => [n.id, n])), [story.nodes]);

  const focus = useMemo(() => {
    if (!selection) return null;
    if (selection.kind === 'node') {
      if (!byId.has(selection.id)) return null;
      const keep = storyPathOf(story, selection.id);
      return { nodes: keep, edges: new Set(story.edges.filter((e) => keep.has(e.source) && keep.has(e.target)).map((e) => e.id)) };
    }
    const edge = story.edges.find((e) => e.id === selection.id);
    return edge ? { nodes: new Set([edge.source, edge.target]), edges: new Set([edge.id]) } : null;
  }, [selection, story, byId]);

  const persist = (next: Record<string, Point>) => {
    try { window.localStorage.setItem(storageKey, JSON.stringify(next)); } catch (e) { /* storage unavailable: layout just isn't remembered */ }
  };

  const reset = () => {
    setOverrides({});
    resetView();
    try { window.localStorage.removeItem(storageKey); } catch (e) { /* ignore */ }
  };

  const toggleNode = (id: string) => onSelectionChange(selection?.kind === 'node' && selection.id === id ? null : { kind: 'node', id });
  const toggleEdge = (id: string) => onSelectionChange(selection?.kind === 'edge' && selection.id === id ? null : { kind: 'edge', id });

  const onNodePointerDown = (event: React.PointerEvent<HTMLDivElement>, id: string) => {
    if (event.button !== 0) return;
    event.stopPropagation();
    try { event.currentTarget.setPointerCapture(event.pointerId); } catch (e) { /* pointer already gone */ }
    const p = nodePos(id);
    drag.current = { id, pointerId: event.pointerId, sx: event.clientX, sy: event.clientY, ox: p.x, oy: p.y, moved: false };
  };
  const onNodePointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d || d.pointerId !== event.pointerId) return;
    const dx = (event.clientX - d.sx) / scale;
    const dy = (event.clientY - d.sy) / scale;
    if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
    if (!d.moved) return;
    setOverrides((current) => ({ ...current, [d.id]: { x: clamp(d.ox + dx, 100, STAGE_W - 100), y: clamp(d.oy + dy, 40, layout.height - 30) } }));
  };
  const onNodePointerUp = (event: React.PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d || d.pointerId !== event.pointerId) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    drag.current = null;
    if (d.moved) persist(overridesRef.current);
    else toggleNode(d.id);
  };
  const onNodeKeyDown = (event: React.KeyboardEvent<HTMLDivElement>, id: string) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      toggleNode(id);
      return;
    }
    const step = event.shiftKey ? 40 : 10;
    const delta: Record<string, Point> = { ArrowLeft: { x: -step, y: 0 }, ArrowRight: { x: step, y: 0 }, ArrowUp: { x: 0, y: -step }, ArrowDown: { x: 0, y: step } };
    const d = delta[event.key];
    if (!d) return;
    event.preventDefault();
    const p = nodePos(id);
    const next = { ...overrides, [id]: { x: clamp(p.x + d.x, 100, STAGE_W - 100), y: clamp(p.y + d.y, 40, layout.height - 30) } };
    setOverrides(next);
    persist(next);
  };

  // Edge geometry + count-label placement that avoids overlapping labels.
  // Focused edges are placed first so their labels win the best spots.
  const edgeGeo = useMemo(() => {
    const out = new Map<string, { d: string; label: Point; w: number; text: string }>();
    const placed: Array<{ x: number; y: number; w: number; h: number }> = [];
    const ordered = [...story.edges].sort((a, b) => (focus && !focus.edges.has(a.id) ? 1 : 0) - (focus && !focus.edges.has(b.id) ? 1 : 0) || b.alertCount - a.alertCount);
    for (const e of ordered) {
      const a = byId.get(e.source)!;
      const b = byId.get(e.target)!;
      const pa = nodePos(a.id);
      const pb = nodePos(b.id);
      const dir = pb.x >= pa.x ? 1 : -1;
      const p0 = { x: pa.x + (widthOf(a) / 2) * dir, y: pa.y };
      const p3 = { x: pb.x - (widthOf(b) / 2 + 2) * dir, y: pb.y };
      const k = Math.max(40, Math.abs(p3.x - p0.x) * 0.5) * dir;
      const p1 = { x: p0.x + k, y: p0.y };
      const p2 = { x: p3.x - k, y: p3.y };
      const d = `M${p0.x},${p0.y} C${p1.x},${p1.y} ${p2.x},${p2.y} ${p3.x},${p3.y}`;
      const text = focus?.edges.has(e.id) ? `${verbFor(a.column, b.column)} · ${e.alertCount.toLocaleString()}` : e.alertCount.toLocaleString();
      const w = Math.max(22, Math.ceil(measureLabel(text, labelFont.family)) + 14);
      let label = bezier(p0, p1, p2, p3, 0.5);
      for (const t of [0.5, 0.4, 0.6, 0.33, 0.67, 0.27, 0.73]) {
        label = bezier(p0, p1, p2, p3, t);
        const box = { x: label.x - w / 2 - 3, y: label.y - 13, w: w + 6, h: 26 };
        const hit = placed.some((q) => box.x < q.x + q.w && q.x < box.x + box.w && box.y < q.y + q.h && q.y < box.y + box.h);
        if (!hit || t === 0.73) { placed.push(box); break; }
      }
      out.set(e.id, { d, label, w, text });
    }
    return out;
  }, [story.edges, byId, nodePos, focus, labelFont]);

  const selectedNode = selection?.kind === 'node' ? byId.get(selection.id) : undefined;
  const selectedEdge = selection?.kind === 'edge' ? story.edges.find((e) => e.id === selection.id) : undefined;
  const infoKey = selectedNode ? selectedNode.label : selectedEdge ? 'Relationship' : 'What happened';
  const infoValue = selectedNode
    ? describeNode(selectedNode, story)
    : selectedEdge
      ? describeEdge(selectedEdge, byId.get(selectedEdge.source)!, byId.get(selectedEdge.target)!)
      : summaryOf(story);
  const hopById = useMemo(() => new Map(hops.map((h) => [h.alertId, h])), [hops]);
  const linkedIds = selectedNode?.alertIds || selectedEdge?.alertIds || [];
  const linkedLabel = selectedNode
    ? selectedNode.label
    : selectedEdge
      ? `${byId.get(selectedEdge.source)!.label} → ${byId.get(selectedEdge.target)!.label}`
      : '';
  const linkedPreview = useMemo(() => linkedIds
    .map((id) => hopById.get(id))
    .filter((h): h is AttackGraphHop => Boolean(h))
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0)), [linkedIds, hopById]);
  const tones = Array.from(new Set(story.edges.map((e) => storyTone(e.maxLevel)).concat(story.nodes.map((n) => storyTone(n.maxLevel)))));
  const legendTones = (['high', 'med', 'low'] as StoryTone[]).filter((t) => tones.includes(t));
  const columnSub = (c: StoryColumn) => {
    const n = story.distinct[c];
    if (c === 'source') return `${n} source address${n === 1 ? '' : 'es'}`;
    if (c === 'host') return `${n} host${n === 1 ? '' : 's'}`;
    if (c === 'user') return `${n} username${n === 1 ? '' : 's'}`;
    return `${n} MITRE ATT&CK technique${n === 1 ? '' : 's'}`;
  };
  const columnTitle = (c: StoryColumn) => COLUMN_TITLE[c];

  return (
    <div className="wamAg__panel">
      <div className="wamAg__ptop">
        <div>
          <h2 className="wamAg__h2">Which hosts and accounts were targeted, and how</h2>
          <p className="wamAg__lede">
            Read it left to right, starting from the {story.columns[0] === 'source' ? <>source addresses: a <b>source</b> targeted a host, and a </> : 'hosts: a '}<b>host</b> saw activity as an <b>account</b>, which was targeted using a <b>technique</b>.
            Arrows show direction, and each line shows how many alerts it covers. Thicker, warmer lines mean more alerts.
            Drag any box to rearrange it. Click a box or a line to see its linked alerts.
          </p>
        </div>
        <div className="wamAg__actions">
          {headerActions}
          <button type="button" className="wamAg__btn" onClick={reset}>Reset layout</button>
        </div>
      </div>

      <div
        ref={wrapRef}
        className={`wamAg__stageWrap${panning ? ' wamAg__stageWrap--panning' : ''}`}
        style={{ height: layout.height * base }}
        onPointerDown={onWrapPointerDown}
        onPointerMove={onWrapPointerMove}
        onPointerUp={onWrapPointerUp}
        onPointerCancel={onWrapPointerUp}
      >
        <div className="wamAg__stage" style={{ width: STAGE_W, height: layout.height, transform: `translate(${pan.x}px, ${pan.y}px) scale(${scale})` }}>
          <div className="wamAg__cols" aria-hidden="true">
            {story.columns.map((c, i) => (
              <div key={c} className="wamAg__col" style={{ left: layout.colX(i) }}>
                <b>{columnTitle(c)}</b>
                <i>{columnSub(c)}</i>
              </div>
            ))}
            {story.columns.slice(1).map((c, i) => (
              <div key={`v-${c}`} className="wamAg__verb" style={{ left: (layout.colX(i) + layout.colX(i + 1)) / 2 }}>
                {verbFor(story.columns[i], c)} →
              </div>
            ))}
          </div>

          <svg className="wamAg__edges" width={STAGE_W} height={layout.height} role="group" aria-label="Attack graph relationships">
            <defs>
              {(['high', 'med', 'low'] as StoryTone[]).map((t) => (
                <marker key={t} id={`${markerId}-${t}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="11" markerHeight="11" markerUnits="userSpaceOnUse" orient="auto">
                  <path d="M0,1 L10,5 L0,9 z" fill={EDGE_HEX[t]} />
                </marker>
              ))}
            </defs>
            {[...story.edges]
              .sort((a, b) => (focus?.edges.has(a.id) ? 1 : 0) - (focus?.edges.has(b.id) ? 1 : 0))
              .map((e) => {
                const geo = edgeGeo.get(e.id)!;
                const tone = storyTone(e.maxLevel);
                const color = EDGE_HEX[tone];
                const a = byId.get(e.source)!;
                const b = byId.get(e.target)!;
                const dim = Boolean(focus && !focus.edges.has(e.id));
                const sentence = `${a.label} ${verbFor(a.column, b.column)} ${b.label} · ${alertsText(e.alertCount)}`;
                return (
                  <g
                    key={e.id}
                    className={`wamAg__eg${dim ? ' wamAg__dim' : ''}`}
                    tabIndex={0}
                    role="button"
                    aria-label={sentence}
                    aria-pressed={selection?.kind === 'edge' && selection.id === e.id}
                    onPointerDown={(ev) => { ev.stopPropagation(); toggleEdge(e.id); }}
                    onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggleEdge(e.id); } }}
                  >
                    <title>{sentence}</title>
                    <path className="wamAg__ehit" d={geo.d} />
                    <path
                      className="wamAg__edge"
                      d={geo.d}
                      stroke={color}
                      strokeWidth={Math.max(2, Math.min(8, 1.5 + e.alertCount * 0.4))}
                      strokeOpacity={tone === 'low' ? 0.7 : 0.9}
                      markerEnd={`url(#${markerId}-${tone})`}
                    />
                    <rect className="wamAg__erect" x={geo.label.x - geo.w / 2} y={geo.label.y - 10} width={geo.w} height={20} rx={10} stroke={color} />
                    <text className={`wamAg__elabel wamAg__elabel--${tone}`} x={geo.label.x} y={geo.label.y} dy={4} textAnchor="middle" fill={color}>{geo.text}</text>
                  </g>
                );
              })}
          </svg>

          {story.nodes.map((n) => {
            const p = nodePos(n.id);
            const tone = storyTone(n.maxLevel);
            const isSource = n.column === 'source';
            const sel = selection?.kind === 'node' && selection.id === n.id;
            const dim = Boolean(focus && !focus.nodes.has(n.id));
            return (
              <div
                key={n.id}
                className={`wamAg__node ${isSource ? 'wamAg__node--source' : `wamAg__node--${tone}`}${sel ? ' wamAg__node--sel' : ''}${dim ? ' wamAg__dim' : ''}`}
                style={{ left: p.x, top: p.y, width: widthOf(n) }}
                tabIndex={0}
                role="button"
                aria-pressed={sel}
                aria-label={`${n.label}, ${alertsText(n.alertCount)}, ${TONE_LABEL[tone]} severity. Enter to focus; arrow keys to move.`}
                onPointerDown={(ev) => onNodePointerDown(ev, n.id)}
                onPointerMove={onNodePointerMove}
                onPointerUp={onNodePointerUp}
                onPointerCancel={onNodePointerUp}
                onKeyDown={(ev) => onNodeKeyDown(ev, n.id)}
              >
                <div className="wamAg__ic"><svg viewBox="0 0 24 24" aria-hidden="true">{ICON[iconFor(n)]}</svg></div>
                <div className="wamAg__t">
                  <div className="wamAg__n" title={n.label}>{n.label}</div>
                  <div className="wamAg__s">{subtitleFor(n, story)}</div>
                </div>
              </div>
            );
          })}
        </div>
        <div className="wamAg__zoom" onPointerDown={(ev) => ev.stopPropagation()}>
          <button type="button" title="Zoom out" aria-label="Zoom out" onClick={() => zoomAt(zoom / 1.2)}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M8 11h6M21 21l-4.3-4.3" /></svg>
          </button>
          <button type="button" className="wamAg__pct" title="Reset zoom" onClick={resetView}>{Math.round(zoom * 100)}%</button>
          <button type="button" title="Zoom in" aria-label="Zoom in" onClick={() => zoomAt(zoom * 1.2)}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M8 11h6M11 8v6M21 21l-4.3-4.3" /></svg>
          </button>
          <span className="wamAg__sep" />
          <button type="button" title="Fit to view" aria-label="Fit to view" onClick={resetView}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" /></svg>
          </button>
        </div>
        <div className="wamAg__hint">Drag boxes to move · drag empty space to pan · use + and − to zoom · click to focus</div>
      </div>

      <div className="wamAg__info" aria-live="polite">
        <div>
          <div className="wamAg__k">{infoKey}</div>
          <div className="wamAg__v">{infoValue}</div>
        </div>
        <div className="wamAg__legend">
          {legendTones.map((t) => <span key={t}><i style={{ background: TONE_HEX[t] }} />{TONE_LABEL[t]}</span>)}
        </div>
      </div>

      {linkedPreview.length > 0 && (
        <div className="wamAg__la">
          <div className="wamAg__lah">
            <b>{alertsText(linkedPreview.length).replace('alert', 'linked alert')} · {linkedLabel}</b>
            {onOpenLinked && (
              <button type="button" className="wamAg__btn" onClick={() => onOpenLinked(linkedPreview.map((h) => h.alertId), linkedLabel)}>
                Open in Linked Alerts
              </button>
            )}
          </div>
          <div className="wamAg__tw">
            <table className="wamAg__at wamAg__at--mini">
              <thead>
                <tr><th>Timestamp</th><th>Rule ID</th><th>Agent</th><th>Level</th><th className="wamAg__desc">Description</th></tr>
              </thead>
              <tbody>
                {linkedPreview.slice(0, 5).map((h) => (
                  <tr key={h.alertId}>
                    <td className="wamAg__ts">{formatAbsolute(h.timestamp)}</td>
                    <td>{h.ruleId ? <span className="wamAg__rid" title="Wazuh rule ID">{h.ruleId}</span> : '—'}</td>
                    <td>{h.host || '—'}</td>
                    <td><span className="wamAg__lv" style={{ '--c': TONE_HEX[storyTone(h.level)] } as React.CSSProperties}>{h.level}</span></td>
                    <td className="wamAg__desc">{h.ruleDescription || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {linkedPreview.length > 5 && <div className="wamAg__lamore">+ {(linkedPreview.length - 5).toLocaleString()} more in Linked Alerts</div>}
        </div>
      )}
    </div>
  );
};
