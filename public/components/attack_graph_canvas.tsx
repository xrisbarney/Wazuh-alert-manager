import React, { useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import { AttackGraph, AttackGraphNode, AttackGraphNodeType } from '../../common';
import { severityBand, SEVERITY_HEX, SEVERITY_LABEL } from '../design';

const TYPE_STYLE: Record<AttackGraphNodeType, { color: string; label: string; single: string }> = {
  host: { color: '#54B399', label: 'Hosts', single: 'Host' },
  user: { color: '#A987D1', label: 'Accounts', single: 'Account' },
  technique: { color: '#F07E61', label: 'Techniques', single: 'Technique' },
};
const LANE_ORDER: AttackGraphNodeType[] = ['host', 'user', 'technique'];
const WIDTH = 1080;
const LANE_TOP = 84;
const NODE_GAP = 104;
const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

interface Positioned extends AttackGraphNode {
  x: number;
  y: number;
  r: number;
}

interface AggregateEdge {
  key: string;
  a: string;
  b: string;
  count: number;
  alertIds: string[];
  maxLevel: number;
  latestAt: number | null;
}

interface Props {
  graph: AttackGraph;
  onSelectAlert?: (alertId: string) => void;
}

export const AttackGraphCanvas: React.FC<Props> = ({ graph, onSelectAlert }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{
    kind: 'pan' | 'node';
    id?: string;
    clientX: number;
    clientY: number;
    moved: boolean;
    pointerId: number;
  } | null>(null);
  const suppressClick = useRef(false);
  const [hovered, setHovered] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [offsets, setOffsets] = useState<Record<string, { x: number; y: number }>>({});

  const layout = useMemo(() => {
    const lanes = LANE_ORDER.filter((type) => graph.nodes.some((node) => node.type === type));
    const laneGap = lanes.length > 1 ? (WIDTH - 240) / (lanes.length - 1) : 0;
    const maxCount = Math.max(1, ...graph.nodes.map((node) => node.alertCount));
    const nodes: Positioned[] = [];
    lanes.forEach((type, laneIndex) => {
      const laneNodes = graph.nodes
        .filter((node) => node.type === type)
        .sort((a, b) => b.alertCount - a.alertCount || a.label.localeCompare(b.label));
      const x = lanes.length > 1 ? 120 + laneIndex * laneGap : WIDTH / 2;
      laneNodes.forEach((node, row) => nodes.push({
        ...node,
        x,
        y: LANE_TOP + row * NODE_GAP,
        r: 14 + Math.round((node.alertCount / maxCount) * 10),
      }));
    });
    const rows = Math.max(1, ...lanes.map((type) => graph.nodes.filter((node) => node.type === type).length));
    return { lanes, nodes, height: Math.max(300, LANE_TOP + rows * NODE_GAP + 36) };
  }, [graph.nodes]);

  const positioned = useMemo(() => layout.nodes.map((node) => ({
    ...node,
    x: node.x + (offsets[node.id]?.x || 0),
    y: node.y + (offsets[node.id]?.y || 0),
  })), [layout.nodes, offsets]);
  const byId = useMemo(() => new Map(positioned.map((node) => [node.id, node])), [positioned]);

  const edges = useMemo(() => {
    const aggregate = new Map<string, AggregateEdge>();
    for (const edge of graph.edges) {
      if (edge.source === edge.target) continue;
      const [a, b] = [edge.source, edge.target].sort();
      const key = `${a}|${b}`;
      const current = aggregate.get(key) || { key, a, b, count: 0, alertIds: [], maxLevel: 0, latestAt: null };
      if (!current.alertIds.includes(edge.alertId)) {
        current.alertIds.push(edge.alertId);
        current.count += 1;
      }
      current.maxLevel = Math.max(current.maxLevel, Number(edge.level) || 0);
      const timestamp = Date.parse(edge.timestamp);
      if (Number.isFinite(timestamp)) current.latestAt = Math.max(current.latestAt || 0, timestamp);
      aggregate.set(key, current);
    }
    return Array.from(aggregate.values());
  }, [graph.edges]);
  const edgeTimeRange = useMemo(() => {
    const times = edges.map((edge) => edge.latestAt).filter((value): value is number => value != null);
    if (times.length < 2) return null;
    const min = Math.min(...times);
    const max = Math.max(...times);
    return max > min ? { min, max } : null;
  }, [edges]);

  const visibleBands = useMemo(() => {
    const bands = new Set(edges.map((edge) => severityBand(edge.maxLevel)));
    return (['low', 'medium', 'high', 'critical'] as const).filter((band) => bands.has(band));
  }, [edges]);

  const focusId = hovered || selected;
  const neighbours = useMemo(() => {
    if (!focusId) return null;
    const ids = new Set([focusId]);
    edges.forEach((edge) => {
      if (edge.a === focusId) ids.add(edge.b);
      if (edge.b === focusId) ids.add(edge.a);
    });
    return ids;
  }, [focusId, edges]);

  const selectedNode = selected ? byId.get(selected) : null;
  const activeEdge = selectedEdge ? edges.find((edge) => edge.key === selectedEdge) : null;
  const selectedAlertIds = useMemo(() => {
    if (activeEdge) return activeEdge.alertIds;
    if (!selected) return [];
    const ids = new Set<string>();
    edges.forEach((edge) => {
      if (edge.a === selected || edge.b === selected) edge.alertIds.forEach((id) => ids.add(id));
    });
    return Array.from(ids);
  }, [activeEdge, selected, edges]);

  const toGraphDelta = (dx: number, dy: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    return { x: (dx / rect.width) * WIDTH / zoom, y: (dy / rect.height) * layout.height / zoom };
  };
  const toView = (clientX: number, clientY: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    return { x: ((clientX - rect.left) / rect.width) * WIDTH, y: ((clientY - rect.top) / rect.height) * layout.height };
  };
  const onWheel = (event: React.WheelEvent) => {
    event.preventDefault();
    const point = toView(event.clientX, event.clientY);
    const next = clamp(zoom * (event.deltaY < 0 ? 1.14 : 1 / 1.14), 0.55, 4);
    const ratio = next / zoom;
    setPan((current) => ({
      x: point.x - (point.x - current.x) * ratio,
      y: point.y - (point.y - current.y) * ratio,
    }));
    setZoom(next);
  };
  const beginPan = (event: React.PointerEvent<SVGSVGElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = { kind: 'pan', clientX: event.clientX, clientY: event.clientY, moved: false, pointerId: event.pointerId };
  };
  const beginNodeDrag = (event: React.PointerEvent, id: string) => {
    event.stopPropagation();
    svgRef.current?.setPointerCapture(event.pointerId);
    drag.current = { kind: 'node', id, clientX: event.clientX, clientY: event.clientY, moved: false, pointerId: event.pointerId };
  };
  const move = (event: React.PointerEvent<SVGSVGElement>) => {
    if (!drag.current || drag.current.pointerId !== event.pointerId || !svgRef.current) return;
    const dx = event.clientX - drag.current.clientX;
    const dy = event.clientY - drag.current.clientY;
    if (Math.abs(dx) + Math.abs(dy) > 2) drag.current.moved = true;
    if (drag.current.kind === 'pan') {
      const rect = svgRef.current.getBoundingClientRect();
      setPan((current) => ({
        x: current.x + (dx / rect.width) * WIDTH,
        y: current.y + (dy / rect.height) * layout.height,
      }));
    } else if (drag.current.id) {
      const delta = toGraphDelta(dx, dy);
      const id = drag.current.id;
      setOffsets((current) => ({
        ...current,
        [id]: { x: (current[id]?.x || 0) + delta.x, y: (current[id]?.y || 0) + delta.y },
      }));
    }
    drag.current.clientX = event.clientX;
    drag.current.clientY = event.clientY;
  };
  const endDrag = (event: React.PointerEvent<SVGSVGElement>) => {
    if (!drag.current || drag.current.pointerId !== event.pointerId) return;
    suppressClick.current = drag.current.kind === 'node' && drag.current.moved;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    drag.current = null;
  };
  const reset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setOffsets({});
    setSelected(null);
    setSelectedEdge(null);
  };
  const changeZoom = (factor: number) => setZoom((current) => clamp(current * factor, 0.55, 4));

  if (!graph.nodes.length) return <EuiText size="s" color="subdued">No entities could be extracted from this case's alerts.</EuiText>;

  return (
    <div>
      <EuiFlexGroup gutterSize="s" alignItems="center" wrap responsive={false}>
        {LANE_ORDER.map((type) => {
          const count = graph.nodes.filter((node) => node.type === type).length;
          return (
            <EuiFlexItem grow={false} key={type}>
              <EuiBadge color="hollow"><span style={{ color: TYPE_STYLE[type].color, fontWeight: 700 }}>{count}</span>{' '}{count === 1 ? TYPE_STYLE[type].single.toLowerCase() : TYPE_STYLE[type].label.toLowerCase()}</EuiBadge>
            </EuiFlexItem>
          );
        })}
        <EuiFlexItem />
        <EuiFlexItem grow={false}><EuiToolTip content="Zoom out"><EuiButtonIcon iconType="minusInCircle" aria-label="Zoom out" onClick={() => changeZoom(1 / 1.2)} /></EuiToolTip></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiBadge color="hollow">{Math.round(zoom * 100)}%</EuiBadge></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiToolTip content="Zoom in"><EuiButtonIcon iconType="plusInCircle" aria-label="Zoom in" onClick={() => changeZoom(1.2)} /></EuiToolTip></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiToolTip content="Reset layout and view"><EuiButtonIcon iconType="refresh" aria-label="Reset graph" onClick={reset} /></EuiToolTip></EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="xs" />
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
        <EuiFlexItem grow={false}><EuiText size="xs" color="subdued">Edge severity present:</EuiText></EuiFlexItem>
        {visibleBands.length ? visibleBands.map((band) => (
          <EuiFlexItem grow={false} key={band}>
            <EuiBadge color="hollow"><span style={{ display: 'inline-block', width: 9, height: 9, borderRadius: 2, background: SEVERITY_HEX[band], marginRight: 5 }} />{SEVERITY_LABEL[band]}</EuiBadge>
          </EuiFlexItem>
        )) : <EuiFlexItem grow={false}><EuiBadge color="hollow">No co-occurrence edges</EuiBadge></EuiFlexItem>}
      </EuiFlexGroup>
      <EuiSpacer size="xs" />
      <EuiText size="xs" color="subdued">
        A line is an undirected co-occurrence: two entities appeared in the same alert, not that movement between them was observed. Color is the highest severity and width is shared-alert count.{edgeTimeRange ? ' Brighter lines have a more recent latest shared alert.' : ''} Drag nodes to untangle them, drag empty space to pan, scroll to zoom, and select a node or line for its source alerts.
      </EuiText>
      <EuiSpacer size="s" />

      <div style={{ border: '1px solid #343741', borderRadius: 6, overflow: 'hidden', background: '#171A21' }}>
        <svg
          ref={svgRef}
          width="100%"
          height={Math.min(620, layout.height)}
          viewBox={`0 0 ${WIDTH} ${layout.height}`}
          onWheel={onWheel}
          onPointerDown={beginPan}
          onPointerMove={move}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
          style={{ cursor: drag.current?.kind === 'pan' ? 'grabbing' : 'grab', display: 'block', userSelect: 'none', touchAction: 'none' }}
          role="group"
          aria-label="Interactive alert entity co-occurrence graph"
        >
          {layout.lanes.map((type, index) => {
            const x = layout.lanes.length > 1 ? 120 + index * ((WIDTH - 240) / (layout.lanes.length - 1)) : WIDTH / 2;
            return <text key={type} x={x} y={30} textAnchor="middle" fontSize={14} fontWeight={700} fill={TYPE_STYLE[type].color}>{TYPE_STYLE[type].label}</text>;
          })}
          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {edges.map((edge) => {
              const a = byId.get(edge.a);
              const b = byId.get(edge.b);
              if (!a || !b) return null;
              const connected = focusId === edge.a || focusId === edge.b;
              const isSelected = selectedEdge === edge.key;
              const dim = Boolean(focusId && !connected) || Boolean(selectedEdge && !isSelected);
              const dx = b.x - a.x;
              const sameLane = Math.abs(dx) < 20;
              const path = sameLane
                ? `M ${a.x} ${a.y} C ${a.x + 70} ${a.y}, ${b.x + 70} ${b.y}, ${b.x} ${b.y}`
                : `M ${a.x} ${a.y} C ${a.x + dx * 0.42} ${a.y}, ${b.x - dx * 0.42} ${b.y}, ${b.x} ${b.y}`;
               const color = SEVERITY_HEX[severityBand(edge.maxLevel)];
               const recency = edgeTimeRange && edge.latestAt != null
                 ? 0.42 + 0.48 * ((edge.latestAt - edgeTimeRange.min) / Math.max(1, edgeTimeRange.max - edgeTimeRange.min))
                 : 0.68;
               const toggleEdge = () => { setSelectedEdge(isSelected ? null : edge.key); setSelected(null); };
               return (
                 <g key={edge.key}>
                   <path d={path} fill="none" stroke="transparent" strokeWidth={14} style={{ cursor: 'pointer' }} tabIndex={0} role="button" aria-label={`Undirected co-occurrence, ${edge.count} shared alerts, highest level ${edge.maxLevel}`} aria-pressed={isSelected} onPointerDown={(event) => event.stopPropagation()} onClick={toggleEdge} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggleEdge(); } }} />
                   <path d={path} fill="none" stroke={color} strokeWidth={isSelected ? 4 : Math.min(5, 1.5 + edge.count * 0.65)} strokeOpacity={dim ? 0.1 : isSelected || connected ? 1 : recency} pointerEvents="none" />
                </g>
              );
            })}
            {positioned.map((node) => {
              const style = TYPE_STYLE[node.type];
              const isSelected = selected === node.id;
              const dim = neighbours ? !neighbours.has(node.id) : Boolean(selectedEdge && activeEdge && activeEdge.a !== node.id && activeEdge.b !== node.id);
              const label = node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label;
              return (
                <g
                  key={node.id}
                  tabIndex={0}
                  role="button"
                  aria-label={`${style.single} ${node.label}, ${node.alertCount} alerts`}
                  aria-pressed={isSelected}
                  onPointerDown={(event) => beginNodeDrag(event, node.id)}
                  onMouseEnter={() => setHovered(node.id)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(node.id)}
                  onBlur={() => setHovered(null)}
                  onClick={() => {
                    if (suppressClick.current) { suppressClick.current = false; return; }
                    setSelected(isSelected ? null : node.id);
                    setSelectedEdge(null);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setSelected(isSelected ? null : node.id);
                      setSelectedEdge(null);
                    }
                  }}
                  style={{ cursor: 'move', opacity: dim ? 0.2 : 1 }}
                >
                  <circle cx={node.x} cy={node.y} r={node.r + (isSelected ? 4 : 0)} fill={style.color} fillOpacity={0.16} stroke={style.color} strokeWidth={isSelected ? 3 : 2} />
                  <circle cx={node.x} cy={node.y} r={Math.max(6, node.r - 7)} fill={style.color} />
                  <text x={node.x} y={node.y + node.r + 18} textAnchor="middle" fontSize={12} fontWeight={700} fill="#F5F7FA">{label}</text>
                  <text x={node.x} y={node.y + node.r + 34} textAnchor="middle" fontSize={10.5} fill="#A7B0C0">{node.alertCount} alert{node.alertCount === 1 ? '' : 's'}</text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {(selectedNode || activeEdge) && (
        <>
          <EuiSpacer size="s" />
          <EuiText size="s">
            {selectedNode ? <><strong style={{ color: TYPE_STYLE[selectedNode.type].color }}>{TYPE_STYLE[selectedNode.type].single}: {selectedNode.label}</strong> · mentioned by {selectedNode.alertCount} alert{selectedNode.alertCount === 1 ? '' : 's'}</> : <><strong>Selected co-occurrence</strong> · {activeEdge!.count} shared alert{activeEdge!.count === 1 ? '' : 's'} · highest level {activeEdge!.maxLevel} ({SEVERITY_LABEL[severityBand(activeEdge!.maxLevel)]})</>}
            {selectedAlertIds.map((id) => <EuiBadge key={id} color="hollow" onClick={() => onSelectAlert?.(id)} onClickAriaLabel="Open source alert" style={{ cursor: onSelectAlert ? 'pointer' : 'default', marginLeft: 6 }}>{id.slice(0, 8)}</EuiBadge>)}
          </EuiText>
        </>
      )}
    </div>
  );
};
