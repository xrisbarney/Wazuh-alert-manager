import React, { useMemo, useRef, useState } from 'react';
import { EuiButtonIcon, EuiToolTip, EuiText, EuiBadge, EuiSpacer, EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { AttackGraph, AttackGraphNode, AttackGraphNodeType } from '../../common';

// Node-type colours from the EUI visualisation palette (the sanctioned place
// for chart/graph colour; JS theme tokens aren't exposed in this OUI fork).
const TYPE_STYLE: Record<AttackGraphNodeType, { color: string; label: string; single: string }> = {
  host: { color: '#0077CC', label: 'Hosts', single: 'Host' },
  user: { color: '#9170B8', label: 'Accounts', single: 'Account' },
  technique: { color: '#E7664C', label: 'Techniques', single: 'Technique' },
};

const LANE_ORDER: AttackGraphNodeType[] = ['host', 'user', 'technique'];

interface Positioned extends AttackGraphNode {
  x: number;
  y: number;
  r: number;
}

interface Props {
  graph: AttackGraph;
  onSelectAlert?: (alertId: string) => void;
}

const WIDTH = 760;
const LANE_TOP = 56;
const NODE_GAP = 66;
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

export const AttackGraphCanvas: React.FC<Props> = ({ graph, onSelectAlert }) => {
  const [hovered, setHovered] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ x: number; y: number; moved: boolean } | null>(null);

  const { positioned, byId, lanes, baseH } = useMemo(() => {
    const present = LANE_ORDER.filter((t) => graph.nodes.some((n) => n.type === t));
    const laneGap = present.length > 1 ? (WIDTH - 160) / (present.length - 1) : 0;
    const maxCount = Math.max(1, ...graph.nodes.map((n) => n.alertCount));
    const pos: Positioned[] = [];
    present.forEach((type, laneIdx) => {
      const laneNodes = graph.nodes.filter((n) => n.type === type).sort((a, b) => b.alertCount - a.alertCount);
      const laneX = present.length > 1 ? 80 + laneIdx * laneGap : WIDTH / 2;
      laneNodes.forEach((n, i) => {
        pos.push({ ...n, x: laneX, y: LANE_TOP + i * NODE_GAP, r: 10 + Math.round((n.alertCount / maxCount) * 12) });
      });
    });
    const map = new Map<string, Positioned>();
    pos.forEach((p) => map.set(p.id, p));
    const maxRows = Math.max(1, ...present.map((t) => graph.nodes.filter((n) => n.type === t).length));
    return { positioned: pos, byId: map, lanes: present, baseH: LANE_TOP + maxRows * NODE_GAP };
  }, [graph.nodes]);

  const edges = useMemo(() => {
    const m = new Map<string, { a: string; b: string; count: number; alertIds: string[] }>();
    for (const e of graph.edges) {
      const [a, b] = [e.source, e.target].sort();
      const key = `${a}|${b}`;
      const cur = m.get(key) || { a, b, count: 0, alertIds: [] };
      cur.count += 1;
      if (!cur.alertIds.includes(e.alertId)) cur.alertIds.push(e.alertId);
      m.set(key, cur);
    }
    return Array.from(m.values());
  }, [graph.edges]);

  // ---- robust pan/zoom: fixed viewBox, content transformed by a <g> ----
  const toViewBox = (clientX: number, clientY: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    return { x: ((clientX - rect.left) / rect.width) * WIDTH, y: ((clientY - rect.top) / rect.height) * baseH };
  };
  const onWheel = (ev: React.WheelEvent) => {
    if (!svgRef.current) return;
    const p = toViewBox(ev.clientX, ev.clientY);
    const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    const next = clamp(zoom * factor, 0.4, 5);
    const k = next / zoom;
    setPan((prev) => ({ x: p.x - (p.x - prev.x) * k, y: p.y - (p.y - prev.y) * k }));
    setZoom(next);
  };
  const onMouseDown = (ev: React.MouseEvent) => {
    drag.current = { x: ev.clientX, y: ev.clientY, moved: false };
  };
  const onMouseMove = (ev: React.MouseEvent) => {
    if (!drag.current || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const dx = ((ev.clientX - drag.current.x) / rect.width) * WIDTH;
    const dy = ((ev.clientY - drag.current.y) / rect.height) * baseH;
    if (Math.abs(dx) + Math.abs(dy) > 1) drag.current.moved = true;
    setPan((prev) => ({ x: prev.x + dx, y: prev.y + dy }));
    drag.current.x = ev.clientX;
    drag.current.y = ev.clientY;
  };
  const endDrag = () => {
    drag.current = null;
  };
  const reset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const neighbours = useMemo(() => {
    if (!hovered) return null;
    const set = new Set<string>([hovered]);
    edges.forEach((e) => {
      if (e.a === hovered) set.add(e.b);
      if (e.b === hovered) set.add(e.a);
    });
    return set;
  }, [hovered, edges]);
  const isDim = (id: string) => (neighbours ? !neighbours.has(id) : false);

  const selectedNode = selected ? byId.get(selected) : null;
  const selectedAlertIds = useMemo(() => {
    if (!selected) return [];
    const ids = new Set<string>();
    edges.forEach((e) => {
      if (e.a === selected || e.b === selected) e.alertIds.forEach((a) => ids.add(a));
    });
    return Array.from(ids);
  }, [selected, edges]);

  if (graph.nodes.length === 0) {
    return (
      <EuiText size="s" color="subdued">
        No entities could be extracted from this case's alerts yet.
      </EuiText>
    );
  }

  return (
    <div>
      <EuiFlexGroup gutterSize="s" alignItems="center" wrap responsive={false}>
        {LANE_ORDER.map((t) => {
          const count = graph.nodes.filter((n) => n.type === t).length;
          const word = count === 1 ? TYPE_STYLE[t].single.toLowerCase() : TYPE_STYLE[t].label.toLowerCase();
          return (
            <EuiFlexItem grow={false} key={t}>
              <EuiBadge color="hollow">
                <span style={{ color: TYPE_STYLE[t].color, fontWeight: 700 }}>{count}</span> {word}
              </EuiBadge>
            </EuiFlexItem>
          );
        })}
        <EuiFlexItem grow={false}>
          <EuiToolTip content="Reset view">
            <EuiButtonIcon iconType="refresh" aria-label="Reset view" onClick={reset} />
          </EuiToolTip>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="xs" />
      <EuiText size="xs" color="subdued">
        Each circle is one entity; its size and the "N alerts" caption show how many alerts mention it. Lines connect
        entities that appeared <strong>in the same alert</strong> (co-occurrence) — not observed attacker movement.
        Scroll to zoom, drag to pan.
      </EuiText>
      <EuiSpacer size="s" />

      <div style={{ border: '1px solid #D3DAE6', borderRadius: 6, overflow: 'hidden', background: '#FBFCFD' }}>
        <svg
          ref={svgRef}
          width="100%"
          height={Math.min(520, Math.max(260, baseH))}
          viewBox={`0 0 ${WIDTH} ${baseH}`}
          onWheel={onWheel}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={endDrag}
          onMouseLeave={endDrag}
          style={{ cursor: drag.current ? 'grabbing' : 'grab', display: 'block' }}
          role="img"
          aria-label="Attack path entity graph"
        >
          {/* lane headers stay fixed (outside the pan/zoom transform) */}
          {lanes.map((t, i) => {
            const laneX = lanes.length > 1 ? 80 + i * ((WIDTH - 160) / (lanes.length - 1)) : WIDTH / 2;
            return (
              <text key={t} x={laneX} y={22} textAnchor="middle" fontSize={13} fontWeight={600} fill={TYPE_STYLE[t].color}>
                {TYPE_STYLE[t].label}
              </text>
            );
          })}

          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {edges.map((e, i) => {
              const a = byId.get(e.a);
              const b = byId.get(e.b);
              if (!a || !b) return null;
              const active = hovered && (e.a === hovered || e.b === hovered);
              const dim = hovered && !active;
              const mx = (a.x + b.x) / 2;
              return (
                <path
                  key={i}
                  d={`M ${a.x} ${a.y} Q ${mx} ${(a.y + b.y) / 2} ${b.x} ${b.y}`}
                  fill="none"
                  stroke={active ? '#0077CC' : '#98A2B3'}
                  strokeWidth={active ? 2.5 : Math.min(4, 1 + e.count * 0.5)}
                  strokeOpacity={dim ? 0.1 : 0.45}
                />
              );
            })}

            {positioned.map((n) => {
              const style = TYPE_STYLE[n.type];
              const dim = isDim(n.id);
              const isSel = selected === n.id;
              const shortLabel = n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label;
              return (
                <g
                  key={n.id}
                  style={{ cursor: 'pointer', opacity: dim ? 0.25 : 1 }}
                  onMouseEnter={() => setHovered(n.id)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => {
                    if (!drag.current?.moved) setSelected((s) => (s === n.id ? null : n.id));
                  }}
                >
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={n.r}
                    fill={style.color}
                    fillOpacity={0.9}
                    stroke={isSel ? '#1D1E24' : '#fff'}
                    strokeWidth={isSel ? 3 : 1.5}
                  />
                  <text x={n.x} y={n.y + n.r + 14} textAnchor="middle" fontSize={11.5} fontWeight={600} fill="#1D1E24">
                    {shortLabel}
                  </text>
                  <text x={n.x} y={n.y + n.r + 27} textAnchor="middle" fontSize={10} fill="#69707D">
                    {n.alertCount} alert{n.alertCount === 1 ? '' : 's'}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {selectedNode && (
        <>
          <EuiSpacer size="s" />
          <EuiText size="s">
            <strong style={{ color: TYPE_STYLE[selectedNode.type].color }}>{TYPE_STYLE[selectedNode.type].single}:</strong>{' '}
            {selectedNode.label} — in {selectedNode.alertCount} alert{selectedNode.alertCount === 1 ? '' : 's'}
            {selectedAlertIds.length > 0 && (
              <>
                {' · '}
                {selectedAlertIds.slice(0, 8).map((aid) => (
                  <EuiBadge
                    key={aid}
                    color="hollow"
                    onClick={() => onSelectAlert?.(aid)}
                    onClickAriaLabel="Open alert"
                    style={{ cursor: onSelectAlert ? 'pointer' : 'default', marginRight: 4 }}
                  >
                    {aid.slice(0, 8)}
                  </EuiBadge>
                ))}
                {selectedAlertIds.length > 8 ? `+${selectedAlertIds.length - 8} more` : ''}
              </>
            )}
          </EuiText>
        </>
      )}
    </div>
  );
};
