import React from 'react';
import { EuiFlexGroup, EuiFlexItem, EuiText } from '@elastic/eui';

export interface DonutSegment {
  label: string;
  value: number;
  color: string;
}

interface Props {
  segments: DonutSegment[];
  // Big number shown in the hole; defaults to the summed total.
  centerValue?: number | string;
  centerLabel?: string;
  size?: number;
}

const TAU = Math.PI * 2;

// Annular-sector path for a donut slice, angles in radians, 0 = 12 o'clock,
// sweeping clockwise.
function slicePath(cx: number, cy: number, rO: number, rI: number, a0: number, a1: number): string {
  const pt = (r: number, a: number) => [cx + r * Math.sin(a), cy - r * Math.cos(a)];
  const large = a1 - a0 > Math.PI ? 1 : 0;
  const [x0, y0] = pt(rO, a0);
  const [x1, y1] = pt(rO, a1);
  const [x2, y2] = pt(rI, a1);
  const [x3, y3] = pt(rI, a0);
  return `M ${x0} ${y0} A ${rO} ${rO} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${rI} ${rI} 0 ${large} 0 ${x3} ${y3} Z`;
}

/**
 * A compact donut chart with a count-style legend on the side — the scannable
 * "coloured dot · label · count · %" layout common to OpenSearch overview
 * dashboards. Pure SVG so it renders identically across every supported OSD
 * version with no charting-library API surface to drift.
 */
export const DonutBreakdown: React.FC<Props> = ({ segments, centerValue, centerLabel, size = 150 }) => {
  const total = segments.reduce((s, x) => s + (x.value || 0), 0);
  const nonZero = segments.filter((s) => s.value > 0);
  const cx = size / 2;
  const cy = size / 2;
  const rO = size / 2 - 4;
  const rI = rO * 0.62;

  let acc = 0;
  const arcs = nonZero.map((s) => {
    const a0 = (acc / total) * TAU;
    acc += s.value;
    const a1 = (acc / total) * TAU;
    return { seg: s, a0, a1 };
  });

  return (
    <EuiFlexGroup gutterSize="m" alignItems="center" responsive={false} wrap>
      <EuiFlexItem grow={false}>
        <svg className="wamDonut" width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Breakdown donut chart">
          {total === 0 ? (
            <circle className="wamDonut__empty" cx={cx} cy={cy} r={(rO + rI) / 2} fill="none" strokeWidth={rO - rI} />
          ) : nonZero.length === 1 ? (
            <circle cx={cx} cy={cy} r={(rO + rI) / 2} fill="none" stroke={nonZero[0].color} strokeWidth={rO - rI} />
          ) : (
            arcs.map((a, i) => <path key={i} d={slicePath(cx, cy, rO, rI, a.a0, a.a1)} fill={a.seg.color} />)
          )}
          {/* Type comes from index.scss: the dashboard's title and text styles. */}
          <text className="wamDonut__value" x={cx} y={cy - 2} textAnchor="middle">
            {centerValue != null ? centerValue : total.toLocaleString()}
          </text>
          {centerLabel && (
            <text className="wamDonut__label" x={cx} y={cy + size * 0.12} textAnchor="middle">
              {centerLabel}
            </text>
          )}
        </svg>
      </EuiFlexItem>
      <EuiFlexItem>
        <div style={{ minWidth: 150 }}>
          {segments.map((s) => {
            const pct = total ? Math.round((s.value / total) * 100) : 0;
            return (
              <EuiFlexGroup key={s.label} gutterSize="s" alignItems="center" responsive={false} style={{ marginBottom: 4 }}>
                <EuiFlexItem grow={false}>
                  <span className="wamDonut__swatch" style={{ background: s.color }} />
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiText size="xs">{s.label}</EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiText size="xs">
                    <span className="wamDonut__count">{s.value.toLocaleString()}</span>
                  </EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 38, textAlign: 'right' }}>
                  <EuiText size="xs" color="subdued">
                    <span className="wamDonut__pct">{pct}%</span>
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
            );
          })}
        </div>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
};
