import React from 'react';
import { EuiText, EuiToolTip } from '@elastic/eui';

interface Props {
  current: number | null | undefined;
  previous: number | null | undefined;
  // For most rates (SLA %, alert count) up is good; for durations (time-to-*)
  // down is good, so pass false.
  higherIsBetter?: boolean;
  // How to render the previous value in the tooltip.
  format?: (n: number) => string;
  label?: string;
}

/**
 * A period-over-period change indicator — the "▲12% vs benchmark" idiom from
 * OpenSearch observability dashboards. Colour encodes better/worse (not just
 * up/down): a rising resolve time is red, a rising SLA% is green.
 */
export const DeltaChip: React.FC<Props> = ({ current, previous, higherIsBetter = true, format, label = 'prior period' }) => {
  if (current == null || previous == null || !isFinite(current) || !isFinite(previous) || previous === 0) {
    return (
      <EuiText size="xs" color="subdued">
        No prior data
      </EuiText>
    );
  }
  const pct = ((current - previous) / Math.abs(previous)) * 100;
  const rounded = Math.round(pct);
  if (rounded === 0) {
    return (
      <EuiText size="xs" color="subdued">
        No change
      </EuiText>
    );
  }
  const up = pct > 0;
  const good = up === higherIsBetter;
  // The theme's success/danger text colours, so the chip reads in light and dark.
  const color = good ? 'success' : 'danger';
  const arrow = up ? '▲' : '▼';
  const fmt = format || ((n: number) => n.toLocaleString());
  return (
    <EuiToolTip content={`${label}: ${fmt(previous)}`}>
      <EuiText size="xs" color={color}>
        <span className="wamDeltaChip">
          {arrow} {Math.abs(rounded)}%
        </span>
      </EuiText>
    </EuiToolTip>
  );
};
