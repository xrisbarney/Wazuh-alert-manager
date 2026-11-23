import React, { useCallback, useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiButtonIcon,
  EuiCopy,
  EuiFlexGroup,
  EuiFlexItem,
  EuiText,
  EuiTitle,
  EuiToolTip,
  EuiSpacer,
} from '@elastic/eui';
import { Indicator, IndicatorType, VerdictHint, groupIndicators, strongestVerdict } from '../../common';
import { formatAbsolute } from '../design';

export const INDICATOR_TYPE_LABELS: Record<IndicatorType, string> = {
  ip: 'IP addresses',
  domain: 'Domains',
  url: 'URLs',
  hash: 'File hashes',
  user: 'Users',
  process: 'Processes',
  host: 'Hosts',
};

const VERDICT_COLORS: Record<string, string> = {
  malicious: 'danger',
  suspicious: 'warning',
  clean: 'success',
  unknown: 'hollow',
  info: 'hollow',
};

function hintLine(hint: VerdictHint): string {
  const bits = [hint.source, hint.verdict];
  if (hint.detail) bits.push(hint.detail);
  if (hint.confidence != null && hint.confidence !== '') bits.push(`confidence ${hint.confidence}`);
  if (hint.matchedField) bits.push(`matched ${hint.matchedField}`);
  return bits.join(' - ');
}

/** One badge summarising the strongest native verdict, with every hint in the tooltip. */
export function VerdictBadges({ hints }: { hints: VerdictHint[] }) {
  if (!hints.length) return null;
  const verdicts = hints.filter((h) => h.verdict !== 'info');
  const geo = hints.filter((h) => h.verdict === 'info');
  const strongest = strongestVerdict(verdicts);
  return (
    <span className="wamIndicatorHints">
      {strongest && (
        <EuiToolTip
          position="top"
          content={
            <div>
              {verdicts.map((h, i) => (
                <div key={i}>{hintLine(h)}</div>
              ))}
            </div>
          }
        >
          <EuiBadge color={VERDICT_COLORS[strongest] || 'hollow'}>
            {strongest} ({verdicts.length})
          </EuiBadge>
        </EuiToolTip>
      )}
      {geo.length > 0 && (
        <EuiToolTip
          position="top"
          content={
            <div>
              {geo.map((h, i) => (
                <div key={i}>{hintLine(h)}</div>
              ))}
              <div>GeoIP hints come from the native pipeline/engine database and may be stale.</div>
            </div>
          }
        >
          <EuiBadge color="hollow" iconType="globe">
            {geo[0].detail}
          </EuiBadge>
        </EuiToolTip>
      )}
    </span>
  );
}

export function CopyValueButton({ value, label }: { value: string; label?: string }) {
  return (
    <EuiCopy textToCopy={value}>
      {(copy) => (
        <EuiButtonIcon
          size="s"
          iconType="copyClipboard"
          aria-label={label || `Copy ${value}`}
          onClick={copy}
          className="wamIndicatorCopy"
        />
      )}
    </EuiCopy>
  );
}

/**
 * Indicator tables (case Indicators section, alert Enrichment tab; step 10.5a).
 * Both tables share these pieces so they look the same: `tableLayout="auto"`
 * with no fixed column widths, narrow columns kept on one line
 * (`INDICATOR_NARROW_CELL`), a growing Value cell with a 160px floor and
 * `break-all` for hashes, verdict badges wrapping inside their own cell and a
 * non-growing right-aligned Actions cell. Below `INDICATOR_TABLE_COMPACT_WIDTH`
 * of content width the case table folds First/Last seen into one Seen column.
 */
export const INDICATOR_TABLE_COMPACT_WIDTH = 1100;

/** Column class for cells that must not wrap (type, counts, timestamps, actions). */
export const INDICATOR_NARROW_CELL = 'wamIndicatorTable__narrow';
/** Column class for the growing Value cell. */
export const INDICATOR_VALUE_CELL = 'wamIndicatorTable__value';
/** Column class for the badge cells (native verdicts, lookups). */
export const INDICATOR_BADGE_CELL = 'wamIndicatorTable__badges';
/** Column class for the right-aligned actions cell. */
export const INDICATOR_ACTIONS_CELL = 'wamIndicatorTable__actions';

/**
 * Whether the element the returned callback ref is attached to is narrower
 * than `INDICATOR_TABLE_COMPACT_WIDTH`. A callback ref (not a RefObject):
 * the case Indicators section mounts only while it is the active section,
 * so the measurement has to start when the element appears. Observed with
 * `ResizeObserver` when the browser has one (the flyout's content column
 * changes width when the section nav collapses), otherwise measured on
 * attach and on window resize. `compact` is false until measured.
 */
export function useIndicatorTableCompact(threshold: number = INDICATOR_TABLE_COMPACT_WIDTH): { ref: (el: HTMLElement | null) => void; compact: boolean } {
  const [el, setEl] = useState<HTMLElement | null>(null);
  const [compact, setCompact] = useState(false);
  const ref = useCallback((node: HTMLElement | null) => setEl(node), []);
  useEffect(() => {
    if (!el) return undefined;
    const measure = () => {
      const width = el.getBoundingClientRect().width;
      // jsdom and a not-yet-laid-out element report 0: keep the full layout.
      setCompact(width > 0 && width < threshold);
    };
    measure();
    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(measure);
      observer.observe(el);
      return () => observer.disconnect();
    }
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [el, threshold]);
  return { ref, compact };
}

interface IndicatorValueCellProps {
  value: string;
  /** Source fields the value was extracted from (tooltip). */
  fields?: string[];
  tags?: string[];
}

/** Copy button, the value in code font (breaks anywhere so hashes fit) and the tags, wrapping as one block. */
export function IndicatorValueCell({ value, fields, tags }: IndicatorValueCellProps) {
  return (
    <div className="wamIndicatorValueCell" data-test-subj="wamIndicatorValueCell">
      <CopyValueButton value={value} />
      <EuiToolTip position="top" content={fields?.length ? `From ${fields.join(', ')}` : undefined}>
        <code className="wamIndicatorValue">{value}</code>
      </EuiToolTip>
      {(tags || []).map((tag) => (
        <EuiBadge color="default" key={tag}>
          {tag}
        </EuiBadge>
      ))}
    </div>
  );
}

/** Compact "Seen" cell: the last-seen time, with both bounds in the tooltip. */
export function IndicatorSeenCell({ firstSeen, lastSeen }: { firstSeen: string | null; lastSeen: string | null }) {
  return (
    <EuiToolTip position="top" content={`First seen ${formatAbsolute(firstSeen)} / Last seen ${formatAbsolute(lastSeen)}`}>
      <span data-test-subj="wamIndicatorSeen">{formatAbsolute(lastSeen)}</span>
    </EuiToolTip>
  );
}

interface IndicatorGroupsProps {
  indicators: Indicator[];
  emptyMessage?: string;
}

/** Indicators grouped by type, one line per value with a copy button and verdict badges. */
export function IndicatorGroups({ indicators, emptyMessage }: IndicatorGroupsProps) {
  const groups = groupIndicators(indicators);
  if (!groups.length) {
    return (
      <EuiText size="s" color="subdued">
        <p>{emptyMessage || 'No indicators could be extracted from this record.'}</p>
      </EuiText>
    );
  }
  return (
    <div className="wamIndicatorGroups" data-test-subj="wamIndicatorGroups">
      {groups.map((group) => (
        <div key={group.type} className="wamIndicatorGroup" data-test-subj={`wamIndicatorGroup-${group.type}`}>
          <EuiTitle size="xxs">
            <h4>
              {INDICATOR_TYPE_LABELS[group.type]} <EuiBadge color="hollow">{group.items.length}</EuiBadge>
            </h4>
          </EuiTitle>
          <EuiSpacer size="xs" />
          {group.items.map((item) => (
            <EuiFlexGroup key={`${item.type}:${item.value}`} gutterSize="xs" alignItems="center" responsive={false} className="wamIndicatorRow">
              <EuiFlexItem grow={false}>
                <CopyValueButton value={item.value} />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiToolTip position="top" content={`From ${item.fields.join(', ')}`}>
                  <code className="wamIndicatorValue">{item.value}</code>
                </EuiToolTip>
              </EuiFlexItem>
              {item.tags.map((tag) => (
                <EuiFlexItem grow={false} key={tag}>
                  <EuiBadge color="default">{tag}</EuiBadge>
                </EuiFlexItem>
              ))}
              {item.verdictHints.length > 0 && (
                <EuiFlexItem grow={false}>
                  <VerdictBadges hints={item.verdictHints} />
                </EuiFlexItem>
              )}
            </EuiFlexGroup>
          ))}
          <EuiSpacer size="s" />
        </div>
      ))}
    </div>
  );
}

/** One value per line, type-grouped, for copy-all and paste into other tools. */
export function indicatorsAsText(indicators: Array<{ value: string }>): string {
  return indicators.map((item) => item.value).join('\n');
}
