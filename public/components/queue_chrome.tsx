import React from 'react';
import { EuiEmptyPrompt, EuiFlexGroup, EuiFlexItem, EuiLoadingSpinner, EuiPanel, EuiStat, EuiText, EuiToolTip } from '@elastic/eui';
import { formatAbsolute, formatRelative } from '../design';

/**
 * Chrome shared by the Alerts and Cases queues (step 8.4): the summary stat
 * tiles, the "Showing x-y of n" results line and the empty state. Both queues
 * render these so their rows, gutters and heights stay identical; the view
 * files keep the data and the handlers.
 */

/**
 * Column widths shared by both queue grids so the fixed columns line up
 * (step 10.2, carried onto the EuiDataGrids of steps 13.1 and 13.2). Every
 * column except the primary one starts at a fixed width; the primary column
 * (alerts Rule, cases Title) has no `initialWidth`, so it is the one column
 * that absorbs whatever the viewport leaves, which keeps both queues free of
 * a horizontal scroll at 1280px and 1920px. From then on every width is the
 * analyst's - the grid remembers what they drag.
 */
export const QUEUE_COLUMN_WIDTH = {
  /** Alerts When and cases Updated: relative age, absolute value as tooltip. */
  timestamp: '110px',
  /** Alerts Agent / IP. */
  agent: '150px',
  severity: '90px',
  status: '110px',
  due: '120px',
  /** Cases: linked-record count. */
  evidence: '80px',
  /** Cases: tasks chip. */
  tasks: '100px',
  assigned: '140px',
  /** Alerts: linked-case badge, truncated with an ellipsis. */
  caseLink: '150px',
  actions: '72px',
} as const;

/**
 * Legacy class of the primary column's cell content under EuiBasicTable
 * (`.euiTableCellContent`, not the `td`). Neither queue renders an
 * EuiBasicTable any more; the constant and its test exist to keep the
 * stylesheet free of a `min-width` on that class, which never could widen a
 * fixed-layout column anyway.
 */
export const QUEUE_PRIMARY_COLUMN_CLASS = 'wamTablePrimaryCol';

/**
 * Design floor of the primary column in px: the fixed widths are chosen so
 * the column keeps at least this much at a 1280px viewport with the OSD nav
 * collapsed (alerts Rule gets 211px there), which keeps 1280 scroll-free.
 * This is the arithmetic the width tests assert about the DEFAULT widths; it
 * is not the runtime floor. At runtime the flexible column is sized by
 * `flexibleColumnWidth` in queue_grid.tsx from the measured grid width, and
 * its floor is `FLEX_COLUMN_MIN_WIDTH` (180). The two differ on purpose: 210
 * is what the default layout must leave at 1280px, while 180 is the last
 * resort once the analyst has widened other columns or hidden none of them -
 * below that the grid scrolls horizontally rather than shrink the title
 * further. EUI's own `Math.max(widthToFill / unsizedColumnCount, 100)` never
 * applies any more, because QueueGrid always passes an `initialWidth`.
 */
export const QUEUE_PRIMARY_MIN_WIDTH = 210;

/** Width of the selection checkbox column (the grid's leading control column). */
export const QUEUE_CHECKBOX_WIDTH = 32;

/**
 * Width (px) the queue's content panel has at a given viewport width:
 * EuiPage `paddingSize="m"` (16px a side), EuiPageContent `paddingSize="l"`
 * (24px a side) and a vertical scrollbar.
 */
export function queueContentWidth(viewportWidth: number): number {
  return viewportWidth - 2 * 16 - 2 * 24 - 15;
}

/** Fixed widths of the alert queue, in column order (checkbox excluded). */
export const ALERT_QUEUE_FIXED_WIDTHS: ReadonlyArray<string> = [
  QUEUE_COLUMN_WIDTH.timestamp,
  QUEUE_COLUMN_WIDTH.agent,
  QUEUE_COLUMN_WIDTH.severity,
  QUEUE_COLUMN_WIDTH.status,
  QUEUE_COLUMN_WIDTH.due,
  QUEUE_COLUMN_WIDTH.assigned,
  QUEUE_COLUMN_WIDTH.caseLink,
  QUEUE_COLUMN_WIDTH.actions,
];

/** Fixed widths of the case queue, in column order (checkbox excluded). */
export const CASE_QUEUE_FIXED_WIDTHS: ReadonlyArray<string> = [
  QUEUE_COLUMN_WIDTH.severity,
  QUEUE_COLUMN_WIDTH.status,
  QUEUE_COLUMN_WIDTH.due,
  QUEUE_COLUMN_WIDTH.evidence,
  QUEUE_COLUMN_WIDTH.tasks,
  QUEUE_COLUMN_WIDTH.assigned,
  QUEUE_COLUMN_WIDTH.timestamp,
  QUEUE_COLUMN_WIDTH.actions,
];

/** Sum in px of CSS pixel widths such as `'110px'`. */
export function sumPixelWidths(widths: ReadonlyArray<string>): number {
  return widths.reduce((total, width) => total + (parseInt(width, 10) || 0), 0);
}

/**
 * Width (px) the growing primary column gets in a table of `tableWidth`
 * once the checkbox and every fixed column have taken theirs.
 */
export function queuePrimaryColumnWidth(tableWidth: number, fixedWidths: ReadonlyArray<string>): number {
  return tableWidth - QUEUE_CHECKBOX_WIDTH - sumPixelWidths(fixedWidths);
}

/**
 * Table-level `min-width` (px) of a queue: checkbox + every fixed column +
 * the primary column's floor. Both queues are EuiDataGrids since steps 13.1
 * and 13.2 and size their own columns, so neither pins a stylesheet
 * `min-width` any more: this value is what each queue's unit test checks the
 * grid column widths against.
 */
export function queueTableMinWidth(fixedWidths: ReadonlyArray<string>): number {
  return QUEUE_CHECKBOX_WIDTH + sumPixelWidths(fixedWidths) + QUEUE_PRIMARY_MIN_WIDTH;
}

interface QueueTimestampProps {
  /** ISO timestamp rendered as a relative age ("6m ago"). */
  value?: string | null;
  /** Tooltip body; defaults to the absolute timestamp. */
  tooltip?: React.ReactNode;
  testSubj?: string;
}

/**
 * Relative age with the absolute value as a tooltip: the narrow timestamp
 * cells of both queues (alerts When, cases Updated).
 */
export const QueueTimestamp: React.FC<QueueTimestampProps> = ({ value, tooltip, testSubj }) => (
  <EuiToolTip content={tooltip ?? formatAbsolute(value)}>
    <span className="wamQueueTimestamp" data-test-subj={testSubj}>
      {formatRelative(value)}
    </span>
  </EuiToolTip>
);

export type QueueStatColor = 'primary' | 'accent' | 'subdued' | 'default';

export interface QueueStatTileSpec {
  id: string;
  description: string;
  value: number;
  /** Colour of the number only; the description keeps the text colour. */
  color?: QueueStatColor;
}

interface QueueStatsProps {
  tiles: QueueStatTileSpec[];
  loading?: boolean;
  testSubj?: string;
}

/** The summary row of a queue: one bordered tile per status count, all the same height. */
export const QueueStats: React.FC<QueueStatsProps> = ({ tiles, loading = false, testSubj = 'wamQueueStats' }) => (
  <EuiFlexGroup gutterSize="s" className="wamQueueStats" wrap data-test-subj={testSubj}>
    {tiles.map((tile) => (
      <EuiFlexItem key={tile.id} className="wamQueueStats__tile">
        <EuiPanel paddingSize="s" hasShadow={false} hasBorder>
          <EuiStat
            titleSize="s"
            title={loading ? <EuiLoadingSpinner size="s" /> : tile.value}
            description={tile.description}
            titleColor={tile.color || 'default'}
            data-test-subj={`${testSubj}-${tile.id}`}
          />
        </EuiPanel>
      </EuiFlexItem>
    ))}
  </EuiFlexGroup>
);

interface QueueResultSummaryProps {
  pageIndex: number;
  pageSize: number;
  total: number;
  /** Plural noun of the rows ("alerts", "cases"). */
  noun: string;
  /** Optional trailing note (a result-window cap, for example). */
  note?: React.ReactNode;
  testSubj?: string;
}

/** "Showing 1-20 of 479 alerts": the same line, height and spacing on both queues. */
export const QueueResultSummary: React.FC<QueueResultSummaryProps> = ({ pageIndex, pageSize, total, noun, note, testSubj = 'wamQueueResultSummary' }) => {
  const first = total === 0 ? 0 : pageIndex * pageSize + 1;
  const last = Math.min((pageIndex + 1) * pageSize, total);
  return (
    <EuiText size="s" color="subdued" className="wamQueueResults" data-test-subj={testSubj}>
      Showing {first}-{last} of {total} {noun}
      {note ? <>; {note}</> : null}
    </EuiText>
  );
};

interface QueueEmptyPromptProps {
  title: string;
  /** One sentence. */
  body: React.ReactNode;
  /** Optional call to action under the sentence (the rules table's "New rule"). */
  actions?: React.ReactNode;
  /** Heading element; a prompt nested under a panel title uses the next level down. */
  headingLevel?: 'h2' | 'h3' | 'h4';
  testSubj?: string;
}

/**
 * The one empty state of the plugin's tables (alert and case queues, the
 * automation rules table, the analyst report tables): search icon, title and
 * a single sentence, optionally followed by an action.
 */
export const QueueEmptyPrompt: React.FC<QueueEmptyPromptProps> = ({
  title,
  body,
  actions,
  headingLevel: Heading = 'h2',
  testSubj = 'wamQueueEmpty',
}) => (
  <EuiEmptyPrompt
    iconType="search"
    className="wamQueueEmpty"
    titleSize="s"
    title={<Heading>{title}</Heading>}
    body={<p>{body}</p>}
    actions={actions}
    data-test-subj={testSubj}
  />
);
