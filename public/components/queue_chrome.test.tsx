/**
 * @jest-environment jsdom
 */
import React from 'react';
import { readFileSync } from 'fs';
import { join } from 'path';
import { EuiBasicTable } from '@elastic/eui';
import { configure, render, screen } from '@testing-library/react';
import {
  ALERT_QUEUE_FIXED_WIDTHS,
  CASE_QUEUE_FIXED_WIDTHS,
  QUEUE_COLUMN_WIDTH,
  QUEUE_PRIMARY_COLUMN_CLASS,
  QUEUE_PRIMARY_MIN_WIDTH,
  QueueEmptyPrompt,
  QueueResultSummary,
  QueueStats,
  QueueTimestamp,
  queueContentWidth,
  queuePrimaryColumnWidth,
  queueTableMinWidth,
  sumPixelWidths,
} from './queue_chrome';
import { buildAlertQueueColumns } from './alerts_view';
import { buildCaseQueueColumns } from './cases_view';

configure({ testIdAttribute: 'data-test-subj' });

describe('QueueStats (step 8.4)', () => {
  test('renders one bordered tile per count, the colour on the number only', () => {
    render(
      <QueueStats
        testSubj="wamAlertQueueStats"
        tiles={[
          { id: 'open', description: 'Open', value: 479, color: 'primary' },
          { id: 'in_progress', description: 'In progress', value: 0, color: 'accent' },
          { id: 'closed', description: 'Closed', value: 13, color: 'subdued' },
          { id: 'total', description: 'Total', value: 492 },
        ]}
      />
    );
    const row = screen.getByTestId('wamAlertQueueStats');
    expect(row.className).toContain('wamQueueStats');
    expect(row.querySelectorAll('.wamQueueStats__tile').length).toBe(4);
    expect(row.querySelectorAll('.euiPanel').length).toBe(4);
    const open = screen.getByTestId('wamAlertQueueStats-open');
    expect(open.textContent).toContain('479');
    expect(open.textContent).toContain('Open');
    expect(open.querySelector('.euiStat__title')!.className).toContain('euiStat__title--primary');
    expect(open.querySelector('.euiStat__description')!.className).not.toContain('primary');
    // Every number is the same title size.
    const titles = Array.from(row.querySelectorAll('.euiStat__title')).map((node) => node.className);
    expect(titles.every((className) => className.includes('euiTitle--small'))).toBe(true);
  });

  test('shows a spinner in place of every number while loading', () => {
    render(<QueueStats loading tiles={[{ id: 'open', description: 'Open', value: 1 }, { id: 'total', description: 'Total', value: 2 }]} />);
    expect(screen.getByTestId('wamQueueStats').querySelectorAll('.euiLoadingSpinner').length).toBe(2);
    expect(screen.getByTestId('wamQueueStats').textContent).not.toContain('1');
  });
});

describe('QueueResultSummary', () => {
  test('prints the page window and the plural noun', () => {
    render(<QueueResultSummary pageIndex={0} pageSize={20} total={479} noun="alerts" testSubj="wamAlertResultSummary" />);
    expect(screen.getByTestId('wamAlertResultSummary').textContent).toBe('Showing 1-20 of 479 alerts');
  });

  test('clamps the last page and appends the note', () => {
    render(<QueueResultSummary pageIndex={2} pageSize={20} total={45} noun="cases" note="the first 45 are browsable" />);
    expect(screen.getByTestId('wamQueueResultSummary').textContent).toBe('Showing 41-45 of 45 cases; the first 45 are browsable');
  });

  test('an empty page starts at 0', () => {
    render(<QueueResultSummary pageIndex={0} pageSize={20} total={0} noun="cases" />);
    expect(screen.getByTestId('wamQueueResultSummary').textContent).toBe('Showing 0-0 of 0 cases');
  });
});

describe('QueueEmptyPrompt', () => {
  test('is the search-icon prompt with a title and one sentence', () => {
    render(<QueueEmptyPrompt title="No cases found" body="No cases matched your filters." testSubj="wamCaseQueueEmpty" />);
    const prompt = screen.getByTestId('wamCaseQueueEmpty');
    expect(prompt.className).toContain('wamQueueEmpty');
    expect(prompt.querySelector('h2')!.textContent).toBe('No cases found');
    expect(prompt.querySelector('p')!.textContent).toBe('No cases matched your filters.');
    expect(prompt.querySelector('[data-euiicon-type="search"], .euiIcon')).not.toBeNull();
  });

  test('takes an action and a lower heading level for prompts nested under a panel title', () => {
    render(
      <QueueEmptyPrompt
        title="No automation rules yet"
        body="Create a draft."
        headingLevel="h3"
        actions={<button data-test-subj="newRule">New rule</button>}
        testSubj="wamRulesEmpty"
      />
    );
    const prompt = screen.getByTestId('wamRulesEmpty');
    expect(prompt.querySelector('h2')).toBeNull();
    expect(prompt.querySelector('h3')!.textContent).toBe('No automation rules yet');
    expect(screen.getByTestId('newRule').textContent).toBe('New rule');
  });
});

describe('QUEUE_COLUMN_WIDTH (step 10.2)', () => {
  test('pins the shared fixed widths both queues use; there is no primary width any more', () => {
    expect(QUEUE_COLUMN_WIDTH).toEqual({
      timestamp: '110px',
      agent: '150px',
      severity: '90px',
      status: '110px',
      due: '120px',
      evidence: '80px',
      tasks: '100px',
      assigned: '140px',
      caseLink: '150px',
      actions: '72px',
    });
    expect((QUEUE_COLUMN_WIDTH as Record<string, string>).primary).toBeUndefined();
  });

  test('both queues fit a 1280px viewport with the OSD nav collapsed and leave the primary column its floor', () => {
    expect(sumPixelWidths(ALERT_QUEUE_FIXED_WIDTHS)).toBe(942);
    expect(sumPixelWidths(CASE_QUEUE_FIXED_WIDTHS)).toBe(822);
    expect(queueContentWidth(1280)).toBe(1185);
    expect(queuePrimaryColumnWidth(queueContentWidth(1280), ALERT_QUEUE_FIXED_WIDTHS)).toBe(211);
    expect(queuePrimaryColumnWidth(queueContentWidth(1280), CASE_QUEUE_FIXED_WIDTHS)).toBe(331);
    // The table min-width (fixed widths + floor) must fit the 1280 content
    // width, otherwise 1280 would scroll; both queues' primary column keeps
    // at least the floor there and far more at 1920.
    expect(queueTableMinWidth(ALERT_QUEUE_FIXED_WIDTHS)).toBe(1184);
    expect(queueTableMinWidth(CASE_QUEUE_FIXED_WIDTHS)).toBe(1064);
    expect(queueTableMinWidth(ALERT_QUEUE_FIXED_WIDTHS)).toBeLessThanOrEqual(queueContentWidth(1280));
    expect(queueTableMinWidth(CASE_QUEUE_FIXED_WIDTHS)).toBeLessThanOrEqual(queueContentWidth(1280));
    expect(queuePrimaryColumnWidth(queueContentWidth(1280), ALERT_QUEUE_FIXED_WIDTHS)).toBeGreaterThanOrEqual(QUEUE_PRIMARY_MIN_WIDTH);
    expect(queuePrimaryColumnWidth(queueContentWidth(1280), CASE_QUEUE_FIXED_WIDTHS)).toBeGreaterThanOrEqual(QUEUE_PRIMARY_MIN_WIDTH);
    expect(queuePrimaryColumnWidth(queueContentWidth(1920), ALERT_QUEUE_FIXED_WIDTHS)).toBe(851);
  });

  // Both queues are EuiDataGrids since steps 13.1 and 13.2: they have no
  // `.euiTable` and size their own columns, so no table min-width is left in
  // the stylesheet. The widths are governed by the grid column tests below.
  test('neither queue pins a table min-width in index.scss, and no cell-content floor remains', () => {
    const scss = readFileSync(join(__dirname, '..', 'index.scss'), 'utf8');
    expect(scss).not.toMatch(/\.wamCaseTable \.euiTable \{/);
    expect(scss).not.toMatch(/\.wamAlertTable \.euiTable \{/);
    // A min-width on the cell content cannot widen a fixed-layout column; it must not come back.
    expect(scss).not.toMatch(/\.wamTablePrimaryCol\s*\{[^}]*min-width/);
    expect(QUEUE_PRIMARY_COLUMN_CLASS).toBe('wamTablePrimaryCol');
  });

  test('the alert grid column widths carry the shared fixed widths, with Rule the only column that grows', () => {
    const columns = buildAlertQueueColumns({ caseTitles: {}, now: Date.now(), openAlertById: jest.fn(), onOpenCase: jest.fn() });
    const visible = columns.filter((column) => !column.hiddenByDefault);
    // Exactly one column absorbs the leftover width (the Rule column).
    expect(visible.filter((column) => column.initialWidth == null).map((column) => column.id)).toEqual(['rule']);
    // 32px selection column + every other default-visible width = the queue's
    // min width without the primary column's floor.
    const SELECTION_COLUMN_WIDTH = 32;
    const fixed = visible.reduce((total, column) => total + (column.initialWidth || 0), 0);
    expect(fixed + SELECTION_COLUMN_WIDTH).toBe(queueTableMinWidth(ALERT_QUEUE_FIXED_WIDTHS) - QUEUE_PRIMARY_MIN_WIDTH);
  });

  test('a primary column without a width leaves the header auto-sized while the fixed columns keep theirs', () => {
    render(
      <EuiBasicTable
        className="wamQueueTable"
        compressed
        items={[{ id: '1', title: 'Case one', severity: 'low' }]}
        itemId="id"
        columns={[
          { field: 'title', name: 'Title', className: QUEUE_PRIMARY_COLUMN_CLASS },
          { field: 'severity', name: 'Severity', width: QUEUE_COLUMN_WIDTH.severity },
        ]}
      />
    );
    const headers = Array.from(document.querySelectorAll('th'));
    expect(headers.find((th) => th.textContent?.includes('Title'))!.style.width).toBe('');
    expect(headers.find((th) => th.textContent?.includes('Severity'))!.style.width).toBe('90px');
    // EuiBasicTable puts the column class on the cell content, not the td.
    expect(document.querySelector('td .euiTableCellContent.wamTablePrimaryCol')).not.toBeNull();
  });

  test('the case grid column widths carry the shared fixed widths, with Title the only column that grows', () => {
    const columns = buildCaseQueueColumns({ unitsLabel: 'Alerts', now: Date.now(), navigateToCase: jest.fn() });
    const visible = columns.filter((column) => !column.hiddenByDefault);
    expect(visible.filter((column) => column.initialWidth == null).map((column) => column.id)).toEqual(['title']);
    const SELECTION_COLUMN_WIDTH = 32;
    const fixed = visible.reduce((total, column) => total + (column.initialWidth || 0), 0);
    expect(fixed + SELECTION_COLUMN_WIDTH).toBe(queueTableMinWidth(CASE_QUEUE_FIXED_WIDTHS) - QUEUE_PRIMARY_MIN_WIDTH);
  });

  test('neither queue gives its primary column a width', () => {
    const read = (name: string) => readFileSync(join(__dirname, name), 'utf8');
    // Both queues are EuiDataGrids (steps 13.1 and 13.2): the growing column
    // (alerts Rule, cases Title) is the one with no `initialWidth`.
    expect(read('cases_view.tsx')).toMatch(/id: 'title',\s+label: 'Title',\s+sortable: true,/);
    expect(read('alerts_view.tsx')).toMatch(/id: 'rule',\s+label: 'Rule',\s+render:/);
    expect(read('cases_view.tsx')).not.toMatch(/QUEUE_COLUMN_WIDTH\.primary/);
    expect(read('alerts_view.tsx')).not.toMatch(/QUEUE_COLUMN_WIDTH\.primary/);
  });
});

describe('QueueTimestamp', () => {
  test('renders the relative age and keeps the absolute value for the tooltip', () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    render(<QueueTimestamp value={twoHoursAgo} testSubj="wamStamp" />);
    const stamp = screen.getByTestId('wamStamp');
    expect(stamp.textContent).toBe('2h ago');
    expect(stamp.className).toContain('wamQueueTimestamp');
    expect(stamp.closest('.euiToolTipAnchor')).not.toBeNull();
  });

  test('a missing value renders the dash', () => {
    render(<QueueTimestamp value={null} testSubj="wamStamp" />);
    expect(screen.getByTestId('wamStamp').textContent).toBe('—');
  });
});
