/**
 * @jest-environment jsdom
 */
import React from 'react';
import { act, configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Case } from '../../common';
import {
  CASE_GRID_STORAGE_KEY,
  CASE_SORT_FIELDS,
  CasesView,
  DEFAULT_CASE_SORT,
  buildCaseQueueColumns,
  caseSortFieldOf,
} from './cases_view';
import { QueueGrid, QueueGridSort } from './queue_grid';
import { QUEUE_COLUMN_WIDTH } from './queue_chrome';
import { formatAbsolute } from '../design';

configure({ testIdAttribute: 'data-test-subj' });

// The case flyout is a subsystem of its own (evidence, tasks, timeline, AI);
// what the queue owes it is the id of the case the analyst opened.
jest.mock('./case_flyout', () => ({
  CaseFlyout: ({ caseId }: { caseId: string }) => <div data-test-subj="wamCaseFlyoutTitle">{caseId}</div>,
}));

const NOW = Date.parse('2026-11-21T10:00:00.000Z');
const CREATED_AT = new Date(NOW - 3 * 24 * 3600 * 1000).toISOString();
const UPDATED_AT = new Date(NOW - 20 * 60000).toISOString();

function caseRow(overrides: Partial<Case> = {}): Case {
  return {
    id: 'case-1',
    case_uid: 'uid-1',
    title: 'Lateral movement from web-01',
    severity: 'high',
    status: 'open',
    assigned_to: 'alice',
    alert_ids: ['a1', 'a2'],
    evidence_count: 2,
    created_by: 'admin',
    created_at: CREATED_AT,
    updated_by: 'alice',
    updated_at: UPDATED_AT,
    task_counts: { open: 2, done: 1 },
    ...overrides,
  } as Case;
}

function renderQueue(items: Case[], extra: { selected?: Case[]; onSelectionChange?: (rows: Case[]) => void; sort?: QueueGridSort } = {}) {
  const navigateToCase = jest.fn((event: React.MouseEvent, _caseId: string) => event.preventDefault());
  const onSort = jest.fn();
  render(
    <QueueGrid<Case>
      className="wamQueueTable wamCaseTable"
      data-test-subj="wamCaseQueueGrid"
      ariaLabel="Case queue"
      storageKey={CASE_GRID_STORAGE_KEY}
      columns={buildCaseQueueColumns({ unitsLabel: 'Alerts', now: NOW, navigateToCase })}
      rows={items}
      getRowId={(caseDoc) => caseDoc.id}
      sort={extra.sort ?? DEFAULT_CASE_SORT}
      onSort={onSort}
      onRowClick={(caseDoc) => navigateToCase({ preventDefault: () => undefined } as any, caseDoc.id)}
      cellClassName="wamCaseQueueCell wamClickableRow"
      rowAnchorClassName="wamCaseRow"
      rowIdAttribute="data-case-id"
      rowClassName={(caseDoc) => `wamCaseRow--${caseDoc.severity}`}
      selection={{ selected: extra.selected ?? [], onChange: extra.onSelectionChange ?? (() => undefined) }}
    />
  );
  return { navigateToCase, onSort };
}

const headerCells = () => Array.from(document.querySelectorAll('.euiDataGridHeaderCell'));
const headerWidth = (name: string) =>
  (headerCells().find((cell) => cell.textContent?.trim().startsWith(name)) as HTMLElement).style.width;

beforeEach(() => {
  window.localStorage.clear();
});

describe('buildCaseQueueColumns on the shared queue grid (step 13.2)', () => {
  test("the default columns are today's queue at the shared widths, with Title the column that grows", () => {
    renderQueue([caseRow()]);
    // Title carries no initial width, so it is the column that absorbs the
    // leftover width (the grid gives it its own minimum under jsdom).
    expect(buildCaseQueueColumns({ unitsLabel: 'Alerts', now: NOW, navigateToCase: jest.fn() })
      .filter((column) => column.initialWidth == null)
      .map((column) => column.id)).toEqual(['title']);
    expect(headerWidth('Severity')).toBe(QUEUE_COLUMN_WIDTH.severity);
    expect(headerWidth('Status')).toBe(QUEUE_COLUMN_WIDTH.status);
    expect(headerWidth('Due')).toBe(QUEUE_COLUMN_WIDTH.due);
    expect(headerWidth('Alerts')).toBe(QUEUE_COLUMN_WIDTH.evidence);
    expect(headerWidth('Tasks')).toBe(QUEUE_COLUMN_WIDTH.tasks);
    expect(headerWidth('Assigned to')).toBe(QUEUE_COLUMN_WIDTH.assigned);
    expect(headerWidth('Updated')).toBe(QUEUE_COLUMN_WIDTH.timestamp);
    expect(headerWidth('Actions')).toBe(QUEUE_COLUMN_WIDTH.actions);
    // Case ID and Created by start hidden; they are selectable. "Created" is
    // not a column of its own (its value lives in the Updated tooltip).
    const names = headerCells().map((cell) => cell.textContent?.trim());
    expect(names.some((text) => text?.startsWith('Case ID'))).toBe(false);
    expect(names.some((text) => text?.startsWith('Created by'))).toBe(false);
    expect(document.body.textContent).not.toContain('admin');
    expect(
      buildCaseQueueColumns({ unitsLabel: 'Alerts', now: NOW, navigateToCase: jest.fn() })
        .filter((column) => column.hiddenByDefault)
        .map((column) => column.id)
    ).toEqual(['caseId', 'createdBy']);
  });

  test('the linked-record count column follows the terminology of the build', () => {
    renderQueue([caseRow()]);
    expect(headerCells().some((cell) => cell.textContent?.trim().startsWith('Alerts'))).toBe(true);
    expect(screen.getByTestId('wamCaseEvidenceCount').textContent).toBe('2');
    const findings = buildCaseQueueColumns({ unitsLabel: 'Findings', now: NOW, navigateToCase: jest.fn() });
    expect(findings.find((column) => column.id === 'evidence')!.label).toBe('Findings');
  });

  test('every cell of a row carries the case id and the first visible column carries the severity band', () => {
    renderQueue([caseRow({ id: 'case-9', severity: 'critical' })]);
    expect(document.querySelectorAll('.wamCaseQueueCell[data-case-id="case-9"]').length).toBeGreaterThan(1);
    const anchors = document.querySelectorAll('.wamCaseRow');
    expect(anchors.length).toBe(1);
    expect(anchors[0].className).toContain('wamCaseRow--critical');
    // The anchor is the Title cell, the first visible column.
    expect(anchors[0].textContent).toContain('Lateral movement from web-01');
  });

  test('the Title cell links to the case and keeps the id as its secondary line', () => {
    const { navigateToCase } = renderQueue([caseRow()]);
    const anchor = document.querySelector('.wamCaseRow')!;
    expect(anchor.querySelector('.wamTableSecondary')!.textContent).toBe('Case case-1');
    fireEvent.click(anchor.querySelector('.euiLink')!);
    expect(navigateToCase).toHaveBeenCalledWith(expect.anything(), 'case-1');
  });

  test('Updated shows the relative age of the last change and its tooltip carries both timestamps', () => {
    jest.useFakeTimers();
    try {
      renderQueue([caseRow()]);
      const stamp = screen.getByTestId('wamCaseUpdated');
      expect(stamp.textContent).toMatch(/ago$/);
      act(() => {
        fireEvent.mouseOver(stamp);
        jest.advanceTimersByTime(1000);
      });
      const tooltip = document.querySelector('.euiToolTipPopover')!;
      expect(tooltip).not.toBeNull();
      expect(tooltip.textContent).toContain(`Created ${formatAbsolute(CREATED_AT)} by admin`);
      expect(tooltip.textContent).toContain(`Updated ${formatAbsolute(UPDATED_AT)} by alice`);
    } finally {
      jest.useRealTimers();
    }
  });

  test('a case never updated falls back to its creation time', () => {
    // formatRelative reads the wall clock, so the fixture is anchored to it.
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString();
    renderQueue([caseRow({ created_at: threeDaysAgo, updated_at: undefined, updated_by: undefined })]);
    expect(screen.getByTestId('wamCaseUpdated').textContent).toBe('3d ago');
  });

  test('the status, SLA and tasks cells keep their badges', () => {
    renderQueue([caseRow({ status: 'closed', disposition: 'false_positive', sla_due_at: new Date(NOW + 3600_000).toISOString() })]);
    expect(screen.getByTestId('wamCaseDisposition')).not.toBeNull();
    expect(screen.getByTestId('wamCaseDue')).not.toBeNull();
    expect(screen.getByTestId('wamCaseTasksChip').textContent).toContain('1/3');
  });

  test('the Actions column renders the inspect button with its subject and label, and it opens the case', () => {
    const { navigateToCase } = renderQueue([caseRow()]);
    const open = screen.getByTestId('wamCaseExpand');
    expect(open.getAttribute('aria-label')).toBe('Open details for Lateral movement from web-01');
    fireEvent.click(open);
    expect(navigateToCase).toHaveBeenCalledWith(expect.anything(), 'case-1');
  });

  test('the hidden columns render their values once selected', () => {
    renderQueue([caseRow()]);
    fireEvent.click(screen.getByTestId('dataGridColumnSelectorButton'));
    // The selector's switch is named after the column id (the test build
    // renders every generated id as "generated-id").
    fireEvent.click(document.querySelector('button[role="switch"][name="caseId"]')!);
    fireEvent.click(document.querySelector('button[role="switch"][name="createdBy"]')!);
    expect(screen.getByTestId('wamCaseIdCell').textContent).toBe('case-1');
    expect(screen.getByTestId('wamCaseCreatedBy').textContent).toBe('admin');
  });

  test('every sortable column maps to a sort field the cases route takes', () => {
    const columns = buildCaseQueueColumns({ unitsLabel: 'Alerts', now: NOW, navigateToCase: jest.fn() });
    const sortable = columns.filter((column) => column.sortable).map((column) => column.id);
    expect(sortable).toEqual(['title', 'severity', 'status', 'due', 'assigned', 'updated', 'createdBy']);
    for (const id of sortable) expect(typeof CASE_SORT_FIELDS[id]).toBe('string');
    expect(CASE_SORT_FIELDS[DEFAULT_CASE_SORT.columnId]).toBe('updated_at');
  });
});

/**
 * The view itself (step 13.2): the wiring between `CasesView` and the shared
 * grid - the page it renders, the flyout a cell click opens, the selection
 * the bulk bar reads, and the refetches a sort or a page change trigger.
 */
function mockApi(overrides: Record<string, any> = {}) {
  const base: Record<string, any> = {
    fetchCases: jest.fn(async () => ({
      cases: [caseRow(), caseRow({ id: 'case-2', title: 'Beaconing from db-02', severity: 'medium' })],
      total: 42,
      summary: { open: 2, in_progress: 0, closed: 0, total: 42 },
    })),
    fetchUsers: jest.fn(async () => ['alice']),
    ...overrides,
  };
  return new Proxy(base, {
    get: (target, key) => {
      if (typeof key !== 'string') return (target as any)[key];
      if (!(key in target)) target[key] = jest.fn(async () => ({}));
      return target[key];
    },
  }) as any;
}

async function renderView(api: any) {
  const onToast = jest.fn();
  const onOpenAlert = jest.fn();
  const onCaseFlyoutClosed = jest.fn();
  await act(async () => {
    render(<CasesView apiService={api} onToast={onToast} onOpenAlert={onOpenAlert} onCaseFlyoutClosed={onCaseFlyoutClosed} />);
  });
  return { onToast, onOpenAlert, onCaseFlyoutClosed };
}

/**
 * Sort the queue from a column header, the way an analyst does: the grid's
 * header action popover ("Sort A-Z" / "Sort Z-A").
 */
async function sortByHeader(columnId: string, label: 'Sort A-Z' | 'Sort Z-A' = 'Sort A-Z') {
  const action = document.querySelector(`[data-test-subj="dataGridHeaderCellActionButton-${columnId}"]`)!;
  await act(async () => {
    fireEvent.click(action.closest('button')!);
  });
  const group = document.querySelector(`[data-test-subj="dataGridHeaderCellActionGroup-${columnId}"]`)!;
  const item = Array.from(group.querySelectorAll('button')).find((button) => button.textContent?.includes(label))!;
  await act(async () => {
    fireEvent.click(item);
  });
}

/** The arguments of the most recent fetchCases call. */
const lastFetch = (api: any) => {
  const calls = api.fetchCases.mock.calls;
  return calls[calls.length - 1][0];
};

describe('CasesView wiring (step 13.2)', () => {
  test('renders the fetched page through the grid', async () => {
    const api = mockApi();
    await renderView(api);
    expect(screen.getByTestId('wamCaseQueueGrid')).not.toBeNull();
    expect(document.querySelectorAll('.wamCaseRow').length).toBe(2);
    expect(document.body.textContent).toContain('Beaconing from db-02');
    expect(lastFetch(api)).toMatchObject({ fromOffset: 0, size: 20, sortField: 'updated_at', sortDirection: 'desc' });
  });

  test('a cell click opens the case flyout', async () => {
    const api = mockApi();
    await renderView(api);
    await act(async () => {
      fireEvent.click(document.querySelector('.wamCaseRow[data-case-id="case-2"] .wamQueueGridCell') as HTMLElement);
    });
    await waitFor(() => expect(screen.getByTestId('wamCaseFlyoutTitle').textContent).toBe('case-2'));
  });

  test('a row checkbox enables the bulk-actions bar', async () => {
    const api = mockApi();
    await renderView(api);
    expect(screen.queryByTestId('wamBulkSetStatus')).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getAllByTestId('wamQueueSelectRow')[0]);
    });
    expect(screen.getByTestId('wamBulkSetStatus')).not.toBeNull();
  });

  test('a page change refetches from the new offset and drops the selection', async () => {
    const api = mockApi();
    await renderView(api);
    await act(async () => {
      fireEvent.click(screen.getAllByTestId('wamQueueSelectRow')[0]);
    });
    expect(screen.getByTestId('wamBulkSetStatus')).not.toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByTestId('pagination-button-1'));
    });
    expect(lastFetch(api)).toMatchObject({ fromOffset: 20, size: 20 });
    expect(screen.queryByTestId('wamBulkSetStatus')).toBeNull();
  });

  test('a sort on a column refetches with that sort field from the first page and is remembered', async () => {
    const api = mockApi();
    await renderView(api);
    await act(async () => {
      fireEvent.click(screen.getByTestId('pagination-button-1'));
    });
    expect(lastFetch(api).fromOffset).toBe(20);
    await sortByHeader('severity');
    await waitFor(() => expect(lastFetch(api)).toMatchObject({ sortField: 'severity', fromOffset: 0 }));
    expect(JSON.parse(window.localStorage.getItem(`${CASE_GRID_STORAGE_KEY}.sort`)!).columnId).toBe('severity');
  });

  test('an unknown stored sort column falls back to Updated instead of an inherited member', async () => {
    window.localStorage.setItem(`${CASE_GRID_STORAGE_KEY}.sort`, JSON.stringify({ columnId: 'toString', direction: 'asc' }));
    const api = mockApi();
    await renderView(api);
    expect(lastFetch(api)).toMatchObject({ sortField: 'updated_at', sortDirection: 'desc' });
    expect(caseSortFieldOf('toString')).toBe('updated_at');
    expect(caseSortFieldOf('constructor')).toBe('updated_at');
  });

  test('the result summary lives in the grid toolbar, so full screen keeps it', async () => {
    const api = mockApi();
    await renderView(api);
    const grid = screen.getByTestId('wamCaseQueueGrid');
    expect(grid.contains(screen.getByTestId('wamCaseResultSummary'))).toBe(true);
  });

  test('a slow earlier fetch cannot overwrite the newest one, nor clear its spinner', async () => {
    // Two overlapping fetches (the Search box commits on every keystroke):
    // the first resolves last and must be ignored outright.
    const deferred: Array<(value: any) => void> = [];
    const page = (title: string) => ({
      cases: [caseRow({ id: 'case-slow', title })],
      total: 1,
      summary: { open: 1, in_progress: 0, closed: 0, total: 1 },
    });
    const api = mockApi({
      fetchCases: jest.fn(() => new Promise((resolve) => deferred.push(resolve))),
    });
    await renderView(api);
    await act(async () => {
      fireEvent.change(screen.getByLabelText('Search cases by title or description'), { target: { value: 'beacon' } });
    });
    expect(deferred.length).toBeGreaterThanOrEqual(2);
    const newest = deferred.pop()!;
    const stale = deferred.shift()!;
    await act(async () => {
      newest(page('newest result'));
    });
    expect(document.body.textContent).toContain('newest result');
    await act(async () => {
      stale(page('stale result'));
    });
    expect(document.body.textContent).toContain('newest result');
    expect(document.body.textContent).not.toContain('stale result');
    // The stale response must not clear a spinner it no longer owns either;
    // the newest one already did, so the grid shows no progress bar.
    expect(screen.queryByTestId('wamQueueGridLoading')).toBeNull();
  });

  test('an empty result shows the queue prompt instead of the grid', async () => {
    const api = mockApi({ fetchCases: jest.fn(async () => ({ cases: [], total: 0, summary: { open: 0, in_progress: 0, closed: 0, total: 0 } })) });
    await renderView(api);
    expect(screen.getByTestId('wamCaseQueueEmpty')).not.toBeNull();
    expect(screen.queryByTestId('wamCaseQueueGrid')).toBeNull();
  });
});
