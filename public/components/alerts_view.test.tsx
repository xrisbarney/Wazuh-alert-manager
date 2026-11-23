/**
 * @jest-environment jsdom
 */
import React from 'react';
import { act, configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Alert } from '../../common';
import { ALERT_GRID_STORAGE_KEY, ALERT_SORT_FIELDS, AlertsView, DEFAULT_ALERT_SORT, buildAlertQueueColumns, alertSortFieldOf } from './alerts_view';
import { QueueGrid, QueueGridSort } from './queue_grid';
import { QUEUE_COLUMN_WIDTH } from './queue_chrome';

configure({ testIdAttribute: 'data-test-subj' });

const LONG_TITLE = 'Credential stuffing against the customer portal from a rotating residential proxy pool'; // 80+ chars
const NOW = Date.parse('2026-11-21T10:00:00.000Z');

function alert(overrides: Partial<Alert['_source']> = {}, id = 'alert-1'): Alert {
  return {
    _id: id,
    _source: {
      '@timestamp': new Date(NOW - 6 * 60000).toISOString(),
      agent: { name: 'web-01', ip: '10.0.0.5' },
      manager: { name: 'wazuh-manager' },
      rule: { id: '5710', description: 'sshd: attempt to login using a non-existent user', level: 5 },
      status: 'open',
      ...overrides,
    } as Alert['_source'],
  } as Alert;
}

function renderQueue(
  items: Alert[],
  caseTitles: Record<string, string> = {},
  extra: { selected?: Alert[]; onSelectionChange?: (rows: Alert[]) => void; sort?: QueueGridSort } = {}
) {
  const openAlertById = jest.fn();
  const onOpenCase = jest.fn();
  const onSort = jest.fn();
  render(
    <QueueGrid<Alert>
      className="wamQueueTable wamAlertTable"
      data-test-subj="wamAlertQueueGrid"
      ariaLabel="Alert queue"
      storageKey={ALERT_GRID_STORAGE_KEY}
      columns={buildAlertQueueColumns({ caseTitles, now: NOW, openAlertById, onOpenCase })}
      rows={items}
      getRowId={(a) => a._id}
      sort={extra.sort ?? DEFAULT_ALERT_SORT}
      onSort={onSort}
      onRowClick={(a) => openAlertById(a._id)}
      cellClassName="wamAlertCell wamClickableRow"
      rowAnchorClassName="wamAlertRow"
      rowIdAttribute="data-alert-id"
      rowClassName={(a) => `wamAlertRow--${(a._source.rule?.level ?? 0) >= 12 ? 'critical' : (a._source.rule?.level ?? 0) >= 7 ? 'high' : (a._source.rule?.level ?? 0) >= 4 ? 'medium' : 'low'}`}
      selection={{ selected: extra.selected ?? [], onChange: extra.onSelectionChange ?? (() => undefined) }}
    />
  );
  return { openAlertById, onOpenCase, onSort };
}

const headerWidth = (name: string) =>
  (Array.from(document.querySelectorAll('.euiDataGridHeaderCell')).find((cell) => cell.textContent?.trim().startsWith(name)) as HTMLElement).style.width;

beforeEach(() => {
  window.localStorage.clear();
});

describe('buildAlertQueueColumns on the shared queue grid (step 13.1)', () => {
  test('the default columns are today\'s queue at the shared widths, with Rule the column that grows', () => {
    renderQueue([alert()]);
    expect(headerWidth('When')).toBe(QUEUE_COLUMN_WIDTH.timestamp);
    expect(headerWidth('Agent / IP')).toBe(QUEUE_COLUMN_WIDTH.agent);
    expect(headerWidth('Severity')).toBe(QUEUE_COLUMN_WIDTH.severity);
    expect(headerWidth('Status')).toBe(QUEUE_COLUMN_WIDTH.status);
    expect(headerWidth('Due')).toBe(QUEUE_COLUMN_WIDTH.due);
    expect(headerWidth('Assigned to')).toBe(QUEUE_COLUMN_WIDTH.assigned);
    expect(headerWidth('Case')).toBe(QUEUE_COLUMN_WIDTH.caseLink);
    expect(headerWidth('Actions')).toBe(QUEUE_COLUMN_WIDTH.actions);
    // Manager, Alert ID and Agent IP start hidden; they are selectable.
    const headers = Array.from(document.querySelectorAll('.euiDataGridHeaderCell')).map((cell) => cell.textContent?.trim());
    expect(headers.some((text) => text?.startsWith('Manager'))).toBe(false);
    expect(headers.some((text) => text?.startsWith('Alert ID'))).toBe(false);
    expect(headers.some((text) => text?.startsWith('Agent IP'))).toBe(false);
    expect(buildAlertQueueColumns({ caseTitles: {}, now: NOW, openAlertById: jest.fn(), onOpenCase: jest.fn() })
      .filter((column) => column.hiddenByDefault)
      .map((column) => column.id)).toEqual(['manager', 'alertId', 'agentIp']);
  });

  test('every cell of a row carries the alert id and the first visible column carries the severity band', () => {
    renderQueue([alert({ rule: { id: '1', description: 'critical thing', level: 13 } }, 'a1')]);
    expect(document.querySelectorAll('.wamAlertCell[data-alert-id="a1"]').length).toBeGreaterThan(1);
    const anchor = document.querySelector('.wamAlertRow[data-alert-id="a1"]')!;
    expect(anchor.className).toContain('wamAlertRow--critical');
    expect(document.querySelectorAll('.wamAlertRow').length).toBe(1);
  });

  test('the rule cell shows the description, the rule id and a stored enrichment verdict', () => {
    renderQueue([alert({ enrichment: { worst_verdict: 'malicious', items: [{}, {}] } as any })]);
    expect(screen.getByTestId('wamEnrichmentQueueBadge').textContent).toBe('malicious');
    expect(document.body.textContent).toContain('sshd: attempt to login using a non-existent user');
    expect(document.body.textContent).toContain('Rule 5710');
  });

  test('When shows the relative age and keeps the absolute value for the tooltip', () => {
    renderQueue([alert()]);
    const when = document.querySelector('.wamQueueTimestamp')!;
    expect(when.textContent).toMatch(/ago$/);
    expect(when.closest('.euiToolTipAnchor')).not.toBeNull();
  });

  test('the linked-case badge is inside a flex-column cell, keeps the full title and opens the case', () => {
    const { onOpenCase } = renderQueue([alert({ case_id: 'case-abcdef12' })], { 'case-abcdef12': LONG_TITLE });
    const badge = screen.getByTestId('wamAlertCaseBadge');
    expect(badge.textContent).toBe(LONG_TITLE);
    expect(badge.getAttribute('title')).toBe(LONG_TITLE);
    expect(badge.className).toContain('wamCaseCell__badge');
    expect(badge.closest('.wamCaseCell')!.tagName).toBe('DIV');
    fireEvent.click(badge);
    expect(onOpenCase).toHaveBeenCalledWith('case-abcdef12');
  });

  test('without a resolved title the badge shows the id prefix; without a case the cell shows a dash', () => {
    renderQueue([alert({ case_id: 'case-abcdef12' }, 'a1'), alert({}, 'a2')]);
    const badge = screen.getByTestId('wamAlertCaseBadge');
    expect(badge.textContent).toBe('case-abc');
    expect(badge.getAttribute('title')).toBe('case-abcdef12');
    const cells = Array.from(document.querySelectorAll('.wamCaseCell'));
    expect(cells.length).toBe(2);
    expect(cells[1].textContent).toBe('—');
  });

  test('the Actions column renders the expand button with its subject and label, and it opens the alert', () => {
    const { openAlertById } = renderQueue([alert()]);
    const expand = screen.getByTestId('wamAlertExpand');
    expect(expand.getAttribute('aria-label')).toBe('Open details for sshd: attempt to login using a non-existent user');
    fireEvent.click(expand);
    expect(openAlertById).toHaveBeenCalledWith('alert-1');
  });

  test('a click on the row opens the flyout', () => {
    const { openAlertById } = renderQueue([alert()]);
    const anchor = document.querySelector('.wamAlertRow[data-alert-id="alert-1"] .wamQueueGridCell') as HTMLElement;
    fireEvent.click(anchor);
    expect(openAlertById).toHaveBeenCalledWith('alert-1');
  });

  test('the row checkbox drives the selection the bulk-actions bar reads', () => {
    const onSelectionChange = jest.fn();
    const rows = [alert({}, 'a1'), alert({}, 'a2')];
    renderQueue(rows, {}, { onSelectionChange });
    fireEvent.click(screen.getAllByTestId('wamQueueSelectRow')[0]);
    expect(onSelectionChange).toHaveBeenCalledWith([rows[0]]);
  });

  test('the hidden columns render their values once selected', () => {
    window.localStorage.setItem(`${ALERT_GRID_STORAGE_KEY}.columns`, JSON.stringify(['manager', 'alertId', 'agentIp']));
    renderQueue([alert()]);
    expect(screen.getByTestId('wamAlertManager').textContent).toBe('wazuh-manager');
    expect(screen.getByTestId('wamAlertIdCell').textContent).toBe('alert-1');
    expect(screen.getByTestId('wamAlertAgentIp').textContent).toBe('10.0.0.5');
  });

  test('every sortable column maps to a sort field the alerts route takes', () => {
    const columns = buildAlertQueueColumns({ caseTitles: {}, now: NOW, openAlertById: jest.fn(), onOpenCase: jest.fn() });
    const sortable = columns.filter((column) => column.sortable).map((column) => column.id);
    expect(sortable).toEqual(['timestamp', 'severity', 'due']);
    for (const id of sortable) expect(typeof ALERT_SORT_FIELDS[id]).toBe('string');
    expect(ALERT_SORT_FIELDS[DEFAULT_ALERT_SORT.columnId]).toBe('@timestamp');
  });
});


/**
 * The view itself (step 13.1): the wiring between `AlertsView` and the shared
 * grid - the page it renders, the flyout a cell click opens, the selection the
 * bulk bar reads, and the refetches a sort or a page change trigger.
 */
function mockApi(overrides: Record<string, any> = {}) {
  const base: Record<string, any> = {
    fetchAlerts: jest.fn(async () => ({ hits: { hits: [alert({}, 'a1'), alert({ rule: { id: '5712', description: 'brute force', level: 10 } }, 'a2')], total: { value: 42 } } })),
    fetchAlertCounts: jest.fn(async () => ({ open: 2, in_progress: 0, closed: 0, total: 2 })),
    fetchFilterOptions: jest.fn(async () => ({ ruleIds: [], agents: [], alertTypes: [], assignees: [], levelRange: { min: 0, max: 15 } })),
    fetchAlert: jest.fn(async (id: string) => alert({}, id)),
    fetchUsers: jest.fn(async () => []),
    // The flyout's own panels are not under test here; the ones that need a
    // shaped answer get one, the rest fall through to the proxy below.
    fetchAssetContext: jest.fn(async () => {
      throw new Error('asset context not available in this test');
    }),
    fetchAlertSiblingVerdicts: jest.fn(async () => ({ siblings: [] })),
    appUrl: (path: string) => path,
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
  const onOpenCase = jest.fn();
  const onToast = jest.fn();
  await act(async () => {
    render(<AlertsView apiService={api} onToast={onToast} onOpenCase={onOpenCase} />);
  });
  return { onOpenCase, onToast };
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

/** The `sortField` / `from` of the most recent fetchAlerts call. */
const lastFetch = (api: any) => {
  const calls = api.fetchAlerts.mock.calls;
  return calls[calls.length - 1][1];
};

describe('AlertsView wiring (step 13.1)', () => {
  test('renders the fetched page through the grid', async () => {
    const api = mockApi();
    await renderView(api);
    expect(screen.getByTestId('wamAlertQueueGrid')).not.toBeNull();
    expect(document.querySelectorAll('.wamAlertRow').length).toBe(2);
    expect(document.body.textContent).toContain('brute force');
    expect(lastFetch(api)).toMatchObject({ from: 0, size: 20, sortField: '@timestamp', sortDirection: 'desc' });
  });

  test('a cell click opens the alert flyout', async () => {
    const api = mockApi();
    await renderView(api);
    await act(async () => {
      fireEvent.click(document.querySelector('.wamAlertRow[data-alert-id="a1"] .wamQueueGridCell') as HTMLElement);
    });
    expect(api.fetchAlert).toHaveBeenCalledWith('a1');
    await waitFor(() => expect(screen.queryByTestId('wamAlertFlyoutTitle')).not.toBeNull());
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
    expect(lastFetch(api)).toMatchObject({ from: 20, size: 20 });
    expect(screen.queryByTestId('wamBulkSetStatus')).toBeNull();
  });

  test('a sort on a column refetches with that sort field from the first page', async () => {
    const api = mockApi();
    await renderView(api);
    await act(async () => {
      fireEvent.click(screen.getByTestId('pagination-button-1'));
    });
    expect(lastFetch(api).from).toBe(20);
    await sortByHeader('severity');
    await waitFor(() => expect(lastFetch(api)).toMatchObject({ sortField: 'rule.level', from: 0 }));
    // The pick is remembered for the next visit.
    expect(JSON.parse(window.localStorage.getItem(`${ALERT_GRID_STORAGE_KEY}.sort`)!).columnId).toBe('severity');
  });

  test('an unknown stored sort column falls back to the timestamp instead of an inherited member', async () => {
    window.localStorage.setItem(`${ALERT_GRID_STORAGE_KEY}.sort`, JSON.stringify({ columnId: 'toString', direction: 'asc' }));
    const api = mockApi();
    await renderView(api);
    expect(lastFetch(api)).toMatchObject({ sortField: '@timestamp', sortDirection: 'desc' });
    expect(alertSortFieldOf('toString')).toBe('@timestamp');
    expect(alertSortFieldOf('constructor')).toBe('@timestamp');
  });

  test('a first fetch still in flight reads as loading, not as an empty queue', async () => {
    let release: (value: any) => void = () => undefined;
    const api = mockApi({ fetchAlerts: jest.fn(() => new Promise((resolve) => { release = resolve; })) });
    render(<AlertsView apiService={api} onToast={jest.fn()} onOpenCase={jest.fn()} />);
    expect(screen.queryByTestId('wamAlertQueueEmpty')).toBeNull();
    expect(document.querySelector('.euiLoadingContent')).not.toBeNull();
    await act(async () => {
      release({ hits: { hits: [], total: { value: 0 } } });
    });
    expect(screen.getByTestId('wamAlertQueueEmpty')).not.toBeNull();
  });
});
