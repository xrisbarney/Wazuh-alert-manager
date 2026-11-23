/**
 * @jest-environment jsdom
 */
import React from 'react';
import { act, cleanup, configure, fireEvent, render, screen, within } from '@testing-library/react';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  QUEUE_GRID_ROW_HOVER_CLASS,
  QueueGrid,
  QueueGridColumn,
  QueueGridSort,
  densityGridStyle,
  densityRowHeight,
  FLEX_COLUMN_MIN_WIDTH,
  flexibleColumnWidth,
  gridPrefKeys,
  mergeVisibleColumns,
  readGridSort,
} from './queue_grid';

configure({ testIdAttribute: 'data-test-subj' });

interface Row {
  id: string;
  name: string;
  owner: string;
}

const ROWS: Row[] = [
  { id: 'r1', name: 'First record', owner: 'alice' },
  { id: 'r2', name: 'Second record', owner: 'bob' },
];

const COLUMNS: Array<QueueGridColumn<Row>> = [
  { id: 'name', label: 'Name', initialWidth: 200, sortable: true, render: (row) => <span data-test-subj="nameCell">{row.name}</span> },
  { id: 'owner', label: 'Owner', initialWidth: 120, render: (row) => <span data-test-subj="ownerCell">{row.owner}</span> },
  { id: 'hidden', label: 'Hidden one', initialWidth: 100, hiddenByDefault: true, render: (row) => <span>{row.id}</span> },
];

const STORAGE_KEY = 'wam.testGrid';

function renderGrid(overrides: Partial<React.ComponentProps<typeof QueueGrid>> = {}) {
  const onRowClick = jest.fn();
  const onSort = jest.fn();
  const utils = render(
    <QueueGrid<Row>
      ariaLabel="Test queue"
      storageKey={STORAGE_KEY}
      columns={COLUMNS}
      rows={ROWS}
      getRowId={(row) => row.id}
      onRowClick={onRowClick}
      onSort={onSort}
      cellClassName="wamTestCell"
      rowAnchorClassName="wamTestRow"
      rowIdAttribute="data-row-id"
      rowClassName={(row) => `wamTestRow--${row.owner}`}
      data-test-subj="wamTestGrid"
      {...(overrides as any)}
    />
  );
  return { onRowClick, onSort, ...utils };
}

/** Open the grid toolbar's column selector popover (EUI's own subject). */
function openColumnSelector() {
  fireEvent.click(screen.getByTestId('dataGridColumnSelectorButton'));
}

beforeEach(() => {
  window.localStorage.clear();
});

describe('flexibleColumnWidth (step 13.3)', () => {
  const columns: Array<QueueGridColumn<any>> = [
    { id: 'when', label: 'When', initialWidth: 110, render: () => null },
    { id: 'rule', label: 'Rule', render: () => null },
    { id: 'status', label: 'Status', initialWidth: 120, render: () => null },
    // Hidden by default and sized: EUI would subtract this from the leftover.
    { id: 'alertId', label: 'Alert ID', initialWidth: 400, hiddenByDefault: true, render: () => null },
  ];
  const visible = ['when', 'rule', 'status'];

  test('gives the flexible column everything the visible sized columns and the checkbox leave', () => {
    expect(flexibleColumnWidth({ gridWidth: 1000, columns, visibleColumns: visible, widths: {}, hasSelection: true })).toBe(
      1000 - 110 - 120 - 32 - 2
    );
    // The hidden Alert ID column must not be counted.
    expect(flexibleColumnWidth({ gridWidth: 1000, columns, visibleColumns: visible, widths: {}, hasSelection: false })).toBe(
      1000 - 110 - 120 - 2
    );
  });

  test('splits the leftover between several flexible columns and never goes below the floor', () => {
    const two = [...columns, { id: 'note', label: 'Note', render: () => null } as QueueGridColumn<any>];
    expect(
      flexibleColumnWidth({ gridWidth: 1000, columns: two, visibleColumns: [...visible, 'note'], widths: {}, hasSelection: false })
    ).toBe(Math.floor((1000 - 110 - 120 - 2) / 2));
    expect(flexibleColumnWidth({ gridWidth: 300, columns, visibleColumns: visible, widths: {}, hasSelection: true })).toBe(
      FLEX_COLUMN_MIN_WIDTH
    );
  });

  test('a dragged width wins over the flexible share, and an unmeasured or fully sized grid gets nothing', () => {
    expect(
      flexibleColumnWidth({ gridWidth: 1000, columns, visibleColumns: visible, widths: { rule: 300 }, hasSelection: false })
    ).toBeUndefined();
    expect(flexibleColumnWidth({ gridWidth: 0, columns, visibleColumns: visible, widths: {}, hasSelection: false })).toBeUndefined();
    expect(
      flexibleColumnWidth({ gridWidth: 1000, columns, visibleColumns: ['when', 'status'], widths: {}, hasSelection: false })
    ).toBeUndefined();
  });
});

describe('QueueGrid (step 13.1)', () => {
  test('renders one page of rows, marks every cell with the row id and the anchor cell with the row class', () => {
    renderGrid();
    expect(screen.getAllByTestId('nameCell').map((cell) => cell.textContent)).toEqual(['First record', 'Second record']);
    // Every cell of a row carries the row id (the grid renders no row element).
    const cells = document.querySelectorAll('.wamTestCell[data-row-id="r1"]');
    expect(cells.length).toBeGreaterThan(1);
    // Exactly one anchor cell per row, and it carries the row class.
    const anchors = document.querySelectorAll('.wamTestRow');
    expect(anchors.length).toBe(2);
    expect(document.querySelector('.wamTestRow[data-row-id="r1"]')!.className).toContain('wamTestRow--alice');
    // Hidden-by-default columns are not rendered.
    expect(screen.queryByText('Hidden one')).toBeNull();
  });

  test('a cell click opens the record, a click on a control inside it does not', () => {
    const onRowClick = jest.fn();
    render(
      <QueueGrid<Row>
        ariaLabel="Test queue"
        storageKey={STORAGE_KEY}
        columns={[{ id: 'name', label: 'Name', render: (row) => <button type="button">{row.name}</button> }]}
        rows={ROWS}
        getRowId={(row) => row.id}
        onRowClick={onRowClick}
      />
    );
    const cell = document.querySelectorAll('.wamQueueGridCell')[0] as HTMLElement;
    fireEvent.click(cell);
    expect(onRowClick).toHaveBeenCalledWith(ROWS[0]);
    onRowClick.mockClear();
    fireEvent.click(within(cell).getByText('First record'));
    expect(onRowClick).not.toHaveBeenCalled();
  });

  test('the column selector hides a column and the choice is persisted', () => {
    const { unmount } = renderGrid();
    expect(screen.getAllByTestId('ownerCell').length).toBe(2);
    openColumnSelector();
    // The selector lists every column; its switch is named after the column id
    // (the test build renders every generated id as "generated-id", so the
    // name attribute is the stable handle).
    fireEvent.click(document.querySelector('button[role="switch"][name="owner"]')!);
    expect(screen.queryAllByTestId('ownerCell').length).toBe(0);
    expect(JSON.parse(window.localStorage.getItem(gridPrefKeys(STORAGE_KEY).columns)!)).toEqual(['name']);
    // The build's full column list is recorded with the choice, so a later
    // version can tell a new column from one the analyst hid.
    expect(JSON.parse(window.localStorage.getItem(gridPrefKeys(STORAGE_KEY).knownColumns)!)).toEqual(['name', 'owner', 'hidden']);
    unmount();
    // A reload restores the stored set.
    renderGrid();
    expect(screen.queryAllByTestId('ownerCell').length).toBe(0);
  });

  test('the density control persists the pick and feeds the grid style and row height', () => {
    renderGrid();
    fireEvent.click(screen.getByTestId('wamGridDensity'));
    fireEvent.click(screen.getByTestId('wamGridDensity-expanded'));
    expect(window.localStorage.getItem(gridPrefKeys(STORAGE_KEY).density)).toBe('"expanded"');
    expect(densityGridStyle('expanded')).toMatchObject({ fontSize: 'l', cellPadding: 'l' });
    expect(densityGridStyle('compact')).toMatchObject({ fontSize: 's', cellPadding: 's' });
    expect(densityRowHeight('expanded')).toBeGreaterThan(densityRowHeight('compact'));
  });

  test('a resized column width is persisted and applied on the next mount', () => {
    const { unmount } = renderGrid();
    const resizer = document.querySelector('.euiDataGridColumnResizer') as HTMLElement;
    expect(resizer).not.toBeNull();
    // The drag itself is EUI's; the persisted value is the plugin's contract.
    act(() => {
      window.localStorage.setItem(gridPrefKeys(STORAGE_KEY).widths, JSON.stringify({ name: 321 }));
    });
    unmount();
    renderGrid();
    const header = screen.getByText('Name').closest('.euiDataGridHeaderCell') as HTMLElement;
    expect(header.style.width).toBe('321px');
  });

  test('Reset layout clears every stored key and returns to the defaults', () => {
    const keys = gridPrefKeys(STORAGE_KEY);
    window.localStorage.setItem(keys.columns, JSON.stringify(['name']));
    window.localStorage.setItem(keys.widths, JSON.stringify({ name: 321 }));
    window.localStorage.setItem(keys.density, JSON.stringify('expanded'));
    window.localStorage.setItem(keys.sort, JSON.stringify({ columnId: 'name', direction: 'asc' }));
    renderGrid({ sort: null });
    expect(screen.queryAllByTestId('ownerCell').length).toBe(0);
    fireEvent.click(screen.getByTestId('wamGridReset'));
    expect(window.localStorage.getItem(keys.columns)).toBeNull();
    expect(window.localStorage.getItem(keys.knownColumns)).toBeNull();
    expect(window.localStorage.getItem(keys.widths)).toBeNull();
    expect(window.localStorage.getItem(keys.density)).toBeNull();
    expect(window.localStorage.getItem(keys.sort)).toBeNull();
    expect(screen.getAllByTestId('ownerCell').length).toBe(2);
  });

  test('the sort is written through and read back', () => {
    const sort: QueueGridSort = { columnId: 'name', direction: 'asc' };
    renderGrid({ sort });
    expect(readGridSort(STORAGE_KEY)).toEqual(sort);
  });

  test('selection: the header checkbox selects the page and a row checkbox toggles one row', () => {
    const onChange = jest.fn();
    renderGrid({ selection: { selected: [], onChange } });
    fireEvent.click(screen.getAllByTestId('wamQueueSelectRow')[1]);
    expect(onChange).toHaveBeenCalledWith([ROWS[1]]);
    onChange.mockClear();
    fireEvent.click(screen.getByTestId('wamQueueSelectAll'));
    expect(onChange).toHaveBeenCalledWith(ROWS);
  });

  test('selection: an unselectable row has a disabled checkbox, and so does the select-all control', () => {
    const onChange = jest.fn();
    // A bulk update in flight: every row is locked. The header checkbox must
    // not stay live, or one click would commit the empty selectable set and
    // wipe what the analyst had picked.
    renderGrid({ selection: { selected: [ROWS[0]], onChange, selectable: () => false } });
    screen.getAllByTestId('wamQueueSelectRow').forEach((box) => expect((box as HTMLInputElement).disabled).toBe(true));
    expect((screen.getByTestId('wamQueueSelectAll') as HTMLInputElement).disabled).toBe(true);
    // Still live when the rows are selectable.
    cleanup();
    renderGrid({ selection: { selected: [], onChange } });
    expect((screen.getByTestId('wamQueueSelectAll') as HTMLInputElement).disabled).toBe(false);
  });

  test('hovering a cell highlights every cell of that row, and leaving the grid clears it', () => {
    renderGrid();
    const cell = document.querySelector('.wamTestCell[data-row-id="r1"]') as HTMLElement;
    fireEvent.mouseOver(cell);
    const hovered = Array.from(document.querySelectorAll(`.${QUEUE_GRID_ROW_HOVER_CLASS}`));
    // EUI's own `rowHover` cannot do this: the virtualized grid renders no row
    // element, so the whole row is its cells.
    expect(document.querySelectorAll('.euiDataGridRow').length).toBe(0);
    expect(hovered.length).toBeGreaterThan(1);
    expect(hovered.every((el) => el.getAttribute('data-row-id') === 'r1')).toBe(true);
    // Moving to the other row moves the highlight with it.
    fireEvent.mouseOver(document.querySelector('.wamTestCell[data-row-id="r2"]') as HTMLElement);
    expect(Array.from(document.querySelectorAll(`.${QUEUE_GRID_ROW_HOVER_CLASS}`)).every((el) => el.getAttribute('data-row-id') === 'r2')).toBe(true);
    fireEvent.mouseLeave(screen.getByTestId('wamTestGrid'));
    expect(document.querySelectorAll(`.${QUEUE_GRID_ROW_HOVER_CLASS}`).length).toBe(0);
  });

  test('the row-hover class is the one index.scss styles, and no inert EUI rowHover is asked for', () => {
    const scss = readFileSync(join(__dirname, '..', 'index.scss'), 'utf8');
    expect(scss).toContain(`.${QUEUE_GRID_ROW_HOVER_CLASS} {`);
    expect(densityGridStyle('normal').rowHover).toBeUndefined();
  });

  // The grid clips `.euiDataGridRowCell__content*`, so a status cell that
  // wrapped its disposition badge onto a second line would have that badge
  // clipped away inside a compact row (step 13.3).
  test('the status cell does not wrap inside the clipped grid cell', () => {
    const scss = readFileSync(join(__dirname, '..', 'index.scss'), 'utf8');
    const rule = /\.wamStatusCell \{([^}]*)\}/.exec(scss);
    expect(rule).not.toBeNull();
    expect(rule![1]).toMatch(/flex-wrap:\s*nowrap/);
  });

  test('loading shows a progress bar instead of the empty caption', () => {
    const { rerender } = renderGrid({ rows: [], loading: true });
    expect(screen.getByTestId('wamQueueGridLoading')).not.toBeNull();
    expect(screen.queryByText('No rows on this page.')).toBeNull();
    rerender(
      <QueueGrid<Row>
        ariaLabel="Test queue"
        storageKey={STORAGE_KEY}
        columns={COLUMNS}
        rows={[]}
        getRowId={(row) => row.id}
        data-test-subj="wamTestGrid"
      />
    );
    expect(screen.queryByTestId('wamQueueGridLoading')).toBeNull();
    expect(screen.getByText('No rows on this page.')).not.toBeNull();
  });

  test('Reset layout tells the view to reset too, so the live sort cannot outlive the stored one', () => {
    const onReset = jest.fn();
    renderGrid({ onReset, sort: { columnId: 'name', direction: 'asc' } as QueueGridSort });
    expect(window.localStorage.getItem(gridPrefKeys(STORAGE_KEY).sort)).not.toBeNull();
    fireEvent.click(screen.getByTestId('wamGridReset'));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  test('a column added since the analyst last chose columns comes back; one they hid stays hidden', () => {
    const keys = gridPrefKeys(STORAGE_KEY);
    // The analyst hid Owner on a build that had name/owner/hidden.
    window.localStorage.setItem(keys.columns, JSON.stringify(['name']));
    window.localStorage.setItem(keys.knownColumns, JSON.stringify(['name', 'owner', 'hidden']));
    renderGrid({
      columns: [...COLUMNS, { id: 'added', label: 'Added later', initialWidth: 90, render: (row: Row) => <span data-test-subj="addedCell">{row.id}</span> }],
    });
    expect(screen.queryAllByTestId('ownerCell').length).toBe(0);
    expect(screen.getAllByTestId('addedCell').length).toBe(2);
  });

  test('mergeVisibleColumns keeps the stored order, drops unknown ids and splices new defaults in place', () => {
    const columnIds = ['a', 'b', 'c', 'd'];
    const defaultVisible = ['a', 'b', 'c', 'd'];
    // `c` is new (not in knownColumns) -> restored between b and d.
    expect(mergeVisibleColumns(['b', 'a', 'd'], columnIds, defaultVisible, ['a', 'b', 'd'])).toEqual(['b', 'a', 'c', 'd']);
    // `c` was known and hidden on purpose -> stays hidden.
    expect(mergeVisibleColumns(['b', 'a', 'd'], columnIds, defaultVisible, columnIds)).toEqual(['b', 'a', 'd']);
    // Nothing recorded (a selection stored before this key existed) -> no merge.
    expect(mergeVisibleColumns(['b', 'a', 'd'], columnIds, defaultVisible, null)).toEqual(['b', 'a', 'd']);
    // An id this build no longer has is dropped.
    expect(mergeVisibleColumns(['a', 'gone'], columnIds, ['a'], ['a', 'gone'])).toEqual(['a']);
  });

  test('a storage that throws leaves the grid on its defaults', () => {
    const original = Object.getOwnPropertyDescriptor(window, 'localStorage')!;
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: {
        getItem: () => {
          throw new Error('blocked');
        },
        setItem: () => {
          throw new Error('blocked');
        },
        removeItem: () => {
          throw new Error('blocked');
        },
      },
    });
    try {
      renderGrid();
      expect(screen.getAllByTestId('nameCell').length).toBe(2);
      fireEvent.click(screen.getByTestId('wamGridDensity'));
      fireEvent.click(screen.getByTestId('wamGridDensity-normal'));
      expect(screen.getAllByTestId('nameCell').length).toBe(2);
    } finally {
      Object.defineProperty(window, 'localStorage', original);
    }
  });
});
