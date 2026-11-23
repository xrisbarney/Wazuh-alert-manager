import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCheckbox,
  EuiDataGrid,
  EuiDataGridColumn,
  EuiDataGridStyle,
  EuiPopover,
  EuiProgress,
  EuiSpacer,
  EuiText,
  htmlIdGenerator,
} from '@elastic/eui';

/**
 * The shared queue grid (step 13.1): both analyst queues (alerts here, cases
 * in 13.2) render through one `EuiDataGrid` so they behave like the Wazuh
 * Threat Hunting findings table - columns resizable by dragging the header
 * edge, a column selector that shows / hides / reorders them, a density
 * control, full screen, and sorting from the header - and so the choices
 * survive a reload.
 *
 * Deliberate differences from the EUI docs, both verified against the OUI
 * forks actually bundled with the dashboards this plugin targets (1.19.0 on
 * OSD 2.19 / Wazuh 4.x, 1.22.1 on OSD 3.6 / Wazuh 5.0):
 *
 * - the density control is `toolbarVisibility.showStyleSelector`, not
 *   upstream EUI's `showDisplaySelector`, and the bundled control reports no
 *   change back to the caller, so the plugin renders its own density popover
 *   into `additionalControls` and drives `gridStyle` itself. That is what
 *   makes the choice persistable.
 * - the grid is virtualized and renders no row element at all (cells are
 *   absolutely positioned; there is no `<tr>` and no `.euiDataGridRow`), so
 *   a row is identified by an attribute repeated on every one of its cells
 *   (`rowIdAttribute`, `data-alert-id` for alerts) and the row's left
 *   severity border lives on the first visible column's cell
 *   (`rowAnchorClassName`, `wamAlertRow`).
 *
 * Paging stays with the view: the grid is handed one page of rows at a time
 * and its own `pagination` prop is left off, because `EuiDataGridPagination`
 * has no notion of a server-side total.
 */

export type QueueGridDensity = 'compact' | 'normal' | 'expanded';

export const QUEUE_GRID_DENSITIES: ReadonlyArray<QueueGridDensity> = ['compact', 'normal', 'expanded'];

const DENSITY_LABEL: Record<QueueGridDensity, string> = {
  compact: 'Compact',
  normal: 'Normal',
  expanded: 'Expanded',
};

/** `gridStyle` of each density, in the EUI font-size / cell-padding scale. */
export function densityGridStyle(density: QueueGridDensity): EuiDataGridStyle {
  const scale: Record<QueueGridDensity, 's' | 'm' | 'l'> = { compact: 's', normal: 'm', expanded: 'l' };
  // No `rowHover`: the virtualized grid renders no row element for EUI's own
  // `euiDataGrid--rowHoverHighlight` to act on, so the whole-row highlight is
  // the plugin's (`QUEUE_GRID_ROW_HOVER_CLASS`, applied to every cell of the
  // hovered row).
  return { fontSize: scale[density], cellPadding: scale[density], border: 'horizontal', header: 'underline', stripes: false };
}

/**
 * Row height (px) of each density. The queue's primary cells stack a name
 * over a secondary line, so a row needs more than EUI's single-line minimum;
 * the three values keep that two-line stack visible at every density.
 */
export function densityRowHeight(density: QueueGridDensity): number {
  const heights: Record<QueueGridDensity, number> = { compact: 44, normal: 52, expanded: 64 };
  return heights[density];
}

/** Width of the selection control column (`leadingControlColumns`). */
const SELECT_COLUMN_WIDTH = 32;

/** Floor for a flexible column when the leftover width is small. */
export const FLEX_COLUMN_MIN_WIDTH = 180;

/**
 * Class every cell of the hovered row carries. The grid is virtualized and
 * has no row element, so a row-wide hover is one class on each of its cells.
 */
export const QUEUE_GRID_ROW_HOVER_CLASS = 'wamQueueGridCell--rowHover';

/**
 * Width each flexible (unsized) visible column gets so the grid fills its
 * container, or `undefined` while the container is unmeasured or every
 * visible column already has a width. Only the VISIBLE columns count: EUI's
 * own `useDefaultColumnWidth` subtracts the hidden ones' widths too, which is
 * what collapsed the Rule / Title column to its 100px floor (step 13.3).
 */
export function flexibleColumnWidth<T>({
  gridWidth,
  columns,
  visibleColumns,
  widths,
  hasSelection,
}: {
  gridWidth: number;
  columns: Array<QueueGridColumn<T>>;
  visibleColumns: string[];
  widths: Record<string, number>;
  hasSelection: boolean;
}): number | undefined {
  if (!gridWidth) return undefined;
  const shown = new Set(visibleColumns);
  const widthOf = (column: QueueGridColumn<T>) => widths[column.id] ?? column.initialWidth;
  const visible = columns.filter((column) => shown.has(column.id));
  const flexible = visible.filter((column) => widthOf(column) == null);
  if (!flexible.length) return undefined;
  const taken = visible.reduce((total, column) => total + (widthOf(column) || 0), 0) + (hasSelection ? SELECT_COLUMN_WIDTH : 0);
  return Math.max(FLEX_COLUMN_MIN_WIDTH, Math.floor((gridWidth - taken - 2) / flexible.length));
}

export interface QueueGridColumn<T> {
  /** Stable id: the localStorage column order and the sort are keyed on it. */
  id: string;
  /** Header text, and the name shown in the column selector. */
  label: string;
  /** Initial width in px; a column without one absorbs the leftover width. */
  initialWidth?: number;
  sortable?: boolean;
  /** Columns the analyst can add from the column selector but that start hidden. */
  hiddenByDefault?: boolean;
  /** Defaults to true; the actions column pins its width. */
  isResizable?: boolean;
  render: (row: T) => React.ReactNode;
}

export interface QueueGridSort {
  columnId: string;
  direction: 'asc' | 'desc';
}

export interface QueueGridSelection<T> {
  selected: T[];
  onChange: (rows: T[]) => void;
  /** Rows that cannot be selected keep an empty checkbox cell. */
  selectable?: (row: T) => boolean;
  /** aria-label of one row's checkbox. */
  rowLabel?: (row: T) => string;
}

export interface QueueGridProps<T> {
  columns: Array<QueueGridColumn<T>>;
  /** One page of rows; the view keeps the cursor paging. */
  rows: T[];
  getRowId: (row: T) => string;
  /** localStorage prefix, e.g. `wam.alertsGrid`; four keys hang off it. */
  storageKey: string;
  ariaLabel: string;
  sort?: QueueGridSort | null;
  onSort?: (sort: QueueGridSort | null) => void;
  selection?: QueueGridSelection<T>;
  onRowClick?: (row: T) => void;
  /** Extra class for the row's anchor cell (the severity band border). */
  rowClassName?: (row: T) => string | undefined;
  /** Class every cell of every row carries. */
  cellClassName?: string;
  /** Class marking the row's anchor cell (its first visible column). */
  rowAnchorClassName?: string;
  /** Attribute carrying the row id on every cell of the row. */
  rowIdAttribute?: string;
  /** Density used until the analyst picks one. */
  density?: QueueGridDensity;
  /** A fetch is in flight: shows a progress bar and suppresses the empty caption. */
  loading?: boolean;
  /** Called after "Reset layout", so the view can also drop its sort and page. */
  onReset?: () => void;
  /** Rendered directly above the grid (the queue's result summary). */
  toolbar?: React.ReactNode;
  className?: string;
  'data-test-subj'?: string;
}

/** The localStorage keys of one grid. */
export function gridPrefKeys(storageKey: string) {
  return {
    columns: `${storageKey}.columns`,
    // Every column id this build had when the analyst last changed the
    // selection, so a column added in a later version can be told apart from
    // one they deliberately hid (see `mergeVisibleColumns`).
    knownColumns: `${storageKey}.knownColumns`,
    widths: `${storageKey}.widths`,
    density: `${storageKey}.density`,
    sort: `${storageKey}.sort`,
  };
}

function readStored<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw == null) return fallback;
    const parsed = JSON.parse(raw);
    return parsed == null ? fallback : (parsed as T);
  } catch (e) {
    // Private windows, blocked site data, jsdom without storage: the grid
    // simply starts from its defaults.
    return fallback;
  }
}

function writeStored(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    /* preference just isn't remembered */
  }
}

function removeStored(key: string): void {
  try {
    window.localStorage.removeItem(key);
  } catch (e) {
    /* nothing to clear */
  }
}

/** The persisted sort of a grid, so a view can seed its own sort state on mount. */
export function readGridSort(storageKey: string): QueueGridSort | null {
  const stored = readStored<any>(gridPrefKeys(storageKey).sort, null);
  if (!stored || typeof stored.columnId !== 'string') return null;
  if (stored.direction !== 'asc' && stored.direction !== 'desc') return null;
  return { columnId: stored.columnId, direction: stored.direction };
}

/** The persisted density of a grid. */
export function readGridDensity(storageKey: string, fallback: QueueGridDensity = 'compact'): QueueGridDensity {
  const stored = readStored<any>(gridPrefKeys(storageKey).density, null);
  return QUEUE_GRID_DENSITIES.includes(stored) ? (stored as QueueGridDensity) : fallback;
}

export interface GridPrefs {
  visibleColumns: string[];
  /** `known` is every column id of the build doing the write (see `gridPrefKeys`). */
  setVisibleColumns: (ids: string[], known?: string[]) => void;
  /** Column ids stored alongside the visible set, or null when nothing was stored. */
  knownColumns: string[] | null;
  widths: Record<string, number>;
  setColumnWidth: (columnId: string, width: number) => void;
  density: QueueGridDensity;
  setDensity: (density: QueueGridDensity) => void;
  /** Clears every stored key and returns to the defaults. */
  reset: () => void;
  /** Bumped by `reset`, so the grid can be remounted and drop its own widths. */
  resetToken: number;
}

/**
 * Column order / visibility, widths and density of one grid, persisted per
 * browser under `<storageKey>.{columns,widths,density}` (the sort is written
 * by the grid itself, and read back with `readGridSort`). Every access is
 * wrapped, so a browser without usable storage still renders the defaults.
 */
export function useGridPrefs(storageKey: string, defaults: { visibleColumns: string[]; density?: QueueGridDensity }): GridPrefs {
  const keys = useMemo(() => gridPrefKeys(storageKey), [storageKey]);
  const [resetToken, setResetToken] = useState(0);
  const [visibleColumns, setVisible] = useState<string[]>(() => {
    const stored = readStored<string[] | null>(keys.columns, null);
    return Array.isArray(stored) && stored.every((id) => typeof id === 'string') ? stored : defaults.visibleColumns;
  });
  const [knownColumns, setKnownColumns] = useState<string[] | null>(() => {
    const stored = readStored<string[] | null>(keys.knownColumns, null);
    return Array.isArray(stored) && stored.every((id) => typeof id === 'string') ? stored : null;
  });
  const [widths, setWidths] = useState<Record<string, number>>(() => {
    const stored = readStored<Record<string, number> | null>(keys.widths, null);
    if (!stored || typeof stored !== 'object') return {};
    const clean: Record<string, number> = {};
    for (const [id, width] of Object.entries(stored)) if (typeof width === 'number' && width > 0) clean[id] = width;
    return clean;
  });
  const [density, setDensityState] = useState<QueueGridDensity>(() => readGridDensity(storageKey, defaults.density || 'compact'));

  const setVisibleColumns = useCallback(
    (ids: string[], known?: string[]) => {
      setVisible(ids);
      writeStored(keys.columns, ids);
      if (known) {
        setKnownColumns(known);
        writeStored(keys.knownColumns, known);
      }
    },
    [keys.columns, keys.knownColumns]
  );

  const setColumnWidth = useCallback(
    (columnId: string, width: number) => {
      setWidths((previous) => {
        const next = { ...previous, [columnId]: Math.round(width) };
        writeStored(keys.widths, next);
        return next;
      });
    },
    [keys.widths]
  );

  const setDensity = useCallback(
    (next: QueueGridDensity) => {
      setDensityState(next);
      writeStored(keys.density, next);
    },
    [keys.density]
  );

  const reset = useCallback(() => {
    removeStored(keys.columns);
    removeStored(keys.knownColumns);
    removeStored(keys.widths);
    removeStored(keys.density);
    // The stored sort goes too; the view is told through `onReset` so the
    // queue's live sort returns to its default with it, instead of storage
    // and the grid drifting apart until the next reload.
    removeStored(keys.sort);
    setVisible(defaults.visibleColumns);
    setKnownColumns(null);
    setWidths({});
    setDensityState(defaults.density || 'compact');
    setResetToken((token) => token + 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys.columns, keys.knownColumns, keys.widths, keys.density, keys.sort, defaults.visibleColumns.join(','), defaults.density]);

  return { visibleColumns, setVisibleColumns, knownColumns, widths, setColumnWidth, density, setDensity, reset, resetToken };
}

/**
 * The columns a grid shows, given what the analyst stored and what this build
 * has. Stored ids this build no longer has are dropped. A default-visible id
 * the stored order does not mention is restored only when the build that
 * wrote the selection did not have it either (`knownColumns`), so a column
 * the analyst deliberately hid stays hidden while a column added in a later
 * plugin version still appears - at its place in the column order.
 */
export function mergeVisibleColumns(stored: string[], columnIds: string[], defaultVisible: string[], knownColumns: string[] | null): string[] {
  const merged = stored.filter((id) => columnIds.includes(id));
  const isNew = (id: string) => knownColumns != null && !knownColumns.includes(id);
  for (const id of defaultVisible) {
    if (merged.includes(id) || !isNew(id)) continue;
    const order = columnIds.indexOf(id);
    let at = merged.length;
    for (let i = 0; i < merged.length; i++) {
      if (columnIds.indexOf(merged[i]) > order) {
        at = i;
        break;
      }
    }
    merged.splice(at, 0, id);
  }
  return merged;
}

/**
 * True when a click landed on a control inside the cell (a badge, a link, a
 * checkbox) rather than on the cell itself, so the row click must not also
 * open the record.
 */
export function isInteractiveCellTarget(target: EventTarget | null, currentTarget: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement) || target === currentTarget) return false;
  return Boolean(target.closest('button, a, input, select, textarea, label, [role="button"], [role="link"], [role="checkbox"], [role="option"]'));
}

interface DensityControlProps {
  density: QueueGridDensity;
  onChange: (density: QueueGridDensity) => void;
  idPrefix: string;
}

/**
 * The density control. EUI's own `showStyleSelector` button reports nothing
 * back, so the plugin owns this one and the choice can be persisted.
 */
const DensityControl: React.FC<DensityControlProps> = ({ density, onChange, idPrefix }) => {
  const [open, setOpen] = useState(false);
  return (
    <EuiPopover
      panelPaddingSize="s"
      isOpen={open}
      closePopover={() => setOpen(false)}
      button={
        <EuiButtonEmpty
          size="xs"
          iconType="tableDensityNormal"
          color="text"
          className="wamGridToolbarButton"
          data-test-subj="wamGridDensity"
          onClick={() => setOpen((isOpen) => !isOpen)}
        >
          Density
        </EuiButtonEmpty>
      }
    >
      <EuiButtonGroup
        legend="Row density"
        buttonSize="compressed"
        options={QUEUE_GRID_DENSITIES.map((value) => ({
          id: `${idPrefix}-${value}`,
          label: DENSITY_LABEL[value],
          'data-test-subj': `wamGridDensity-${value}`,
        }))}
        idSelected={`${idPrefix}-${density}`}
        onChange={(id: string) => {
          const picked = QUEUE_GRID_DENSITIES.find((value) => id === `${idPrefix}-${value}`);
          if (picked) onChange(picked);
        }}
      />
    </EuiPopover>
  );
};

export function QueueGrid<T>({
  columns,
  rows,
  getRowId,
  storageKey,
  ariaLabel,
  sort,
  onSort,
  selection,
  onRowClick,
  rowClassName,
  cellClassName,
  rowAnchorClassName,
  rowIdAttribute = 'data-row-id',
  density: defaultDensity = 'compact',
  loading,
  onReset,
  toolbar,
  className,
  'data-test-subj': testSubj,
}: QueueGridProps<T>): React.ReactElement {
  const columnIds = useMemo(() => columns.map((column) => column.id), [columns]);
  const defaultVisible = useMemo(
    () => columns.filter((column) => !column.hiddenByDefault).map((column) => column.id),
    [columns]
  );
  const prefs = useGridPrefs(storageKey, { visibleColumns: defaultVisible, density: defaultDensity });
  const idPrefix = useMemo(() => htmlIdGenerator('wamQueueGrid')(), []);

  // A stored order can name a column this build no longer has (or miss one it
  // gained); keep what still exists, never show an unknown id, and add back a
  // default-visible column this build gained since the selection was stored.
  const visibleColumns = useMemo(
    () => mergeVisibleColumns(prefs.visibleColumns, columnIds, defaultVisible, prefs.knownColumns),
    [prefs.visibleColumns, columnIds, defaultVisible, prefs.knownColumns]
  );

  // The write records this build's full column list beside the selection, so
  // a later version can tell a new column from a hidden one.
  const setVisibleColumns = useCallback(
    (ids: string[]) => prefs.setVisibleColumns(ids, columnIds),
    [prefs.setVisibleColumns, columnIds]
  );

  useEffect(() => {
    if (sort) writeStored(gridPrefKeys(storageKey).sort, sort);
    else removeStored(gridPrefKeys(storageKey).sort);
  }, [storageKey, sort?.columnId, sort?.direction]);

  // Measured width of the wrapper. EUI only sizes the columns that carry no
  // `initialWidth`, and it does that from `gridWidth - every column's defined
  // width`, counting the HIDDEN ones too; on these queues that leftover came
  // out at EUI's 100px floor, so the flexible column (Rule / Title) collapsed
  // and the grid stopped well short of the page. The plugin therefore sizes
  // the flexible columns itself from the container width (step 13.3).
  const [gridWidth, setGridWidth] = useState(0);

  const flexColumnWidth = useMemo(
    () => flexibleColumnWidth({ gridWidth, columns, visibleColumns, widths: prefs.widths, hasSelection: Boolean(selection) }),
    [gridWidth, columns, visibleColumns, prefs.widths, Boolean(selection)]
  );

  const gridColumns: EuiDataGridColumn[] = useMemo(
    () =>
      columns.map((column) => ({
        id: column.id,
        displayAsText: column.label,
        initialWidth: prefs.widths[column.id] ?? column.initialWidth ?? flexColumnWidth,
        isSortable: Boolean(column.sortable),
        isResizable: column.isResizable !== false,
        // No cell popover: queue cells are badges and links, and the expand
        // button would sit on top of them.
        isExpandable: false,
      })),
    // Re-derived whenever the caller's column array changes identity (so the
    // caller must memoize it) and whenever a reset remounts the grid; the
    // stored widths are read here, and a later drag is EUI's own state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [columns, prefs.resetToken, flexColumnWidth]
  );

  // Whole-row hover (the grid has no row element, and EUI's own
  // `rowHover: 'highlight'` is therefore inert). The class is toggled on the
  // DOM rather than held in state on purpose: a hovered-row state would
  // change `renderCellValue`'s identity, and EUI renders that callback as a
  // component type, so every cell of the page would unmount and remount on
  // each mouse move. `reapplyRowHover` runs after every render, because a
  // re-render rewrites the cell classNames from `cellPropsOf`.
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const hoveredRowIdRef = useRef<string | null>(null);

  const applyRowHover = useCallback(
    (rowId: string | null) => {
      hoveredRowIdRef.current = rowId;
      const root = wrapperRef.current;
      if (!root) return;
      Array.from(root.querySelectorAll(`[${rowIdAttribute}]`)).forEach((cell) => {
        cell.classList.toggle(QUEUE_GRID_ROW_HOVER_CLASS, rowId != null && cell.getAttribute(rowIdAttribute) === rowId);
      });
    },
    [rowIdAttribute]
  );

  useEffect(() => {
    if (hoveredRowIdRef.current) applyRowHover(hoveredRowIdRef.current);
  });

  // Measured from the `.euiDataGrid` element rather than the wrapper, because
  // EUI's full-screen button gives that element `position: fixed` with all
  // four insets at 0: it is then viewport-wide while the wrapper keeps its
  // panel width, and measuring the wrapper would leave the flexible column
  // panel-sized in full screen - the very gap step 13.3 closed. The grid
  // element is a block at 100% of the wrapper otherwise, and its own width
  // never depends on the column widths (only `.euiDataGrid__content` does),
  // so observing it cannot feed back into itself.
  useEffect(() => {
    const node = wrapperRef.current;
    if (!node) return undefined;
    // Re-resolved on every measure: the grid child mounts after the first
    // paint, and full screen re-renders it.
    const measure = () => setGridWidth((node.querySelector('.euiDataGrid') ?? node).clientWidth);
    measure();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    const grid = node.querySelector('.euiDataGrid');
    if (grid) observer.observe(grid);
    return () => observer.disconnect();
  }, []);

  const anchorColumnId = visibleColumns[0];
  const selectedIds = useMemo(
    () => new Set((selection?.selected || []).map((row) => getRowId(row))),
    [selection?.selected, getRowId]
  );

  const cellPropsOf = useCallback(
    (row: T, columnId: string) => {
      const classes = [cellClassName];
      if (rowAnchorClassName && columnId === anchorColumnId) {
        classes.push(rowAnchorClassName);
        const extra = rowClassName?.(row);
        if (extra) classes.push(extra);
      }
      return {
        className: classes.filter(Boolean).join(' '),
        [rowIdAttribute]: getRowId(row),
      } as any;
    },
    [cellClassName, rowAnchorClassName, anchorColumnId, rowClassName, rowIdAttribute, getRowId]
  );

  const renderCellValue = useCallback(
    ({ rowIndex, columnId, setCellProps }: { rowIndex: number; columnId: string; setCellProps: (props: any) => void }) => {
      const row = rows[rowIndex];
      const column = columns.find((candidate) => candidate.id === columnId);
      // eslint-disable-next-line react-hooks/rules-of-hooks
      useEffect(() => {
        if (row) setCellProps(cellPropsOf(row, columnId));
      }, [row, columnId]);
      if (!row || !column) return null;
      return (
        <div
          className="wamQueueGridCell"
          onClick={
            onRowClick
              ? (event: React.MouseEvent) => {
                  if (!isInteractiveCellTarget(event.target, event.currentTarget)) onRowClick(row);
                }
              : undefined
          }
        >
          {column.render(row)}
        </div>
      );
    },
    [rows, columns, cellPropsOf, onRowClick]
  );

  const leadingControlColumns = useMemo(() => {
    if (!selection) return undefined;
    const selectableRows = rows.filter((row) => (selection.selectable ? selection.selectable(row) : true));
    const allSelected = selectableRows.length > 0 && selectableRows.every((row) => selectedIds.has(getRowId(row)));
    return [
      {
        id: 'wamQueueSelect',
        width: 32,
        headerCellRender: () => (
          <EuiCheckbox
            id={`${idPrefix}-selectAll`}
            aria-label="Select all rows on this page"
            data-test-subj="wamQueueSelectAll"
            checked={allSelected}
            // Follows the same `selectable` predicate as the row checkboxes:
            // while every row is locked (a bulk update in flight) the header
            // control must not be clickable either, or one click would set the
            // selection to the empty `selectableRows` and wipe what the
            // analyst had picked.
            disabled={rows.length > 0 && selectableRows.length === 0}
            onChange={() => selection.onChange(allSelected ? [] : selectableRows)}
          />
        ),
        rowCellRender: ({ rowIndex, setCellProps }: { rowIndex: number; setCellProps: (props: any) => void }) => {
          const row = rows[rowIndex];
          // eslint-disable-next-line react-hooks/rules-of-hooks
          useEffect(() => {
            if (row) setCellProps(cellPropsOf(row, 'wamQueueSelect'));
          }, [row]);
          if (!row) return null;
          const id = getRowId(row);
          const disabled = selection.selectable ? !selection.selectable(row) : false;
          return (
            <EuiCheckbox
              id={`${idPrefix}-select-${id}`}
              aria-label={selection.rowLabel ? selection.rowLabel(row) : `Select row ${id}`}
              data-test-subj="wamQueueSelectRow"
              disabled={disabled}
              checked={selectedIds.has(id)}
              onChange={() =>
                selection.onChange(
                  selectedIds.has(id)
                    ? selection.selected.filter((candidate) => getRowId(candidate) !== id)
                    : [...selection.selected, row]
                )
              }
            />
          );
        },
      },
    ];
  }, [selection, rows, selectedIds, getRowId, idPrefix, cellPropsOf]);

  const sorting = onSort
    ? {
        columns: sort && columnIds.includes(sort.columnId) ? [{ id: sort.columnId, direction: sort.direction }] : [],
        onSort: (next: Array<{ id: string; direction: 'asc' | 'desc' }>) => {
          // The queue sorts on one column at a time (the route takes one
          // sort field); the last entry EUI reports is the one just picked.
          const picked = next[next.length - 1];
          onSort(picked ? { columnId: picked.id, direction: picked.direction } : null);
        },
      }
    : undefined;

  return (
    <div
      className={['wamQueueGridWrapper', className].filter(Boolean).join(' ')}
      data-test-subj={testSubj}
      ref={wrapperRef}
      onMouseOver={(event: React.MouseEvent) => {
        const target = event.target as HTMLElement | null;
        const cell = target && typeof target.closest === 'function' ? target.closest(`[${rowIdAttribute}]`) : null;
        const rowId = cell ? cell.getAttribute(rowIdAttribute) : null;
        if (rowId !== hoveredRowIdRef.current) applyRowHover(rowId);
      }}
      onMouseLeave={() => applyRowHover(null)}
    >
      {toolbar}
      {toolbar ? <EuiSpacer size="s" /> : null}
      {loading ? <EuiProgress size="xs" color="accent" data-test-subj="wamQueueGridLoading" /> : null}
      <EuiDataGrid
        key={`${storageKey}-${prefs.resetToken}`}
        aria-label={ariaLabel}
        className="wamQueueGrid"
        columns={gridColumns}
        columnVisibility={{ visibleColumns, setVisibleColumns }}
        leadingControlColumns={leadingControlColumns}
        rowCount={rows.length}
        renderCellValue={renderCellValue}
        gridStyle={densityGridStyle(prefs.density)}
        rowHeightsOptions={{ defaultHeight: densityRowHeight(prefs.density) }}
        onColumnResize={({ columnId, width }) => prefs.setColumnWidth(columnId, width)}
        toolbarVisibility={{
          showColumnSelector: { allowHide: true, allowReorder: true },
          // EUI's own density button cannot report its choice back, so the
          // plugin renders its own below and keeps EUI's off.
          showStyleSelector: false,
          showSortSelector: Boolean(onSort),
          showFullScreenSelector: true,
          additionalControls: (
            <>
              <DensityControl density={prefs.density} onChange={prefs.setDensity} idPrefix={idPrefix} />
              <EuiButtonEmpty
                size="xs"
                color="text"
                iconType="refresh"
                className="wamGridToolbarButton"
                data-test-subj="wamGridReset"
                onClick={() => {
                  prefs.reset();
                  // The sort lives in the view; the reset drops it there too,
                  // so the queue's order matches the layout it just restored.
                  onReset?.();
                }}
              >
                Reset layout
              </EuiButtonEmpty>
            </>
          ),
        }}
        sorting={sorting}
      />
      {rows.length === 0 && !loading ? (
        <EuiText size="s" color="subdued" className="wamQueueGridEmptyRow">
          No rows on this page.
        </EuiText>
      ) : null}
    </div>
  );
}
