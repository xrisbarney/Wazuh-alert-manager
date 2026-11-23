import { useTerminology } from '../terminology';
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiComboBox,
  EuiFieldSearch,
  EuiButton,
  EuiFormRow,
  EuiSuperDatePicker,
  EuiText,
  EuiButtonIcon,
  EuiPanel,
  EuiTitle,
  EuiButtonEmpty,
  EuiLink,
  EuiFilterGroup,
  EuiFilterButton,
  EuiTablePagination,
} from '@elastic/eui';
import { Case, CaseSeverity, CaseStatus, SlaState, DISPOSITIONS, DISPOSITION_LABELS } from '../../common';
import type { Disposition } from '../../common';
import { AlertsApiService, CaseListSortField, downloadBlob } from '../services/api';
import { SlaDue, useNowTicker } from './sla_due';
import { SLA_QUICK_FILTERS } from './filter_bar';
import { StatusBadge, CaseSeverityBadge, DispositionBadge } from './status_badge';
import { formatAbsolute, statusLabel } from '../design';
import { CaseFlyout } from './case_flyout';
import { BulkActionsBar } from './bulk_actions_bar';
import { CaseTasksChip } from './case_tasks_tab';
import { QUEUE_COLUMN_WIDTH, QueueEmptyPrompt, QueueResultSummary, QueueStats, QueueTimestamp } from './queue_chrome';
import { QueueGrid, QueueGridColumn, QueueGridSort, readGridSort } from './queue_grid';

const CASE_RESULT_WINDOW = 10000;

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  openCaseId?: string;
  onOpenAlert: (alertId: string) => void;
  onCaseFlyoutClosed: () => void;
}

export interface CaseQueueColumnOptions {
  /** Header of the linked-record count column (terminology: "Alerts" / "Findings"). */
  unitsLabel: string;
  /** Minute ticker the Due countdown renders against. */
  now: number;
  navigateToCase: (event: React.MouseEvent, caseId: string) => void;
}

/** localStorage prefix of the case queue's grid preferences (step 13.2). */
export const CASE_GRID_STORAGE_KEY = 'wam.casesGrid';

/**
 * Grid column id -> the sort field the cases route takes. Only the columns
 * flagged `sortable` appear here; anything else falls back to Updated.
 */
export const CASE_SORT_FIELDS: Record<string, CaseListSortField> = {
  title: 'title',
  severity: 'severity',
  status: 'status',
  due: 'sla_due_at',
  assigned: 'assigned_to',
  updated: 'updated_at',
  createdBy: 'created_by',
};

/** True for a column id the cases route can actually sort on. */
export function isCaseSortColumn(columnId: unknown): columnId is string {
  return typeof columnId === 'string' && Object.prototype.hasOwnProperty.call(CASE_SORT_FIELDS, columnId);
}

/**
 * The sort field of a grid column id. A plain `CASE_SORT_FIELDS[id]` walks
 * the prototype chain, and the column id comes back from localStorage as any
 * string - `toString` would resolve to an inherited function and send a
 * non-field value to the route.
 */
export function caseSortFieldOf(columnId: string): CaseListSortField {
  return isCaseSortColumn(columnId) ? CASE_SORT_FIELDS[columnId] : CASE_SORT_FIELDS.updated;
}

export const DEFAULT_CASE_SORT: QueueGridSort = { columnId: 'updated', direction: 'desc' };

/** Pixel value of one of the shared queue widths ('110px' -> 110). */
const px = (width: string): number => parseInt(width, 10);

/**
 * The case queue columns (step 13.2, on the shared queue grid of 13.1 in
 * place of the EuiBasicTable columns of 10.2). Title has no width and is the
 * one growing column; every other column starts at one of the shared fixed
 * widths (`QUEUE_COLUMN_WIDTH`), and from there every width is the analyst's:
 * the grid remembers what they drag, which columns they show and in what
 * order.
 *
 * Case ID and Created by start hidden and are added from the column selector
 * (the case overview and the CSV export carry both values either way - the
 * export's `created_by` column exists for exactly this reason);
 * Created and Updated stay one "Updated" column - the relative age of the
 * last change, with both absolute timestamps in its tooltip.
 *
 * Each cell takes the whole case record: `EuiBasicTable`'s `field`
 * indirection (and the `__row_identity` scalar that worked around its stale
 * row rendering) is gone, because the grid renders a row object directly.
 */
export function buildCaseQueueColumns({ unitsLabel, now, navigateToCase }: CaseQueueColumnOptions): Array<QueueGridColumn<Case>> {
  return [
    {
      id: 'title',
      label: 'Title',
      sortable: true,
      render: (caseDoc: Case) => (
        <div className="wamTablePrimary">
          {/* The cell truncates and the grid's cell-expand popover is off
              (`isExpandable: false`), so the full text is the title. */}
          <strong title={caseDoc.title}>
            <EuiLink onClick={(event: React.MouseEvent) => navigateToCase(event, caseDoc.id)}>{caseDoc.title}</EuiLink>
          </strong>
          <span className="wamTableSecondary" title={caseDoc.id}>Case {caseDoc.id}</span>
        </div>
      ),
    },
    {
      id: 'severity',
      label: 'Severity',
      initialWidth: px(QUEUE_COLUMN_WIDTH.severity),
      sortable: true,
      render: (caseDoc: Case) => <CaseSeverityBadge severity={caseDoc.severity} />,
    },
    {
      id: 'status',
      label: 'Status',
      initialWidth: px(QUEUE_COLUMN_WIDTH.status),
      sortable: true,
      render: (caseDoc: Case) => (
        <span className="wamStatusCell">
          <StatusBadge status={caseDoc.status} />
          <DispositionBadge
            disposition={caseDoc.disposition}
            status={caseDoc.status}
            className="wamDispositionQueueBadge"
            testSubj="wamCaseDisposition"
          />
        </span>
      ),
    },
    {
      id: 'due',
      label: 'Due',
      initialWidth: px(QUEUE_COLUMN_WIDTH.due),
      sortable: true,
      render: (caseDoc: Case) => <SlaDue dueAt={caseDoc.sla_due_at} status={caseDoc.status} now={now} compact testSubj="wamCaseDue" />,
    },
    {
      id: 'evidence',
      label: unitsLabel,
      initialWidth: px(QUEUE_COLUMN_WIDTH.evidence),
      render: (caseDoc: Case) => (
        <span data-test-subj="wamCaseEvidenceCount">{caseDoc.evidence_count ?? caseDoc.alert_ids?.length ?? 0}</span>
      ),
    },
    {
      id: 'tasks',
      label: 'Tasks',
      initialWidth: px(QUEUE_COLUMN_WIDTH.tasks),
      render: (caseDoc: Case) => <CaseTasksChip counts={caseDoc.task_counts} testSubj="wamCaseTasksChip" />,
    },
    {
      id: 'assigned',
      label: 'Assigned to',
      initialWidth: px(QUEUE_COLUMN_WIDTH.assigned),
      sortable: true,
      render: (caseDoc: Case) =>
        caseDoc.assigned_to || (
          <EuiText size="s" color="subdued">
            Unassigned
          </EuiText>
        ),
    },
    {
      id: 'updated',
      label: 'Updated',
      initialWidth: px(QUEUE_COLUMN_WIDTH.timestamp),
      sortable: true,
      render: (caseDoc: Case) => (
        <QueueTimestamp
          value={caseDoc.updated_at || caseDoc.created_at}
          testSubj="wamCaseUpdated"
          tooltip={
            <>
              Created {formatAbsolute(caseDoc.created_at)}
              {caseDoc.created_by ? ` by ${caseDoc.created_by}` : ''}
              <br />
              Updated {formatAbsolute(caseDoc.updated_at || caseDoc.created_at)}
              {caseDoc.updated_by ? ` by ${caseDoc.updated_by}` : ''}
            </>
          }
        />
      ),
    },
    // Hidden until the analyst adds them from the column selector (13.2).
    {
      id: 'caseId',
      label: 'Case ID',
      initialWidth: 180,
      hiddenByDefault: true,
      render: (caseDoc: Case) => (
        <span className="wamQueueMonospace" data-test-subj="wamCaseIdCell" title={caseDoc.id}>
          {caseDoc.id}
        </span>
      ),
    },
    {
      id: 'createdBy',
      label: 'Created by',
      initialWidth: px(QUEUE_COLUMN_WIDTH.assigned),
      hiddenByDefault: true,
      sortable: true,
      render: (caseDoc: Case) => (
        <span data-test-subj="wamCaseCreatedBy">
          {caseDoc.created_by || (
            <EuiText size="s" color="subdued">
              —
            </EuiText>
          )}
        </span>
      ),
    },
    {
      id: 'actions',
      label: 'Actions',
      initialWidth: px(QUEUE_COLUMN_WIDTH.actions),
      isResizable: false,
      render: (caseDoc: Case) => (
        <EuiButtonIcon
          iconType="inspect"
          data-test-subj="wamCaseExpand"
          aria-label={`Open details for ${caseDoc.title}`}
          onClick={(event) => navigateToCase(event, caseDoc.id)}
        />
      ),
    },
  ];
}

export const CasesView: React.FC<Props> = ({ apiService, onToast, openCaseId, onOpenAlert, onCaseFlyoutClosed }) => {
  const terms = useTerminology();
  const [cases, setCases] = useState<Case[]>([]);
  const [totalCases, setTotalCases] = useState(0);
  const [summary, setSummary] = useState({ open: 0, in_progress: 0, closed: 0, total: 0 });
  const [summaryExpanded, setSummaryExpanded] = useState(() => {
    try { return window.localStorage.getItem('wam.caseSummary') !== 'collapsed'; } catch (e) { return true; }
  });
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<CaseStatus[]>(['open', 'in_progress']);
  const [severityFilter, setSeverityFilter] = useState<CaseSeverity[]>([]);
  const [assigneeFilter, setAssigneeFilter] = useState<string[]>([]);
  const [slaFilter, setSlaFilter] = useState<SlaState | undefined>(undefined);
  // Close outcome (step 2.4); empty = any.
  const [dispositionFilter, setDispositionFilter] = useState<Disposition[]>([]);
  const now = useNowTicker();
  const [analysts, setAnalysts] = useState<string[]>([]);
  const [query, setQuery] = useState('');
  // Filters on case creation time. Defaults to a wide window; the picker also
  // supports absolute custom ranges. Date-math and ISO both flow straight into
  // the /cases created_at range query.
  const [start, setStart] = useState('now-1y');
  const [end, setEnd] = useState('now');
  const [selectedCaseId, setSelectedCaseId] = useState<string | undefined>(openCaseId);
  const [selectedCases, setSelectedCases] = useState<Case[]>([]);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  // Grid sort (step 13.2): the analyst's last sort is restored from the grid
  // preferences, so the queue comes back the way they left it. A stored
  // column id is any string; only one this build can sort on is restored.
  const [sort, setSort] = useState<QueueGridSort>(() => {
    const stored = readGridSort(CASE_GRID_STORAGE_KEY);
    return stored && isCaseSortColumn(stored.columnId) ? stored : DEFAULT_CASE_SORT;
  });
  const sortField = caseSortFieldOf(sort.columnId);
  const sortDirection = sort.direction;
  const pageableCases = Math.min(totalCases, CASE_RESULT_WINDOW);

  const clearSelection = useCallback(() => {
    setSelectedCases([]);
  }, []);

  // Only the newest fetch may touch the queue state. The Search box commits on
  // every keystroke (`query` is a `loadCases` dependency and the effect below
  // refetches whenever `loadCases` changes), so several requests are in flight
  // at once and a slow early one would otherwise land last and leave the rows,
  // the total and the pager showing a different query's result - or clear the
  // spinner while a newer fetch is still running. Same guard as the alerts
  // queue's `alertsRequestGeneration`.
  const casesRequestGeneration = useRef(0);

  useEffect(
    () => () => {
      // Unmounted: nothing in flight may write state any more.
      casesRequestGeneration.current += 1;
    },
    []
  );

  const loadCases = useCallback(async (preserveSelection: Case[] = []) => {
    const generation = ++casesRequestGeneration.current;
    try {
      if (!preserveSelection.length) clearSelection();
      setLoading(true);
      const res = await apiService.fetchCases({
        status: statusFilter.length ? statusFilter : undefined,
        severity: severityFilter.length ? severityFilter : undefined,
        assignedTo: assigneeFilter.length ? assigneeFilter : undefined,
        slaState: slaFilter,
        disposition: dispositionFilter.length ? dispositionFilter : undefined,
        q: query || undefined,
        from: start,
        to: end,
        fromOffset: pageIndex * pageSize,
        size: pageSize,
        sortField,
        sortDirection,
      });
      if (generation !== casesRequestGeneration.current) return;
      const nextTotal = res?.total || 0;
      if (pageIndex > 0 && pageIndex * pageSize >= nextTotal) {
        setPageIndex(Math.max(0, Math.ceil(nextTotal / pageSize) - 1));
        return;
      }
      // The grid hands each cell the whole case record, so a refresh cannot
      // combine a new title with a stale id the way EuiBasicTable's field
      // indirection could (the `__row_identity` scalar of 10.2 is gone).
      setCases(res?.cases || []);
      setTotalCases(nextTotal);
      setSummary(res?.summary || { open: 0, in_progress: 0, closed: 0, total: nextTotal });
      if (preserveSelection.length) {
        const failedIds = new Set(preserveSelection.map((caseDoc) => caseDoc.id));
        const refreshedSelection = res.cases.filter((caseDoc) => failedIds.has(caseDoc.id));
        const retainedSelection = refreshedSelection.length ? refreshedSelection : preserveSelection;
        setSelectedCases(retainedSelection);
      }
    } catch (e: any) {
      if (generation !== casesRequestGeneration.current) return;
      onToast('Failed to load cases', 'danger', e?.body?.message || e.message);
    } finally {
      if (generation === casesRequestGeneration.current) setLoading(false);
    }
  }, [apiService, statusFilter, severityFilter, assigneeFilter, slaFilter, dispositionFilter, query, start, end, pageIndex, pageSize, sortField, sortDirection, clearSelection, onToast]);

  const load = useCallback(() => loadCases(), [loadCases]);

  // CSV of the current filter state (same parameters as loadCases), capped server-side.
  const exportCsv = useCallback(async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const result = await apiService.exportCasesCsv({
        status: statusFilter.length ? statusFilter : undefined,
        severity: severityFilter.length ? severityFilter : undefined,
        assignedTo: assigneeFilter.length ? assigneeFilter : undefined,
        slaState: slaFilter,
        disposition: dispositionFilter.length ? dispositionFilter : undefined,
        q: query || undefined,
        from: start,
        to: end,
      });
      downloadBlob(result.filename, result.blob);
      if (result.truncated) {
        onToast('Export truncated', 'primary', 'The CSV holds the first 10,000 matching cases. Narrow the filters to export the rest.');
      }
    } catch (e: any) {
      onToast('Export failed', 'danger', e?.body?.message || e?.message || 'The CSV could not be generated.');
    } finally {
      setExporting(false);
    }
  }, [apiService, exporting, statusFilter, severityFilter, assigneeFilter, slaFilter, dispositionFilter, query, start, end, onToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    apiService.fetchUsers().then(setAnalysts).catch(() => setAnalysts([]));
  }, [apiService]);

  useEffect(() => {
    // Only a real deep link should override a selection made in this view.
    // On the first render, an undefined prop effect can otherwise race a fast
    // row click and immediately erase it before the flyout mounts.
    if (openCaseId) setSelectedCaseId(openCaseId);
  }, [openCaseId]);

  const runBulkUpdate = async (changes: { status?: 'open' | 'in_progress'; assignedTo?: string | null }) => {
    try {
      setBulkBusy(true);
      const result = await apiService.bulkUpdateCases(selectedCases.map((caseDoc) => caseDoc.id), changes);
      const failures = result.results.filter((item) => !item.ok);
      const failedIds = new Set(failures.map((item) => item.id));
      const failedCases = selectedCases.filter((caseDoc) => failedIds.has(caseDoc.id));
      if (result.failed) {
        onToast(
          `Updated ${result.updated} of ${result.requested} cases`,
          'danger',
          failures.map((item) => `${item.id}: ${item.error}`).join('; ')
        );
      } else {
        onToast(`Updated ${result.updated} case${result.updated === 1 ? '' : 's'}`, 'success');
      }
      if (result.updated > 0 || failures.some((item) => item.mutationApplied)) {
        await loadCases(failedCases);
      } else if (failures.length) {
        setSelectedCases(failedCases);
      }
    } catch (e: any) {
      onToast('Bulk case update failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  // Sorting from the grid header: one column at a time (the route takes one
  // sort field), back to the first page, selection dropped because the page
  // it was taken from is gone.
  const onSortChange = (next: QueueGridSort | null) => {
    const picked = next && isCaseSortColumn(next.columnId) ? next : DEFAULT_CASE_SORT;
    if (picked.columnId === sort.columnId && picked.direction === sort.direction) return;
    clearSelection();
    setSort(picked);
    setPageIndex(0);
  };

  // "Reset layout" in the grid toolbar restores the default columns, widths
  // and density; the sort lives here, so it goes back to the default with
  // them.
  const onGridReset = () => {
    clearSelection();
    setSort(DEFAULT_CASE_SORT);
    setPageIndex(0);
  };

  const onPageChange = (nextIndex: number) => {
    if (nextIndex === pageIndex) return;
    clearSelection();
    setPageIndex(nextIndex);
  };

  const onPageSizeChange = (nextSize: number) => {
    if (nextSize === pageSize) return;
    clearSelection();
    setPageSize(nextSize);
    setPageIndex(0);
  };

  const toggleSummary = () => {
    setSummaryExpanded((expanded) => {
      const next = !expanded;
      try { window.localStorage.setItem('wam.caseSummary', next ? 'expanded' : 'collapsed'); } catch (e) { /* optional */ }
      return next;
    });
  };

  const navigateToCase = useCallback((event: React.MouseEvent, caseId: string) => {
    event.preventDefault();
    event.stopPropagation();
    setSelectedCaseId(caseId);
  }, []);

  // Stable identities for everything the grid folds into `cellPropsOf` ->
  // `renderCellValue` and into `leadingControlColumns`: EUI renders those
  // callbacks as component types (`var CellElement = renderCellValue`), so a
  // fresh arrow on every render would unmount and remount every cell and every
  // checkbox on the page - on a keystroke, a loading toggle, a selection
  // change or a minute tick - closing open tooltips and dropping focus.
  const getCaseId = useCallback((caseDoc: Case) => caseDoc.id, []);
  const openCase = useCallback((caseDoc: Case) => setSelectedCaseId(caseDoc.id), []);
  const caseRowClass = useCallback((caseDoc: Case) => `wamCaseRow--${caseDoc.severity}`, []);
  const isCaseSelectable = useCallback(() => !bulkBusy, [bulkBusy]);
  const caseRowLabel = useCallback((caseDoc: Case) => `Select ${caseDoc.title}`, []);
  const gridSelection = useMemo(
    () => ({
      selected: selectedCases,
      onChange: setSelectedCases,
      selectable: isCaseSelectable,
      rowLabel: caseRowLabel,
    }),
    [selectedCases, isCaseSelectable, caseRowLabel]
  );

  // Memoized: `QueueGrid` derives its EuiDataGrid columns and its
  // `renderCellValue` from this array's identity, and EUI renders that
  // callback as a component type - a fresh array on every minute tick of
  // `useNowTicker` would unmount and remount every cell on the page.
  const columns = useMemo(
    () => buildCaseQueueColumns({ unitsLabel: terms.Units, now, navigateToCase }),
    [terms.Units, now]
  );

  // Every filter change drops the selection and returns to the first page.
  const resetAndSet = <T,>(setter: (value: T) => void) => (value: T) => {
    clearSelection();
    setPageIndex(0);
    setter(value);
  };

  return (
    <>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap>
        <EuiFlexItem grow={false}>
          <EuiTitle size="s"><h2>Case queue</h2></EuiTitle>
          <EuiText size="s" color="subdued">Investigations across ownership, severity, and lifecycle state.</EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty className="wamSummaryToggle" size="xs" iconType={summaryExpanded ? 'arrowUp' : 'arrowDown'} onClick={toggleSummary} aria-expanded={summaryExpanded}>
                {summaryExpanded ? 'Hide summary' : 'Show summary'}
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                className="wamExportButton"
                size="xs"
                iconType="exportAction"
                onClick={exportCsv}
                isLoading={exporting}
                isDisabled={exporting}
                data-test-subj="wamExportCasesCsv"
              >
                Export CSV
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>

      {summaryExpanded && (
        <>
          <EuiSpacer size="m" />
          <QueueStats
            loading={loading}
            testSubj="wamCaseQueueStats"
            tiles={[
              { id: 'open', description: 'Open', value: summary.open, color: 'primary' },
              { id: 'in_progress', description: 'In progress', value: summary.in_progress, color: 'accent' },
              { id: 'closed', description: 'Closed', value: summary.closed, color: 'subdued' },
              { id: 'total', description: 'Total', value: summary.total },
            ]}
          />
        </>
      )}

      <EuiSpacer size="m" />

      {/* Same grid as the alerts FilterBar: the query row (search, created range, Refresh), then the structured filters. */}
      <EuiPanel paddingSize="s" hasShadow={false} hasBorder className="wamFilterBar">
        <EuiFlexGroup gutterSize="s" alignItems="flexStart" wrap className="wamQueryRow">
          <EuiFlexItem className="wamQueryRow__query">
            <EuiFormRow label="Search" fullWidth>
              <EuiFieldSearch
                fullWidth
                placeholder="Search by title/description"
                value={query}
                onChange={(e) => resetAndSet(setQuery)(e.target.value)}
                onSearch={load}
                isClearable
                aria-label="Search cases by title or description"
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false} className="wamQueryRow__time">
            <EuiFormRow label="Created">
              <EuiSuperDatePicker
                start={start}
                end={end}
                onTimeChange={({ start: s, end: e }) => {
                  clearSelection();
                  setPageIndex(0);
                  setStart(s);
                  setEnd(e);
                }}
                onRefresh={({ start: s, end: e }) => {
                  if (s === start && e === end) load();
                  else {
                    clearSelection();
                    setPageIndex(0);
                    setStart(s);
                    setEnd(e);
                  }
                }}
                isLoading={loading}
                showUpdateButton
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false} className="wamQueryRow__apply">
            <EuiFormRow label="Apply filters">
              <EuiButton fill onClick={load} isLoading={loading} iconType="refresh" data-test-subj="wamCasesRefresh">
                Refresh
              </EuiButton>
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size="m" />

        <EuiFlexGroup gutterSize="s" wrap alignItems="flexEnd" className="wamStructuredFilters">
          <EuiFlexItem className="wamStructuredFilters__item">
            <EuiFormRow label="Status" display="rowCompressed">
              <EuiComboBox
                options={[
                  { label: 'Open', value: 'open' },
                  { label: 'In progress', value: 'in_progress' },
                  { label: 'Closed', value: 'closed' },
                ]}
                selectedOptions={statusFilter.map((s) => ({ label: statusLabel(s), value: s }))}
                onChange={(sel) => resetAndSet(setStatusFilter)(sel.map((s) => s.value as CaseStatus))}
                placeholder="All statuses"
                compressed
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem className="wamStructuredFilters__item">
            <EuiFormRow label="Severity" display="rowCompressed">
              <EuiComboBox
                aria-label="Filter cases by severity"
                placeholder="All severities"
                options={(['critical', 'high', 'medium', 'low'] as CaseSeverity[]).map((severity) => ({
                  label: severity.charAt(0).toUpperCase() + severity.slice(1), value: severity,
                }))}
                selectedOptions={severityFilter.map((severity) => ({
                  label: severity.charAt(0).toUpperCase() + severity.slice(1), value: severity,
                }))}
                onChange={(selected) => resetAndSet(setSeverityFilter)(selected.map((option) => option.value as CaseSeverity))}
                isClearable
                compressed
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false} className="wamStructuredFilters__chips">
            <EuiFormRow label="SLA" display="rowCompressed">
              <EuiFilterGroup>
                {SLA_QUICK_FILTERS.map((o) => {
                  const active = slaFilter === o.value;
                  return (
                    <EuiFilterButton
                      key={o.value}
                      hasActiveFilters={active}
                      isSelected={active}
                      title={o.title.replace('alerts', 'cases')}
                      className={`wamSlaFilter wamSlaFilter--${o.value}${active ? ' wamSlaFilter--active' : ''}`}
                      data-test-subj={`wamCaseSlaFilter-${o.value}`}
                      onClick={() => resetAndSet(setSlaFilter)(active ? undefined : o.value)}
                    >
                      {o.label}
                    </EuiFilterButton>
                  );
                })}
              </EuiFilterGroup>
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem className="wamStructuredFilters__item">
            <EuiFormRow label="Disposition" display="rowCompressed">
              <EuiComboBox
                aria-label="Filter cases by disposition"
                placeholder="Any disposition"
                options={DISPOSITIONS.map((value) => ({ label: DISPOSITION_LABELS[value], value }))}
                selectedOptions={dispositionFilter.map((value) => ({ label: DISPOSITION_LABELS[value], value }))}
                onChange={(selected) => resetAndSet(setDispositionFilter)(selected.map((option) => option.value as Disposition))}
                isClearable
                compressed
                data-test-subj="wamCaseDispositionFilter"
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem className="wamStructuredFilters__item">
            <EuiFormRow label="Assignee" display="rowCompressed">
              <EuiComboBox
                aria-label="Filter cases by assignee"
                placeholder="All assignees"
                options={[
                  { label: 'Unassigned', value: '__unassigned__' },
                  ...analysts.map((analyst) => ({ label: analyst, value: analyst })),
                ]}
                selectedOptions={assigneeFilter.map((assignee) => ({
                  label: assignee === '__unassigned__' ? 'Unassigned' : assignee, value: assignee,
                }))}
                onChange={(selected) => resetAndSet(setAssigneeFilter)(selected.map((option) => String(option.value)))}
                isClearable
                compressed
              />
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiPanel>

      <EuiSpacer size="m" />

      <BulkActionsBar<'open' | 'in_progress'>
        apiService={apiService}
        selectedCount={selectedCases.length}
        onSetStatus={(status) => runBulkUpdate({ status })}
        onAssign={(assignedTo) => runBulkUpdate({ assignedTo })}
        onClear={clearSelection}
        busy={bulkBusy}
        statusOptions={[
          { value: 'open', text: 'Open' },
          { value: 'in_progress', text: 'In progress' },
        ]}
        statusHelpText="Close cases individually from case details so linked alerts and retained evidence are handled safely."
      />

      {cases.length === 0 && !loading ? (
        <QueueEmptyPrompt
          title="No cases found"
          body={`No cases matched your filters; select ${terms.units} in the ${terms.Units} tab and use "Create case from selected" or "Add to case".`}
          testSubj="wamCaseQueueEmpty"
        />
      ) : (
        <>
          <QueueGrid<Case>
            className="wamQueueTable wamCaseTable"
            data-test-subj="wamCaseQueueGrid"
            ariaLabel="Case queue"
            storageKey={CASE_GRID_STORAGE_KEY}
            columns={columns}
            rows={cases}
            getRowId={getCaseId}
            sort={sort}
            onSort={onSortChange}
            loading={loading}
            onReset={onGridReset}
            onRowClick={openCase}
            cellClassName="wamCaseQueueCell wamClickableRow"
            rowAnchorClassName="wamCaseRow"
            rowIdAttribute="data-case-id"
            rowClassName={caseRowClass}
            selection={gridSelection}
            toolbar={
              <QueueResultSummary
                pageIndex={pageIndex}
                pageSize={pageSize}
                total={pageableCases}
                noun={pageableCases === 1 ? 'case' : 'cases'}
                note={totalCases > CASE_RESULT_WINDOW
                  ? `${totalCases.toLocaleString()} match and the first ${CASE_RESULT_WINDOW.toLocaleString()} are browsable. Refine filters to reach the remainder.`
                  : undefined}
                testSubj="wamCaseResultSummary"
              />
            }
          />
          <EuiSpacer size="s" />
          {/* The grid is handed one page at a time (EuiDataGrid's own pager
              knows nothing of a server-side total), so the queue keeps its
              own pager below it. */}
          <EuiTablePagination
            activePage={pageIndex}
            pageCount={Math.max(1, Math.ceil(pageableCases / pageSize))}
            itemsPerPage={pageSize}
            itemsPerPageOptions={[10, 20, 50]}
            onChangePage={onPageChange}
            onChangeItemsPerPage={onPageSizeChange}
          />
        </>
      )}

      {selectedCaseId && (
        <CaseFlyout
          caseId={selectedCaseId}
          apiService={apiService}
          onClose={() => {
            setSelectedCaseId(undefined);
            onCaseFlyoutClosed();
          }}
          onError={(msg) => onToast('Error', 'danger', msg)}
          onToast={onToast}
          onChanged={load}
          onOpenAlert={(alert) => onOpenAlert(alert._id)}
        />
      )}
    </>
  );
};
