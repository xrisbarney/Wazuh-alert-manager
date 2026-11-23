import { useTerminology } from '../terminology';
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiTablePagination,
  EuiText,
  EuiBadge,
  EuiToolTip,
  EuiTitle,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiLink,
  EuiLoadingContent,
} from '@elastic/eui';
import { Alert, AlertStatus, AlertCounts, FilterOptions } from '../../common';
import { QueueGrid, QueueGridColumn, QueueGridSort, readGridSort } from './queue_grid';
import { formatAbsolute, formatRelative, severityBand } from '../design';
import { AssetBadge } from './asset_badge';
import { NativeCaseChip } from './native_case_chip';
import { AlertsApiService, AlertFilterParams, BulkAlertUpdateResponse, downloadBlob } from '../services/api';
import { FilterBar, AlertFilterState } from './filter_bar';
import { BulkActionsBar } from './bulk_actions_bar';
import { CreateCaseModal } from './create_case_modal';
import { AlertFlyout } from './alert_flyout';
import { StatusBadge, SeverityBadge, DispositionBadge } from './status_badge';
import { SlaDue, useNowTicker } from './sla_due';
import { CloseCaseDialog, CloseOutcome } from './close_case_dialog';
import { QUEUE_COLUMN_WIDTH, QueueEmptyPrompt, QueueResultSummary, QueueStats } from './queue_chrome';

interface TimeRange {
  from: string;
  to: string;
  mode?: 'absolute' | 'relative';
}

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onOpenCase: (caseId: string) => void;
  openAlertId?: string;
  onOpenAlertHandled?: () => void;
}

const failedAlertIds = (result: BulkAlertUpdateResponse, requestedIds: string[]): string[] => {
  const failed = new Set<string>();
  for (const item of result.failed || []) if (item.alertId) failed.add(item.alertId);
  for (const linkage of result.linkage || []) {
    for (const id of linkage.unknownAlertIds || []) failed.add(id);
    for (const id of linkage.retryAlertIds || []) failed.add(id);
    for (const id of linkage.conflictedAlertIds || []) failed.add(id);
    for (const error of linkage.errors || []) if (error.alertId) failed.add(error.alertId);
    if (!linkage.ok) {
      const completed = new Set([...(linkage.linkedAlertIds || []), ...(linkage.unlinkedAlertIds || [])]);
      for (const id of requestedIds) if (!completed.has(id)) failed.add(id);
    }
  }
  if (result.updated < result.requested && failed.size === 0) requestedIds.forEach((id) => failed.add(id));
  return Array.from(failed);
};

const isPartialAlertUpdate = (result: BulkAlertUpdateResponse) =>
  result.updated < result.requested ||
  Boolean(result.failed?.length) ||
  Boolean(result.linkage?.some((item) => !item.ok));

export interface AlertQueueColumnOptions {
  /** case_id -> title, resolved lazily by the view; a missing title falls back to the id. */
  caseTitles: Record<string, string>;
  /** Minute ticker the Due countdown renders against. */
  now: number;
  openAlertById: (alertId: string) => void;
  onOpenCase: (caseId: string) => void;
}

/** localStorage prefix of the alert queue's grid preferences (step 13.1). */
export const ALERT_GRID_STORAGE_KEY = 'wam.alertsGrid';

/**
 * Grid column id -> the sort field the alerts route takes. Only the columns
 * flagged `sortable` appear here; anything else falls back to the timestamp.
 */
export const ALERT_SORT_FIELDS: Record<string, string> = {
  timestamp: '@timestamp',
  severity: 'rule.level',
  due: 'reporting.sla_due_at',
};

/** True for a column id the alerts route can actually sort on. */
export function isAlertSortColumn(columnId: unknown): columnId is string {
  return typeof columnId === 'string' && Object.prototype.hasOwnProperty.call(ALERT_SORT_FIELDS, columnId);
}

/**
 * The sort field of a grid column id. A plain `ALERT_SORT_FIELDS[id]` walks
 * the prototype chain, and the column id comes back from localStorage as any
 * string - `toString` would resolve to an inherited function and skip the
 * fallback, sending a non-string sort field to the route.
 */
export function alertSortFieldOf(columnId: string): string {
  return isAlertSortColumn(columnId) ? ALERT_SORT_FIELDS[columnId] : ALERT_SORT_FIELDS.timestamp;
}

export const DEFAULT_ALERT_SORT: QueueGridSort = { columnId: 'timestamp', direction: 'desc' };

/** Pixel value of one of the shared queue widths ('110px' -> 110). */
const px = (width: string): number => parseInt(width, 10);

/**
 * The alert queue columns (step 13.1, replacing the EuiBasicTable columns of
 * 10.2). Every column but Rule starts at one of the shared fixed widths
 * (`QUEUE_COLUMN_WIDTH`); Rule has none and is the column that absorbs the
 * leftover width, so the queue fits the viewport instead of scrolling
 * sideways. From here each width is the analyst's: the grid remembers what
 * they drag, which columns they show and in what order.
 *
 * Manager, Alert ID and Agent IP start hidden and are added from the column
 * selector. The Case cell is a flex column (`.wamCaseCell`) so a long case
 * title truncates with an ellipsis inside its width instead of covering the
 * expand button; the full title stays in the badge's `title`, and the
 * native-case chip wraps under the badge.
 */
export function buildAlertQueueColumns({ caseTitles, now, openAlertById, onOpenCase }: AlertQueueColumnOptions): Array<QueueGridColumn<Alert>> {
  return [
    {
      id: 'timestamp',
      label: 'When',
      initialWidth: px(QUEUE_COLUMN_WIDTH.timestamp),
      sortable: true,
      render: (alert: Alert) => (
        <EuiToolTip content={formatAbsolute(alert._source['@timestamp'])}>
          <EuiLink
            className="wamQueueTimestamp"
            onClick={(event) => {
              event.stopPropagation();
              openAlertById(alert._id);
            }}
          >
            {formatRelative(alert._source['@timestamp'])}
          </EuiLink>
        </EuiToolTip>
      ),
    },
    {
      id: 'agent',
      label: 'Agent / IP',
      initialWidth: px(QUEUE_COLUMN_WIDTH.agent),
      render: (alert: Alert) => {
        const v = alert._source;
        return (
          <div className="wamTablePrimary">
            <strong>{v.agent?.name || v.agent?.ip || 'Unknown agent'}</strong>
            {/* 13.3: the IP and the criticality chip share the second line.
                On three lines the cell is taller than the compact row height
                and the grid clips the agent name and the chip in half. */}
            <span className="wamTableSecondary wamAgentMetaLine">
              {v.agent?.name && v.agent?.ip ? <span className="wamAgentMetaIp">({v.agent.ip})</span> : null}
              <AssetBadge asset={v.asset} compact className="wamAssetQueueBadge" testSubj="wamAssetQueueBadge" />
            </span>
          </div>
        );
      },
    },
    {
      id: 'rule',
      label: 'Rule',
      render: (alert: Alert) => {
        const v = alert._source;
        const verdict = v.enrichment?.worst_verdict;
        const flagged = verdict === 'malicious' || verdict === 'suspicious';
        return (
          <div className="wamTablePrimary">
            {/* The cell truncates and the grid's cell-expand popover is off
                (`isExpandable: false`), so the full text is the title. */}
            <strong title={v.rule?.description || 'Unknown rule'}>{v.rule?.description || 'Unknown rule'}</strong>
            {v.rule?.id && <span className="wamTableSecondary">Rule {v.rule.id}</span>}
            {flagged && (
              <EuiToolTip content={`Stored enrichment verdict: ${verdict} (${v.enrichment?.items?.length ?? 0} lookup result(s))`}>
                <EuiBadge
                  color={verdict === 'malicious' ? 'danger' : 'warning'}
                  className="wamEnrichmentQueueBadge"
                  data-test-subj="wamEnrichmentQueueBadge"
                >
                  {verdict}
                </EuiBadge>
              </EuiToolTip>
            )}
          </div>
        );
      },
    },
    {
      id: 'severity',
      label: 'Severity',
      initialWidth: px(QUEUE_COLUMN_WIDTH.severity),
      sortable: true,
      render: (alert: Alert) => <SeverityBadge level={alert._source.rule?.level as number} label={alert._source?.severity_label} />,
    },
    {
      id: 'status',
      label: 'Status',
      initialWidth: px(QUEUE_COLUMN_WIDTH.status),
      render: (alert: Alert) => (
        <span className="wamStatusCell">
          <StatusBadge status={alert._source.status} />
          <DispositionBadge
            disposition={alert._source.disposition}
            status={alert._source.status}
            className="wamDispositionQueueBadge"
            testSubj="wamAlertDisposition"
          />
        </span>
      ),
    },
    {
      // The route takes the stored path and its short alias `sla_due_at`, and
      // puts undated alerts last.
      id: 'due',
      label: 'Due',
      initialWidth: px(QUEUE_COLUMN_WIDTH.due),
      sortable: true,
      render: (alert: Alert) => (
        <SlaDue dueAt={alert._source.reporting?.sla_due_at} status={alert._source?.status} now={now} compact testSubj="wamAlertDue" />
      ),
    },
    {
      id: 'assigned',
      label: 'Assigned to',
      initialWidth: px(QUEUE_COLUMN_WIDTH.assigned),
      render: (alert: Alert) =>
        alert._source.assigned_to || (
          <EuiText size="s" color="subdued">
            Unassigned
          </EuiText>
        ),
    },
    {
      id: 'case',
      label: 'Case',
      initialWidth: px(QUEUE_COLUMN_WIDTH.caseLink),
      render: (alert: Alert) => {
        const v = alert._source;
        return (
          <div className="wamCaseCell">
            {v.case_id ? (
              <EuiBadge
                color="primary"
                iconType="folderOpen"
                className="wamCaseCell__badge"
                data-test-subj="wamAlertCaseBadge"
                onClick={(event: any) => {
                  event.stopPropagation();
                  onOpenCase(v.case_id!);
                }}
                onClickAriaLabel="Open linked case"
                title={caseTitles[v.case_id] || v.case_id}
              >
                {caseTitles[v.case_id] || v.case_id.slice(0, 8)}
              </EuiBadge>
            ) : (
              <EuiText size="s" color="subdued">
                —
              </EuiText>
            )}
            {/* Step 2.6: compact native-case badge; renders nothing on a 4.x build or without a projection. */}
            <NativeCaseChip nativeCase={v.native_case} compact testSubj="wamAlertNativeCaseQueue" />
          </div>
        );
      },
    },
    // Hidden until the analyst adds them from the column selector (13.1).
    {
      id: 'manager',
      label: 'Manager',
      initialWidth: px(QUEUE_COLUMN_WIDTH.agent),
      hiddenByDefault: true,
      render: (alert: Alert) => (
        <span data-test-subj="wamAlertManager">
          {alert._source.manager?.name || (
            <EuiText size="s" color="subdued">
              —
            </EuiText>
          )}
        </span>
      ),
    },
    {
      id: 'alertId',
      label: 'Alert ID',
      initialWidth: 180,
      hiddenByDefault: true,
      render: (alert: Alert) => (
        <span className="wamQueueMonospace" data-test-subj="wamAlertIdCell" title={alert._id}>
          {alert._id}
        </span>
      ),
    },
    {
      id: 'agentIp',
      label: 'Agent IP',
      initialWidth: px(QUEUE_COLUMN_WIDTH.status),
      hiddenByDefault: true,
      render: (alert: Alert) => (
        <span data-test-subj="wamAlertAgentIp">
          {alert._source.agent?.ip || (
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
      render: (alert: Alert) => (
        <EuiButtonIcon
          iconType="expand"
          data-test-subj="wamAlertExpand"
          aria-label={`Open details for ${alert._source.rule?.description || alert._id}`}
          onClick={(event) => {
            event.stopPropagation();
            openAlertById(alert._id);
          }}
        />
      ),
    },
  ];
}

export const AlertsView: React.FC<Props> = ({ apiService, onToast, onOpenCase, openAlertId, onOpenAlertHandled }) => {
  const terms = useTerminology();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  // case_id -> case title, resolved lazily so the Case column shows a readable
  // name instead of a raw id.
  const [caseTitles, setCaseTitles] = useState<Record<string, string>>({});
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [counts, setCounts] = useState<AlertCounts>({ open: 0, in_progress: 0, closed: 0, total: 0 });
  const [loading, setLoading] = useState(true);
  const [loadingCounts, setLoadingCounts] = useState(true);
  const [updating, setUpdating] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  // Grid sort (step 13.1): the analyst's last sort is restored from the grid
  // preferences, so the queue comes back the way they left it.
  const [sort, setSort] = useState<QueueGridSort>(() => {
    // A stored column id is any string; only one this build can sort on is
    // restored, everything else falls back to the default.
    const stored = readGridSort(ALERT_GRID_STORAGE_KEY);
    return stored && isAlertSortColumn(stored.columnId) ? stored : DEFAULT_ALERT_SORT;
  });
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedIds, setSelectedIds] = useState<Alert[]>([]);
  const [showCreateCase, setShowCreateCase] = useState(false);
  // A close (single from the flyout, or bulk from the selection) first asks
  // for the disposition (step 2.4); the request is kept until the dialog answers.
  const [closeRequest, setCloseRequest] = useState<{ mode: 'single' | 'bulk'; alerts: Alert[] } | null>(null);
  const [filterOptions, setFilterOptions] = useState<FilterOptions | null>(null);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(false);
  const [summaryExpanded, setSummaryExpanded] = useState(() => {
    try { return window.localStorage.getItem('wam.alertSummary') !== 'collapsed'; } catch (e) { return true; }
  });
  // Bumped whenever a committed query input changes that the table-driven
  // effect does not otherwise watch (filters applied, time range changed).
  // `filters` is live draft state synced on every keystroke, so the fetch
  // effect must NOT depend on it directly - it keys on this counter instead,
  // which only advances on an explicit commit. This is the single query trigger.
  const [queryVersion, setQueryVersion] = useState(0);

  const [filters, setFilters] = useState<AlertFilterState>({
    // Default to the active work queue - open + in progress - so the analyst
    // lands on what needs attention, not a wall of closed noise.
    statuses: ['open', 'in_progress'],
    ruleIds: [],
    agentNames: [],
    alertTypes: [],
    assignedTo: [],
    q: '',
  });
  const [timeRange, setTimeRange] = useState<TimeRange>({ from: 'now-24h', to: 'now', mode: 'relative' });
  const appliedFilters = useRef(filters);
  const appliedTimeRange = useRef(timeRange);
  const alertsRequestGeneration = useRef(0);
  const countsRequestGeneration = useRef(0);

  // Due countdowns re-render once a minute without a refetch.
  const now = useNowTicker();

  const clearSelection = () => {
    setSelectedIds([]);
  };

  const buildFilterParams = useCallback(
    (): AlertFilterParams => ({
      statuses: appliedFilters.current.statuses,
      levelMin: appliedFilters.current.levelMin,
      levelMax: appliedFilters.current.levelMax,
      ruleIds: appliedFilters.current.ruleIds,
      agentNames: appliedFilters.current.agentNames,
      alertTypes: appliedFilters.current.alertTypes,
      assignedTo: appliedFilters.current.assignedTo,
      enrichmentVerdict: appliedFilters.current.enrichmentVerdict,
      assetCriticality: appliedFilters.current.assetCriticality,
      slaState: appliedFilters.current.slaState,
      disposition: appliedFilters.current.disposition,
      q: appliedFilters.current.q || undefined,
      from: appliedTimeRange.current.from,
      to: appliedTimeRange.current.to,
    }),
    []
  );

  const fetchCounts = useCallback(async () => {
    const generation = ++countsRequestGeneration.current;
    try {
      setLoadingCounts(true);
      const res: any = await apiService.fetchAlertCounts(buildFilterParams());
      if (generation !== countsRequestGeneration.current) return;
      setCounts({ open: res.open || 0, in_progress: res.in_progress || 0, closed: res.closed || 0, total: res.total || 0 });
    } catch (e) {
      // non-fatal
    } finally {
      if (generation === countsRequestGeneration.current) setLoadingCounts(false);
    }
  }, [buildFilterParams]);

  const fetchAlerts = useCallback(async () => {
    const generation = ++alertsRequestGeneration.current;
    try {
      setLoading(true);
      const res: any = await apiService.fetchAlerts(buildFilterParams(), {
        from: pageIndex * pageSize,
        size: pageSize,
        sortField: alertSortFieldOf(sort.columnId),
        sortDirection: sort.direction,
      });
      if (generation !== alertsRequestGeneration.current) return;
      const hits: Alert[] = res?.hits?.hits || [];
      setAlerts(hits);
      setTotalAlerts(res?.hits?.total?.value || 0);
      resolveCaseTitles(hits);
    } catch (e: any) {
      if (generation !== alertsRequestGeneration.current) return;
      onToast('Error fetching alerts', 'danger', e?.body?.message || e.message);
    } finally {
      if (generation === alertsRequestGeneration.current) setLoading(false);
    }
  }, [buildFilterParams, pageIndex, pageSize, sort.columnId, sort.direction]);

  // Fetch titles for any case_ids on the page we haven't seen yet, so the Case
  // column can show the case name. Best-effort; failures leave the id fallback.
  const resolveCaseTitles = useCallback(
    (hits: Alert[]) => {
      const ids = Array.from(
        new Set(hits.map((h) => h._source.case_id).filter((id): id is string => !!id))
      ).filter((id) => !caseTitles[id]);
      if (!ids.length) return;
      ids.forEach((id) => {
        apiService
          .fetchCase(id)
          .then((res: any) => {
            if (res?.case?.title) setCaseTitles((prev) => ({ ...prev, [id]: res.case.title }));
          })
          .catch(() => {
            /* leave the id fallback */
          });
      });
    },
    [caseTitles, apiService]
  );

  const fetchFilterOptions = useCallback(async () => {
    try {
      const res = await apiService.fetchFilterOptions();
      setFilterOptions(res as FilterOptions);
    } catch (e) {
      // non-fatal
    }
  }, []);

  useEffect(() => {
    fetchFilterOptions();
    return () => {
      alertsRequestGeneration.current += 1;
      countsRequestGeneration.current += 1;
    };
  }, [fetchFilterOptions]);

  // Single fetch trigger: paging/sort (watched directly) or a committed
  // query change (via queryVersion). React batches the state updates in a
  // commit handler into one render, so this runs exactly once per commit -
  // no double-fetch when Apply also resets the page, and a time-range change
  // always refetches even when the page was already 0.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    fetchAlerts();
    fetchCounts();
  }, [pageIndex, pageSize, sort.columnId, sort.direction, queryVersion]);

  useEffect(() => {
    if (!autoRefreshEnabled) return;
    const id = setInterval(() => {
      fetchAlerts();
      fetchCounts();
    }, 5 * 60 * 1000);
    return () => clearInterval(id);
  }, [autoRefreshEnabled, fetchAlerts, fetchCounts]);

  const openAlertById = useCallback(
    async (alertId: string) => {
      try {
        const doc: any = await apiService.fetchAlert(alertId);
        setSelectedAlert({ ...doc, _id: doc?._id || alertId, _source: doc._source });
      } catch (e) {
        onToast('Failed to open alert', 'danger');
      }
    },
    [apiService]
  );

  useEffect(() => {
    if (openAlertId) {
      openAlertById(openAlertId).finally(() => onOpenAlertHandled?.());
    }
  }, [openAlertId]);

  const applyFilters = () => {
    appliedFilters.current = filters;
    appliedTimeRange.current = timeRange;
    clearSelection();
    setPageIndex(0);
    setQueryVersion((v) => v + 1);
  };

  // CSV of the applied filters (what the queue shows), capped server-side.
  const exportCsv = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const result = await apiService.exportAlertsCsv(buildFilterParams());
      downloadBlob(result.filename, result.blob);
      if (result.truncated) {
        onToast('Export truncated', 'primary', 'The CSV holds the first 10,000 matching rows. Narrow the filters or time range to export the rest.');
      }
    } catch (e: any) {
      onToast('Export failed', 'danger', e?.body?.message || e?.message || 'The CSV could not be generated.');
    } finally {
      setExporting(false);
    }
  };

  const toggleSummary = () => {
    setSummaryExpanded((expanded) => {
      const next = !expanded;
      try { window.localStorage.setItem('wam.alertSummary', next ? 'expanded' : 'collapsed'); } catch (e) { /* optional */ }
      return next;
    });
  };

  const addLuceneFilter = (field: string, value: unknown, negate: boolean) => {
    const escaped = String(value).replace(/([\\"])/g, '\\$1');
    const literal = typeof value === 'number' || typeof value === 'boolean' ? String(value) : `"${escaped}"`;
    const clause = `${negate ? 'NOT ' : ''}${field}:${literal}`;
    const next = { ...filters, q: filters.q ? `(${filters.q}) AND ${clause}` : clause };
    setFilters(next);
    appliedFilters.current = next;
    appliedTimeRange.current = timeRange;
    setSelectedAlert(null);
    clearSelection();
    setPageIndex(0);
    setQueryVersion((version) => version + 1);
    onToast(negate ? `Excluded ${field}` : `Filtered by ${field}`, 'success', clause);
  };

  // Sorting from the grid header: one column at a time (the route takes one
  // sort field), back to the first page, selection dropped because the page
  // it was taken from is gone.
  const onSortChange = (next: QueueGridSort | null) => {
    const picked = next && isAlertSortColumn(next.columnId) ? next : DEFAULT_ALERT_SORT;
    if (picked.columnId === sort.columnId && picked.direction === sort.direction) return;
    clearSelection();
    setSort(picked);
    setPageIndex(0);
  };

  // "Reset layout" in the grid toolbar restores the default columns, widths
  // and density; the sort lives here, so it goes back to the default with
  // them - otherwise the queue would keep an order the stored preferences no
  // longer mention.
  const onGridReset = () => {
    clearSelection();
    setSort(DEFAULT_ALERT_SORT);
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

  const updateAlerts = async (
    ids: string[],
    changes: { status?: AlertStatus; caseId?: string | null; assignedTo?: string | null; disposition?: CloseOutcome['disposition']; closureReason?: string | null }
  ): Promise<BulkAlertUpdateResponse> => {
    let result: BulkAlertUpdateResponse;
    try {
      result = await apiService.bulkUpdateAlerts(ids, changes);
    } catch (error: any) {
      // OSD versions differ on whether a structured HTTP 207 is resolved or thrown.
      if (typeof error?.body?.requested !== 'number' || typeof error?.body?.updated !== 'number') throw error;
      result = error.body as BulkAlertUpdateResponse;
    }
    await Promise.all([fetchAlerts(), fetchCounts()]);
    if (selectedAlert && ids.includes(selectedAlert._id)) await openAlertById(selectedAlert._id);
    return result;
  };

  const retainFailedSelection = (
    requested: Alert[],
    failureIds: string[],
    result: BulkAlertUpdateResponse
  ) => {
    const failures = new Set(failureIds);
    const retained = requested.filter((alert) => failures.has(alert._id));
    const partial = isPartialAlertUpdate(result);
    setSelectedIds(retained);
    onToast(
      partial ? `Updated ${result.updated} of ${result.requested} alerts` : `Updated ${result.updated} alert(s)`,
      partial ? 'danger' : 'success',
      partial ? result.message || (failureIds.length ? `Failed alerts retained: ${failureIds.join(', ')}` : 'A related operation was incomplete.') : undefined
    );
  };

  const updateAlertStatus = async (alertId: string, newStatus: AlertStatus, outcome?: CloseOutcome) => {
    if (newStatus === 'closed' && !outcome) {
      // Ask for the disposition first; confirmClose re-enters with the outcome.
      const alert = alerts.find((a) => a._id === alertId) || (selectedAlert && selectedAlert._id === alertId ? selectedAlert : null);
      if (alert) {
        setCloseRequest({ mode: 'single', alerts: [alert] });
        return;
      }
    }
    try {
      setUpdating(alertId);
      const result = await updateAlerts([alertId], { status: newStatus, ...(outcome ? { disposition: outcome.disposition, closureReason: outcome.closureReason } : {}) });
      const failures = failedAlertIds(result, [alertId]);
      const partial = isPartialAlertUpdate(result);
      onToast(
        partial ? 'Status update incomplete' : 'Status updated',
        partial ? 'danger' : 'success',
        partial ? result.message || (failures.length ? `Failed alert: ${failures.join(', ')}` : 'A related operation was incomplete.') : undefined
      );
    } catch (e: any) {
      onToast('Error updating status', 'danger', e?.body?.message || e.message);
    } finally {
      setUpdating(null);
    }
  };

  const bulkSetStatus = async (status: AlertStatus, outcome?: CloseOutcome, requestedAlerts?: Alert[]) => {
    if (status === 'closed' && !outcome) {
      // One dialog for the whole selection (step 2.4); confirmClose re-enters with the outcome.
      if (selectedIds.length) setCloseRequest({ mode: 'bulk', alerts: selectedIds });
      return;
    }
    try {
      setBulkBusy(true);
      const requested = requestedAlerts || selectedIds;
      const ids = requested.map((alert) => alert._id);
      const result = await updateAlerts(ids, { status, ...(outcome ? { disposition: outcome.disposition, closureReason: outcome.closureReason } : {}) });
      retainFailedSelection(requested, failedAlertIds(result, ids), result);
    } catch (e: any) {
      onToast('Bulk update failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const confirmClose = async (outcome: CloseOutcome) => {
    const request = closeRequest;
    if (!request) return;
    setCloseRequest(null);
    if (request.mode === 'single') await updateAlertStatus(request.alerts[0]._id, 'closed', outcome);
    else await bulkSetStatus('closed', outcome, request.alerts);
  };

  const bulkAssign = async (assignedTo: string | null) => {
    try {
      setBulkBusy(true);
      const requested = selectedIds;
      const ids = requested.map((alert) => alert._id);
      const result = await updateAlerts(ids, { assignedTo });
      retainFailedSelection(requested, failedAlertIds(result, ids), result);
    } catch (e: any) {
      onToast('Assignment failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const updateAlertAssignee = async (alertId: string, assignedTo: string | null) => {
    try {
      setUpdating(alertId);
      const result = await updateAlerts([alertId], { assignedTo });
      const failures = failedAlertIds(result, [alertId]);
      const partial = isPartialAlertUpdate(result);
      onToast(
        partial ? 'Assignment incomplete' : assignedTo ? `Assigned to ${assignedTo}` : 'Unassigned',
        partial ? 'danger' : 'success',
        partial ? result.message || (failures.length ? `Failed alert: ${failures.join(', ')}` : 'A related operation was incomplete.') : undefined
      );
    } catch (e: any) {
      onToast('Assignment failed', 'danger', e?.body?.message || e.message);
    } finally {
      setUpdating(null);
    }
  };

  const updateAlertCase = async (alertId: string, caseId: string | null) => {
    try {
      setUpdating(alertId);
      const result = await updateAlerts([alertId], { caseId });
      const failures = failedAlertIds(result, [alertId]);
      const partial = isPartialAlertUpdate(result);
      onToast(
        partial ? 'Case link update incomplete' : caseId ? 'Linked to case' : 'Removed from case',
        partial ? 'danger' : 'success',
        partial ? result.message || (failures.length ? `Failed alert: ${failures.join(', ')}` : 'A related operation was incomplete.') : undefined
      );
    } catch (e: any) {
      onToast('Failed to update case link', 'danger', e?.body?.message || e.message);
    } finally {
      setUpdating(null);
    }
  };

  const bulkAddToCase = async (caseId: string | null) => {
    if (!caseId) return;
    try {
      setBulkBusy(true);
      const requested = selectedIds;
      const ids = requested.map((alert) => alert._id);
      const result = await updateAlerts(ids, { caseId });
      retainFailedSelection(requested, failedAlertIds(result, ids), result);
      if (result.updated > 0) onOpenCase(caseId);
    } catch (e: any) {
      onToast('Failed to add to case', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const createCaseFromSelection = async (payload: { title: string; description: string; severity: any; assignedTo?: string | null; taskListId?: string | null }) => {
    try {
      setBulkBusy(true);
      const created: any = await apiService.createCase({ ...payload, alertIds: selectedIds.map((a) => a._id) });
      onToast('Case created', 'success', `Linked ${selectedIds.length} alert(s) to "${payload.title}"`);
      // The task list (step 2.2) is applied server-side after creation; a failure never undoes the case.
      if (created?.taskList) {
        if (created.taskList.applied) onToast('Task list applied', 'success', `Added ${created.taskList.tasks_added ?? 0} task(s) to the new case`);
        else onToast('Task list not applied', 'danger', created.taskList.error || 'The case was created without the task list tasks.');
      }
      setShowCreateCase(false);
      setSelectedIds([]);
      fetchAlerts();
      onOpenCase(created.id);
    } catch (e: any) {
      onToast('Failed to create case', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  // Memoized: `QueueGrid` derives its EuiDataGrid columns and its
  // `renderCellValue` from this array's identity, and EUI renders that
  // callback as a component type - a fresh array on every minute tick of
  // `useNowTicker` would unmount and remount every cell on the page.
  const columns = useMemo(
    () => buildAlertQueueColumns({ caseTitles, now, openAlertById, onOpenCase }),
    [caseTitles, now, openAlertById, onOpenCase]
  );

  // Same reason as `columns`: these three callbacks end up inside the grid's
  // `cellPropsOf` -> `renderCellValue` and its `leadingControlColumns`, which
  // EUI renders as component types, so an inline arrow would remount every
  // cell and every checkbox on each render.
  const getAlertId = useCallback((alert: Alert) => alert._id, []);
  const openAlertRow = useCallback((alert: Alert) => openAlertById(alert._id), [openAlertById]);
  const alertRowClass = useCallback(
    (alert: Alert) => `wamAlertRow--${severityBand(alert._source.rule?.level, alert._source.severity_label)}`,
    []
  );
  const alertRowLabel = useCallback((alert: Alert) => `Select ${alert._source.rule?.description || alert._id}`, []);
  const gridSelection = useMemo(
    () => ({ selected: selectedIds, onChange: setSelectedIds, rowLabel: alertRowLabel }),
    [selectedIds, alertRowLabel]
  );

  return (
    <>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap>
        <EuiFlexItem grow={false}>
          <EuiTitle size="s"><h2>{terms.Unit} queue</h2></EuiTitle>
          <EuiText size="s" color="subdued">Prioritized triage with explicit query and time-range controls.</EuiText>
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
                data-test-subj="wamExportAlertsCsv"
              >
                Export CSV
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiBadge color={autoRefreshEnabled ? 'success' : 'hollow'} iconType={autoRefreshEnabled ? 'refresh' : 'clock'}>
                {autoRefreshEnabled ? 'Auto-refresh on · 5 min' : 'Auto-refresh off'}
              </EuiBadge>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>

      {summaryExpanded && (
        <>
          <EuiSpacer size="m" />
          <QueueStats
            loading={loadingCounts}
            testSubj="wamAlertQueueStats"
            tiles={[
              { id: 'open', description: 'Open', value: counts.open, color: 'primary' },
              { id: 'in_progress', description: 'In progress', value: counts.in_progress, color: 'accent' },
              { id: 'closed', description: 'Closed', value: counts.closed, color: 'subdued' },
              { id: 'total', description: 'Total', value: counts.total },
            ]}
          />
        </>
      )}

      <EuiSpacer size="m" />

      <FilterBar
        key={queryVersion}
        filters={filters}
        onChange={setFilters}
        timeRange={timeRange}
        onTimeRangeChange={(tr) => {
          setTimeRange(tr);
        }}
        filterOptions={filterOptions}
        onApply={applyFilters}
        loading={loading || loadingCounts}
        autoRefreshEnabled={autoRefreshEnabled}
        onToggleAutoRefresh={() => setAutoRefreshEnabled((v) => !v)}
      />

      <EuiSpacer size="m" />

      <BulkActionsBar
        apiService={apiService}
        selectedCount={selectedIds.length}
        onSetStatus={bulkSetStatus}
        onAssign={bulkAssign}
        onAddToCase={bulkAddToCase}
        onCreateCase={() => setShowCreateCase(true)}
        onClear={() => setSelectedIds([])}
        busy={bulkBusy}
      />

      {alerts.length === 0 ? (
        // An in-flight first fetch must read as loading, not as an empty page.
        loading ? (
          <EuiLoadingContent lines={5} data-test-subj="wamAlertQueueLoading" />
        ) : (
          <QueueEmptyPrompt title="No alerts found" body="No alerts matched your search criteria." testSubj="wamAlertQueueEmpty" />
        )
      ) : (
        <>
          <QueueGrid<Alert>
            className="wamQueueTable wamAlertTable"
            data-test-subj="wamAlertQueueGrid"
            ariaLabel="Alert queue"
            storageKey={ALERT_GRID_STORAGE_KEY}
            columns={columns}
            rows={alerts}
            getRowId={getAlertId}
            sort={sort}
            onSort={onSortChange}
            loading={loading}
            onReset={onGridReset}
            onRowClick={openAlertRow}
            cellClassName="wamAlertCell wamClickableRow"
            rowAnchorClassName="wamAlertRow"
            rowIdAttribute="data-alert-id"
            rowClassName={alertRowClass}
            selection={gridSelection}
            toolbar={
              <QueueResultSummary pageIndex={pageIndex} pageSize={pageSize} total={totalAlerts} noun="alerts" testSubj="wamAlertResultSummary" />
            }
          />
          <EuiSpacer size="s" />
          {/* The grid is handed one page at a time (EuiDataGrid's own pager
              knows nothing of a server-side total), so the queue keeps its
              own pager below it. */}
          <EuiTablePagination
            activePage={pageIndex}
            pageCount={Math.max(1, Math.ceil(totalAlerts / pageSize))}
            itemsPerPage={pageSize}
            itemsPerPageOptions={[10, 20, 50, 100]}
            onChangePage={onPageChange}
            onChangeItemsPerPage={onPageSizeChange}
          />
        </>
      )}

      {closeRequest && (
        <CloseCaseDialog
          title={closeRequest.mode === 'bulk'
            ? `Close ${closeRequest.alerts.length} ${closeRequest.alerts.length === 1 ? terms.unit : terms.units}?`
            : `Close this ${terms.unit}?`}
          confirmLabel={closeRequest.mode === 'bulk' ? `Close ${closeRequest.alerts.length}` : 'Close'}
          busy={bulkBusy || updating != null}
          onCancel={() => setCloseRequest(null)}
          onConfirm={confirmClose}
          testSubj="wamAlertCloseDialog"
        />
      )}

      {selectedAlert && (
        <AlertFlyout
          key={selectedAlert._id}
          alert={selectedAlert}
          apiService={apiService}
          updating={updating === selectedAlert._id}
          onClose={() => setSelectedAlert(null)}
          onStatusChange={(status) => updateAlertStatus(selectedAlert._id, status as AlertStatus)}
          onAssigneeChange={(assignee) => updateAlertAssignee(selectedAlert._id, assignee)}
          onCaseChange={(caseId) => updateAlertCase(selectedAlert._id, caseId)}
          onError={(msg) => onToast('Error', 'danger', msg)}
          onToast={onToast}
          onOpenCase={onOpenCase}
          onOpenAlert={(a) => openAlertById(a._id)}
          onAnalysisGenerated={(alertId, analysis) => {
            setSelectedAlert((prev) => (prev && prev._id === alertId ? { ...prev, _source: { ...prev._source, ai_analysis: analysis } } : prev));
            setAlerts((prev) => prev.map((a) => (a._id === alertId ? { ...a, _source: { ...a._source, ai_analysis: analysis } } : a)));
          }}
          onEnrichmentUpdated={(alertId, enrichment) => {
            setSelectedAlert((prev) => (prev && prev._id === alertId ? { ...prev, _source: { ...prev._source, enrichment } } : prev));
            setAlerts((prev) => prev.map((a) => (a._id === alertId ? { ...a, _source: { ...a._source, enrichment } } : a)));
          }}
          onAddFilter={addLuceneFilter}
        />
      )}

      {showCreateCase && (
        <CreateCaseModal
          apiService={apiService}
          alertCount={selectedIds.length}
          busy={bulkBusy}
          onClose={() => setShowCreateCase(false)}
          onCreate={createCaseFromSelection}
        />
      )}
    </>
  );
};
