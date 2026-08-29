import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiBasicTable,
  CriteriaWithPagination,
  EuiEmptyPrompt,
  EuiText,
  EuiBadge,
  EuiToolTip,
  EuiTitle,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiLink,
} from '@elastic/eui';
import { Alert, AlertStatus, AlertCounts, FilterOptions } from '../../common';
import { formatAbsolute, formatRelative } from '../design';
import { AlertsApiService, AlertFilterParams, BulkAlertUpdateResponse } from '../services/api';
import { FilterBar, AlertFilterState } from './filter_bar';
import { BulkActionsBar } from './bulk_actions_bar';
import { CreateCaseModal } from './create_case_modal';
import { AlertFlyout } from './alert_flyout';
import { StatusBadge, SeverityBadge } from './status_badge';

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

const isInteractiveRowTarget = (target: EventTarget | null, currentTarget: EventTarget | null) => {
  if (!(target instanceof HTMLElement) || target === currentTarget) return false;
  return Boolean(target.closest('button, a, input, select, textarea, label, [role="button"], [role="link"], [role="checkbox"], [role="option"]'));
};

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

export const AlertsView: React.FC<Props> = ({ apiService, onToast, onOpenCase, openAlertId, onOpenAlertHandled }) => {
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
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [sortField, setSortField] = useState('_source.@timestamp');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedIds, setSelectedIds] = useState<Alert[]>([]);
  const [showCreateCase, setShowCreateCase] = useState(false);
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

  const tableRef = useRef<EuiBasicTable<Alert>>(null);

  const clearSelection = () => {
    setSelectedIds([]);
    tableRef.current?.setSelection([]);
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
        sortField: sortField.replace(/^_source\./, ''),
        sortDirection,
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
  }, [buildFilterParams, pageIndex, pageSize, sortField, sortDirection]);

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
  }, [pageIndex, pageSize, sortField, sortDirection, queryVersion]);

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

  const onTableChange = (criteria: CriteriaWithPagination<Alert>) => {
    const sortChanged = Boolean(
      criteria.sort &&
      (String(criteria.sort.field) !== sortField || criteria.sort.direction !== sortDirection)
    );
    const pageChanged = Boolean(
      criteria.page && (criteria.page.index !== pageIndex || criteria.page.size !== pageSize)
    );
    if (sortChanged || pageChanged) clearSelection();
    if (criteria.sort) {
      setSortField(String(criteria.sort.field));
      setSortDirection(criteria.sort.direction);
      setPageIndex(0);
    }
    if (criteria.page) {
      setPageIndex(criteria.page.index);
      setPageSize(criteria.page.size);
    }
  };

  const updateAlerts = async (
    ids: string[],
    changes: { status?: AlertStatus; caseId?: string | null; assignedTo?: string | null }
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
    tableRef.current?.setSelection(retained);
    onToast(
      partial ? `Updated ${result.updated} of ${result.requested} alerts` : `Updated ${result.updated} alert(s)`,
      partial ? 'danger' : 'success',
      partial ? result.message || (failureIds.length ? `Failed alerts retained: ${failureIds.join(', ')}` : 'A related operation was incomplete.') : undefined
    );
  };

  const updateAlertStatus = async (alertId: string, newStatus: AlertStatus) => {
    try {
      setUpdating(alertId);
      const result = await updateAlerts([alertId], { status: newStatus });
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

  const bulkSetStatus = async (status: AlertStatus) => {
    try {
      setBulkBusy(true);
      const requested = selectedIds;
      const ids = requested.map((alert) => alert._id);
      const result = await updateAlerts(ids, { status });
      retainFailedSelection(requested, failedAlertIds(result, ids), result);
    } catch (e: any) {
      onToast('Bulk update failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
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

  const createCaseFromSelection = async (payload: { title: string; description: string; severity: any; assignedTo?: string | null }) => {
    try {
      setBulkBusy(true);
      const created: any = await apiService.createCase({ ...payload, alertIds: selectedIds.map((a) => a._id) });
      onToast('Case created', 'success', `Linked ${selectedIds.length} alert(s) to "${payload.title}"`);
      setShowCreateCase(false);
      setSelectedIds([]);
      tableRef.current?.setSelection([]);
      fetchAlerts();
      onOpenCase(created.id);
    } catch (e: any) {
      onToast('Failed to create case', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const columns = [
    {
      field: '_source.@timestamp',
      name: 'When',
      width: '110px',
      sortable: true,
      render: (value: string, alert: Alert) => (
        <EuiToolTip content={formatAbsolute(value)}>
          <EuiLink
            onClick={(event) => {
              event.stopPropagation();
              openAlertById(alert._id);
            }}
          >
            {formatRelative(value)}
          </EuiLink>
        </EuiToolTip>
      ),
    },
    {
      field: '_source',
      name: 'Agent / IP',
      width: '190px',
      render: (v: Alert['_source']) => (
        <div className="wamTablePrimary">
          <strong>{v.agent?.name || v.agent?.ip || 'Unknown agent'}</strong>
          {v.agent?.name && v.agent?.ip && <span className="wamTableSecondary">({v.agent.ip})</span>}
        </div>
      ),
    },
    {
      field: '_source',
      name: 'Rule',
      render: (v: Alert['_source']) => (
        <div className="wamTablePrimary">
          <strong>{v.rule?.description || 'Unknown rule'}</strong>
          {v.rule?.id && <span className="wamTableSecondary">Rule {v.rule.id}</span>}
        </div>
      ),
    },
    {
      field: '_source.rule.level',
      name: 'Severity',
      width: '120px',
      sortable: true,
      render: (level: number) => <SeverityBadge level={level} />,
    },
    {
      field: '_source',
      name: 'Status',
      width: '130px',
      render: (v: Alert['_source']) => <StatusBadge status={v.status} />,
    },
    {
      field: '_source',
      name: 'Assigned to',
      render: (v: Alert['_source']) =>
        v.assigned_to || (
          <EuiText size="s" color="subdued">
            Unassigned
          </EuiText>
        ),
    },
    {
      field: '_source',
      name: 'Case',
      render: (v: Alert['_source']) =>
        v.case_id ? (
          <EuiBadge
            color="primary"
            iconType="folderOpen"
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
        ),
    },
    {
      name: 'Actions',
      width: '70px',
      align: 'right',
      render: (alert: Alert) => (
        <EuiButtonIcon
          iconType="expand"
          aria-label={`Open details for ${alert._source.rule?.description || alert._id}`}
          onClick={(event) => {
            event.stopPropagation();
            openAlertById(alert._id);
          }}
        />
      ),
    },
  ];

  return (
    <>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap>
        <EuiFlexItem grow={false}>
          <EuiTitle size="s"><h2>Alert queue</h2></EuiTitle>
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
              <EuiBadge color={autoRefreshEnabled ? 'success' : 'hollow'} iconType={autoRefreshEnabled ? 'refresh' : 'clock'}>
                {autoRefreshEnabled ? 'Auto-refresh on · 5 min' : 'Auto-refresh off'}
              </EuiBadge>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>

      {summaryExpanded && <><EuiSpacer size="m" /><EuiFlexGroup gutterSize="s" className="wamQueueStats" wrap>
        <EuiFlexItem>
          <EuiPanel paddingSize="s" hasShadow={false} hasBorder>
            <EuiStat titleSize="s" title={loadingCounts ? <EuiLoadingSpinner size="s" /> : counts.open} description="Open" titleColor="primary" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="s" hasShadow={false} hasBorder>
            <EuiStat titleSize="s" title={loadingCounts ? <EuiLoadingSpinner size="s" /> : counts.in_progress} description="In progress" titleColor="accent" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="s" hasShadow={false} hasBorder>
            <EuiStat titleSize="s" title={loadingCounts ? <EuiLoadingSpinner size="s" /> : counts.closed} description="Closed" titleColor="subdued" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="s" hasShadow={false} hasBorder>
            <EuiStat titleSize="s" title={loadingCounts ? <EuiLoadingSpinner size="s" /> : counts.total} description="Total" titleColor="default" />
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup></>}

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
        onClear={() => {
          setSelectedIds([]);
          tableRef.current?.setSelection([]);
        }}
        busy={bulkBusy}
      />

      {alerts.length === 0 && !loading ? (
        <EuiEmptyPrompt title={<h2>No alerts found</h2>} body={<p>No alerts matched your search criteria.</p>} />
      ) : (
        <>
          <EuiText size="s" color="subdued">
            Showing {pageIndex * pageSize + 1}-{Math.min((pageIndex + 1) * pageSize, totalAlerts)} of {totalAlerts} alerts
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable<Alert>
            className="wamAlertTable"
            ref={tableRef}
            items={alerts}
            itemId="_id"
            columns={columns}
            loading={loading}
            sorting={{ sort: { field: sortField as any, direction: sortDirection } }}
            pagination={{ pageIndex, pageSize, totalItemCount: totalAlerts, pageSizeOptions: [10, 20, 50, 100] }}
            onChange={onTableChange}
            selection={{ selectable: () => true, onSelectionChange: setSelectedIds }}
            rowProps={(alert) => ({
              className: `wamAlertRow wamClickableRow wamAlertRow--${alert._source.rule?.level >= 12 ? 'critical' : alert._source.rule?.level >= 7 ? 'high' : alert._source.rule?.level >= 4 ? 'medium' : 'low'}`,
              onClick: (event: React.MouseEvent) => {
                if (!isInteractiveRowTarget(event.target, event.currentTarget)) openAlertById(alert._id);
              },
            })}
          />
        </>
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
