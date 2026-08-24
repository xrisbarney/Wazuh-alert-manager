import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiHorizontalRule,
  EuiBasicTable,
  CriteriaWithPagination,
  EuiEmptyPrompt,
  EuiText,
  EuiHealth,
} from '@elastic/eui';
import { Alert, AlertStatus, AlertCounts, FilterOptions } from '../../common';
import { AlertsApiService, AlertFilterParams } from '../services/api';
import { FilterBar, AlertFilterState } from './filter_bar';
import { BulkActionsBar } from './bulk_actions_bar';
import { CreateCaseModal } from './create_case_modal';
import { AlertFlyout } from './alert_flyout';
import { StatusBadge } from './status_badge';

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

export const AlertsView: React.FC<Props> = ({ apiService, onToast, onOpenCase, openAlertId, onOpenAlertHandled }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
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

  const [filters, setFilters] = useState<AlertFilterState>({
    statuses: [],
    ruleIds: [],
    agentNames: [],
    alertTypes: [],
    assignedTo: [],
    q: '',
  });
  const [timeRange, setTimeRange] = useState<TimeRange>({ from: 'now-24h', to: 'now', mode: 'relative' });

  const tableRef = useRef<EuiBasicTable<Alert>>(null);

  const buildFilterParams = useCallback(
    (): AlertFilterParams => ({
      statuses: filters.statuses,
      levelMin: filters.levelMin,
      levelMax: filters.levelMax,
      ruleIds: filters.ruleIds,
      agentNames: filters.agentNames,
      alertTypes: filters.alertTypes,
      assignedTo: filters.assignedTo,
      q: filters.q || undefined,
      from: timeRange.from,
      to: timeRange.to,
    }),
    [filters, timeRange]
  );

  const fetchCounts = useCallback(async () => {
    try {
      setLoadingCounts(true);
      const res: any = await apiService.fetchAlertCounts(buildFilterParams());
      setCounts({ open: res.open || 0, in_progress: res.in_progress || 0, closed: res.closed || 0, total: res.total || 0 });
    } catch (e) {
      // non-fatal
    } finally {
      setLoadingCounts(false);
    }
  }, [buildFilterParams]);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchAlerts(buildFilterParams(), {
        from: pageIndex * pageSize,
        size: pageSize,
        sortField: sortField.replace(/^_source\./, ''),
        sortDirection,
      });
      setAlerts(res?.hits?.hits || []);
      setTotalAlerts(res?.hits?.total?.value || 0);
    } catch (e: any) {
      onToast('Error fetching alerts', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [buildFilterParams, pageIndex, pageSize, sortField, sortDirection]);

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
  }, [fetchFilterOptions]);

  useEffect(() => {
    fetchAlerts();
    fetchCounts();
  }, [pageIndex, pageSize, sortField, sortDirection]);

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
        setSelectedAlert({ _id: alertId, _source: doc._source });
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
    setPageIndex(0);
    fetchAlerts();
    fetchCounts();
  };

  const onTableChange = (criteria: CriteriaWithPagination<Alert>) => {
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

  const updateAlertStatus = async (alertId: string, newStatus: AlertStatus) => {
    try {
      setUpdating(alertId);
      await apiService.bulkUpdateAlerts([alertId], { status: newStatus });
      setAlerts((prev) => prev.map((a) => (a._id === alertId ? { ...a, _source: { ...a._source, status: newStatus } } : a)));
      if (selectedAlert?._id === alertId) {
        setSelectedAlert({ ...selectedAlert, _source: { ...selectedAlert._source, status: newStatus } });
      }
      fetchCounts();
      onToast('Status updated', 'success');
    } catch (e: any) {
      onToast('Error updating status', 'danger', e?.body?.message || e.message);
    } finally {
      setUpdating(null);
    }
  };

  const bulkSetStatus = async (status: AlertStatus) => {
    try {
      setBulkBusy(true);
      await apiService.bulkUpdateAlerts(selectedIds.map((a) => a._id), { status });
      onToast(`Updated ${selectedIds.length} alert(s)`, 'success');
      setSelectedIds([]);
      tableRef.current?.setSelection([]);
      fetchAlerts();
      fetchCounts();
    } catch (e: any) {
      onToast('Bulk update failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const bulkAssign = async (assignedTo: string | null) => {
    try {
      setBulkBusy(true);
      await apiService.bulkUpdateAlerts(selectedIds.map((a) => a._id), { assignedTo });
      onToast(
        assignedTo ? `Assigned ${selectedIds.length} alert(s) to ${assignedTo}` : `Unassigned ${selectedIds.length} alert(s)`,
        'success'
      );
      setSelectedIds([]);
      tableRef.current?.setSelection([]);
      fetchAlerts();
    } catch (e: any) {
      onToast('Assignment failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const updateAlertAssignee = async (alertId: string, assignedTo: string | null) => {
    try {
      setUpdating(alertId);
      await apiService.bulkUpdateAlerts([alertId], { assignedTo });
      setAlerts((prev) => prev.map((a) => (a._id === alertId ? { ...a, _source: { ...a._source, assigned_to: assignedTo } } : a)));
      if (selectedAlert?._id === alertId) {
        setSelectedAlert({ ...selectedAlert, _source: { ...selectedAlert._source, assigned_to: assignedTo } });
      }
      onToast(assignedTo ? `Assigned to ${assignedTo}` : 'Unassigned', 'success');
    } catch (e: any) {
      onToast('Assignment failed', 'danger', e?.body?.message || e.message);
    } finally {
      setUpdating(null);
    }
  };

  const updateAlertCase = async (alertId: string, caseId: string | null) => {
    try {
      setUpdating(alertId);
      await apiService.bulkUpdateAlerts([alertId], { caseId });
      setAlerts((prev) => prev.map((a) => (a._id === alertId ? { ...a, _source: { ...a._source, case_id: caseId } } : a)));
      if (selectedAlert?._id === alertId) {
        setSelectedAlert({ ...selectedAlert, _source: { ...selectedAlert._source, case_id: caseId } });
      }
      onToast(caseId ? 'Linked to case' : 'Removed from case', 'success');
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
      await apiService.bulkUpdateAlerts(selectedIds.map((a) => a._id), { caseId });
      onToast(`Added ${selectedIds.length} alert(s) to case`, 'success');
      setSelectedIds([]);
      tableRef.current?.setSelection([]);
      fetchAlerts();
      onOpenCase(caseId);
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
      name: 'Timestamp',
      sortable: true,
      render: (value: string) => new Date(value).toLocaleString(),
    },
    { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || 'N/A' },
    { field: '_source', name: 'Agent IP', render: (v: Alert['_source']) => v.agent?.ip || 'N/A' },
    { field: '_source', name: 'Rule Description', render: (v: Alert['_source']) => v.rule?.description || 'N/A' },
    {
      field: '_source.rule.level',
      name: 'Level',
      sortable: true,
      render: (level: number) => {
        const lvl = level || 0;
        return <EuiHealth color={lvl >= 7 ? 'danger' : lvl >= 5 ? 'warning' : 'success'}>{lvl}</EuiHealth>;
      },
    },
    { field: '_source', name: 'Status', render: (v: Alert['_source']) => <StatusBadge status={v.status} /> },
    { field: '_source', name: 'Assigned to', render: (v: Alert['_source']) => v.assigned_to || <EuiText size="s" color="subdued">Unassigned</EuiText> },
    { field: '_source', name: 'Case', render: (v: Alert['_source']) => (v.case_id ? v.case_id.slice(0, 8) : '-') },
    {
      name: 'Actions',
      actions: [
        {
          render: (alert: Alert) => (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }} onClick={(e) => e.stopPropagation()}>
              <select
                value={alert._source.status}
                disabled={updating === alert._id}
                onChange={(e) => updateAlertStatus(alert._id, e.target.value as AlertStatus)}
              >
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="closed">Closed</option>
              </select>
              {updating === alert._id && <EuiLoadingSpinner size="s" />}
            </div>
          ),
        },
      ],
    },
  ];

  return (
    <>
      <EuiFlexGroup gutterSize="m">
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={loadingCounts ? <EuiLoadingSpinner size="m" /> : counts.open} description="Open" titleColor="danger" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={loadingCounts ? <EuiLoadingSpinner size="m" /> : counts.in_progress} description="In Progress" titleColor="warning" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={loadingCounts ? <EuiLoadingSpinner size="m" /> : counts.closed} description="Closed" titleColor="success" />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
            <EuiStat title={loadingCounts ? <EuiLoadingSpinner size="m" /> : counts.total} description="Total" />
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="l" />
      <EuiHorizontalRule />
      <EuiSpacer size="l" />

      <FilterBar
        filters={filters}
        onChange={setFilters}
        timeRange={timeRange}
        onTimeRangeChange={(tr) => {
          setTimeRange(tr);
          setPageIndex(0);
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
            ref={tableRef}
            items={alerts}
            itemId="_id"
            columns={columns}
            loading={loading}
            sorting={{ sort: { field: sortField as any, direction: sortDirection } }}
            pagination={{ pageIndex, pageSize, totalItemCount: totalAlerts, pageSizeOptions: [10, 20, 50, 100] }}
            onChange={onTableChange}
            selection={{ selectable: () => true, onSelectionChange: setSelectedIds }}
            rowProps={(alert) => ({ onClick: () => setSelectedAlert(alert), style: { cursor: 'pointer' } })}
          />
        </>
      )}

      {selectedAlert && (
        <AlertFlyout
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
