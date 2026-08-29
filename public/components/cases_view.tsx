import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  EuiBasicTable,
  CriteriaWithPagination,
  EuiSpacer,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiComboBox,
  EuiFieldSearch,
  EuiButton,
  EuiFormRow,
  EuiSuperDatePicker,
  EuiText,
  EuiButtonIcon,
  EuiLink,
  EuiPanel,
  EuiStat,
  EuiLoadingSpinner,
  EuiTitle,
  EuiButtonEmpty,
} from '@elastic/eui';
import { Case, CaseSeverity, CaseStatus } from '../../common';
import { AlertsApiService, CaseListSortField } from '../services/api';
import { StatusBadge, CaseSeverityBadge } from './status_badge';
import { formatAbsolute, statusLabel } from '../design';
import { CaseFlyout } from './case_flyout';
import { BulkActionsBar } from './bulk_actions_bar';

const CASE_RESULT_WINDOW = 10000;

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  openCaseId?: string;
  onOpenAlert: (alertId: string) => void;
  onCaseFlyoutClosed: () => void;
}

export const CasesView: React.FC<Props> = ({ apiService, onToast, openCaseId, onOpenAlert, onCaseFlyoutClosed }) => {
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
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [sortField, setSortField] = useState<CaseListSortField>('updated_at');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const tableRef = useRef<EuiBasicTable<Case>>(null);
  const pageableCases = Math.min(totalCases, CASE_RESULT_WINDOW);

  const clearSelection = useCallback(() => {
    setSelectedCases([]);
    tableRef.current?.setSelection([]);
  }, []);

  const loadCases = useCallback(async (preserveSelection: Case[] = []) => {
    try {
      if (!preserveSelection.length) clearSelection();
      setLoading(true);
      const res = await apiService.fetchCases({
        status: statusFilter.length ? statusFilter : undefined,
        severity: severityFilter.length ? severityFilter : undefined,
        assignedTo: assigneeFilter.length ? assigneeFilter : undefined,
        q: query || undefined,
        from: start,
        to: end,
        fromOffset: pageIndex * pageSize,
        size: pageSize,
        sortField,
        sortDirection,
      });
      const nextTotal = res?.total || 0;
      if (pageIndex > 0 && pageIndex * pageSize >= nextTotal) {
        setPageIndex(Math.max(0, Math.ceil(nextTotal / pageSize) - 1));
        return;
      }
      setCases(res?.cases || []);
      setTotalCases(nextTotal);
      setSummary(res?.summary || { open: 0, in_progress: 0, closed: 0, total: nextTotal });
      if (preserveSelection.length) {
        const failedIds = new Set(preserveSelection.map((caseDoc) => caseDoc.id));
        const refreshedSelection = res.cases.filter((caseDoc) => failedIds.has(caseDoc.id));
        const retainedSelection = refreshedSelection.length ? refreshedSelection : preserveSelection;
        setSelectedCases(retainedSelection);
        tableRef.current?.setSelection(retainedSelection);
      }
    } catch (e: any) {
      onToast('Failed to load cases', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [apiService, statusFilter, severityFilter, assigneeFilter, query, start, end, pageIndex, pageSize, sortField, sortDirection, clearSelection, onToast]);

  const load = useCallback(() => loadCases(), [loadCases]);

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
        tableRef.current?.setSelection(failedCases);
      }
    } catch (e: any) {
      onToast('Bulk case update failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const onTableChange = (criteria: CriteriaWithPagination<Case>) => {
    const sortChanged = Boolean(
      criteria.sort &&
      (criteria.sort.field !== sortField || criteria.sort.direction !== sortDirection)
    );
    clearSelection();
    if (sortChanged && criteria.sort) {
      setSortField(criteria.sort.field as CaseListSortField);
      setSortDirection(criteria.sort.direction);
      setPageIndex(0);
    }
    if (criteria.page) {
      if (!sortChanged) setPageIndex(criteria.page.index);
      setPageSize(criteria.page.size);
    }
  };

  const toggleSummary = () => {
    setSummaryExpanded((expanded) => {
      const next = !expanded;
      try { window.localStorage.setItem('wam.caseSummary', next ? 'expanded' : 'collapsed'); } catch (e) { /* optional */ }
      return next;
    });
  };

  const navigateToCase = (event: React.MouseEvent, caseId: string) => {
    event.preventDefault();
    const url = new URL(window.location.href);
    url.searchParams.set('tab', 'cases');
    url.searchParams.set('case', caseId);
    // A native navigation deliberately remounts the app. The dashboard's SPA
    // link interceptor otherwise updates the URL without replaying App's
    // initial deep-link state, leaving the case visibly unopened.
    window.location.assign(url.toString());
  };

  const columns = [
    {
      field: 'title',
      name: 'Title',
      sortable: true,
      render: (title: string, caseDoc: Case) => (
        <EuiLink
          href={`?tab=cases&case=${encodeURIComponent(caseDoc.id)}`}
          onClick={(event) => navigateToCase(event, caseDoc.id)}
        >
          {title}
        </EuiLink>
      ),
    },
    { field: 'severity', name: 'Severity', sortable: true, render: (s: string) => <CaseSeverityBadge severity={s} /> },
    { field: 'status', name: 'Status', sortable: true, render: (s: CaseStatus) => <StatusBadge status={s} /> },
    { field: 'alert_ids', name: 'Alerts', render: (ids: string[]) => ids?.length || 0 },
    { field: 'assigned_to', name: 'Assigned to', sortable: true, render: (v: string | null) => v || 'Unassigned' },
    { field: 'created_by', name: 'Created by', sortable: true },
    { field: 'created_at', name: 'Created', sortable: true, render: (v: string) => formatAbsolute(v) },
    { field: 'updated_at', name: 'Updated', sortable: true, render: (v: string) => formatAbsolute(v) },
    {
      name: 'Details',
      width: '64px',
      align: 'right',
      render: (caseDoc: Case) => (
        <EuiButtonIcon
          iconType="inspect"
          aria-label={`Open details for ${caseDoc.title}`}
          href={`?tab=cases&case=${encodeURIComponent(caseDoc.id)}`}
          onClick={(event) => navigateToCase(event, caseDoc.id)}
        />
      ),
    },
  ];

  return (
    <>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap>
        <EuiFlexItem grow={false}>
          <EuiTitle size="s"><h2>Case queue</h2></EuiTitle>
          <EuiText size="s" color="subdued">Investigations across ownership, severity, and lifecycle state.</EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty className="wamSummaryToggle" size="xs" iconType={summaryExpanded ? 'arrowUp' : 'arrowDown'} onClick={toggleSummary} aria-expanded={summaryExpanded}>
            {summaryExpanded ? 'Hide summary' : 'Show summary'}
          </EuiButtonEmpty>
        </EuiFlexItem>
      </EuiFlexGroup>

      {summaryExpanded && <><EuiSpacer size="m" /><EuiFlexGroup gutterSize="s" className="wamQueueStats" wrap>
        <EuiFlexItem><EuiPanel paddingSize="s" hasShadow={false} hasBorder><EuiStat titleSize="s" title={loading ? <EuiLoadingSpinner size="s" /> : summary.open} description="Open" titleColor="primary" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel paddingSize="s" hasShadow={false} hasBorder><EuiStat titleSize="s" title={loading ? <EuiLoadingSpinner size="s" /> : summary.in_progress} description="In progress" titleColor="accent" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel paddingSize="s" hasShadow={false} hasBorder><EuiStat titleSize="s" title={loading ? <EuiLoadingSpinner size="s" /> : summary.closed} description="Closed" titleColor="subdued" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel paddingSize="s" hasShadow={false} hasBorder><EuiStat titleSize="s" title={loading ? <EuiLoadingSpinner size="s" /> : summary.total} description="Total" /></EuiPanel></EuiFlexItem>
      </EuiFlexGroup></>}

      <EuiSpacer size="m" />
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd" wrap>
        <EuiFlexItem style={{ maxWidth: 260 }}>
          <EuiFormRow label="Status" display="rowCompressed">
            <EuiComboBox
              options={[
                { label: 'Open', value: 'open' },
                { label: 'In progress', value: 'in_progress' },
                { label: 'Closed', value: 'closed' },
              ]}
              selectedOptions={statusFilter.map((s) => ({ label: statusLabel(s), value: s }))}
              onChange={(sel) => {
                clearSelection();
                setPageIndex(0);
                setStatusFilter(sel.map((s) => s.value as CaseStatus));
              }}
              placeholder="All statuses"
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 220, maxWidth: 280 }}>
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
              onChange={(selected) => {
                clearSelection();
                setPageIndex(0);
                setSeverityFilter(selected.map((option) => option.value as CaseSeverity));
              }}
              isClearable
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 240, maxWidth: 320 }}>
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
              onChange={(selected) => {
                clearSelection();
                setPageIndex(0);
                setAssigneeFilter(selected.map((option) => String(option.value)));
              }}
              isClearable
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Created" display="rowCompressed">
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
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 220 }}>
          <EuiFormRow label="Search" display="rowCompressed">
            <EuiFieldSearch
              placeholder="Search by title/description"
              value={query}
              onChange={(e) => {
                clearSelection();
                setPageIndex(0);
                setQuery(e.target.value);
              }}
              onSearch={load}
              isClearable
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="&nbsp;" display="rowCompressed">
            <EuiButton size="s" onClick={load} isLoading={loading} iconType="refresh">
              Refresh
            </EuiButton>
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="s" />
      <EuiText size="s" color="subdued">
        {totalCases} case{totalCases === 1 ? '' : 's'}
        {totalCases > CASE_RESULT_WINDOW
          ? `; the first ${CASE_RESULT_WINDOW.toLocaleString()} are browsable. Refine filters to reach the remainder.`
          : ''}
      </EuiText>
      <EuiSpacer size="s" />

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
        <EuiEmptyPrompt
          title={<h2>No cases found</h2>}
          body={
            <p>
              No cases matched your filters. Select alerts in the Alerts tab and use "Create case from selected" to
              start one, or "Add to case" to link them to an existing one.
            </p>
          }
        />
      ) : (
        <EuiBasicTable<Case>
          ref={tableRef}
          className="wamCaseTable"
          items={cases}
          itemId="id"
          columns={columns}
          loading={loading}
          sorting={{ sort: { field: sortField, direction: sortDirection } }}
          pagination={{ pageIndex, pageSize, totalItemCount: pageableCases, pageSizeOptions: [10, 20, 50] }}
          selection={{ selectable: () => !bulkBusy, onSelectionChange: setSelectedCases }}
          onChange={onTableChange}
        />
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
