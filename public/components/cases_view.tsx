import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiInMemoryTable,
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
} from '@elastic/eui';
import { Case, CaseStatus } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge, CaseSeverityBadge } from './status_badge';
import { formatAbsolute, statusLabel } from '../design';
import { CaseFlyout } from './case_flyout';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  openCaseId?: string;
  onOpenAlert: (alertId: string) => void;
  onCaseFlyoutClosed: () => void;
}

export const CasesView: React.FC<Props> = ({ apiService, onToast, openCaseId, onOpenAlert, onCaseFlyoutClosed }) => {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<CaseStatus[]>(['open', 'in_progress']);
  const [query, setQuery] = useState('');
  // Filters on case creation time. Defaults to a wide window; the picker also
  // supports absolute custom ranges. Date-math and ISO both flow straight into
  // the /cases created_at range query.
  const [start, setStart] = useState('now-1y');
  const [end, setEnd] = useState('now');
  const [selectedCaseId, setSelectedCaseId] = useState<string | undefined>(openCaseId);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchCases({
        status: statusFilter.length ? statusFilter : undefined,
        q: query || undefined,
        from: start,
        to: end,
      });
      setCases(res?.cases || []);
    } catch (e: any) {
      onToast('Failed to load cases', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, query, start, end]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    setSelectedCaseId(openCaseId);
  }, [openCaseId]);

  const columns = [
    { field: 'title', name: 'Title', sortable: true },
    { field: 'severity', name: 'Severity', sortable: true, render: (s: string) => <CaseSeverityBadge severity={s} /> },
    { field: 'status', name: 'Status', sortable: true, render: (s: CaseStatus) => <StatusBadge status={s} /> },
    { field: 'alert_ids', name: 'Alerts', render: (ids: string[]) => ids?.length || 0 },
    { field: 'assigned_to', name: 'Assigned to', sortable: true, render: (v: string | null) => v || 'Unassigned' },
    { field: 'created_by', name: 'Created by', sortable: true },
    { field: 'created_at', name: 'Created', sortable: true, render: (v: string) => formatAbsolute(v) },
    { field: 'updated_at', name: 'Updated', sortable: true, render: (v: string) => formatAbsolute(v) },
  ];

  return (
    <>
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
              onChange={(sel) => setStatusFilter(sel.map((s) => s.value as CaseStatus))}
              placeholder="All statuses"
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
                setStart(s);
                setEnd(e);
              }}
              onRefresh={({ start: s, end: e }) => {
                setStart(s);
                setEnd(e);
              }}
              isLoading={loading}
              showUpdateButton
              compressed
              width="auto"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 220 }}>
          <EuiFormRow label="Search" display="rowCompressed">
            <EuiFieldSearch
              placeholder="Search by title/description"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
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
        {cases.length} case{cases.length === 1 ? '' : 's'}
      </EuiText>
      <EuiSpacer size="s" />

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
        <EuiInMemoryTable<Case>
          items={cases}
          itemId="id"
          columns={columns}
          loading={loading}
          sorting={{ sort: { field: 'updated_at', direction: 'desc' } }}
          pagination={{ initialPageSize: 20, pageSizeOptions: [10, 20, 50] }}
          rowProps={(c) => ({ onClick: () => setSelectedCaseId(c.id), style: { cursor: 'pointer' } })}
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
