import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBasicTable,
  EuiSpacer,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiComboBox,
  EuiFieldSearch,
  EuiButton,
  EuiFormRow,
} from '@elastic/eui';
import { Case, CaseStatus } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge } from './status_badge';
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
  const [statusFilter, setStatusFilter] = useState<CaseStatus[]>(['open']);
  const [query, setQuery] = useState('');
  const [selectedCaseId, setSelectedCaseId] = useState<string | undefined>(openCaseId);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchCases({ status: statusFilter.length ? statusFilter : undefined, q: query || undefined });
      setCases(res?.cases || []);
    } catch (e: any) {
      onToast('Failed to load cases', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, query]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    setSelectedCaseId(openCaseId);
  }, [openCaseId]);

  const columns = [
    { field: 'title', name: 'Title', sortable: true },
    { field: 'severity', name: 'Severity' },
    { field: 'status', name: 'Status', render: (s: CaseStatus) => <StatusBadge status={s} /> },
    { field: 'alert_ids', name: 'Alerts', render: (ids: string[]) => ids?.length || 0 },
    { field: 'assigned_to', name: 'Assigned to', render: (v: string | null) => v || 'Unassigned' },
    { field: 'created_by', name: 'Created by' },
    { field: 'updated_at', name: 'Updated', render: (v: string) => (v ? new Date(v).toLocaleString() : '-') },
  ];

  return (
    <>
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd">
        <EuiFlexItem style={{ maxWidth: 260 }}>
          <EuiFormRow label="Status" display="rowCompressed">
            <EuiComboBox
              options={[
                { label: 'Open', value: 'open' },
                { label: 'Closed', value: 'closed' },
              ]}
              selectedOptions={statusFilter.map((s) => ({ label: s === 'open' ? 'Open' : 'Closed', value: s }))}
              onChange={(sel) => setStatusFilter(sel.map((s) => s.value as CaseStatus))}
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiFormRow label="Search" display="rowCompressed">
            <EuiFieldSearch value={query} onChange={(e) => setQuery(e.target.value)} onSearch={load} isClearable compressed />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" onClick={load} isLoading={loading}>
            Refresh
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />

      {cases.length === 0 && !loading ? (
        <EuiEmptyPrompt
          title={<h2>No cases yet</h2>}
          body={<p>Select alerts in the Alerts tab and use "Create case from selected" to start one.</p>}
        />
      ) : (
        <EuiBasicTable<Case>
          items={cases}
          itemId="id"
          columns={columns}
          loading={loading}
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
          onChanged={load}
          onOpenAlert={(alert) => onOpenAlert(alert._id)}
        />
      )}
    </>
  );
};
