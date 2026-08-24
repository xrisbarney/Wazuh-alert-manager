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
  EuiPopover,
  EuiText,
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

interface TimeRangeOption {
  id: string;
  label: string;
  from?: string;
}

const TIME_RANGE_OPTIONS: TimeRangeOption[] = [
  { id: 'any', label: 'Any time created' },
  { id: '24h', label: 'Created in last 24 hours', from: 'now-24h' },
  { id: '7d', label: 'Created in last 7 days', from: 'now-7d' },
  { id: '30d', label: 'Created in last 30 days', from: 'now-30d' },
  { id: '90d', label: 'Created in last 90 days', from: 'now-90d' },
];

export const CasesView: React.FC<Props> = ({ apiService, onToast, openCaseId, onOpenAlert, onCaseFlyoutClosed }) => {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<CaseStatus[]>(['open']);
  const [query, setQuery] = useState('');
  const [timeRangeId, setTimeRangeId] = useState('any');
  const [isTimePopoverOpen, setIsTimePopoverOpen] = useState(false);
  const [selectedCaseId, setSelectedCaseId] = useState<string | undefined>(openCaseId);

  const load = useCallback(async () => {
    const range = TIME_RANGE_OPTIONS.find((r) => r.id === timeRangeId);
    try {
      setLoading(true);
      const res: any = await apiService.fetchCases({
        status: statusFilter.length ? statusFilter : undefined,
        q: query || undefined,
        from: range?.from,
        to: range?.from ? 'now' : undefined,
      });
      setCases(res?.cases || []);
    } catch (e: any) {
      onToast('Failed to load cases', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, query, timeRangeId]);

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
    { field: 'created_at', name: 'Created', render: (v: string) => (v ? new Date(v).toLocaleString() : '-') },
    { field: 'updated_at', name: 'Updated', render: (v: string) => (v ? new Date(v).toLocaleString() : '-') },
  ];

  const currentRangeLabel = TIME_RANGE_OPTIONS.find((r) => r.id === timeRangeId)?.label ?? 'Any time created';

  return (
    <>
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd" wrap>
        <EuiFlexItem style={{ maxWidth: 260 }}>
          <EuiFormRow label="Status" display="rowCompressed">
            <EuiComboBox
              options={[
                { label: 'Open', value: 'open' },
                { label: 'Closed', value: 'closed' },
              ]}
              selectedOptions={statusFilter.map((s) => ({ label: s === 'open' ? 'Open' : 'Closed', value: s }))}
              onChange={(sel) => setStatusFilter(sel.map((s) => s.value as CaseStatus))}
              placeholder="All statuses"
              compressed
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="&nbsp;" display="rowCompressed">
            <EuiPopover
              button={
                <EuiButton size="s" iconType="arrowDown" iconSide="right" onClick={() => setIsTimePopoverOpen((v) => !v)}>
                  {currentRangeLabel}
                </EuiButton>
              }
              isOpen={isTimePopoverOpen}
              closePopover={() => setIsTimePopoverOpen(false)}
              panelPaddingSize="s"
            >
              <div style={{ width: 240 }}>
                {TIME_RANGE_OPTIONS.map((r) => (
                  <EuiButton
                    key={r.id}
                    size="s"
                    fullWidth
                    color={r.id === timeRangeId ? 'primary' : 'text'}
                    onClick={() => {
                      setTimeRangeId(r.id);
                      setIsTimePopoverOpen(false);
                    }}
                    style={{ marginBottom: 4, justifyContent: 'flex-start' }}
                  >
                    {r.label}
                  </EuiButton>
                ))}
              </div>
            </EuiPopover>
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
          onToast={onToast}
          onChanged={load}
          onOpenAlert={(alert) => onOpenAlert(alert._id)}
        />
      )}
    </>
  );
};
