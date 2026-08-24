import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiTitle,
  EuiTabbedContent,
  EuiDescriptionList,
  EuiDescriptionListTitle,
  EuiDescriptionListDescription,
  EuiSpacer,
  EuiSelect,
  EuiLoadingSpinner,
  EuiBasicTable,
  EuiButtonIcon,
  EuiText,
  EuiTextArea,
  EuiFieldText,
  EuiButton,
  EuiFormRow,
  EuiFlexGroup,
  EuiFlexItem,
  EuiToolTip,
} from '@elastic/eui';
import { Alert, Case } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge, CASE_SEVERITY_OPTIONS } from './status_badge';
import { CommentsThread } from './comments_thread';
import { HistoryList } from './history_list';
import { AssigneePicker } from './assignee_picker';

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onClose: () => void;
  onError: (message: string) => void;
  onChanged: () => void;
  onOpenAlert?: (alert: Alert) => void;
}

export const CaseFlyout: React.FC<Props> = ({ caseId, apiService, onClose, onError, onChanged, onOpenAlert }) => {
  const [loading, setLoading] = useState(true);
  const [caseDoc, setCaseDoc] = useState<Case | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [busy, setBusy] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchCase(caseId);
      setCaseDoc(res.case);
      setAlerts(res.alerts || []);
      setTitle(res.case.title);
      setDescription(res.case.description || '');
    } catch (e) {
      onError('Failed to load case');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    load();
  }, [load]);

  const update = async (payload: Parameters<AlertsApiService['updateCase']>[1]) => {
    try {
      setBusy(true);
      const updated: any = await apiService.updateCase(caseId, payload);
      setCaseDoc(updated);
      onChanged();
    } catch (e) {
      onError('Failed to update case');
    } finally {
      setBusy(false);
      load();
    }
  };

  if (loading || !caseDoc) {
    return (
      <EuiFlyout onClose={onClose} size="m">
        <EuiFlyoutBody>
          <EuiLoadingSpinner size="xl" />
        </EuiFlyoutBody>
      </EuiFlyout>
    );
  }

  return (
    <EuiFlyout onClose={onClose} size={isExpanded ? '95vw' : 'l'} aria-labelledby="case-details-flyout">
      <EuiFlyoutHeader hasBorder>
        <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
          <EuiFlexItem>
            <EuiTitle size="m">
              <h2>{caseDoc.title}</h2>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiToolTip content={isExpanded ? 'Collapse' : 'Expand to full screen'}>
              <EuiButtonIcon
                iconType={isExpanded ? 'minimize' : 'expand'}
                aria-label={isExpanded ? 'Collapse' : 'Expand to full screen'}
                onClick={() => setIsExpanded((v) => !v)}
                display="empty"
              />
            </EuiToolTip>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiTabbedContent
          tabs={[
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <EuiDescriptionList type="column" compressed>
                    <EuiDescriptionListTitle>Status</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      <StatusBadge status={caseDoc.status} />
                    </EuiDescriptionListDescription>
                    <EuiDescriptionListTitle>Created</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {caseDoc.created_by} at {new Date(caseDoc.created_at).toLocaleString()}
                    </EuiDescriptionListDescription>
                    {caseDoc.updated_by && (
                      <>
                        <EuiDescriptionListTitle>Last updated</EuiDescriptionListTitle>
                        <EuiDescriptionListDescription>
                          {caseDoc.updated_by} at {new Date(caseDoc.updated_at!).toLocaleString()}
                        </EuiDescriptionListDescription>
                      </>
                    )}
                  </EuiDescriptionList>

                  <EuiSpacer size="m" />
                  <EuiFormRow label="Title" fullWidth>
                    <EuiFieldText fullWidth value={title} onChange={(e) => setTitle(e.target.value)} />
                  </EuiFormRow>
                  <EuiFormRow label="Description" fullWidth>
                    <EuiTextArea fullWidth value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
                  </EuiFormRow>
                  <EuiButton size="s" onClick={() => update({ title, description })} isLoading={busy}>
                    Save
                  </EuiButton>

                  <EuiSpacer size="m" />
                  <EuiFormRow label="Severity">
                    <EuiSelect
                      options={CASE_SEVERITY_OPTIONS}
                      value={caseDoc.severity}
                      onChange={(e) => update({ severity: e.target.value as Case['severity'] })}
                      disabled={busy}
                    />
                  </EuiFormRow>
                  <EuiFormRow label="Status">
                    <EuiSelect
                      options={[
                        { value: 'open', text: 'Open' },
                        { value: 'closed', text: 'Closed' },
                      ]}
                      value={caseDoc.status}
                      onChange={(e) => update({ status: e.target.value as Case['status'] })}
                      disabled={busy}
                    />
                  </EuiFormRow>
                  <EuiFormRow label="Assigned to">
                    <AssigneePicker
                      apiService={apiService}
                      value={caseDoc.assigned_to}
                      onChange={(assignee) => update({ assignedTo: assignee })}
                      compressed={false}
                    />
                  </EuiFormRow>
                </div>
              ),
            },
            {
              id: 'alerts',
              name: `Linked Alerts (${alerts.length})`,
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <EuiBasicTable
                    items={alerts}
                    columns={[
                      {
                        field: '_source',
                        name: 'Timestamp',
                        render: (v: Alert['_source']) => new Date(v['@timestamp']).toLocaleString(),
                      },
                      { field: '_source', name: 'Rule', render: (v: Alert['_source']) => v.rule?.description || 'N/A' },
                      { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || 'N/A' },
                      {
                        field: '_source',
                        name: 'Status',
                        render: (v: Alert['_source']) => <StatusBadge status={v.status} />,
                      },
                      {
                        name: 'Actions',
                        actions: [
                          {
                            render: (alert: Alert) => (
                              <>
                                <EuiButtonIcon iconType="eye" aria-label="View" onClick={() => onOpenAlert?.(alert)} />
                                <EuiButtonIcon
                                  iconType="unlink"
                                  aria-label="Remove from case"
                                  onClick={() => update({ removeAlertIds: [alert._id] })}
                                />
                              </>
                            ),
                          },
                        ],
                      },
                    ]}
                  />
                </div>
              ),
            },
            {
              id: 'comments',
              name: 'Comments',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <CommentsThread apiService={apiService} target={{ caseId }} onError={onError} />
                </div>
              ),
            },
            {
              id: 'history',
              name: 'History',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <HistoryList history={caseDoc.history} />
                </div>
              ),
            },
          ]}
        />
      </EuiFlyoutBody>
    </EuiFlyout>
  );
};
