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
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiCallOut,
  EuiCheckbox,
  EuiButtonEmpty,
} from '@elastic/eui';
import { Alert, Case, AiAnalysis } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge, CASE_SEVERITY_OPTIONS } from './status_badge';
import { CommentsThread } from './comments_thread';
import { HistoryList } from './history_list';
import { AssigneePicker } from './assignee_picker';
import { AttackPathView } from './attack_path_view';
import { AlertMultiPicker } from './alert_multi_picker';
import { AiAnalysisTab } from './ai_analysis_tab';

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onClose: () => void;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onChanged: () => void;
  onOpenAlert?: (alert: Alert) => void;
}

function describeCaseUpdate(payload: Record<string, any>): string {
  if (payload.status != null) return payload.status === 'closed' ? 'Case closed' : 'Case reopened';
  if (payload.assignedTo !== undefined) return payload.assignedTo ? `Assigned to ${payload.assignedTo}` : 'Unassigned';
  if (payload.addAlertIds?.length) return 'Alert added to case';
  if (payload.removeAlertIds?.length) return 'Alert removed from case';
  if (payload.severity != null) return 'Severity updated';
  return 'Case updated';
}

export const CaseFlyout: React.FC<Props> = ({ caseId, apiService, onClose, onError, onToast, onChanged, onOpenAlert }) => {
  const [loading, setLoading] = useState(true);
  const [caseDoc, setCaseDoc] = useState<Case | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [busy, setBusy] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);
  const [closeConfirm, setCloseConfirm] = useState<{ openAlerts: Alert[]; excluded: Set<string> } | null>(null);

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
      onToast?.(describeCaseUpdate(payload), 'success');
    } catch (e) {
      onError('Failed to update case');
    } finally {
      setBusy(false);
      load();
    }
  };

  const requestStatusChange = (status: Case['status']) => {
    if (status === 'closed' && caseDoc?.status !== 'closed') {
      const openAlerts = alerts.filter((a) => a._source.status !== 'closed');
      if (openAlerts.length > 0) {
        setCloseConfirm({ openAlerts, excluded: new Set() });
        return;
      }
    }
    update({ status });
  };

  const confirmClose = async () => {
    if (!closeConfirm) return;
    const idsToClose = closeConfirm.openAlerts
      .map((a) => a._id)
      .filter((id) => !closeConfirm.excluded.has(id));
    try {
      setBusy(true);
      const updated: any = await apiService.updateCase(caseId, { status: 'closed' });
      setCaseDoc(updated);
      if (idsToClose.length) {
        await apiService.bulkUpdateAlerts(idsToClose, { status: 'closed' });
      }
      onChanged();
      onToast?.(
        'Case closed',
        'success',
        idsToClose.length ? `Closed ${idsToClose.length} linked alert(s) with it.` : undefined
      );
    } catch (e) {
      onError('Failed to close case');
    } finally {
      setBusy(false);
      setCloseConfirm(null);
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
    <>
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
                      onChange={(e) => requestStatusChange(e.target.value as Case['status'])}
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
                  <EuiSpacer size="l" />
                  <AlertMultiPicker
                    apiService={apiService}
                    excludeIds={caseDoc.alert_ids}
                    onLinkSelected={(ids) => update({ addAlertIds: ids })}
                    linking={busy}
                    buttonLabel="Add to case"
                    title="Add an existing alert to this case"
                  />
                </div>
              ),
            },
            {
              id: 'attack-path',
              name: 'Attack Path',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <AttackPathView caseId={caseId} apiService={apiService} onError={onError} />
                </div>
              ),
            },
            {
              id: 'ai',
              name: 'AI Analysis',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <AiAnalysisTab
                    analysis={caseDoc.ai_analysis}
                    apiService={apiService}
                    onGenerate={() => apiService.analyzeCase(caseId) as Promise<AiAnalysis>}
                    onGenerated={(analysis) => {
                      setCaseDoc((prev) => (prev ? { ...prev, ai_analysis: analysis } : prev));
                      onChanged();
                    }}
                    onError={onError}
                    onToast={onToast}
                    emptyMessage="No AI analysis generated yet for this case. It will summarize all linked alerts and comments together."
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
                  <CommentsThread apiService={apiService} target={{ caseId }} onError={onError} onToast={onToast} />
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
    {closeConfirm && (
      <EuiModal onClose={() => setCloseConfirm(null)}>
        <EuiModalHeader>
          <EuiModalHeaderTitle>Close this case?</EuiModalHeaderTitle>
        </EuiModalHeader>
        <EuiModalBody>
          <EuiCallOut title="This will also close linked alerts" color="warning" iconType="alert">
            <p>
              {closeConfirm.openAlerts.length} linked alert{closeConfirm.openAlerts.length === 1 ? '' : 's'} still
              open will be closed along with this case. Uncheck any alert you want to leave open.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          {closeConfirm.openAlerts.map((a) => (
            <EuiCheckbox
              key={a._id}
              id={`close-with-case-${a._id}`}
              label={`${a._source.rule?.description || a._id} (${a._source.agent?.name || 'unknown agent'})`}
              checked={!closeConfirm.excluded.has(a._id)}
              onChange={(e) => {
                setCloseConfirm((prev) => {
                  if (!prev) return prev;
                  const excluded = new Set(prev.excluded);
                  if (e.target.checked) excluded.delete(a._id);
                  else excluded.add(a._id);
                  return { ...prev, excluded };
                });
              }}
            />
          ))}
        </EuiModalBody>
        <EuiModalFooter>
          <EuiButtonEmpty onClick={() => setCloseConfirm(null)}>Cancel</EuiButtonEmpty>
          <EuiButton color="danger" onClick={confirmClose} isLoading={busy} fill>
            {closeConfirm.openAlerts.length - closeConfirm.excluded.size > 0
              ? `Close case and ${closeConfirm.openAlerts.length - closeConfirm.excluded.size} alert(s)`
              : 'Close case'}
          </EuiButton>
        </EuiModalFooter>
      </EuiModal>
    )}
    </>
  );
};
