import React, { useMemo, useState } from 'react';
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
  EuiFormRow,
  EuiCodeBlock,
  EuiText,
  EuiButton,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonIcon,
  EuiToolTip,
  EuiCallOut,
  EuiBasicTable,
  EuiFieldSearch,
  EuiBadge,
} from '@elastic/eui';
import { Alert, AiAnalysis } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge } from './status_badge';
import { StatusButtonGroup } from './status_button_group';
import { formatAbsolute } from '../design';
import { PrecedentCallout } from './precedent_callout';
import { CommentsThread } from './comments_thread';
import { HistoryList } from './history_list';
import { RelatedAlertsPanel } from './related_alerts_panel';
import { AiAnalysisTab } from './ai_analysis_tab';
import { AssigneePicker } from './assignee_picker';
import { CasePicker } from './case_picker';

interface Props {
  alert: Alert;
  apiService: AlertsApiService;
  updating: boolean;
  onClose: () => void;
  onStatusChange: (status: string) => void;
  onAssigneeChange: (assignee: string | null) => void;
  onCaseChange: (caseId: string | null) => void;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onOpenCase?: (caseId: string) => void;
  onOpenAlert?: (alert: Alert) => void;
  onAnalysisGenerated?: (alertId: string, analysis: AiAnalysis) => void;
  onAddFilter?: (field: string, value: unknown, negate: boolean) => void;
}

interface FieldRow { field: string; value: unknown; display: string; operational: boolean; }

function flattenFields(value: any, operational: boolean, prefix = '', rows: FieldRow[] = []): FieldRow[] {
  if (Array.isArray(value)) {
    if (value.length === 0) rows.push({ field: prefix, value, display: '[]', operational });
    for (const child of value) flattenFields(child, operational, prefix, rows);
  } else if (value != null && typeof value === 'object') {
    if (Object.keys(value).length === 0) rows.push({ field: prefix, value, display: '{}', operational });
    for (const [key, child] of Object.entries(value)) flattenFields(child, operational, prefix ? `${prefix}.${key}` : key, rows);
  } else {
    rows.push({
      field: prefix,
      value,
      display: value == null ? '—' : String(value),
      operational,
    });
  }
  return rows;
}

export const AlertFlyout: React.FC<Props> = ({
  alert,
  apiService,
  updating,
  onClose,
  onStatusChange,
  onAssigneeChange,
  onCaseChange,
  onError,
  onToast,
  onOpenCase,
  onOpenAlert,
  onAnalysisGenerated,
  onAddFilter,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [fieldSearch, setFieldSearch] = useState('');
  const fieldRows = useMemo(() => {
    const byField = new Map<string, FieldRow>();
    const rows = [
      ...flattenFields(alert._raw_source || {}, false),
      ...flattenFields(alert._source, true),
      ...flattenFields({ _id: alert._id, _index: alert._index }, false),
    ];
    // One row per path: the indexed operational projection is authoritative.
    for (const row of rows) byField.set(row.field, row);
    const query = fieldSearch.trim().toLowerCase();
    const uniqueRows = Array.from(byField.values()).sort((a, b) => a.field.localeCompare(b.field));
    return query
      ? uniqueRows.filter((row) => row.field.toLowerCase().includes(query) || row.display.toLowerCase().includes(query))
      : uniqueRows;
  }, [alert, fieldSearch]);
  const agentName = alert._source.agent?.name;
  const agentIp = alert._source.agent?.ip;
  const agentLabel = agentName && agentIp ? `${agentName} (${agentIp})` : agentName || agentIp || '—';

  return (
    <EuiFlyout onClose={onClose} size={isExpanded ? '95vw' : 'l'} aria-labelledby="alert-details-flyout" className="wamAlertFlyout">
      <EuiFlyoutHeader hasBorder>
        <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
          <EuiFlexItem>
            <EuiTitle size="m">
              <h2 id="alert-details-flyout">Alert details</h2>
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
          className="wamAlertFlyoutTabs"
          tabs={[
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <PrecedentCallout alertId={alert._id} apiService={apiService} />
                  <EuiSpacer size="s" />
                  <EuiDescriptionList type="column" compressed>
                    <EuiDescriptionListTitle>Alert ID</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription className="wamAlertId"><code>{alert._id}</code></EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Timestamp</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>{formatAbsolute(alert._source['@timestamp'])}</EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Status</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      <StatusBadge status={alert._source.status} />
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Agent</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {agentLabel}
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Rule</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {alert._source.rule?.description} (Level {alert._source.rule?.level})
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Manager</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>{alert._source.manager?.name}</EuiDescriptionListDescription>

                    {alert._source.updated_by && (
                      <>
                        <EuiDescriptionListTitle>Last updated</EuiDescriptionListTitle>
                        <EuiDescriptionListDescription>
                          {alert._source.updated_by} at {formatAbsolute(alert._source.updated_at)}
                        </EuiDescriptionListDescription>
                      </>
                    )}
                  </EuiDescriptionList>

                  <EuiSpacer size="l" />

                  <EuiFlexGroup gutterSize="m" alignItems="flexStart" wrap style={isExpanded ? { maxWidth: 600 } : undefined}>
                    <EuiFlexItem grow={false}>
                      <EuiFormRow label="Status" display="rowCompressed">
                        <StatusButtonGroup
                          status={alert._source.status}
                          disabled={updating}
                          idPrefix={`fly-${alert._id}`}
                          onChange={(s) => onStatusChange(s)}
                        />
                      </EuiFormRow>
                    </EuiFlexItem>
                    <EuiFlexItem>
                      <EuiFormRow label="Assigned to" display="rowCompressed" fullWidth>
                        <AssigneePicker
                          apiService={apiService}
                          value={alert._source.assigned_to}
                          onChange={onAssigneeChange}
                          fullWidth
                          compressed={false}
                        />
                      </EuiFormRow>
                    </EuiFlexItem>
                  </EuiFlexGroup>

                  <EuiSpacer size="m" />
                  <EuiFlexGroup gutterSize="s" alignItems="flexEnd" wrap style={isExpanded ? { maxWidth: 600 } : undefined}>
                    <EuiFlexItem>
                      <EuiText size="xs" color="subdued">
                        Case
                      </EuiText>
                      <CasePicker
                        apiService={apiService}
                        value={alert._source.case_id}
                        onChange={(caseId) => onCaseChange(caseId)}
                        fullWidth
                        compressed={false}
                      />
                    </EuiFlexItem>
                    {alert._source.case_id && (
                      <EuiFlexItem grow={false}>
                        <EuiButton
                          size="s"
                          iconType="folderOpen"
                          onClick={() => onOpenCase?.(alert._source.case_id!)}
                        >
                          Open case
                        </EuiButton>
                      </EuiFlexItem>
                    )}
                  </EuiFlexGroup>
                </div>
              ),
            },
            {
              id: 'comments',
              name: 'Comments',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <CommentsThread
                    apiService={apiService}
                    target={{ alertId: alert._id }}
                    onError={onError}
                    onToast={onToast}
                  />
                </div>
              ),
            },
            {
              id: 'related',
              name: 'Related Alerts',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <RelatedAlertsPanel
                    alertId={alert._id}
                    apiService={apiService}
                    onError={onError}
                    onToast={onToast}
                    onOpenAlert={(a) => onOpenAlert?.(a)}
                  />
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
                    analysis={alert._source.ai_analysis}
                    apiService={apiService}
                    onGenerate={() => apiService.analyzeAlert(alert._id) as Promise<AiAnalysis>}
                    onGenerated={(analysis) => onAnalysisGenerated?.(alert._id, analysis)}
                    onError={onError}
                    onToast={onToast}
                    emptyMessage="No AI analysis generated yet for this alert."
                  />
                </div>
              ),
            },
            {
              id: 'history',
              name: 'History',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <HistoryList history={alert._source.history} />
                </div>
              ),
            },
            {
              id: 'details',
              name: 'Fields',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  <EuiFieldSearch
                    fullWidth
                    compressed
                    placeholder="Search fields or values"
                    value={fieldSearch}
                    onChange={(event) => setFieldSearch(event.target.value)}
                    aria-label="Search alert fields and values"
                  />
                  <EuiSpacer size="s" />
                  <EuiText size="xs" color="subdued">
                    {fieldRows.length.toLocaleString()} matching field{fieldRows.length === 1 ? '' : 's'}. Only operational fields can be added to the alert query.
                  </EuiText>
                  <EuiSpacer size="xs" />
                  <EuiBasicTable
                    className="wamDocumentFields"
                    tableCaption="Alert document fields"
                    items={fieldRows}
                    columns={[
                      { field: 'field', name: 'Field', width: '38%', render: (value: string) => <code className="wamFieldName">{value}</code> },
                      { field: 'display', name: 'Value', render: (value: string) => <span className="wamFieldValue">{value}</span> },
                      { field: 'operational', name: 'Source', width: '105px', render: (value: boolean) => <EuiBadge color={value ? 'primary' : 'hollow'}>{value ? 'Operational' : 'Raw only'}</EuiBadge> },
                      {
                        name: 'Filter', width: '82px', align: 'right',
                        render: (row: FieldRow) => onAddFilter && row.operational && row.value != null && typeof row.value !== 'object' ? (
                          <>
                            <EuiToolTip content="Filter for this value"><EuiButtonIcon iconType="plusInCircle" aria-label={`Filter for ${row.field}`} onClick={() => onAddFilter(row.field, row.value, false)} /></EuiToolTip>
                            <EuiToolTip content="Exclude this value"><EuiButtonIcon iconType="minusInCircle" aria-label={`Exclude ${row.field}`} onClick={() => onAddFilter(row.field, row.value, true)} /></EuiToolTip>
                          </>
                        ) : null,
                      },
                    ] as any}
                  />
                </div>
              ),
            },
            {
              id: 'raw',
              name: 'Raw JSON',
              content: (
                <>
                  {alert._source_available === false && (
                    <>
                      <EuiCallOut
                        size="s"
                        color="warning"
                        iconType="clock"
                        title="Original Wazuh evidence is no longer available"
                      >
                        The compact operational record is retained, but its native Wazuh source document could not be retrieved.
                      </EuiCallOut>
                      <EuiSpacer size="s" />
                    </>
                  )}
                  <EuiCodeBlock language="json" isCopyable>
                    {JSON.stringify(alert._raw_source || alert._source, null, 2)}
                  </EuiCodeBlock>
                </>
              ),
            },
          ]}
        />
      </EuiFlyoutBody>
    </EuiFlyout>
  );
};
