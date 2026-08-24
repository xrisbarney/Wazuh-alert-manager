import React, { useState } from 'react';
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
  EuiCodeBlock,
  EuiAccordion,
  EuiPanel,
  EuiText,
  EuiLink,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonIcon,
  EuiToolTip,
} from '@elastic/eui';
import { Alert, AiAnalysis } from '../../common';
import { AlertsApiService } from '../services/api';
import { StatusBadge, STATUS_OPTIONS } from './status_badge';
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
}

const renderNestedObject = (obj: any, depth = 0): React.ReactNode => {
  if (obj === null || obj === undefined) return null;
  if (typeof obj === 'object') {
    return (
      <EuiPanel paddingSize="s" hasShadow={false} style={{ margin: '5px 0' }}>
        {Object.entries(obj).map(([key, value]) => (
          <div key={key} style={{ marginLeft: depth > 0 ? 15 : 0 }}>
            <EuiText size="s">
              <strong>{key}:</strong>
            </EuiText>
            {typeof value === 'object' ? renderNestedObject(value, depth + 1) : <EuiText size="s" style={{ marginLeft: 10 }}>{String(value)}</EuiText>}
          </div>
        ))}
      </EuiPanel>
    );
  }
  return <EuiText size="s">{String(obj)}</EuiText>;
};

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
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <EuiFlyout onClose={onClose} size={isExpanded ? '95vw' : 'm'} aria-labelledby="alert-details-flyout">
      <EuiFlyoutHeader hasBorder>
        <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
          <EuiFlexItem>
            <EuiTitle size="m">
              <h2>Alert Details</h2>
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
                    <EuiDescriptionListTitle>Alert ID</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>{alert._id}</EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Timestamp</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>{new Date(alert._source['@timestamp']).toLocaleString()}</EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Status</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      <StatusBadge status={alert._source.status} />
                    </EuiDescriptionListDescription>

                    <EuiDescriptionListTitle>Agent</EuiDescriptionListTitle>
                    <EuiDescriptionListDescription>
                      {alert._source.agent?.name} ({alert._source.agent?.ip})
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
                          {alert._source.updated_by} at {new Date(alert._source.updated_at!).toLocaleString()}
                        </EuiDescriptionListDescription>
                      </>
                    )}
                  </EuiDescriptionList>

                  <EuiSpacer size="l" />

                  <EuiFlexGroup gutterSize="m" style={isExpanded ? { maxWidth: 600 } : undefined}>
                    <EuiFlexItem>
                      <EuiText size="xs" color="subdued">
                        Status
                      </EuiText>
                      <EuiSelect
                        options={STATUS_OPTIONS}
                        value={alert._source.status}
                        onChange={(e) => onStatusChange(e.target.value)}
                        disabled={updating}
                        fullWidth
                      />
                    </EuiFlexItem>
                    <EuiFlexItem>
                      <EuiText size="xs" color="subdued">
                        Assigned to
                      </EuiText>
                      <AssigneePicker
                        apiService={apiService}
                        value={alert._source.assigned_to}
                        onChange={onAssigneeChange}
                        fullWidth
                        compressed={false}
                      />
                    </EuiFlexItem>
                  </EuiFlexGroup>
                  {updating && <EuiLoadingSpinner size="s" />}

                  <EuiSpacer size="m" />
                  <EuiFlexGroup gutterSize="s" alignItems="flexEnd" style={isExpanded ? { maxWidth: 600 } : undefined}>
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
                        <EuiLink onClick={() => onOpenCase?.(alert._source.case_id!)}>Open case</EuiLink>
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
              name: 'Detailed Data',
              content: (
                <div>
                  <EuiSpacer size="m" />
                  {Object.entries(alert._source).map(([key, value]) => (
                    <EuiAccordion key={key} id={key} buttonContent={key} paddingSize="m">
                      {typeof value === 'object' ? (
                        renderNestedObject(value)
                      ) : (
                        <EuiCodeBlock language="json" fontSize="m" paddingSize="s">
                          {JSON.stringify(value, null, 2)}
                        </EuiCodeBlock>
                      )}
                    </EuiAccordion>
                  ))}
                </div>
              ),
            },
            {
              id: 'raw',
              name: 'Raw JSON',
              content: (
                <EuiCodeBlock language="json" isCopyable>
                  {JSON.stringify(alert, null, 2)}
                </EuiCodeBlock>
              ),
            },
          ]}
        />
      </EuiFlyoutBody>
    </EuiFlyout>
  );
};
