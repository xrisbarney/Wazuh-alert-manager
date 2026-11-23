import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiLoadingSpinner,
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiToolTip,
} from '@elastic/eui';
import { Alert } from '../../common';
import { AlertsApiService } from '../services/api';
import { AlertMultiPicker } from './alert_multi_picker';
import { formatAbsolute } from '../design';

interface Suggested {
  _id: string;
  _source: any;
  reasons: string[];
  score: number;
}

interface Props {
  alertId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onOpenAlert: (alert: Alert) => void;
  /** Reports the linked (not suggested) total after every load, for the flyout's section rail (11.1). */
  onCountChanged?: (total: number) => void;
}

/**
 * One related / suggested alert on the shared history grid (step 8.2):
 * time | description + agent + shared keys | actions. The same row classes
 * as the audit history so the two lists align inside the flyout.
 */
const RelatedAlertRow: React.FC<{
  source: any;
  reasons?: string[];
  actions: React.ReactNode;
  testSubj: string;
}> = ({ source, reasons, actions, testSubj }) => (
  <li className="wamHistoryRow wamHistoryRow--actions" data-test-subj={testSubj}>
    <span className="wamHistoryRow__time" title={source?.['@timestamp']}>
      {formatAbsolute(source?.['@timestamp'])}
    </span>
    <div className="wamHistoryRow__body">
      <EuiText size="s" className="wamHistoryRow__event">
        <span className="wamHistoryRow__actor">{source?.agent?.name || '—'}</span>{' '}
        <span className="wamHistoryRow__action">{source?.rule?.description || '—'}</span>
      </EuiText>
      {reasons && reasons.length > 0 ? (
        <span className="wamHistoryRow__details wamHistoryRow__chips">
          {reasons.map((r) => (
            <EuiBadge color="hollow" key={r}>
              {r}
            </EuiBadge>
          ))}
        </span>
      ) : null}
    </div>
    <span className="wamHistoryRow__actions">{actions}</span>
  </li>
);

export const RelatedAlertsPanel: React.FC<Props> = ({ alertId, apiService, onError, onToast, onOpenAlert, onCountChanged }) => {
  const [related, setRelated] = useState<Alert[]>([]);
  const [suggested, setSuggested] = useState<Suggested[]>([]);
  const [loading, setLoading] = useState(true);
  const [linking, setLinking] = useState(false);
  // Held in a ref so an inline callback from the host never re-keys `load`
  // (and the mount effect) — the list is fetched once per alert id.
  const onCountRef = useRef(onCountChanged);
  useEffect(() => {
    onCountRef.current = onCountChanged;
  });

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchRelatedAlerts(alertId);
      const alerts: Alert[] = res?.alerts || [];
      setRelated(alerts);
      onCountRef.current?.(alerts.length);
    } catch (e) {
      onError('Failed to load related alerts');
    } finally {
      setLoading(false);
    }
    // Suggestions are advisory — a failure here shouldn't disturb the panel.
    try {
      const sug: any = await apiService.fetchSuggestedAlerts(alertId);
      setSuggested(sug?.alerts || []);
    } catch (e) {
      setSuggested([]);
    }
  }, [alertId]);

  useEffect(() => {
    load();
  }, [load]);

  const linkSelected = async (ids: string[]) => {
    try {
      setLinking(true);
      await apiService.updateRelatedAlerts(alertId, ids, 'add');
      await load();
      onToast?.(`Linked ${ids.length} alert(s)`, 'success');
    } catch (e) {
      onError('Failed to link alerts');
    } finally {
      setLinking(false);
    }
  };

  const linkOne = async (id: string) => {
    try {
      setLinking(true);
      await apiService.updateRelatedAlerts(alertId, [id], 'add');
      await load();
      onToast?.('Alert linked', 'success');
    } catch (e) {
      onError('Failed to link alert');
    } finally {
      setLinking(false);
    }
  };

  const unlink = async (id: string) => {
    try {
      await apiService.updateRelatedAlerts(alertId, [id], 'remove');
      await load();
      onToast?.('Alert unlinked', 'success');
    } catch (e) {
      onError('Failed to unlink alert');
    }
  };

  return (
    <div className="wamRelatedAlerts" data-test-subj="wamRelatedAlerts">
      <EuiPanel hasBorder paddingSize="m" className="wamRelatedAlertsPanel" data-test-subj="wamRelatedLinked">
        <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} className="wamPanelHeader">
          <EuiFlexItem>
            <EuiTitle size="xs">
              <h3>Currently linked</h3>
            </EuiTitle>
          </EuiFlexItem>
          {related.length > 0 ? (
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued">
                {related.length} linked
              </EuiText>
            </EuiFlexItem>
          ) : null}
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        {loading ? (
          <EuiLoadingSpinner size="m" />
        ) : related.length === 0 ? (
          <EuiText size="s" color="subdued">
            No related alerts linked yet.
          </EuiText>
        ) : (
          <ol className="wamHistoryList" data-test-subj="wamRelatedLinkedList">
            {related.map((a) => (
              <RelatedAlertRow
                key={a._id}
                source={a._source}
                testSubj="wamRelatedLinkedRow"
                actions={
                  <>
                    <EuiToolTip content="View">
                      <EuiButtonIcon iconType="eye" aria-label="View" onClick={() => onOpenAlert(a)} />
                    </EuiToolTip>
                    <EuiToolTip content="Unlink">
                      <EuiButtonIcon iconType="unlink" aria-label="Unlink" onClick={() => unlink(a._id)} />
                    </EuiToolTip>
                  </>
                }
              />
            ))}
          </ol>
        )}
      </EuiPanel>

      {suggested.length > 0 && (
        <>
          <EuiSpacer size="m" />
          <EuiPanel hasBorder paddingSize="m" className="wamRelatedAlertsPanel" data-test-subj="wamRelatedSuggested">
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} className="wamPanelHeader">
              <EuiFlexItem>
                <EuiTitle size="xs">
                  <h3>Suggested</h3>
                </EuiTitle>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="s" />
            <EuiText size="xs" color="subdued">
              Alerts near this one in time that share a host, source IP, user, or rule. Ranked by overlap.
            </EuiText>
            <EuiSpacer size="s" />
            <ol className="wamHistoryList" data-test-subj="wamRelatedSuggestedList">
              {suggested.map((s) => (
                <RelatedAlertRow
                  key={s._id}
                  source={s._source}
                  reasons={s.reasons}
                  testSubj="wamRelatedSuggestedRow"
                  actions={
                    <>
                      <EuiToolTip content="View">
                        <EuiButtonIcon iconType="eye" aria-label="View" onClick={() => onOpenAlert({ _id: s._id, _source: s._source })} />
                      </EuiToolTip>
                      <EuiButtonEmpty size="xs" iconType="link" onClick={() => linkOne(s._id)} isDisabled={linking}>
                        Link
                      </EuiButtonEmpty>
                    </>
                  }
                />
              ))}
            </ol>
          </EuiPanel>
        </>
      )}

      <EuiSpacer size="m" />
      <EuiPanel hasBorder paddingSize="m" className="wamRelatedAlertsPanel" data-test-subj="wamRelatedPicker">
        <AlertMultiPicker
          apiService={apiService}
          excludeIds={[alertId]}
          onLinkSelected={linkSelected}
          linking={linking}
          buttonLabel="Link selected"
          title="Link another alert"
        />
      </EuiPanel>
    </div>
  );
};
