import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBasicTable,
  EuiSpacer,
  EuiText,
  EuiButtonIcon,
  EuiButton,
  EuiLoadingSpinner,
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHorizontalRule,
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
}

export const RelatedAlertsPanel: React.FC<Props> = ({ alertId, apiService, onError, onToast, onOpenAlert }) => {
  const [related, setRelated] = useState<Alert[]>([]);
  const [suggested, setSuggested] = useState<Suggested[]>([]);
  const [loading, setLoading] = useState(true);
  const [linking, setLinking] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res: any = await apiService.fetchRelatedAlerts(alertId);
      setRelated(res?.alerts || []);
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
    <div>
      <EuiText size="s">
        <h4>Currently linked</h4>
      </EuiText>
      <EuiSpacer size="s" />
      {loading ? (
        <EuiLoadingSpinner size="m" />
      ) : related.length === 0 ? (
        <EuiText size="s" color="subdued">
          No related alerts linked yet.
        </EuiText>
      ) : (
        <EuiBasicTable
          items={related}
          columns={[
            { field: '_source', name: 'Timestamp', render: (v: Alert['_source']) => formatAbsolute(v['@timestamp']) },
            { field: '_source', name: 'Rule', render: (v: Alert['_source']) => v.rule?.description || '—' },
            { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || '—' },
            {
              name: 'Actions',
              actions: [
                { render: (a: Alert) => <EuiButtonIcon iconType="eye" aria-label="View" onClick={() => onOpenAlert(a)} /> },
                { render: (a: Alert) => <EuiButtonIcon iconType="unlink" aria-label="Unlink" onClick={() => unlink(a._id)} /> },
              ],
            },
          ]}
        />
      )}

      {suggested.length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiHorizontalRule margin="none" />
          <EuiSpacer size="m" />
          <EuiText size="s">
            <h4>Suggested</h4>
          </EuiText>
          <EuiText size="xs" color="subdued">
            Alerts near this one in time that share a host, source IP, user, or rule. Ranked by overlap.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={suggested}
            columns={[
              { field: '_source', name: 'Timestamp', render: (v: any) => formatAbsolute(v['@timestamp']) },
              { field: '_source', name: 'Rule', render: (v: any) => v.rule?.description || '—' },
              {
                name: 'Shared',
                render: (s: Suggested) => (
                  <EuiFlexGroup gutterSize="xs" wrap responsive={false}>
                    {s.reasons.map((r) => (
                      <EuiFlexItem grow={false} key={r}>
                        <EuiBadge color="hollow">{r}</EuiBadge>
                      </EuiFlexItem>
                    ))}
                  </EuiFlexGroup>
                ),
              },
              {
                name: 'Actions',
                width: '150px',
                actions: [
                  { render: (s: Suggested) => <EuiButtonIcon iconType="eye" aria-label="View" onClick={() => onOpenAlert({ _id: s._id, _source: s._source })} /> },
                  {
                    render: (s: Suggested) => (
                      <EuiButton size="s" iconType="link" onClick={() => linkOne(s._id)} isDisabled={linking}>
                        Link
                      </EuiButton>
                    ),
                  },
                ],
              },
            ]}
          />
        </>
      )}

      <EuiSpacer size="l" />
      <AlertMultiPicker
        apiService={apiService}
        excludeIds={[alertId]}
        onLinkSelected={linkSelected}
        linking={linking}
        buttonLabel="Link selected"
        title="Link another alert"
      />
    </div>
  );
};
