import React, { useState, useEffect, useCallback } from 'react';
import { EuiBasicTable, EuiSpacer, EuiText, EuiButtonIcon, EuiLoadingSpinner } from '@elastic/eui';
import { Alert } from '../../common';
import { AlertsApiService } from '../services/api';
import { AlertMultiPicker } from './alert_multi_picker';

interface Props {
  alertId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
  onToast?: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
  onOpenAlert: (alert: Alert) => void;
}

export const RelatedAlertsPanel: React.FC<Props> = ({ alertId, apiService, onError, onToast, onOpenAlert }) => {
  const [related, setRelated] = useState<Alert[]>([]);
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
            { field: '_source', name: 'Timestamp', render: (v: Alert['_source']) => new Date(v['@timestamp']).toLocaleString() },
            { field: '_source', name: 'Rule', render: (v: Alert['_source']) => v.rule?.description || 'N/A' },
            { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || 'N/A' },
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
