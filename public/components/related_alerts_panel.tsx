import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBasicTable,
  EuiSpacer,
  EuiText,
  EuiFieldSearch,
  EuiButtonIcon,
  EuiButton,
  EuiCheckbox,
  EuiLoadingSpinner,
} from '@elastic/eui';
import { Alert } from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  alertId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
  onOpenAlert: (alert: Alert) => void;
}

export const RelatedAlertsPanel: React.FC<Props> = ({ alertId, apiService, onError, onOpenAlert }) => {
  const [related, setRelated] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState<Alert[]>([]);
  const [searching, setSearching] = useState(false);
  const [checked, setChecked] = useState<Record<string, boolean>>({});
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

  const runSearch = async () => {
    if (!searchTerm.trim()) {
      setSearchResults([]);
      return;
    }
    try {
      setSearching(true);
      const hits = await apiService.searchAlertsQuick(searchTerm.trim(), alertId);
      setSearchResults(hits);
    } catch (e) {
      onError('Search failed');
    } finally {
      setSearching(false);
    }
  };

  const linkChecked = async () => {
    const ids = Object.entries(checked).filter(([, v]) => v).map(([id]) => id);
    if (ids.length === 0) return;
    try {
      setLinking(true);
      await apiService.updateRelatedAlerts(alertId, ids, 'add');
      setChecked({});
      setSearchTerm('');
      setSearchResults([]);
      await load();
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
      <EuiText size="s">
        <h4>Link another alert</h4>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFieldSearch
        placeholder="Search by rule description, agent, etc."
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        onSearch={runSearch}
        isLoading={searching}
        compressed
      />
      <EuiSpacer size="s" />
      {searchResults.length > 0 && (
        <>
          <EuiBasicTable
            items={searchResults}
            itemId="_id"
            columns={[
              {
                name: '',
                render: (a: Alert) => (
                  <EuiCheckbox
                    id={`link-${a._id}`}
                    checked={!!checked[a._id]}
                    onChange={(e) => setChecked({ ...checked, [a._id]: e.target.checked })}
                  />
                ),
              },
              { field: '_source', name: 'Timestamp', render: (v: Alert['_source']) => new Date(v['@timestamp']).toLocaleString() },
              { field: '_source', name: 'Rule', render: (v: Alert['_source']) => v.rule?.description || 'N/A' },
              { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || 'N/A' },
            ]}
          />
          <EuiSpacer size="s" />
          <EuiButton size="s" onClick={linkChecked} isLoading={linking} isDisabled={!Object.values(checked).some(Boolean)}>
            Link selected
          </EuiButton>
        </>
      )}
    </div>
  );
};
