import React, { useState } from 'react';
import { EuiBasicTable, EuiSpacer, EuiText, EuiFieldSearch, EuiButton, EuiCheckbox } from '@elastic/eui';
import { Alert } from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  excludeIds?: string[];
  onLinkSelected: (ids: string[]) => Promise<void> | void;
  linking: boolean;
  buttonLabel?: string;
  title?: string;
  searchPlaceholder?: string;
}

/**
 * Search-and-select-multiple picker for alerts, by rule description,
 * agent, rule ID, or a pasted alert ID (see AlertsApiService.searchAlertsQuick).
 * Shared by the alert flyout's "Related Alerts" tab and the case flyout's
 * "Linked Alerts" tab - same interaction, different target for the ids.
 */
export const AlertMultiPicker: React.FC<Props> = ({
  apiService,
  excludeIds = [],
  onLinkSelected,
  linking,
  buttonLabel = 'Link selected',
  title = 'Search for alerts',
  searchPlaceholder = 'Search by rule description, agent, rule ID, or paste an alert ID',
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [results, setResults] = useState<Alert[]>([]);
  const [searching, setSearching] = useState(false);
  const [checked, setChecked] = useState<Record<string, boolean>>({});

  const runSearch = async () => {
    if (!searchTerm.trim()) {
      setResults([]);
      return;
    }
    try {
      setSearching(true);
      const hits = await apiService.searchAlertsQuick(searchTerm.trim());
      setResults(hits.filter((h: Alert) => !excludeIds.includes(h._id)));
    } finally {
      setSearching(false);
    }
  };

  const linkChecked = async () => {
    const ids = Object.entries(checked).filter(([, v]) => v).map(([id]) => id);
    if (ids.length === 0) return;
    await onLinkSelected(ids);
    setChecked({});
    setSearchTerm('');
    setResults([]);
  };

  return (
    <div>
      <EuiText size="s">
        <h4>{title}</h4>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFieldSearch
        placeholder={searchPlaceholder}
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        onSearch={runSearch}
        isLoading={searching}
        compressed
      />
      <EuiSpacer size="s" />
      {searchTerm && !searching && results.length === 0 && (
        <EuiText size="s" color="subdued">
          No matching alerts.
        </EuiText>
      )}
      {results.length > 0 && (
        <>
          <EuiBasicTable
            items={results}
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
            {buttonLabel}
          </EuiButton>
        </>
      )}
    </div>
  );
};
