import React, { useState } from 'react';
import { EuiBasicTable, EuiSpacer, EuiText, EuiFieldSearch, EuiButton, EuiCheckbox } from '@elastic/eui';
import { Alert } from '../../common';
import { AlertsApiService } from '../services/api';
import { formatAbsolute } from '../design';

interface Props {
  apiService: AlertsApiService;
  excludeIds?: string[];
  onLinkSelected: (ids: string[]) => Promise<void> | void;
  linking: boolean;
  buttonLabel?: string;
  title?: string;
  searchPlaceholder?: string;
  /** 'console' renders the case flyout's redesigned look (with rule IDs); 'default' keeps the standard dashboard UI. */
  variant?: 'default' | 'console';
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
  variant = 'default',
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

  if (variant === 'console') {
    const anyChecked = Object.values(checked).some(Boolean);
    return (
      <div>
        <h2 className="wamAg__addh">{title}</h2>
        <form
          className="wamAg__srch"
          role="search"
          onSubmit={(e) => { e.preventDefault(); runSearch(); }}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></svg>
          <input
            type="search"
            aria-label={title}
            placeholder={searchPlaceholder}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searching && <span className="wamAg__spin" aria-label="Searching" />}
        </form>
        {searchTerm && !searching && results.length === 0 && (
          <p className="wamAg__empty wamAg__pickmsg">No matching alerts. Press Enter to search.</p>
        )}
        {results.length > 0 && (
          <>
            <div className="wamAg__tw wamAg__pick">
              <table className="wamAg__at wamAg__at--mini">
                <thead>
                  <tr><th aria-label="Select" /><th>Timestamp</th><th>Rule ID</th><th>Agent</th><th className="wamAg__desc">Description</th></tr>
                </thead>
                <tbody>
                  {results.map((a) => (
                    <tr key={a._id}>
                      <td>
                        <input
                          type="checkbox"
                          id={`link-${a._id}`}
                          aria-label={`Select ${a._source.rule?.description || a._id}`}
                          checked={!!checked[a._id]}
                          onChange={(e) => setChecked({ ...checked, [a._id]: e.target.checked })}
                        />
                      </td>
                      <td className="wamAg__ts">{formatAbsolute(a._source['@timestamp'])}</td>
                      <td>{a._source.rule?.id ? <span className="wamAg__rid" title="Wazuh rule ID">{a._source.rule.id}</span> : '—'}</td>
                      <td>{a._source.agent?.name || '—'}</td>
                      <td className="wamAg__desc">{a._source.rule?.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <button type="button" className="wamAg__btn wamAg__btn--primary" onClick={linkChecked} disabled={linking || !anyChecked}>
              {linking ? 'Adding…' : buttonLabel}
            </button>
          </>
        )}
      </div>
    );
  }

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
              { field: '_source', name: 'Timestamp', render: (v: Alert['_source']) => formatAbsolute(v['@timestamp']) },
              { field: '_source', name: 'Rule ID', width: '90px', render: (v: Alert['_source']) => v.rule?.id || '—' },
              { field: '_source', name: 'Rule', render: (v: Alert['_source']) => v.rule?.description || '—' },
              { field: '_source', name: 'Agent', render: (v: Alert['_source']) => v.agent?.name || '—' },
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
