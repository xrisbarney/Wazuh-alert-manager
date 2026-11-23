import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLink,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  DISCOVER_APP_PATH,
  REPORTING_APP_PATH,
  SAVED_OBJECTS_MANAGEMENT_PATH,
  SavedObjectsBridgeStatus,
  TARGET_OSD_VERSION,
  WAM_ALERTS_INDEX_PATTERN_ID,
  WAM_CASES_INDEX_PATTERN_ID,
  WAM_OPEN_ALERTS_COLUMNS,
  WAM_OPEN_ALERTS_SEARCH_ID,
  WAM_OPEN_CASES_COLUMNS,
  WAM_OPEN_CASES_SEARCH_ID,
  discoverIndexPatternUrl,
  discoverSavedSearchUrl,
} from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
}

export interface DiscoverBridgeLinks {
  discoverApp: string;
  reportingApp: string;
  savedObjects: string;
  /** Deep links exist only when the target dashboard's Discover URL shape is known (OSD 2.10+). */
  alertsPattern: string | null;
  casesPattern: string | null;
  openAlertsSearch: string | null;
  openCasesSearch: string | null;
}

/**
 * Links built in the browser from the build target so server.basePath is
 * honoured; the deep links are hidden (null) when the Discover URL shape of
 * the target dashboard is uncertain (OSD 3.x) and only the app link remains.
 */
export function discoverBridgeLinks(apiService: Pick<AlertsApiService, 'appUrl'>, osdVersion: string = TARGET_OSD_VERSION): DiscoverBridgeLinks {
  const prepend = (path: string | null) => (path == null ? null : apiService.appUrl(path));
  return {
    discoverApp: apiService.appUrl(DISCOVER_APP_PATH),
    reportingApp: apiService.appUrl(REPORTING_APP_PATH),
    savedObjects: apiService.appUrl(SAVED_OBJECTS_MANAGEMENT_PATH),
    alertsPattern: prepend(
      discoverIndexPatternUrl(WAM_ALERTS_INDEX_PATTERN_ID, {
        columns: WAM_OPEN_ALERTS_COLUMNS,
        sortField: '@timestamp',
        timeFrom: 'now-24h',
        timeTo: 'now',
        osdVersion,
      })
    ),
    casesPattern: prepend(
      discoverIndexPatternUrl(WAM_CASES_INDEX_PATTERN_ID, {
        columns: WAM_OPEN_CASES_COLUMNS,
        sortField: 'created_at',
        timeFrom: 'now-30d',
        timeTo: 'now',
        osdVersion,
      })
    ),
    openAlertsSearch: prepend(discoverSavedSearchUrl(WAM_OPEN_ALERTS_SEARCH_ID, osdVersion)),
    openCasesSearch: prepend(discoverSavedSearchUrl(WAM_OPEN_CASES_SEARCH_ID, osdVersion)),
  };
}

const BADGE: Record<SavedObjectsBridgeStatus['indexPatterns'], { color: string; label: string }> = {
  ok: { color: 'success', label: 'Provisioned' },
  skipped: { color: 'hollow', label: 'Not provisioned' },
  error: { color: 'danger', label: 'Provisioning failed' },
};

export const DiscoverBridgeCard: React.FC<Props> = ({ apiService }) => {
  const [status, setStatus] = useState<SavedObjectsBridgeStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const generation = useRef(0);

  const load = useCallback(async () => {
    const request = ++generation.current;
    setLoading(true);
    setLoadError(null);
    try {
      const result = await apiService.fetchSavedObjectsBridgeStatus();
      if (request === generation.current) setStatus(result);
    } catch (e: any) {
      if (request === generation.current) setLoadError(e?.body?.message || e.message || 'Bridge status could not be loaded.');
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, [apiService]);

  useEffect(() => {
    load();
    return () => {
      generation.current += 1;
    };
  }, [load]);

  const links = discoverBridgeLinks(apiService);
  const state = status?.indexPatterns || 'skipped';
  const badge = BADGE[state];
  const deepLinks = Boolean(links.alertsPattern);

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamDiscoverBridgeCard" data-test-subj="wamDiscoverBridgeCard">
      <EuiFlexGroup gutterSize="m" alignItems="flexStart" wrap>
        <EuiFlexItem grow={false}>
          <span className="wamSettingsIcon"><EuiIcon type="discoverApp" size="l" /></span>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
            <EuiFlexItem grow={false}><EuiTitle size="xxs"><h4>Discover and Reporting</h4></EuiTitle></EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiBadge color={badge.color} data-test-subj="wamDiscoverBridgeState">{loading && !status ? 'Checking' : badge.label}</EuiBadge>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiText size="xs" color="subdued">
            On start the plugin provisions the index patterns <code>{WAM_ALERTS_INDEX_PATTERN_ID}</code> (alerts) and{' '}
            <code>{WAM_CASES_INDEX_PATTERN_ID}</code> (cases) and the saved searches <code>{WAM_OPEN_ALERTS_SEARCH_ID}</code> and{' '}
            <code>{WAM_OPEN_CASES_SEARCH_ID}</code> in the global tenant, so Discover and OpenSearch Reporting can work on the plugin's own
            indices. Nothing is set as the default index pattern.
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="m" />
      {loadError && (
        <>
          <EuiCallOut color="warning" iconType="alert" title="Bridge status could not be loaded" size="s">
            <p>{loadError}</p>
            <EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {status && status.indexPatterns !== 'ok' && (
        <>
          <EuiCallOut
            color={status.indexPatterns === 'error' ? 'danger' : 'primary'}
            iconType={status.indexPatterns === 'error' ? 'alert' : 'iInCircle'}
            title={status.indexPatterns === 'error' ? 'Index patterns could not be provisioned' : 'Index patterns were not provisioned'}
            size="s"
            data-test-subj="wamDiscoverBridgeMessage"
          >
            <p>{status.message}</p>
            <p>
              Typical causes: the dashboard's internal user lacks write access to the saved-objects index, or the security plugin's
              multi-tenancy routes the internal repository elsewhere. The links below still open the apps; create the patterns by hand if needed.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      <EuiFlexGroup gutterSize="s" wrap responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" iconType="discoverApp" href={links.alertsPattern || links.discoverApp} target="_blank" data-test-subj="wamDiscoverBridgeAlerts">
            {deepLinks ? 'Alerts in Discover' : 'Open Discover'}
          </EuiButton>
        </EuiFlexItem>
        {links.casesPattern && (
          <EuiFlexItem grow={false}>
            <EuiButton size="s" iconType="discoverApp" href={links.casesPattern} target="_blank" data-test-subj="wamDiscoverBridgeCases">
              Cases in Discover
            </EuiButton>
          </EuiFlexItem>
        )}
        <EuiFlexItem grow={false}>
          <EuiButton size="s" iconType="reportingApp" href={links.reportingApp} target="_blank" data-test-subj="wamDiscoverBridgeReporting">
            Open Reporting
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      {deepLinks && (
        <>
          <EuiSpacer size="s" />
          <EuiText size="xs">
            Saved searches:{' '}
            <EuiLink href={links.openAlertsSearch || undefined} target="_blank" data-test-subj="wamDiscoverBridgeOpenAlerts">{WAM_OPEN_ALERTS_SEARCH_ID}</EuiLink>
            {' · '}
            <EuiLink href={links.openCasesSearch || undefined} target="_blank" data-test-subj="wamDiscoverBridgeOpenCases">{WAM_OPEN_CASES_SEARCH_ID}</EuiLink>
            {' · '}
            <EuiLink href={links.savedObjects} target="_blank">Saved objects</EuiLink>
          </EuiText>
        </>
      )}
      <EuiSpacer size="m" />
      <EuiText size="xs" color="subdued" className="wamDiscoverBridgeCard__notes">
        <ul>
          <li>
            Analysts need the <code>kibana_user</code> role to read saved objects (the patterns and searches) and read access to{' '}
            <code>wazuh-alert-status-v2-*</code> / <code>wazuh-alert-manager-v2-*</code> (the plugin's own role grants it).
          </li>
          <li>
            OpenSearch Reporting (saved-search CSV, dashboard PDF) additionally needs <code>reports_full_access</code>; its scheduled
            reports deliver nothing on 4.x, so use the plugin's own CSV export and scheduled summaries for delivery.
          </li>
          <li>
            The objects live in the global tenant only. Users working in a private tenant will not see them and must create their own.
          </li>
          {!deepLinks && (
            <li>
              Deep links are hidden because the Discover URL shape of OpenSearch Dashboards {TARGET_OSD_VERSION} is not known to this build;
              pick <code>{WAM_ALERTS_INDEX_PATTERN_ID}</code> from the index pattern selector in Discover.
            </li>
          )}
        </ul>
      </EuiText>
      <EuiButtonEmpty size="xs" iconType="refresh" onClick={load} isLoading={loading} data-test-subj="wamDiscoverBridgeRefresh">
        Refresh status
      </EuiButtonEmpty>
    </EuiPanel>
  );
};
