import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiCallOut,
  EuiDescriptionList,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiTitle,
  EuiButton,
} from '@elastic/eui';
import { PLUGIN_BUILD_ID } from '../../common';
import { AlertsApiService, BuildInfo } from '../services/api';
import { SettingsPageHeader } from './settings_page';

export const AboutView: React.FC<{ apiService: AlertsApiService }> = ({ apiService }) => {
  const [server, setServer] = useState<BuildInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const generation = useRef(0);

  const load = useCallback(async () => {
    const request = ++generation.current;
    setLoading(true);
    setError(null);
    try {
      const result = await apiService.fetchBuildInfo();
      if (request === generation.current) setServer(result);
    } catch (e: any) {
      if (request === generation.current) setError(e?.body?.message || e.message);
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, [apiService]);

  useEffect(() => {
    load();
    return () => { generation.current += 1; };
  }, [load]);

  if (!server && loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="l" /></div>;

  const matches = server?.buildId === PLUGIN_BUILD_ID;
  const items = server ? [
    { title: 'Plugin version', description: server.pluginVersion },
    { title: 'Browser build ID', description: <code>{PLUGIN_BUILD_ID}</code> },
    { title: 'Server build ID', description: <code>{server.buildId}</code> },
    { title: 'Built at', description: server.builtAt },
    { title: 'Target OpenSearch Dashboards', description: server.targetOsdVersion },
    {
      title: 'Target Wazuh',
      description: server.targetWazuhVersion
        ? `${server.targetWazuhVersion} (reads ${server.targetWazuhMajor === 5 ? 'wazuh-findings-v5-* data streams' : 'wazuh-alerts-* indices'}, read only)`
        : 'unknown',
    },
    { title: 'Bundle state', description: <EuiBadge color={matches ? 'success' : 'warning'}>{matches ? 'Current' : 'Update available'}</EuiBadge> },
  ] : [];

  return (
    <div className="wamSettingsPage wamAbout" data-test-subj="wamAbout">
      <SettingsPageHeader
        title="About Workbench"
        description="Artifact identity reported independently by this browser bundle and the running server plugin."
      />
      {error ? (
        <EuiCallOut size="s" color="danger" iconType="alert" title="Build information is unavailable"><p>{error}</p><EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton></EuiCallOut>
      ) : (
        <EuiPanel hasBorder hasShadow={false} paddingSize="m">
          <EuiTitle size="xs"><h4>Build</h4></EuiTitle>
          <EuiSpacer size="s" />
          <EuiDescriptionList type="column" compressed className="wamMetaList" listItems={items as any} />
        </EuiPanel>
      )}
    </div>
  );
};
