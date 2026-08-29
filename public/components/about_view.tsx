import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiCallOut,
  EuiDescriptionList,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiButton,
} from '@elastic/eui';
import { PLUGIN_BUILD_ID } from '../../common';
import { AlertsApiService, BuildInfo } from '../services/api';

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

  if (!server && loading) return <EuiLoadingSpinner size="l" />;

  const matches = server?.buildId === PLUGIN_BUILD_ID;
  const items = server ? [
    { title: 'Plugin version', description: server.pluginVersion },
    { title: 'Browser build ID', description: <code>{PLUGIN_BUILD_ID}</code> },
    { title: 'Server build ID', description: <code>{server.buildId}</code> },
    { title: 'Built at', description: server.builtAt },
    { title: 'Target OpenSearch Dashboards', description: server.targetOsdVersion },
    { title: 'Bundle state', description: <EuiBadge color={matches ? 'success' : 'warning'}>{matches ? 'Current' : 'Update available'}</EuiBadge> },
  ] : [];

  return (
    <div>
      <EuiTitle size="s"><h3>About Workbench</h3></EuiTitle>
      <EuiText size="s" color="subdued">Artifact identity reported independently by this browser bundle and the running server plugin.</EuiText>
      <EuiSpacer size="m" />
      {error ? (
        <EuiCallOut color="danger" title="Build information is unavailable"><p>{error}</p><EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton></EuiCallOut>
      ) : (
        <EuiDescriptionList type="column" listItems={items as any} />
      )}
    </div>
  );
};
