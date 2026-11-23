import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiButton,
  EuiCallOut,
  EuiFieldNumber,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
  EuiFlexGroup,
  EuiFlexItem,
  EuiBadge,
  EuiDescriptionList,
} from '@elastic/eui';
import { AlertsApiService } from '../services/api';
import { DiscoverBridgeCard } from './discover_bridge_card';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const SyncSettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [settings, setSettings] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [canManage, setCanManage] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const loadGeneration = useRef(0);

  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setLoadError(null);
    const settingsRequest = apiService.fetchSyncSettings();
    const capabilitiesRequest = apiService.fetchSystemCapabilities();
    const healthRequest = apiService.fetchSystemHealth();

    settingsRequest.then((value) => {
      if (generation === loadGeneration.current) setSettings(value);
    }, () => undefined);
    capabilitiesRequest.then((value: any) => {
      if (generation === loadGeneration.current) setCanManage(Boolean(value?.canManageLifecycle));
    }, () => undefined);
    healthRequest.then((value) => {
      if (generation === loadGeneration.current) setHealth(value);
    }, () => undefined);

    const [settingsResult, capabilitiesResult, healthResult] = await Promise.allSettled([
      settingsRequest,
      capabilitiesRequest,
      healthRequest,
    ]);
    if (generation !== loadGeneration.current) return;

    const errors: string[] = [];
    if (settingsResult.status === 'fulfilled') setSettings(settingsResult.value);
    else errors.push(settingsResult.reason?.body?.message || settingsResult.reason?.message || 'Sync settings could not be loaded.');

    if (capabilitiesResult.status === 'fulfilled') {
      setCanManage(Boolean((capabilitiesResult.value as any)?.canManageLifecycle));
    } else {
      setCanManage(false);
      errors.push(capabilitiesResult.reason?.body?.message || capabilitiesResult.reason?.message || 'Permissions could not be loaded.');
    }
    if (healthResult.status === 'fulfilled') setHealth(healthResult.value);
    else errors.push(healthResult.reason?.body?.message || healthResult.reason?.message || 'Sync health could not be loaded.');
    setLoadError(errors.length ? errors.join(' ') : null);
    setLoading(false);
  }, [apiService]);

  useEffect(() => {
    load();
    return () => {
      loadGeneration.current += 1;
    };
  }, [load]);

  if (loading && !settings) {
    return <div className="wamSettingsLoading"><EuiLoadingSpinner size="l" /></div>;
  }

  if (!settings) {
    return (
      <div className="wamSettingsPage wamSyncSettings" data-test-subj="wamSyncSettings">
        <SettingsPageHeader
          title="Background alert sync"
          description="Schedule ingestion from the read-only Wazuh alert source into the operational work queue."
        />
        <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load background sync settings">
          <p>{loadError || 'The settings request did not return data.'}</p>
          <EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton>
        </EuiCallOut>
        <EuiSpacer size="m" />
        <DiscoverBridgeCard apiService={apiService} />
      </div>
    );
  }

  const intervalValid = settings.intervalSeconds >= 15 && settings.intervalSeconds <= 3600;
  const sync = health?.sync;
  const hasCursor = Boolean(sync?.search_after?.length || sync?.window_from || sync?.window_to);
  const completedAt = Date.parse(sync?.completed_at || '');
  const watermarkAgeSeconds = Number.isFinite(completedAt) ? Math.max(0, Math.floor((Date.now() - completedAt) / 1000)) : null;
  const watermarkStale = watermarkAgeSeconds != null && watermarkAgeSeconds > Math.max(Number(settings.intervalSeconds) * 3, 300);
  const healthLabel = !settings.enabled ? 'Paused' : !sync ? 'Awaiting first successful sync' : hasCursor ? 'Catching up' : watermarkStale ? 'Stale watermark' : 'Watermark advancing';

  const save = async () => {
    try {
      setSaving(true);
      setSettings(await apiService.saveSyncSettings({
        enabled: Boolean(settings.enabled),
        intervalSeconds: Number(settings.intervalSeconds),
      }));
      onToast('Background sync settings saved', 'success', 'The new interval takes effect after the current sync cycle.');
    } catch (e: any) {
      onToast('Failed to save sync settings', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="wamSettingsPage wamSyncSettings" data-test-subj="wamSyncSettings">
      <SettingsPageHeader
        title="Background alert sync"
        description="Schedule ingestion from the read-only Wazuh alert source into the operational work queue."
        actions={
          <EuiBadge color={settings.enabled ? 'success' : 'hollow'} iconType={settings.enabled ? 'play' : 'pause'}>
            {settings.enabled ? `Running every ${settings.intervalSeconds}s` : 'Paused'}
          </EuiBadge>
        }
      />
      {loadError && (
        <>
          <EuiCallOut size="s" color="warning" iconType="alert" title="Some sync settings data could not be loaded">
            <p>{loadError}</p>
            <EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {!canManage && <><EuiCallOut size="s" color="primary" iconType="lock" title="Sync settings are read only for your role" /><EuiSpacer size="m" /></>}
      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamSyncHealthPanel">
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
          <EuiFlexItem grow={false}><EuiTitle size="xs"><h4>Runtime health</h4></EuiTitle></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiBadge color={!settings.enabled ? 'hollow' : !sync || hasCursor ? 'warning' : watermarkStale ? 'danger' : 'success'}>{healthLabel}</EuiBadge></EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiDescriptionList
          type="column"
          compressed
          className="wamMetaList"
          listItems={[
            { title: 'Last successful watermark', description: sync?.completed_at ? new Date(sync.completed_at).toLocaleString() : 'Not available yet' },
            { title: 'Watermark age', description: watermarkAgeSeconds == null ? 'Unavailable' : `${watermarkAgeSeconds.toLocaleString()} seconds` },
            { title: 'Last state update', description: sync?.updated_at ? new Date(sync.updated_at).toLocaleString() : 'Not available yet' },
            { title: 'Cursor', description: hasCursor ? `${sync.window_from || 'unknown'} to ${sync.window_to || 'unknown'} (${sync.search_after?.length || 0} sort values)` : 'No continuation cursor' },
            { title: 'Failures', description: `${health?.counts?.dlq == null ? 'Sync DLQ count unavailable' : `${health.counts.dlq.toLocaleString()} item(s) in the sync DLQ`}; last failure time is not exposed` },
            { title: 'Active leader', description: 'Not exposed by the current server health contract' },
          ]}
        />
      </EuiPanel>
      <EuiSpacer size="m" />
      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamSyncSettingsPanel">
        <EuiTitle size="xs"><h4>Sync schedule</h4></EuiTitle>
        <EuiText size="s" color="subdued">
          Native Wazuh storage (4.x <code>wazuh-alerts-*</code>, 5.0 <code>wazuh-findings-v5-*</code>) remains read only. Changes take effect after the current cycle without restarting Dashboards.
        </EuiText>
        <EuiSpacer size="m" />
        <EuiFormRow label="Background sync" fullWidth hasChildLabel={false}>
          <EuiSwitch
            label="Enable background sync"
            checked={Boolean(settings.enabled)}
            disabled={!canManage}
            onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })}
          />
        </EuiFormRow>
        <EuiFormRow
          label="Sync interval"
          fullWidth
          helpText="Allowed range: 15 to 3,600 seconds. Leader locking scales automatically across dashboard replicas."
          isInvalid={!intervalValid}
          error={!intervalValid ? 'Enter an interval from 15 to 3,600 seconds.' : undefined}
        >
          <EuiFieldNumber
            fullWidth
            min={15}
            max={3600}
            append="seconds"
            value={settings.intervalSeconds}
            disabled={!canManage}
            onChange={(e) => setSettings({ ...settings, intervalSeconds: Number(e.target.value) })}
          />
        </EuiFormRow>
        <EuiSpacer size="m" />
        <SettingsFormActions>
          <EuiButton size="s" fill iconType="save" disabled={!canManage || !intervalValid} isLoading={saving} onClick={save}>Save changes</EuiButton>
        </SettingsFormActions>
      </EuiPanel>
      <EuiSpacer size="m" />
      <DiscoverBridgeCard apiService={apiService} />
    </div>
  );
};
