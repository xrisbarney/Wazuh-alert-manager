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
  EuiIcon,
  EuiBadge,
  EuiDescriptionList,
} from '@elastic/eui';
import { AlertsApiService } from '../services/api';

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
      <div className="wamSettingsSection">
        <EuiCallOut color="danger" iconType="alert" title="Failed to load background sync settings">
          <p>{loadError || 'The settings request did not return data.'}</p>
          <EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton>
        </EuiCallOut>
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
    <div className="wamSettingsSection">
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m" wrap>
        <EuiFlexItem>
          <EuiTitle size="s"><h3>Background alert sync</h3></EuiTitle>
          <EuiText size="s" color="subdued">
            Schedule ingestion from the read-only Wazuh alert source into the operational work queue.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color={settings.enabled ? 'success' : 'hollow'} iconType={settings.enabled ? 'play' : 'pause'}>
            {settings.enabled ? `Running every ${settings.intervalSeconds}s` : 'Paused'}
          </EuiBadge>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="m" />
      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamSyncHealthPanel">
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
          <EuiFlexItem grow={false}><EuiTitle size="xxs"><h4>Runtime health</h4></EuiTitle></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiBadge color={!settings.enabled ? 'hollow' : !sync || hasCursor ? 'warning' : watermarkStale ? 'danger' : 'success'}>{healthLabel}</EuiBadge></EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiDescriptionList
          type="column"
          compressed
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
      {loadError && (
        <>
          <EuiCallOut color="warning" iconType="alert" title="Some sync settings data could not be loaded">
            <p>{loadError}</p>
            <EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {!canManage && <><EuiCallOut color="primary" iconType="lock" title="Sync settings are read only for your role" /><EuiSpacer size="m" /></>}
      <EuiPanel hasBorder hasShadow={false} paddingSize="l" className="wamSyncSettingsPanel">
        <EuiFlexGroup gutterSize="m" alignItems="flexStart" wrap>
          <EuiFlexItem grow={false}>
            <span className="wamSettingsIcon"><EuiIcon type="refresh" size="l" /></span>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiTitle size="xxs"><h4>Sync schedule</h4></EuiTitle>
            <EuiText size="xs" color="subdued">
              Native <code>wazuh-alerts-*</code> indices remain read only. Changes take effect after the current cycle without restarting Dashboards.
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="l" />
        <EuiSwitch
          label="Enable background sync"
          checked={Boolean(settings.enabled)}
          disabled={!canManage}
          onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })}
        />
        <EuiSpacer size="m" />
        <EuiFormRow
          label="Sync interval"
          helpText="Allowed range: 15 to 3,600 seconds. Leader locking scales automatically across dashboard replicas."
          isInvalid={!intervalValid}
          error={!intervalValid ? 'Enter an interval from 15 to 3,600 seconds.' : undefined}
        >
          <EuiFieldNumber
            min={15}
            max={3600}
            append="seconds"
            value={settings.intervalSeconds}
            disabled={!canManage}
            onChange={(e) => setSettings({ ...settings, intervalSeconds: Number(e.target.value) })}
          />
        </EuiFormRow>
        <EuiSpacer size="m" />
        <EuiButton fill iconType="save" disabled={!canManage || !intervalValid} isLoading={saving} onClick={save}>Save changes</EuiButton>
      </EuiPanel>
    </div>
  );
};
