import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiCallOut,
  EuiConfirmModal,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFieldNumber,
  EuiFieldText,
  EuiFormRow,
  EuiIcon,
  EuiLoadingSpinner,
  EuiLink,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiSwitch,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { AlertsApiService } from '../services/api';

const LIFECYCLE_ROLE_HELP =
  'Requires the effective OpenSearch Security role all_access or index_management_full_access. Backend roles or SSO/LDAP groups must be mapped to one of these roles.';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const StorageHealthView: React.FC<Props> = ({ apiService, onToast }) => {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [rolling, setRolling] = useState<string | null>(null);
  const [retirementPlan, setRetirementPlan] = useState<any>(null);
  const [retiring, setRetiring] = useState(false);
  const [lifecycleSettings, setLifecycleSettings] = useState<any>(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [purgeIndex, setPurgeIndex] = useState<string | null>(null);
  const [purging, setPurging] = useState(false);
  const [restoreIndex, setRestoreIndex] = useState<string | null>(null);
  const [restoring, setRestoring] = useState(false);
  const [capabilities, setCapabilities] = useState<any>(null);
  const [activityRetireIndex, setActivityRetireIndex] = useState<string | null>(null);
  const [activityPurgeIndex, setActivityPurgeIndex] = useState<string | null>(null);
  const [evidenceRetireIndex, setEvidenceRetireIndex] = useState<string | null>(null);
  const [evidencePurgeIndex, setEvidencePurgeIndex] = useState<string | null>(null);
  const [caseRetirementPlan, setCaseRetirementPlan] = useState<any>(null);
  const [caseRetiring, setCaseRetiring] = useState(false);
  const [casePurgeIndex, setCasePurgeIndex] = useState<string | null>(null);
  const [casePurging, setCasePurging] = useState(false);
  const [reopenIndex, setReopenIndex] = useState<string | null>(null);
  const [reopenCaseId, setReopenCaseId] = useState('');
  const [reopening, setReopening] = useState(false);
  const loadGeneration = useRef(0);
  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setLoadError(null);
    const healthRequest = apiService.fetchSystemHealth();
    const settingsRequest = apiService.fetchLifecycleSettings();
    const capabilitiesRequest = apiService.fetchSystemCapabilities();

    // These requests have very different costs. Publish each successful result as
    // soon as it arrives so a slow generation inventory cannot blank the policy UI.
    healthRequest.then((value) => {
      if (generation === loadGeneration.current) setHealth(value);
    }, () => undefined);
    settingsRequest.then((value) => {
      if (generation === loadGeneration.current) setLifecycleSettings(value);
    }, () => undefined);
    capabilitiesRequest.then((value) => {
      if (generation === loadGeneration.current) setCapabilities(value);
    }, () => undefined);

    const results = await Promise.allSettled([healthRequest, settingsRequest, capabilitiesRequest]);
    if (generation !== loadGeneration.current) return;
    const errors: string[] = [];
    if (results[0].status === 'fulfilled') setHealth(results[0].value);
    else errors.push(results[0].reason?.body?.message || results[0].reason?.message || 'Storage health is unavailable.');
    if (results[1].status === 'fulfilled') setLifecycleSettings(results[1].value);
    else errors.push(results[1].reason?.body?.message || results[1].reason?.message || 'Lifecycle settings are unavailable.');
    if (results[2].status === 'fulfilled') setCapabilities(results[2].value);
    else errors.push(results[2].reason?.body?.message || results[2].reason?.message || 'Permissions are unavailable.');
    setLoadError(errors.length ? errors.join(' ') : null);
    setLoading(false);
  }, [apiService]);

  useEffect(() => {
    load();
    return () => { loadGeneration.current += 1; };
  }, [load]);

  const rollover = async (family: 'alerts' | 'activity' | 'cases' | 'evidence') => {
    try {
      setRolling(family);
      await apiService.rolloverStorage(family);
      const label = family === 'alerts' ? 'Alert' : family === 'activity' ? 'Activity'
        : family === 'cases' ? 'Case' : 'Evidence';
      onToast(`${label} generation rolled over`, 'success');
      await load();
    } catch (e: any) {
      onToast('Rollover failed', 'danger', e?.body?.message || e.message);
    } finally {
      setRolling(null);
    }
  };

  const planRetirement = async (index: string) => {
    try {
      setRetirementPlan(await apiService.planAlertRetirement(index));
    } catch (e: any) {
      onToast('Unable to plan generation retirement', 'danger', e?.body?.message || e.message);
    }
  };

  const executeRetirement = async () => {
    if (!retirementPlan) return;
    try {
      setRetiring(true);
      const result = await apiService.retireAlertGeneration(retirementPlan.retiringIndex);
      onToast(
        'Alert generation retired safely',
        'success',
        `${result.carriedDocuments} active alerts carried forward; the source index was retained.`
      );
      setRetirementPlan(null);
      await load();
    } catch (e: any) {
      onToast('Generation retirement failed', 'danger', e?.body?.message || e.message);
    } finally {
      setRetiring(false);
    }
  };

  const saveLifecycleSettings = async () => {
    if (!lifecycleSettings) return;
    try {
      setSavingSettings(true);
      setLifecycleSettings(await apiService.saveLifecycleSettings(lifecycleSettings));
      onToast('Lifecycle settings saved', 'success', 'The background lifecycle check will use them on its next run.');
    } catch (e: any) {
      onToast('Failed to save lifecycle settings', 'danger', e?.body?.message || e.message);
    } finally {
      setSavingSettings(false);
    }
  };

  const purgeRetired = async () => {
    if (!purgeIndex) return;
    try {
      setPurging(true);
      await apiService.purgeRetiredAlertGeneration(purgeIndex);
      onToast('Retired generation purged', 'success', `${purgeIndex} was permanently removed.`);
      setPurgeIndex(null);
      await load();
    } catch (e: any) {
      onToast('Purge failed', 'danger', e?.body?.message || e.message);
    } finally {
      setPurging(false);
    }
  };

  const restoreRetired = async () => {
    if (!restoreIndex) return;
    try {
      setRestoring(true);
      const result = await apiService.restoreRetiredAlertGeneration(restoreIndex);
      onToast(
        'Retired alerts restored to the live Workbench',
        'success',
        `${result.restored.toLocaleString()} missing alerts restored; ${result.alreadyLive.toLocaleString()} newer live records were preserved.`
      );
      setRestoreIndex(null);
      await load();
    } catch (e: any) {
      onToast('Restore failed', 'danger', e?.body?.message || e.message);
    } finally {
      setRestoring(false);
    }
  };

  const retireActivity = async () => {
    if (!activityRetireIndex) return;
    try {
      setRetiring(true);
      await apiService.retireActivityGeneration(activityRetireIndex);
      onToast('Activity generation retired', 'success', 'The physical index is retained outside the live alias.');
      setActivityRetireIndex(null);
      await load();
    } catch (e: any) {
      onToast('Activity retirement failed', 'danger', e?.body?.message || e.message);
    } finally {
      setRetiring(false);
    }
  };

  const purgeActivity = async () => {
    if (!activityPurgeIndex) return;
    try {
      setPurging(true);
      await apiService.purgeRetiredActivityGeneration(activityPurgeIndex);
      onToast('Retired activity generation purged', 'success');
      setActivityPurgeIndex(null);
      await load();
    } catch (e: any) {
      onToast('Activity purge failed', 'danger', e?.body?.message || e.message);
    } finally {
      setPurging(false);
    }
  };

  const retireEvidence = async () => {
    if (!evidenceRetireIndex) return;
    try {
      setRetiring(true);
      const result = await apiService.retireEvidenceGeneration(evidenceRetireIndex);
      onToast('Evidence generation compacted', 'success', `${result.copied} relationships carried to the current writer; the source remains retained.`);
      setEvidenceRetireIndex(null);
      await load();
    } catch (e: any) {
      onToast('Evidence retirement failed', 'danger', e?.body?.message || e.message);
    } finally {
      setRetiring(false);
    }
  };

  const purgeEvidence = async () => {
    if (!evidencePurgeIndex) return;
    try {
      setPurging(true);
      await apiService.purgeRetiredEvidenceGeneration(evidencePurgeIndex);
      onToast('Retired evidence generation purged', 'success');
      setEvidencePurgeIndex(null);
      await load();
    } catch (e: any) {
      onToast('Evidence purge failed', 'danger', e?.body?.message || e.message);
    } finally {
      setPurging(false);
    }
  };

  const planCaseRetirement = async (index: string) => {
    try {
      setCaseRetirementPlan(await apiService.planCaseRetirement(index));
    } catch (e: any) {
      onToast('Unable to plan case generation retirement', 'danger', e?.body?.message || e.message);
    }
  };

  const executeCaseRetirement = async () => {
    if (!caseRetirementPlan) return;
    try {
      setCaseRetiring(true);
      const result = await apiService.retireCaseGeneration(caseRetirementPlan.retiringIndex);
      onToast(
        'Case generation retired safely',
        'success',
        `${result.carried} active or recent cases carried forward; ${result.archived} expired closed cases moved to Archived Cases.`
      );
      setCaseRetirementPlan(null);
      await load();
    } catch (e: any) {
      onToast('Case generation retirement failed', 'danger', e?.body?.message || e.message);
    } finally {
      setCaseRetiring(false);
    }
  };

  const purgeArchivedCaseGen = async () => {
    if (!casePurgeIndex) return;
    try {
      setCasePurging(true);
      await apiService.purgeArchivedCaseGeneration(casePurgeIndex);
      onToast('Archived case generation purged', 'success', `${casePurgeIndex} was permanently removed.`);
      setCasePurgeIndex(null);
      await load();
    } catch (e: any) {
      onToast('Case purge failed', 'danger', e?.body?.message || e.message);
    } finally {
      setCasePurging(false);
    }
  };

  const reopenCase = async () => {
    const caseId = reopenCaseId.trim();
    if (!caseId) return;
    try {
      setReopening(true);
      await apiService.reopenArchivedCase(caseId);
      onToast('Case reopened', 'success', `${caseId} was copied back into the live case list.`);
      setReopenIndex(null);
      setReopenCaseId('');
      await load();
    } catch (e: any) {
      onToast('Reopen failed', 'danger', e?.body?.message || e.message);
    } finally {
      setReopening(false);
    }
  };

  if (loading && !health && !lifecycleSettings && !capabilities) return <EuiLoadingSpinner size="xl" />;
  if (!health && !loading && !lifecycleSettings && !capabilities) return <EuiCallOut color="danger" iconType="alert" title="Storage health is unavailable"><p>{loadError || 'The server returned no health data.'}</p><EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton></EuiCallOut>;
  const counts = health?.counts || {};
  const migration = health?.migration;
  const canManageLifecycle = Boolean(capabilities?.canManageLifecycle);
  const rows = [
    { store: 'Operational alerts', alias: 'wazuh-alert-status-v2-read', documents: counts.alerts },
    { store: 'Cases', alias: 'wazuh-alert-manager-v2-cases-read', documents: counts.cases },
    { store: 'Evidence relationships', alias: 'wazuh-alert-manager-v2-evidence-read', documents: counts.evidence },
    { store: 'Activity events', alias: 'wazuh-alert-manager-v2-activity-read', documents: counts.activity },
    { store: 'Sync dead-letter queue', alias: 'wazuh-alert-manager-v2-sync-dlq', documents: counts.dlq },
    { store: 'Legacy alerts (retained)', alias: 'wazuh-alert-status', documents: counts.legacyAlerts },
  ];

  return (
    <div>
      <EuiTitle size="s"><h3>Storage and lifecycle</h3></EuiTitle>
      <EuiText size="s" color="subdued">
        Plugin writes are restricted to its <code>wazuh-alert-status-v2-*</code> and{' '}
        <code>wazuh-alert-manager-v2-*</code> families. Native <code>wazuh-alerts-*</code> indices are read only.
      </EuiText>
      <EuiSpacer size="m" />
      {loadError && <><EuiCallOut color="warning" iconType="alert" title="Some storage data could not be refreshed"><p>{loadError}</p><EuiButton size="s" iconType="refresh" onClick={load} isLoading={loading}>Retry</EuiButton></EuiCallOut><EuiSpacer size="m" /></>}
      {!canManageLifecycle && (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="lock"
            title="Lifecycle controls are read only for your role"
          >
            Saving, rollover, retirement, restore, and purge require the effective OpenSearch Security role{' '}
            <code>all_access</code> or <code>index_management_full_access</code>. SAML and LDAP/AD groups inherit this through their existing Wazuh backend-role mapping.{' '}
            <EuiLink href="https://documentation.wazuh.com/current/user-manual/user-administration/index.html" target="_blank" external>
              Wazuh user administration
            </EuiLink>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {lifecycleSettings && (
        <>
          <EuiPanel hasBorder hasShadow={false} paddingSize="m">
            <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" wrap className="wamLifecycleHeader">
              <EuiFlexItem>
                <EuiTitle size="xs"><h4>Lifecycle policy</h4></EuiTitle>
                <EuiText size="s" color="subdued">
                  Rollover limits the size of each physical index. Retention only marks older, non-current generations as due for review; it never deletes data automatically.
                </EuiText>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiToolTip content={canManageLifecycle ? 'When enabled, the plugin checks about every five minutes and starts a new plugin-owned generation when either the age or size limit is reached. It never rolls over a native Wazuh index.' : LIFECYCLE_ROLE_HELP}>
                  <span>
                    <EuiSwitch
                      label="Automatic rollover"
                      checked={Boolean(lifecycleSettings.enabled)}
                      disabled={!canManageLifecycle}
                      onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, enabled: e.target.checked })}
                    />
                  </span>
                </EuiToolTip>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="m" />
            <EuiFlexGroup gutterSize="m" wrap className="wamLifecycleFields">
              <EuiFlexItem>
                <EuiFormRow
                  label={<span>Maximum generation age <EuiToolTip content="The oldest a current plugin-owned physical index may become before rollover. Reaching this OR the size limit starts a new generation; it does not archive or delete the old one."><EuiIcon type="iInCircle" /></EuiToolTip></span>}
                  helpText="Rollover threshold. Examples: 12h, 7d, 30d"
                >
                  <EuiFieldText
                    value={lifecycleSettings.rolloverAge}
                    disabled={!canManageLifecycle}
                    onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, rolloverAge: e.target.value })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow
                  label={<span>Closed case retention (days) <EuiToolTip content="Days a closed case stays live-searchable before case retirement can move it to Archived Cases. Active cases are always carried forward."><EuiIcon type="iInCircle" /></EuiToolTip></span>}
                  helpText="Live-searchable retention for closed cases. Minimum 30 days."
                >
                  <EuiFieldNumber
                    min={30}
                    max={3650}
                    value={lifecycleSettings.caseRetentionDays}
                    disabled={!canManageLifecycle}
                    onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, caseRetentionDays: Number(e.target.value) })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow
                  label={<span>Full evidence retention (days) <EuiToolTip content="Minimum retention before a referenced alert archive can become purge-eligible. Holds and active-case references remain blockers."><EuiIcon type="iInCircle" /></EuiToolTip></span>}
                  helpText="Purge eligibility threshold only. Minimum 30 days."
                >
                  <EuiFieldNumber
                    min={30}
                    max={3650}
                    value={lifecycleSettings.evidenceRetentionDays}
                    disabled={!canManageLifecycle}
                    onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, evidenceRetentionDays: Number(e.target.value) })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow
                  label={<span>Maximum generation size <EuiToolTip content="The maximum primary data size of the current plugin-owned generation. Reaching this OR the age limit starts a new generation; replicas and native Wazuh alert indices are unaffected."><EuiIcon type="iInCircle" /></EuiToolTip></span>}
                  helpText="Rollover threshold. Examples: 500mb, 20gb, 1tb"
                >
                  <EuiFieldText
                    value={lifecycleSettings.rolloverSize}
                    disabled={!canManageLifecycle}
                    onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, rolloverSize: e.target.value })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow
                  label={<span>Alert retention (days) <EuiToolTip content="After this age, a non-current alert generation is marked Due. Nothing is deleted automatically. An administrator must review and retire it; open, in-progress, and case-linked alerts are carried forward, while the original remains restorable until explicitly purged."><EuiIcon type="iInCircle" /></EuiToolTip></span>}
                  helpText="Review threshold only; minimum 7 days. No automatic deletion."
                >
                  <EuiFieldNumber
                    min={7}
                    max={3650}
                    value={lifecycleSettings.operationalRetentionDays}
                    disabled={!canManageLifecycle}
                    onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, operationalRetentionDays: Number(e.target.value) })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow
                  label={<span>Activity retention (days) <EuiToolTip content="After this age, a non-current audit/activity generation is marked Due. An administrator may detach it from live reports, but it remains retained until an explicit purge."><EuiIcon type="iInCircle" /></EuiToolTip></span>}
                  helpText="Review threshold only; minimum 30 days. No automatic deletion."
                >
                  <EuiFieldNumber
                    min={30}
                    max={3650}
                    value={lifecycleSettings.activityRetentionDays}
                    disabled={!canManageLifecycle}
                    onChange={(e) => setLifecycleSettings({ ...lifecycleSettings, activityRetentionDays: Number(e.target.value) })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiFlexGroup justifyContent="flexEnd" gutterSize="s" wrap className="wamLifecycleActions">
              <EuiFlexItem grow={false}>
                <EuiToolTip content={canManageLifecycle ? 'Save the policy used by the plugin lifecycle worker' : LIFECYCLE_ROLE_HELP}>
                  <span>
                    <EuiButton fill disabled={!canManageLifecycle} onClick={saveLifecycleSettings} isLoading={savingSettings}>Save lifecycle policy</EuiButton>
                  </span>
                </EuiToolTip>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiPanel>
          <EuiSpacer size="s" />
          <EuiCallOut size="s" iconType="iInCircle" title="Rollover, retirement, and purge are separate safeguards">
            <p>
              <strong>Rollover</strong> creates a new writable generation. <strong>Retention</strong> marks an older generation as due.
              <strong> Retirement</strong> is a reviewed carry-forward and archive step. <strong>Purge</strong> is the only permanent deletion and always requires a separate confirmation.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {migration && (
        <>
          <EuiCallOut
            size="s"
            color={migration.status === 'failed' ? 'danger' : migration.status === 'completed' ? 'success' : 'primary'}
            title={`Legacy migration: ${migration.status || 'not started'}`}
          >
            Phase: {migration.phase || '—'} · Migrated: {(migration.migrated || 0).toLocaleString()} · Legacy indices are retained.
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      <EuiFlexGroup gutterSize="m" wrap className="wamStorageStats">
        <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiStat title={counts.alerts ?? '—'} description="Operational alerts" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiStat title={counts.cases ?? '—'} description="Cases" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiStat title={counts.evidence ?? '—'} description="Evidence relationships" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiStat title={counts.activity ?? '—'} description="Activity events" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasBorder hasShadow={false}><EuiStat title={counts.dlq ?? '—'} description="Failed sync items" titleColor={counts.dlq ? 'danger' : 'success'} /></EuiPanel></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiCallOut
        size="s"
        color="primary"
        title={`Evidence state: ${(counts.heldEvidence || 0).toLocaleString()} held · ${(counts.archivedEvidence || 0).toLocaleString()} archived · ${(counts.purgedEvidence || 0).toLocaleString()} purged stubs`}
      >
        Cases are alias-backed with numeric rollover generations. Case retirement carries active and recently-closed
        cases forward and moves expired closed cases to Archived Cases; reopening copies an archived case back into
        the live case list. See the case controls below.
      </EuiCallOut>
      <EuiSpacer size="m" />
      <EuiBasicTable
        items={rows}
        columns={[
          { field: 'store', name: 'Store' },
          { field: 'alias', name: 'Index / alias', render: (v: string) => <EuiBadge color="hollow">{v}</EuiBadge> },
          { field: 'documents', name: 'Documents', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
        ]}
      />
      {(health?.generations?.alerts || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Alert generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">
            Retirement carries unresolved alerts plus closed alerts required by active cases or explicit evidence holds into a compact index, atomically swaps the read alias, and retains the original generation.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.alerts}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Total', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'active', name: 'Active', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'ageDays', name: 'Age', render: (v: number) => `${v}d` },
              { field: 'retentionEligible', name: 'Retention', render: (v: boolean, item: any) => <EuiBadge color={v ? 'warning' : 'hollow'}>{item.isWriteIndex ? 'Current' : v ? 'Due' : 'Within policy'}</EuiBadge> },
              { field: 'isWriteIndex', name: 'Role', render: (v: boolean) => <EuiBadge color={v ? 'primary' : 'hollow'}>{v ? 'Current writer' : 'Retirable'}</EuiBadge> },
              {
                name: 'Actions',
                actions: [{
                  name: 'Plan retirement',
                  description: canManageLifecycle ? 'Carry active alerts forward and retain this generation' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'archive',
                  enabled: (item: any) => canManageLifecycle && !item.isWriteIndex,
                  onClick: (item: any) => planRetirement(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      {(health?.generations?.evidence || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Evidence generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">Bounded case-alert relationships, compact snapshots, holds, and trusted archive locators. Retirement copies every current relationship into the writer before detaching the old generation.</EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.evidence}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Relationships', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'isWriteIndex', name: 'Role', render: (v: boolean) => <EuiBadge color={v ? 'primary' : 'hollow'}>{v ? 'Current writer' : 'Retirable'}</EuiBadge> },
              {
                name: 'Actions',
                actions: [{
                  name: 'Compact and retire', type: 'icon', icon: 'archive',
                  description: canManageLifecycle ? 'Carry every relationship forward, then detach this generation' : LIFECYCLE_ROLE_HELP,
                  enabled: (item: any) => canManageLifecycle && !item.isWriteIndex,
                  onClick: (item: any) => setEvidenceRetireIndex(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      {(health?.generations?.archivedEvidenceRelationships || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Retired evidence generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">Detached source generations retained after every relationship was carried into the live writer.</EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.archivedEvidenceRelationships}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Retained relationships', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'status', name: 'Status', render: (v: string) => <EuiBadge color={v === 'completed' ? 'success' : 'warning'}>{v}</EuiBadge> },
              { name: 'Actions', actions: [{
                name: 'Purge permanently', type: 'icon', icon: 'trash',
                description: canManageLifecycle ? 'Delete this redundant retained source generation' : LIFECYCLE_ROLE_HELP,
                enabled: (item: any) => canManageLifecycle && item.purgeEligible,
                onClick: (item: any) => setEvidencePurgeIndex(item.index),
              }] },
            ]}
          />
        </>
      )}
      {(health?.generations?.cases || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Case generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">
            Case retirement carries active and recently-closed cases into the current generation and moves expired closed cases to Archived Cases. The retired physical generation is retained outside the live read alias.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.cases}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Cases', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'ageDays', name: 'Age', render: (v: number) => `${v}d` },
              { field: 'retentionEligible', name: 'Retention', render: (v: boolean, item: any) => <EuiBadge color={v ? 'warning' : 'hollow'}>{item.isWriteIndex ? 'Current' : v ? 'Due' : 'Within policy'}</EuiBadge> },
              { field: 'isWriteIndex', name: 'Role', render: (v: boolean) => <EuiBadge color={v ? 'primary' : 'hollow'}>{v ? 'Current writer' : 'Retirable'}</EuiBadge> },
              {
                name: 'Actions',
                actions: [{
                  name: 'Plan retirement',
                  description: canManageLifecycle ? 'Carry active and recent cases forward; move expired closed cases to Archived Cases' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'archive',
                  enabled: (item: any) => canManageLifecycle && !item.isWriteIndex,
                  onClick: (item: any) => planCaseRetirement(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      {(health?.generations?.archivedCases || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Archived case generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">
            Expired closed cases retained outside live search. Reopen copies a case back into the current generation; purge permanently deletes the retained generation.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.archivedCases}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'documents', name: 'Retained cases', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'carried', name: 'Carried forward', render: (v: number) => v.toLocaleString() },
              { field: 'archived', name: 'Archived', render: (v: number) => v.toLocaleString() },
              {
                name: 'Actions',
                actions: [{
                  name: 'Reopen a case',
                  description: canManageLifecycle ? 'Copy an archived case back into the live case list' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'folderOpen',
                  enabled: () => canManageLifecycle,
                  onClick: (item: any) => setReopenIndex(item.index),
                }, {
                  name: 'Purge permanently',
                  description: canManageLifecycle ? 'Permanently delete the retained case generation' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'trash',
                  enabled: () => canManageLifecycle,
                  onClick: (item: any) => setCasePurgeIndex(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      {(health?.generations?.archivedAlerts || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Retained retired generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">
            These indices are outside live aliases. Restore missing alerts with one guarded action, or explicitly purge the archive after your backup and validation window.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.archivedAlerts}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Retained documents', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'status', name: 'State', render: (v: string) => <EuiBadge color={v === 'completed' ? 'success' : 'warning'}>{v}</EuiBadge> },
              {
                field: 'purgeBlockedReasons',
                name: 'Purge guard',
                render: (v: string[]) => v?.length
                  ? <EuiToolTip content={v.join(' · ')}><EuiBadge color="warning">Blocked ({v.length})</EuiBadge></EuiToolTip>
                  : <EuiBadge color="success">Eligible</EuiBadge>,
              },
              {
                name: 'Actions',
                actions: [{
                  name: 'Restore to live',
                  description: canManageLifecycle ? 'Restore missing archived alerts without overwriting newer live records' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'refresh',
                  enabled: (item: any) => canManageLifecycle && item.restoreEligible,
                  onClick: (item: any) => setRestoreIndex(item.index),
                }, {
                  name: 'Purge permanently',
                  description: canManageLifecycle ? 'Permanently delete the retained source generation' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'trash',
                  enabled: (item: any) => canManageLifecycle && item.purgeEligible,
                  onClick: (item: any) => setPurgeIndex(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      {(health?.generations?.activity || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Activity generations</h4></EuiTitle>
          <EuiText size="s" color="subdued">
            Activity is append-only. Once a non-write generation reaches the configured retention age it can be detached from live comments, audit, reports, and SLA calculations, retained as an archive, and purged separately.
          </EuiText>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.activity}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Events', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'ageDays', name: 'Age', render: (v: number) => `${v}d` },
              { field: 'retentionEligible', name: 'Retention', render: (v: boolean, item: any) => <EuiBadge color={v ? 'warning' : 'hollow'}>{item.isWriteIndex ? 'Current' : v ? 'Due' : 'Within policy'}</EuiBadge> },
              {
                name: 'Actions',
                actions: [{
                  name: 'Retire activity generation',
                  description: canManageLifecycle ? 'Detach this aged generation from live comments, audit views, reports, and SLA calculations' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'archive',
                  enabled: (item: any) => canManageLifecycle && !item.isWriteIndex && item.retentionEligible,
                  onClick: (item: any) => setActivityRetireIndex(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      {(health?.generations?.archivedActivity || []).length > 0 && (
        <>
          <EuiSpacer size="l" />
          <EuiTitle size="xs"><h4>Retained activity archives</h4></EuiTitle>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={health.generations.archivedActivity}
            columns={[
              { field: 'index', name: 'Physical index' },
              { field: 'total', name: 'Events', render: (v: number | null) => v == null ? 'Unavailable' : v.toLocaleString() },
              { field: 'status', name: 'State' },
              {
                name: 'Actions',
                actions: [{
                  name: 'Purge permanently',
                  description: canManageLifecycle ? 'Permanently delete the retained activity index' : LIFECYCLE_ROLE_HELP,
                  type: 'icon',
                  icon: 'trash',
                  enabled: (item: any) => canManageLifecycle && item.purgeEligible,
                  onClick: (item: any) => setActivityPurgeIndex(item.index),
                }],
              },
            ]}
          />
        </>
      )}
      <EuiSpacer size="m" />
      <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" wrap className="wamLifecycleActions">
        <EuiFlexItem grow={false}><EuiButton onClick={load} isLoading={loading}>Refresh health</EuiButton></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiToolTip content={canManageLifecycle ? 'Start a new activity generation' : LIFECYCLE_ROLE_HELP}><span><EuiButton disabled={!canManageLifecycle} onClick={() => rollover('activity')} isLoading={rolling === 'activity'}>Roll activity generation</EuiButton></span></EuiToolTip></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiToolTip content={canManageLifecycle ? 'Start a new alert generation' : LIFECYCLE_ROLE_HELP}><span><EuiButton disabled={!canManageLifecycle} onClick={() => rollover('alerts')} isLoading={rolling === 'alerts'}>Roll alert generation</EuiButton></span></EuiToolTip></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiToolTip content={canManageLifecycle ? 'Start a new case generation' : LIFECYCLE_ROLE_HELP}><span><EuiButton disabled={!canManageLifecycle} onClick={() => rollover('cases')} isLoading={rolling === 'cases'}>Roll case generation</EuiButton></span></EuiToolTip></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiToolTip content={canManageLifecycle ? 'Start a new evidence relationship generation' : LIFECYCLE_ROLE_HELP}><span><EuiButton disabled={!canManageLifecycle} onClick={() => rollover('evidence')} isLoading={rolling === 'evidence'}>Roll evidence generation</EuiButton></span></EuiToolTip></EuiFlexItem>
      </EuiFlexGroup>
      {retirementPlan && (
        <EuiConfirmModal
          title={`Retire ${retirementPlan.retiringIndex}?`}
          onCancel={() => setRetirementPlan(null)}
          onConfirm={executeRetirement}
          cancelButtonText="Cancel"
          confirmButtonText="Carry active alerts and retire"
          buttonColor="danger"
          isLoading={retiring}
        >
          <p>
            {retirementPlan.activeDocuments.toLocaleString()} open or in-progress alerts and{' '}
            {retirementPlan.carriedCaseLinkedDocuments.toLocaleString()} closed alerts from active or held cases will be
            carried forward. {retirementPlan.archivedCaseLinkedDocuments.toLocaleString()} closed alerts from closed,
            non-held cases will become archive-only and leave live reports. The complete physical source index is retained,
            write-blocked, and can be restored from this screen. A later restore can make alerts reappear and change reports
            for historical time ranges.
          </p>
        </EuiConfirmModal>
      )}
      {purgeIndex && (
        <EuiConfirmModal
          title={`Permanently purge ${purgeIndex}?`}
          onCancel={() => setPurgeIndex(null)}
          onConfirm={purgeRetired}
          cancelButtonText="Keep retained index"
          confirmButtonText="Purge permanently"
          buttonColor="danger"
          isLoading={purging}
        >
          <p>
            This deletes the retired physical index and cannot be undone by the plugin. Continue only after your backup and rollback window are complete.
          </p>
        </EuiConfirmModal>
      )}
      {restoreIndex && (
        <EuiConfirmModal
          title={`Restore alerts from ${restoreIndex}?`}
          onCancel={() => setRestoreIndex(null)}
          onConfirm={restoreRetired}
          cancelButtonText="Keep archive only"
          confirmButtonText="Restore missing alerts"
          isLoading={restoring}
        >
          <p>
            Missing alerts will be copied into the current live generation. They can reappear in the Workbench and in reports,
            changing totals, status breakdowns, and timing or SLA results for historical time ranges. Existing live records are
            never overwritten, so newer status, assignment, case, and analysis changes win. The retained archive remains available
            until separately purged.
          </p>
        </EuiConfirmModal>
      )}
      {activityRetireIndex && (
        <EuiConfirmModal
          title={`Retire ${activityRetireIndex}?`}
          onCancel={() => setActivityRetireIndex(null)}
          onConfirm={retireActivity}
          cancelButtonText="Cancel"
          confirmButtonText="Retire and retain"
          isLoading={retiring}
        >
          <p>This aged non-write generation will leave live comments, audit views, reports, and SLA calculations. Its write-blocked physical index remains retained until a separate explicit purge.</p>
        </EuiConfirmModal>
      )}
      {activityPurgeIndex && (
        <EuiConfirmModal
          title={`Permanently purge ${activityPurgeIndex}?`}
          onCancel={() => setActivityPurgeIndex(null)}
          onConfirm={purgeActivity}
          cancelButtonText="Keep retained index"
          confirmButtonText="Purge permanently"
          buttonColor="danger"
          isLoading={purging}
        >
          <p>This permanently removes the retained activity index. Verify your backup and reporting requirements first.</p>
        </EuiConfirmModal>
      )}
      {evidenceRetireIndex && (
        <EuiConfirmModal
          title={`Compact and retire ${evidenceRetireIndex}?`}
          onCancel={() => setEvidenceRetireIndex(null)}
          onConfirm={retireEvidence}
          cancelButtonText="Cancel"
          confirmButtonText="Carry all relationships and retire"
          isLoading={retiring}
        >
          <p>Every relationship, snapshot, trusted archive locator, and evidence hold is copied insert-only into the current writer before this generation leaves the live alias. The source remains write-blocked and retained.</p>
        </EuiConfirmModal>
      )}
      {evidencePurgeIndex && (
        <EuiConfirmModal
          title={`Permanently purge ${evidencePurgeIndex}?`}
          onCancel={() => setEvidencePurgeIndex(null)}
          onConfirm={purgeEvidence}
          cancelButtonText="Keep retained generation"
          confirmButtonText="Purge redundant source"
          buttonColor="danger"
          isLoading={purging}
        >
          <p>This deletes the retired source generation. Its relationships have already been carried into the live evidence writer, but the old physical copy cannot be recovered after purge.</p>
        </EuiConfirmModal>
      )}
      {caseRetirementPlan && (
        <EuiConfirmModal
          title={`Retire ${caseRetirementPlan.retiringIndex}?`}
          onCancel={() => setCaseRetirementPlan(null)}
          onConfirm={executeCaseRetirement}
          cancelButtonText="Cancel"
          confirmButtonText="Carry active cases and retire"
          buttonColor="danger"
          isLoading={caseRetiring}
        >
          <p>
            {caseRetirementPlan.active.toLocaleString()} open or in-progress cases and{' '}
            {caseRetirementPlan.recentClosed.toLocaleString()} recently-closed cases will be carried into the current
            generation. {caseRetirementPlan.expiredClosed.toLocaleString()} expired closed cases will move to Archived
            Cases and leave the live case list and reports. The physical source generation is retained and can be
            reopened or purged from this screen.
          </p>
        </EuiConfirmModal>
      )}
      {casePurgeIndex && (
        <EuiConfirmModal
          title={`Permanently purge ${casePurgeIndex}?`}
          onCancel={() => setCasePurgeIndex(null)}
          onConfirm={purgeArchivedCaseGen}
          cancelButtonText="Keep retained generation"
          confirmButtonText="Purge permanently"
          buttonColor="danger"
          isLoading={casePurging}
        >
          <p>This permanently deletes the retained archived case generation and cannot be undone by the plugin. Continue only after your backup window is complete.</p>
        </EuiConfirmModal>
      )}
      {reopenIndex && (
        <EuiConfirmModal
          title={`Reopen an archived case from ${reopenIndex}?`}
          onCancel={() => { setReopenIndex(null); setReopenCaseId(''); }}
          onConfirm={reopenCase}
          cancelButtonText="Cancel"
          confirmButtonText="Reopen case"
          isLoading={reopening}
          confirmButtonDisabled={!reopenCaseId.trim()}
        >
          <EuiFormRow label="Case ID">
            <EuiFieldText
              placeholder="Paste the archived case ID"
              value={reopenCaseId}
              onChange={(e) => setReopenCaseId(e.target.value)}
            />
          </EuiFormRow>
          <EuiSpacer size="s" />
          <p>The archived case is copied into the current generation as an open case. The original archived document is retained.</p>
        </EuiConfirmModal>
      )}
    </div>
  );
};
