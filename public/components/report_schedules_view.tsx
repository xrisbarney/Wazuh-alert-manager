import React, { useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  REPORT_SCHEDULES_MAX,
  REPORT_SCHEDULE_MAX_CHANNELS,
  REPORT_SCHEDULE_MAX_RANGE_DAYS,
  ReportRunSummary,
  ReportSchedule,
  ReportScheduleCadence,
} from '../../common';
import { AlertsApiService, downloadBlob } from '../services/api';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ADMIN_HELP =
  'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control report schedules.';

const DAY_OPTIONS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].map((text, value) => ({ value: String(value), text }));
const CADENCE_OPTIONS: Array<{ value: ReportScheduleCadence; text: string }> = [
  { value: 'daily', text: 'Daily' },
  { value: 'weekly', text: 'Weekly' },
];

/** Lower-case id derived from the name; unique within the list. */
export function suggestScheduleId(name: string, existing: ReportSchedule[]): string {
  const base = name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 56) || 'summary';
  let id = base;
  let n = 2;
  while (existing.some((entry) => entry.id === id)) id = `${base}-${n++}`;
  return id;
}

function newSchedule(existing: ReportSchedule[]): ReportSchedule {
  return { id: suggestScheduleId('daily-summary', existing), name: 'Daily summary', cadence: 'daily', dayOfWeek: 1, hourUtc: 7, rangeDays: 1, channelIds: [], enabled: true };
}

function splitCsv(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

export function describeCadence(schedule: ReportSchedule): string {
  const time = `${pad(schedule.hourUtc)}:00 UTC`;
  return schedule.cadence === 'weekly' ? `Weekly, ${DAY_OPTIONS[schedule.dayOfWeek]?.text ?? 'Monday'} ${time}` : `Daily, ${time}`;
}

export function formatSlot(iso: string | undefined | null): string {
  if (!iso) return '-';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
}

export const LastRunCell: React.FC<{ run: ReportRunSummary | undefined }> = ({ run }) => {
  if (!run) {
    return (
      <span className="wamReportScheduleLastRun" data-test-subj="wamReportScheduleLastRun">
        <EuiBadge color="hollow">Never</EuiBadge>
      </span>
    );
  }
  // The stored report (last success) and the last failed attempt are
  // independent: a failure never discards the previous Markdown.
  const stored = run.markdown_bytes > 0;
  return (
    <span className="wamReportScheduleLastRun" data-test-subj="wamReportScheduleLastRun">
      {stored && (
        <>
          <EuiBadge color="success">{run.truncated ? 'Stored (truncated)' : 'Stored'}</EuiBadge>
          <span className="wamReportScheduleWhen">
            slot {formatSlot(run.slot)} · by {run.triggered_by}
          </span>
        </>
      )}
      {run.error && (
        <>
          <EuiToolTip content={run.error}>
            <EuiBadge color="danger" iconType="alert" data-test-subj="wamReportScheduleFailed">
              {stored ? 'Last attempt failed' : 'Failed'}
            </EuiBadge>
          </EuiToolTip>
          <span className="wamReportScheduleWhen">
            slot {formatSlot(run.failed_slot)} · attempt {run.attempts || 1}
          </span>
        </>
      )}
    </span>
  );
};

export const ReportSchedulesView: React.FC<Props> = ({ apiService, onToast }) => {
  const [loading, setLoading] = useState(true);
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [canAdminister, setCanAdminister] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [schedules, setSchedules] = useState<ReportSchedule[]>([]);
  const [lastRuns, setLastRuns] = useState<Record<string, ReportRunSummary>>({});
  const [nextSlots, setNextSlots] = useState<Record<string, string>>({});
  const [meta, setMeta] = useState<{ updated_at?: string; updated_by?: string }>({});
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [editing, setEditing] = useState<ReportSchedule | null>(null);
  const [editingOriginalId, setEditingOriginalId] = useState<string | null>(null);
  const [idTouched, setIdTouched] = useState(false);
  const [channelsText, setChannelsText] = useState('');

  const applyResponse = (res: { schedules: ReportSchedule[]; lastRuns: Record<string, ReportRunSummary>; nextSlots: Record<string, string>; updated_at?: string; updated_by?: string }) => {
    setSchedules(res.schedules || []);
    setLastRuns(res.lastRuns || {});
    setNextSlots(res.nextSlots || {});
    setMeta({ updated_at: res.updated_at, updated_by: res.updated_by });
  };

  const load = async () => {
    try {
      applyResponse(await apiService.fetchReportSchedules());
      setLoadError(null);
      setDirty(false);
    } catch (e: any) {
      setLoadError(e?.body?.message || e?.message || 'Failed to load report schedules');
    }
  };

  useEffect(() => {
    apiService
      .fetchSystemCapabilities()
      .then((capabilities: any) => setCanAdminister(Boolean(capabilities?.isPluginAdmin)))
      .catch(() => setCanAdminister(false))
      .finally(() => setCapabilitiesLoaded(true));
    load().finally(() => setLoading(false));
  }, []);

  const update = (next: ReportSchedule[]) => {
    setSchedules(next);
    setDirty(true);
  };

  const openEditor = (entry: ReportSchedule, originalId: string | null) => {
    setEditing({ ...entry, channelIds: [...entry.channelIds] });
    setEditingOriginalId(originalId);
    setIdTouched(originalId !== null);
    setChannelsText(entry.channelIds.join(', '));
  };

  const closeEditor = () => {
    setEditing(null);
    setEditingOriginalId(null);
  };

  const commitEditor = () => {
    if (!editing) return;
    const draft: ReportSchedule = {
      ...editing,
      id: editing.id.trim(),
      name: editing.name.trim(),
      channelIds: Array.from(new Set(splitCsv(channelsText))).slice(0, REPORT_SCHEDULE_MAX_CHANNELS),
    };
    if (!draft.id || !draft.name) {
      onToast('Id and name are required', 'danger');
      return;
    }
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(draft.id)) {
      onToast('Id must be 1-64 lower-case letters, digits, - or _', 'danger');
      return;
    }
    if (!Number.isInteger(draft.hourUtc) || draft.hourUtc < 0 || draft.hourUtc > 23) {
      onToast('Hour must be between 0 and 23 (UTC)', 'danger');
      return;
    }
    if (!Number.isInteger(draft.rangeDays) || draft.rangeDays < 1 || draft.rangeDays > REPORT_SCHEDULE_MAX_RANGE_DAYS) {
      onToast(`Range must be between 1 and ${REPORT_SCHEDULE_MAX_RANGE_DAYS} days`, 'danger');
      return;
    }
    if (schedules.some((entry) => entry.id === draft.id && entry.id !== editingOriginalId)) {
      onToast(`Schedule id "${draft.id}" is already used`, 'danger');
      return;
    }
    const exists = editingOriginalId !== null && schedules.some((entry) => entry.id === editingOriginalId);
    update(exists ? schedules.map((entry) => (entry.id === editingOriginalId ? draft : entry)) : [...schedules, draft]);
    closeEditor();
  };

  const save = async () => {
    try {
      setSaving(true);
      applyResponse(await apiService.saveReportSchedules({ schedules }));
      setDirty(false);
      onToast('Report schedules saved', 'success', 'Each enabled schedule is rendered at its next UTC slot by whichever dashboard replica holds the scheduler lease.');
    } catch (e: any) {
      onToast('Failed to save report schedules', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  const runNow = async (entry: ReportSchedule) => {
    try {
      setBusyId(entry.id);
      const { run } = await apiService.runReportScheduleNow(entry.id);
      setLastRuns((current) => ({ ...current, [entry.id]: run }));
      if (run.error) onToast(`"${entry.name}" failed to render`, 'danger', `${run.error}${run.markdown_bytes > 0 ? ' The previously stored report is kept.' : ''}`);
      else onToast(`"${entry.name}" rendered`, 'success', `Slot ${formatSlot(run.slot)} stored (${Math.round(run.markdown_bytes / 1024)} KiB).`);
    } catch (e: any) {
      onToast('Run now failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBusyId(null);
    }
  };

  const download = async (entry: ReportSchedule) => {
    try {
      setBusyId(entry.id);
      const result = await apiService.downloadReportScheduleLastRun(entry.id);
      downloadBlob(result.filename, result.blob);
    } catch (e: any) {
      onToast('Download failed', 'danger', e?.body?.message || e.message);
    } finally {
      setBusyId(null);
    }
  };

  if (loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="xl" /></div>;

  const description = (
    <>
      Each schedule renders the Reports metrics for its range (alert volume by severity, status breakdown, SLA summary, top rules and
      agents, cases) as a Markdown summary at the chosen hour in UTC. The last run of each schedule is stored and can be downloaded
      here; a slot missed while the dashboard was down is rendered at the next check. Each rendered run is also delivered to the
      schedule's notification channels (Settings &gt; Notifications) as a <code>report.scheduled</code> notification with the
      Markdown as the message; unknown or disabled channel ids are skipped and logged.
    </>
  );

  if (!capabilitiesLoaded || !canAdminister) {
    return (
      <div className="wamSettingsPage wamReportSchedules">
        <SettingsPageHeader title="Scheduled summaries" description={description} />
        <EuiCallOut
          size="s"
          color={capabilitiesLoaded ? 'warning' : 'primary'}
          iconType="lock"
          title={capabilitiesLoaded ? 'Report schedules are administered by Wazuh administrators' : 'Checking permissions'}
        >
          {capabilitiesLoaded && <p>{ADMIN_HELP}</p>}
        </EuiCallOut>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="wamSettingsPage wamReportSchedules">
        <SettingsPageHeader title="Scheduled summaries" description={description} />
        <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load report schedules" data-test-subj="wamReportScheduleLoadError">
          <p>{loadError}</p>
          <EuiButton
            size="s"
            color="danger"
            iconType="refresh"
            data-test-subj="wamReportScheduleRetry"
            onClick={() => {
              setLoading(true);
              load().finally(() => setLoading(false));
            }}
          >
            Retry
          </EuiButton>
        </EuiCallOut>
      </div>
    );
  }

  const columns: any[] = [
    {
      field: 'name',
      name: 'Name',
      render: (name: string, entry: ReportSchedule) => (
        <span data-test-subj={`wamReportSchedule-${entry.id}`}>
          {name} <code className="wamReportScheduleWhen">{entry.id}</code>
        </span>
      ),
    },
    { name: 'Cadence', render: (entry: ReportSchedule) => describeCadence(entry) },
    { field: 'rangeDays', name: 'Range', width: '90px', render: (days: number) => `${days} day${days === 1 ? '' : 's'}` },
    {
      field: 'enabled',
      name: 'Enabled',
      width: '90px',
      render: (enabled: boolean) => <EuiBadge color={enabled ? 'success' : 'hollow'}>{enabled ? 'On' : 'Off'}</EuiBadge>,
    },
    {
      name: 'Next slot',
      render: (entry: ReportSchedule) => (
        <span className="wamReportScheduleWhen">{dirty ? 'save to compute' : entry.enabled ? formatSlot(nextSlots[entry.id]) : 'paused'}</span>
      ),
    },
    { name: 'Last run', render: (entry: ReportSchedule) => <LastRunCell run={lastRuns[entry.id]} /> },
    {
      name: 'Actions',
      width: '170px',
      render: (entry: ReportSchedule) => {
        const saved = !dirty;
        const run = lastRuns[entry.id];
        return (
          <EuiFlexGroup gutterSize="xs" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiToolTip content={dirty ? 'Save first to run the saved schedule' : 'Render this schedule now for its current slot'}>
                <EuiButtonIcon
                  iconType="play"
                  aria-label={`Run ${entry.name} now`}
                  isDisabled={!saved || busyId !== null || editing !== null}
                  data-test-subj={`wamReportScheduleRunNow-${entry.id}`}
                  onClick={() => runNow(entry)}
                />
              </EuiToolTip>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiToolTip content={run && run.markdown_bytes > 0 ? 'Download the last stored report as Markdown' : 'No stored run to download'}>
                <EuiButtonIcon
                  iconType="download"
                  aria-label={`Download the last run of ${entry.name}`}
                  isDisabled={!run || run.markdown_bytes === 0 || busyId !== null}
                  data-test-subj={`wamReportScheduleDownload-${entry.id}`}
                  onClick={() => download(entry)}
                />
              </EuiToolTip>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="pencil" aria-label={`Edit ${entry.name}`} isDisabled={editing !== null} onClick={() => openEditor(entry, entry.id)} />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon
                iconType="trash"
                color="danger"
                aria-label={`Remove ${entry.name}`}
                isDisabled={editing !== null}
                data-test-subj={`wamReportScheduleRemove-${entry.id}`}
                onClick={() => update(schedules.filter((item) => item.id !== entry.id))}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
        );
      },
    },
  ];

  return (
    <div className="wamSettingsPage wamReportSchedules" data-test-subj="wamReportSchedules">
      <SettingsPageHeader
        title="Scheduled summaries"
        description={description}
        actions={
          <EuiButton
            size="s"
            fill
            iconType="plusInCircle"
            disabled={schedules.length >= REPORT_SCHEDULES_MAX || editing !== null}
            onClick={() => openEditor(newSchedule(schedules), null)}
            data-test-subj="wamReportScheduleAdd"
          >
            New schedule
          </EuiButton>
        }
      />

      {dirty && (
        <>
          <EuiCallOut size="s" color="warning" iconType="alert" title="Unsaved changes" data-test-subj="wamReportScheduleDirty" />
          <EuiSpacer size="m" />
        </>
      )}

      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamReportSchedulesPanel">
      <EuiTitle size="xs">
        <h4>Schedules</h4>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable items={schedules} columns={columns} className="wamReportScheduleTable" tableLayout="auto" noItemsMessage="No report schedules yet." />
      <EuiSpacer size="m" />

      <SettingsFormActions
        meta={
          <>
            {schedules.length}/{REPORT_SCHEDULES_MAX} schedules
            {meta.updated_by ? ` · last saved by ${meta.updated_by}` : ''}
          </>
        }
      >
        {dirty ? (
          <EuiButtonEmpty size="s" onClick={() => load()} disabled={saving}>
            Discard
          </EuiButtonEmpty>
        ) : null}
        <EuiButton size="s" fill iconType="save" isLoading={saving} disabled={!dirty || editing !== null} onClick={save} data-test-subj="wamReportScheduleSave">
          Save
        </EuiButton>
      </SettingsFormActions>
      </EuiPanel>

      {editing && (
        <>
          <EuiSpacer size="m" />
          <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamReportScheduleEditor" data-test-subj="wamReportScheduleEditor">
            <EuiForm component="form" onSubmit={(event) => { event.preventDefault(); commitEditor(); }}>
              <EuiFlexGroup gutterSize="m" wrap>
                <EuiFlexItem style={{ minWidth: 220 }}>
                  <EuiFormRow fullWidth label="Name">
                    <EuiFieldText fullWidth
                      value={editing.name}
                      onChange={(e) => {
                        const name = e.target.value;
                        const autoId = editingOriginalId === null && !idTouched;
                        setEditing({ ...editing, name, id: autoId ? suggestScheduleId(name, schedules) : editing.id });
                      }}
                      data-test-subj="wamReportScheduleEditorName"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 200 }}>
                  <EuiFormRow fullWidth label="Id" helpText="Lower-case letters, digits, - and _. Names the stored run.">
                    <EuiFieldText fullWidth
                      value={editing.id}
                      onChange={(e) => { setIdTouched(true); setEditing({ ...editing, id: e.target.value.toLowerCase() }); }}
                      data-test-subj="wamReportScheduleEditorId"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 140 }}>
                  <EuiFormRow fullWidth label="Cadence">
                    <EuiSelect fullWidth
                      options={CADENCE_OPTIONS}
                      value={editing.cadence}
                      onChange={(e) => setEditing({ ...editing, cadence: e.target.value as ReportScheduleCadence })}
                      data-test-subj="wamReportScheduleEditorCadence"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                {editing.cadence === 'weekly' && (
                  <EuiFlexItem style={{ minWidth: 160 }}>
                    <EuiFormRow fullWidth label="Day (UTC)">
                      <EuiSelect fullWidth
                        options={DAY_OPTIONS}
                        value={String(editing.dayOfWeek)}
                        onChange={(e) => setEditing({ ...editing, dayOfWeek: Number(e.target.value) })}
                        data-test-subj="wamReportScheduleEditorDay"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                )}
                <EuiFlexItem style={{ minWidth: 120 }}>
                  <EuiFormRow fullWidth label="Hour (UTC)" helpText="0-23">
                    <EuiFieldNumber fullWidth
                      min={0}
                      max={23}
                      step={1}
                      value={editing.hourUtc}
                      onChange={(e) => setEditing({ ...editing, hourUtc: e.target.value === '' ? NaN : Number(e.target.value) })}
                      data-test-subj="wamReportScheduleEditorHour"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 120 }}>
                  <EuiFormRow fullWidth label="Range (days)" helpText={`1-${REPORT_SCHEDULE_MAX_RANGE_DAYS}, ending at the slot`}>
                    <EuiFieldNumber fullWidth
                      min={1}
                      max={REPORT_SCHEDULE_MAX_RANGE_DAYS}
                      step={1}
                      value={editing.rangeDays}
                      onChange={(e) => setEditing({ ...editing, rangeDays: e.target.value === '' ? NaN : Number(e.target.value) })}
                      data-test-subj="wamReportScheduleEditorRange"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 260 }}>
                  <EuiFormRow fullWidth
                    label="Notification channels"
                    helpText={`Comma separated ids of channels from Settings > Notifications, at most ${REPORT_SCHEDULE_MAX_CHANNELS}. Each run is delivered to them as a report.scheduled notification; unknown or disabled ids are skipped.`}
                  >
                    <EuiFieldText fullWidth value={channelsText} onChange={(e) => setChannelsText(e.target.value)} placeholder="slack-soc" data-test-subj="wamReportScheduleEditorChannels" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFormRow fullWidth label="Enabled" hasChildLabel={false}>
                    <EuiSwitch
                      label={editing.enabled ? 'On' : 'Off'}
                      checked={editing.enabled}
                      onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })}
                      data-test-subj="wamReportScheduleEditorEnabled"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="s" />
              <SettingsFormActions>
                <EuiButtonEmpty size="s" onClick={closeEditor}>
                  Cancel
                </EuiButtonEmpty>
                <EuiButton size="s" fill type="submit" data-test-subj="wamReportScheduleEditorApply">
                  Apply
                </EuiButton>
              </SettingsFormActions>
            </EuiForm>
          </EuiPanel>
        </>
      )}
    </div>
  );
};
