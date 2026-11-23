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
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import {
  SLA_BANDS,
  SLA_ESCALATION_MAX_NOTIFY,
  SLA_MAX_ESCALATIONS,
  SLA_MINUTES_MAX,
  SLA_MINUTES_MIN,
  SlaBand,
  SlaEscalation,
  SlaEscalationStatusResponse,
  SlaPolicy,
  SlaTarget,
  TARGET_WAZUH_MAJOR,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { formatDuration, SEVERITY_HEX } from '../design';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ADMIN_HELP =
  'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control SLA administration.';

export const SLA_BAND_LABEL: Record<SlaBand, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

/** The 4.x `rule.level` range of each band; a 5.0 build shows the label instead. */
const BAND_RANGE: Record<SlaBand, string> = { critical: 'level 12+', high: 'level 7-11', medium: 'level 4-6', low: 'level 0-3' };

export const BAND_COLOR: Record<SlaBand, string> = {
  critical: SEVERITY_HEX.critical,
  high: SEVERITY_HEX.high,
  medium: SEVERITY_HEX.medium,
  low: SEVERITY_HEX.low,
};

type TargetField = keyof SlaTarget;
/** What the user typed, per band and field; empty string while clearing a field. */
type Draft = Record<SlaBand, Record<TargetField, string>>;

function toDraft(policy: SlaPolicy): Draft {
  const draft = {} as Draft;
  for (const band of SLA_BANDS) {
    draft[band] = {
      resolveMinutes: String(policy.targets[band].resolveMinutes),
      assignMinutes: String(policy.targets[band].assignMinutes),
    };
  }
  return draft;
}

function parseMinutes(value: string): number | null {
  if (!/^\d+$/.test(value.trim())) return null;
  const n = Number(value);
  return n >= SLA_MINUTES_MIN && n <= SLA_MINUTES_MAX ? n : null;
}

/** Human form of a minutes input ("4h", "3d"), or the reason it is invalid. */
export function minutesHelper(value: string): { text: string; invalid: boolean } {
  const n = parseMinutes(value);
  if (n == null) return { text: `${SLA_MINUTES_MIN}-${SLA_MINUTES_MAX} whole minutes`, invalid: true };
  return { text: n < 60 ? `${n} min` : formatDuration(n), invalid: false };
}

/** Validated policy from the draft, or null while any field is invalid. */
export function draftToTargets(draft: Draft): SlaPolicy['targets'] | null {
  const targets = {} as SlaPolicy['targets'];
  for (const band of SLA_BANDS) {
    const resolveMinutes = parseMinutes(draft[band].resolveMinutes);
    const assignMinutes = parseMinutes(draft[band].assignMinutes);
    if (resolveMinutes == null || assignMinutes == null) return null;
    targets[band] = { resolveMinutes, assignMinutes };
  }
  return targets;
}

export function sameTargets(a: SlaPolicy['targets'], b: SlaPolicy['targets']): boolean {
  return SLA_BANDS.every(
    (band) => a[band].resolveMinutes === b[band].resolveMinutes && a[band].assignMinutes === b[band].assignMinutes
  );
}

// ---------------------------------------------------------------------------
// Escalations editor (step 3.3)
// ---------------------------------------------------------------------------

const ESCALATION_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** What the form holds while an escalation is being added or edited. */
export interface EscalationDraft {
  id: string;
  name: string;
  target: SlaEscalation['target'];
  thresholdPercent: string;
  condition: SlaEscalation['condition'];
  assignTo: string;
  raiseSeverity: boolean;
  comment: string;
  /** Channel ids, one per line or comma-separated. */
  notify: string;
  enabled: boolean;
}

export const EMPTY_ESCALATION_DRAFT: EscalationDraft = {
  id: '',
  name: '',
  target: 'alert',
  thresholdPercent: '50',
  condition: 'unassigned',
  assignTo: '',
  raiseSeverity: false,
  comment: '',
  notify: '',
  enabled: true,
};

export function escalationToDraft(escalation: SlaEscalation): EscalationDraft {
  return {
    id: escalation.id,
    name: escalation.name,
    target: escalation.target,
    thresholdPercent: String(escalation.thresholdPercent),
    condition: escalation.condition,
    assignTo: escalation.actions.assignTo || '',
    raiseSeverity: Boolean(escalation.actions.raiseSeverity),
    comment: escalation.actions.comment || '',
    notify: (escalation.actions.notify || []).join('\n'),
    enabled: escalation.enabled !== false,
  };
}

/** A stable id from the name ("First response" -> "first-response"). */
export function suggestEscalationId(name: string): string {
  return name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
}

export function parseChannelIds(raw: string): string[] {
  const out: string[] = [];
  for (const item of String(raw || '').split(/[\n,]/)) {
    const value = item.trim();
    if (value && !out.includes(value)) out.push(value);
  }
  return out;
}

/** Validate a draft the way the server does (`normaliseSlaPolicy`); returns the escalation or the first problem. */
export function draftToEscalation(
  draft: EscalationDraft,
  existingIds: string[]
): { escalation: SlaEscalation; error?: undefined } | { escalation?: undefined; error: string } {
  const id = draft.id.trim();
  if (!ESCALATION_ID.test(id)) return { error: 'Id must be 1-64 lower-case letters, digits, "-" or "_".' };
  if (existingIds.includes(id)) return { error: `Id "${id}" is already used by another escalation.` };
  const name = draft.name.trim();
  if (!name) return { error: 'Name is required.' };
  if (name.length > 120) return { error: 'Name must be at most 120 characters.' };
  const thresholdPercent = /^\d+$/.test(draft.thresholdPercent.trim()) ? Number(draft.thresholdPercent) : NaN;
  if (!Number.isInteger(thresholdPercent) || thresholdPercent < 1 || thresholdPercent > 100) {
    return { error: 'Threshold must be a whole number between 1 and 100 percent.' };
  }
  const actions: SlaEscalation['actions'] = {};
  const assignTo = draft.assignTo.trim();
  if (assignTo.length > 256) return { error: 'Assignee must be at most 256 characters.' };
  if (assignTo) actions.assignTo = assignTo;
  if (draft.raiseSeverity) {
    if (draft.target !== 'case') return { error: 'Raise severity applies to cases only.' };
    actions.raiseSeverity = true;
  }
  const comment = draft.comment.trim();
  if (comment.length > 2000) return { error: 'Comment must be at most 2000 characters.' };
  if (comment) actions.comment = comment;
  const notify = parseChannelIds(draft.notify);
  if (notify.length > SLA_ESCALATION_MAX_NOTIFY) return { error: `At most ${SLA_ESCALATION_MAX_NOTIFY} channel ids.` };
  if (notify.some((channel) => channel.length > 128)) return { error: 'Channel ids must be at most 128 characters.' };
  if (notify.length) actions.notify = notify;
  if (!actions.assignTo && !actions.raiseSeverity && !actions.comment && !actions.notify) {
    return { error: 'At least one action (assign to, raise severity, comment, notify) is required.' };
  }
  return {
    escalation: { id, name, target: draft.target, thresholdPercent, condition: draft.condition, actions, enabled: draft.enabled },
  };
}

export function sameEscalations(a: SlaEscalation[], b: SlaEscalation[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

const CONDITION_LABEL: Record<SlaEscalation['condition'], string> = {
  unassigned: 'Unassigned',
  untouched: 'Untouched',
  any: 'Any',
};

/** Short summary of the actions for the table ("assign to bob · comment · notify 2"). */
export function describeEscalationActions(actions: SlaEscalation['actions']): string {
  const parts: string[] = [];
  if (actions.assignTo) parts.push(`assign to ${actions.assignTo}`);
  if (actions.raiseSeverity) parts.push('raise severity');
  if (actions.comment) parts.push('comment');
  if (actions.notify?.length) parts.push(`notify ${actions.notify.length}`);
  return parts.join(' · ');
}

/** One line for the scanner status (null response = the route is unavailable). */
export function describeEscalationStatus(res: SlaEscalationStatusResponse | null): string {
  if (!res) return 'Scanner status unavailable.';
  if (res.enabled === null) return 'Scanner not running on this dashboard (plugin not initialised).';
  if (!res.enabled) return 'Scanner disabled on this dashboard (wazuh_alert_manager.sla.escalation.enabled).';
  if (!res.status) return `Scanner enabled (every ${res.tickSeconds}s); no tick recorded yet.`;
  const s = res.status;
  const last = s.last_tick_at ? new Date(s.last_tick_at).toLocaleString() : 'unknown';
  const errors = s.errors?.length ? `; ${s.errors.length} recent error(s)` : '';
  return `Last tick ${last}: ${s.breached_alerts} alert(s) and ${s.breached_cases} case(s) newly breached, ${s.escalated} escalated${s.capped ? ' (capped, continuing next tick)' : ''}${errors}.`;
}

export const SlaSettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [loading, setLoading] = useState(true);
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [canAdminister, setCanAdminister] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [policy, setPolicy] = useState<SlaPolicy | null>(null);
  const [defaults, setDefaults] = useState<SlaPolicy | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [meta, setMeta] = useState<{ updated_at?: string; updated_by?: string }>({});
  const [storedInvalid, setStoredInvalid] = useState(false);
  const [saving, setSaving] = useState(false);
  const [escalations, setEscalations] = useState<SlaEscalation[]>([]);
  const [editing, setEditing] = useState<{ index: number | null; draft: EscalationDraft } | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [scannerStatus, setScannerStatus] = useState<SlaEscalationStatusResponse | null>(null);

  const applyResponse = (res: { policy: SlaPolicy; defaults: SlaPolicy; updated_at?: string; updated_by?: string; storedInvalid?: boolean }) => {
    setPolicy(res.policy);
    setDefaults(res.defaults);
    setDraft(toDraft(res.policy));
    setEscalations(res.policy.escalations || []);
    setMeta({ updated_at: res.updated_at, updated_by: res.updated_by });
    setStoredInvalid(Boolean(res.storedInvalid));
  };

  const load = async () => {
    try {
      const res = await apiService.fetchSlaPolicy();
      applyResponse(res);
      setLoadError(null);
    } catch (e: any) {
      setLoadError(e?.body?.message || e?.message || 'Failed to load the SLA policy');
    }
  };

  const loadScannerStatus = () => {
    if (typeof (apiService as any).fetchSlaEscalationStatus !== 'function') return;
    apiService
      .fetchSlaEscalationStatus()
      .then((res) => setScannerStatus(res))
      .catch(() => setScannerStatus(null));
  };

  useEffect(() => {
    apiService
      .fetchSystemCapabilities()
      .then((capabilities: any) => setCanAdminister(Boolean(capabilities?.isPluginAdmin)))
      .catch(() => setCanAdminister(false))
      .finally(() => setCapabilitiesLoaded(true));
    load().finally(() => setLoading(false));
    loadScannerStatus();
  }, []);

  const setField = (band: SlaBand, field: TargetField, value: string) => {
    if (!draft) return;
    setDraft({ ...draft, [band]: { ...draft[band], [field]: value } });
  };

  const draftTargets = draft ? draftToTargets(draft) : null;
  const targetsDirty = Boolean(policy && draftTargets && !sameTargets(draftTargets, policy.targets)) || Boolean(draft && !draftTargets);
  const escalationsDirty = Boolean(policy && !sameEscalations(escalations, policy.escalations || []));
  const dirty = targetsDirty || escalationsDirty;
  const isDefault = Boolean(policy && defaults && sameTargets(policy.targets, defaults.targets));

  const save = async () => {
    if (!policy || !draftTargets) return;
    try {
      setSaving(true);
      const res = await apiService.saveSlaPolicy({ targets: draftTargets, escalations });
      applyResponse(res);
      onToast('SLA policy saved', 'success', 'New closes and reports use the new targets within a minute on every dashboard replica; the escalation scanner picks the rules up on its next tick.');
    } catch (e: any) {
      onToast('Failed to save the SLA policy', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  const discard = () => {
    if (!policy) return;
    setDraft(toDraft(policy));
    setEscalations(policy.escalations || []);
    setEditing(null);
    setEditError(null);
  };

  const openEditor = (index: number | null) => {
    setEditError(null);
    setEditing({ index, draft: index == null ? { ...EMPTY_ESCALATION_DRAFT } : escalationToDraft(escalations[index]) });
  };

  const setEditField = <K extends keyof EscalationDraft>(field: K, value: EscalationDraft[K]) => {
    if (!editing) return;
    const next = { ...editing.draft, [field]: value };
    // A new rule gets its id from the name until the id is typed by hand.
    if (field === 'name' && editing.index == null && (editing.draft.id === '' || editing.draft.id === suggestEscalationId(editing.draft.name))) {
      next.id = suggestEscalationId(String(value));
    }
    if (field === 'target' && value !== 'case') next.raiseSeverity = false;
    setEditing({ ...editing, draft: next });
  };

  const applyEditor = () => {
    if (!editing) return;
    const otherIds = escalations.filter((_entry, index) => index !== editing.index).map((entry) => entry.id);
    const result = draftToEscalation(editing.draft, otherIds);
    if (result.error) {
      setEditError(result.error);
      return;
    }
    const next = [...escalations];
    if (editing.index == null) next.push(result.escalation);
    else next[editing.index] = result.escalation;
    setEscalations(next);
    setEditing(null);
    setEditError(null);
  };

  const removeEscalation = (index: number) => {
    setEscalations(escalations.filter((_entry, i) => i !== index));
    if (editing && editing.index === index) setEditing(null);
  };

  const toggleEscalation = (index: number, enabled: boolean) => {
    setEscalations(escalations.map((entry, i) => (i === index ? { ...entry, enabled } : entry)));
  };

  if (loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="xl" /></div>;

  const header = (
    <SettingsPageHeader
      title="SLA targets"
      description={
        <>
          Minutes from an alert's event time to its first assignment and to its resolution, per severity band.
          {Number(TARGET_WAZUH_MAJOR) === 5
            ? ' Wazuh 5.0 severity labels map onto the bands directly (informational counts as Low).'
            : ' Bands follow rule.level: Low 0-3, Medium 4-6, High 7-11, Critical 12+.'}{' '}
          Changing a target affects alerts closed from now on and the targets Reports cite; closed alerts keep the SLA
          verdict recorded when they were closed.
        </>
      }
    />
  );

  if (!capabilitiesLoaded || !canAdminister) {
    return (
      <div className="wamSettingsPage wamSlaSettings">
        {header}
        <EuiCallOut
          size="s"
          color={capabilitiesLoaded ? 'warning' : 'primary'}
          iconType="lock"
          title={capabilitiesLoaded ? 'SLA targets are administered by Wazuh administrators' : 'Checking permissions'}
        >
          {capabilitiesLoaded && (
            <p>
              {ADMIN_HELP} Analysts still see the targets an administrator configured in Reports.
            </p>
          )}
        </EuiCallOut>
        {policy && (
          <>
            <EuiSpacer size="m" />
            <EuiText size="s" color="subdued" data-test-subj="wamSlaReadOnlySummary">
              <p>
                Current targets{isDefault ? ' (default policy)' : ''}:{' '}
                {SLA_BANDS.map((band) => `${SLA_BAND_LABEL[band]} ${formatDuration(policy.targets[band].resolveMinutes)}`).join(' · ')}
              </p>
            </EuiText>
          </>
        )}
      </div>
    );
  }

  if (loadError || !policy || !draft) {
    return (
      <div className="wamSettingsPage wamSlaSettings">
        {header}
        <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load the SLA policy" data-test-subj="wamSlaLoadError">
          <p>{loadError || 'The policy document could not be read.'}</p>
          <EuiButton
            size="s"
            color="danger"
            iconType="refresh"
            data-test-subj="wamSlaRetry"
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

  const field = (band: SlaBand, name: TargetField) => {
    const value = draft[band][name];
    const helper = minutesHelper(value);
    return (
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiFieldNumber fullWidth
            compressed
            min={SLA_MINUTES_MIN}
            max={SLA_MINUTES_MAX}
            step={1}
            value={value}
            isInvalid={helper.invalid}
            aria-label={`${SLA_BAND_LABEL[band]} ${name === 'resolveMinutes' ? 'resolve' : 'assign'} target in minutes`}
            onChange={(e) => setField(band, name, e.target.value)}
            data-test-subj={`wamSla-${band}-${name}`}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText size="xs" color={helper.invalid ? 'danger' : 'subdued'} className="wamSlaTargets__helper">
            {helper.text}
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
    );
  };

  return (
    <div className="wamSettingsPage wamSlaSettings">
      {header}

      {storedInvalid && (
        <>
          <EuiCallOut size="s" color="warning" iconType="alert" title="Stored policy is unreadable" data-test-subj="wamSlaStoredInvalid">
            <p>The saved policy document no longer validates, so the built-in targets are in effect. Save to replace it.</p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {isDefault && !dirty && !storedInvalid && (
        <>
          <EuiCallOut size="s" color="primary" iconType="iInCircle" title="Default policy" data-test-subj="wamSlaDefaultPolicy">
            <p>These are the built-in targets; nothing has been customised yet.</p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {dirty && (
        <>
          <EuiCallOut size="s" color="warning" iconType="alert" title="Unsaved changes" data-test-subj="wamSlaDirty" />
          <EuiSpacer size="m" />
        </>
      )}

      <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamSlaTargetsPanel">
      <EuiTitle size="xs">
        <h4>Targets per severity band</h4>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable<{ band: SlaBand }>
        items={SLA_BANDS.map((band) => ({ band }))}
        itemId="band"
        rowProps={(item) => ({ 'data-test-subj': `wamSlaTargets-${item.band}` })}
        columns={[
          {
            field: 'band',
            name: 'Severity',
            render: (band: SlaBand) => (
              <>
                <EuiBadge color={BAND_COLOR[band]}>{SLA_BAND_LABEL[band]}</EuiBadge>{' '}
                {Number(TARGET_WAZUH_MAJOR) === 5 ? null : (
                  <EuiText size="xs" color="subdued" style={{ display: 'inline' }}>
                    {BAND_RANGE[band]}
                  </EuiText>
                )}
              </>
            ),
          },
          { field: 'band', name: 'Assign within', render: (band: SlaBand) => field(band, 'assignMinutes') },
          { field: 'band', name: 'Resolve within', render: (band: SlaBand) => field(band, 'resolveMinutes') },
        ]}
        className="wamSlaTargets"
        tableLayout="auto"
        data-test-subj="wamSlaTargets"
      />
      <EuiSpacer size="m" />

      <SettingsFormActions
        meta={
          <>
            {meta.updated_by ? `Last saved by ${meta.updated_by}` : 'Never saved'}
            {meta.updated_at ? ` on ${new Date(meta.updated_at).toLocaleString()}` : ''}
          </>
        }
      >
        {dirty ? (
          <EuiButtonEmpty size="s" onClick={discard} disabled={saving} data-test-subj="wamSlaDiscard">
            Discard
          </EuiButtonEmpty>
        ) : null}
        <EuiButtonEmpty
          size="s"
          iconType="refresh"
          disabled={saving || !defaults || (draftTargets != null && sameTargets(draftTargets, defaults.targets))}
          onClick={() => defaults && setDraft(toDraft(defaults))}
          data-test-subj="wamSlaResetDefaults"
        >
          Reset to defaults
        </EuiButtonEmpty>
        <EuiButton size="s" fill iconType="save" isLoading={saving} disabled={!dirty || !draftTargets} onClick={save} data-test-subj="wamSlaSave">
          Save
        </EuiButton>
      </SettingsFormActions>
      </EuiPanel>

      <EuiSpacer size="m" />
      <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamSlaEscalations" data-test-subj="wamSlaEscalations">
        <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} justifyContent="spaceBetween">
          <EuiFlexItem grow={false}>
            <EuiTitle size="xs">
              <h4>Escalations</h4>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              size="s"
              iconType="plusInCircle"
              onClick={() => openEditor(null)}
              disabled={saving || Boolean(editing) || escalations.length >= SLA_MAX_ESCALATIONS}
              data-test-subj="wamSlaEscalationAdd"
            >
              Add escalation
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiText size="s" color="subdued">
          <p>
            When a percentage of a record's resolve target has elapsed and the condition holds, the scanner applies the actions once
            per record under the actor <code>system:sla</code>: assign (moves an open record to in progress), raise a case's severity
            one band, leave a comment ({'{{id}}'}, {'{{severity}}'}, {'{{due_at}}'}, {'{{escalation}}'} are substituted) or record
            notification channel ids. Rules are saved together with the targets.
          </p>
        </EuiText>
        <EuiText size="xs" color="subdued" className="wamSlaEscalationStatus" data-test-subj="wamSlaEscalationStatus">
          {describeEscalationStatus(scannerStatus)}
        </EuiText>
        <EuiSpacer size="s" />
        {escalations.length === 0 && !editing ? (
          <EuiText size="s" color="subdued" data-test-subj="wamSlaEscalationsEmpty">
            <p>No escalations are configured.</p>
          </EuiText>
        ) : null}
        {escalations.length > 0 && (
          <EuiBasicTable<SlaEscalation & { index: number }>
            items={escalations.map((entry, index) => ({ ...entry, index }))}
            itemId="id"
            rowProps={(item) => ({ 'data-test-subj': `wamSlaEscalation-${item.id}` })}
            columns={[
              {
                field: 'name',
                name: 'Name',
                render: (name: string, item) => (
                  <>
                    {name} <code>{item.id}</code>
                  </>
                ),
              },
              { field: 'target', name: 'Target', render: (target: string) => (target === 'case' ? 'Cases' : 'Alerts') },
              { field: 'thresholdPercent', name: 'Threshold', render: (value: number) => `${value}% of resolve target` },
              { field: 'condition', name: 'Condition', render: (value: SlaEscalation['condition']) => CONDITION_LABEL[value] || value },
              { field: 'actions', name: 'Actions', render: (actions: SlaEscalation['actions']) => describeEscalationActions(actions) },
              {
                field: 'enabled',
                name: 'Enabled',
                render: (enabled: boolean, item) => (
                  <EuiSwitch
                    compressed
                    showLabel={false}
                    label={enabled ? 'Enabled' : 'Disabled'}
                    checked={enabled}
                    onChange={(e) => toggleEscalation(item.index, e.target.checked)}
                    data-test-subj={`wamSlaEscalationToggle-${item.id}`}
                  />
                ),
              },
              {
                name: '',
                render: (item: SlaEscalation & { index: number }) => (
                  <EuiFlexGroup gutterSize="xs" responsive={false}>
                    <EuiFlexItem grow={false}>
                      <EuiButtonIcon
                        iconType="pencil"
                        aria-label={`Edit ${item.name}`}
                        onClick={() => openEditor(item.index)}
                        disabled={saving || Boolean(editing)}
                        data-test-subj={`wamSlaEscalationEdit-${item.id}`}
                      />
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiButtonIcon
                        iconType="trash"
                        color="danger"
                        aria-label={`Delete ${item.name}`}
                        onClick={() => removeEscalation(item.index)}
                        disabled={saving}
                        data-test-subj={`wamSlaEscalationDelete-${item.id}`}
                      />
                    </EuiFlexItem>
                  </EuiFlexGroup>
                ),
              },
            ]}
            tableLayout="auto"
            data-test-subj="wamSlaEscalationsTable"
          />
        )}
        {editing && (
          <>
            <EuiSpacer size="m" />
            <EuiPanel paddingSize="m" hasShadow={false} hasBorder className="wamSlaEscalationForm" data-test-subj="wamSlaEscalationForm">
              <EuiTitle size="xxs">
                <h5>{editing.index == null ? 'New escalation' : `Edit "${escalations[editing.index]?.name}"`}</h5>
              </EuiTitle>
              <EuiSpacer size="s" />
              {editError && (
                <>
                  <EuiCallOut size="s" color="danger" iconType="alert" title={editError} data-test-subj="wamSlaEscalationError" />
                  <EuiSpacer size="s" />
                </>
              )}
              <EuiForm component="div">
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Name" display="rowCompressed">
                      <EuiFieldText fullWidth
                        compressed
                        value={editing.draft.name}
                        maxLength={120}
                        onChange={(e) => setEditField('name', e.target.value)}
                        data-test-subj="wamSlaEscalation-name"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Id" helpText="Lower-case letters, digits, - or _; stored on escalated records." display="rowCompressed">
                      <EuiFieldText fullWidth
                        compressed
                        value={editing.draft.id}
                        maxLength={64}
                        disabled={editing.index != null}
                        onChange={(e) => setEditField('id', e.target.value)}
                        data-test-subj="wamSlaEscalation-id"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Target" display="rowCompressed">
                      <EuiSelect fullWidth
                        compressed
                        options={[
                          { value: 'alert', text: 'Alerts' },
                          { value: 'case', text: 'Cases' },
                        ]}
                        value={editing.draft.target}
                        onChange={(e) => setEditField('target', e.target.value as SlaEscalation['target'])}
                        data-test-subj="wamSlaEscalation-target"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Threshold (% of resolve target elapsed)" display="rowCompressed">
                      <EuiFieldNumber fullWidth
                        compressed
                        min={1}
                        max={100}
                        step={1}
                        value={editing.draft.thresholdPercent}
                        onChange={(e) => setEditField('thresholdPercent', e.target.value)}
                        data-test-subj="wamSlaEscalation-thresholdPercent"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Condition" display="rowCompressed">
                      <EuiSelect fullWidth
                        compressed
                        options={[
                          { value: 'unassigned', text: 'Unassigned' },
                          { value: 'untouched', text: 'Untouched (open, never assigned, no analyst activity)' },
                          { value: 'any', text: 'Any' },
                        ]}
                        value={editing.draft.condition}
                        onChange={(e) => setEditField('condition', e.target.value as SlaEscalation['condition'])}
                        data-test-subj="wamSlaEscalation-condition"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Assign to" helpText="User name; an open record also moves to in progress." display="rowCompressed">
                      <EuiFieldText fullWidth
                        compressed
                        value={editing.draft.assignTo}
                        maxLength={256}
                        onChange={(e) => setEditField('assignTo', e.target.value)}
                        data-test-subj="wamSlaEscalation-assignTo"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiFormRow fullWidth label="Raise severity" helpText="Cases only: one band up, capped at critical." display="rowCompressed">
                      <EuiSwitch
                        compressed
                        label="One band up"
                        checked={editing.draft.raiseSeverity}
                        disabled={editing.draft.target !== 'case'}
                        onChange={(e) => setEditField('raiseSeverity', e.target.checked)}
                        data-test-subj="wamSlaEscalation-raiseSeverity"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFormRow label="Comment" helpText="Placeholders: {{id}}, {{severity}}, {{due_at}}, {{escalation}}." display="rowCompressed" fullWidth>
                  <EuiTextArea
                    compressed
                    rows={2}
                    fullWidth
                    value={editing.draft.comment}
                    maxLength={2000}
                    onChange={(e) => setEditField('comment', e.target.value)}
                    data-test-subj="wamSlaEscalation-comment"
                  />
                </EuiFormRow>
                <EuiFormRow
                  label="Channel ids (delivered when notifications are enabled in phase 1)"
                  helpText="One per line or comma-separated; recorded on the escalation event, nothing is sent yet."
                  display="rowCompressed"
                  fullWidth
                >
                  <EuiTextArea
                    compressed
                    rows={2}
                    fullWidth
                    value={editing.draft.notify}
                    onChange={(e) => setEditField('notify', e.target.value)}
                    data-test-subj="wamSlaEscalation-notify"
                  />
                </EuiFormRow>
                <EuiFormRow fullWidth display="rowCompressed">
                  <EuiSwitch
                    compressed
                    label="Enabled"
                    checked={editing.draft.enabled}
                    onChange={(e) => setEditField('enabled', e.target.checked)}
                    data-test-subj="wamSlaEscalation-enabled"
                  />
                </EuiFormRow>
                <EuiSpacer size="s" />
                <SettingsFormActions>
                  <EuiButtonEmpty
                    size="s"
                    onClick={() => {
                      setEditing(null);
                      setEditError(null);
                    }}
                    data-test-subj="wamSlaEscalationCancel"
                  >
                    Cancel
                  </EuiButtonEmpty>
                  <EuiButton size="s" fill onClick={applyEditor} data-test-subj="wamSlaEscalationApply">
                    {editing.index == null ? 'Add' : 'Apply'}
                  </EuiButton>
                </SettingsFormActions>
              </EuiForm>
            </EuiPanel>
          </>
        )}
      </EuiPanel>
    </div>
  );
};
