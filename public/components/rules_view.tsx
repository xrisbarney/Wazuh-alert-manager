import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBasicTable,
  EuiButton,
  EuiSwitch,
  EuiSpacer,
  EuiText,
  EuiEmptyPrompt,
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiTitle,
  EuiFormRow,
  EuiFieldText,
  EuiFieldNumber,
  EuiComboBox,
  EuiSelect,
  EuiButtonGroup,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiBadge,
  EuiPanel,
  EuiConfirmModal,
} from '@elastic/eui';
import {
  CorrelationRule,
  CorrelationRulePreview,
  MatchMode,
  CORRELATION_ENTITIES,
  CASE_SEVERITIES,
  ALERT_STATUSES,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { formatRelative, statusLabel } from '../design';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ENTITY_LABEL: Record<string, string> = {
  agent: 'Agent (host)',
  srcip: 'Source IP',
  dstip: 'Destination IP',
  user: 'Source user',
  dstuser: 'Destination user',
  process: 'Process',
};

// Bring any rule (including ones saved before the trigger model) into the
// editor's canonical shape.
const normalizeForEdit = (r: any): Partial<CorrelationRule> => {
  const trigger =
    r.trigger && r.trigger.type
      ? r.trigger
      : r.entity
      ? { type: 'burst', entity: r.entity, windowMinutes: r.windowMinutes, threshold: r.threshold }
      : { type: 'per_alert' };
  const actions = {
    createCase: !!(r.actions?.createCase ?? r.entity),
    caseSeverity: r.actions?.caseSeverity ?? r.caseSeverity ?? 'medium',
    setStatus: r.actions?.setStatus ?? null,
    assignTo: r.actions?.assignTo ?? null,
  };
  return { ...r, trigger, actions };
};

const emptyRule = (): Partial<CorrelationRule> => ({
  name: '',
  enabled: true,
  match: {},
  trigger: { type: 'burst', entity: 'agent', windowMinutes: 10, threshold: 3 },
  actions: { createCase: true, caseSeverity: 'medium', setStatus: null, assignTo: null },
});

const toOpts = (vals?: string[]) => (vals || []).map((v) => ({ label: v }));

// Only editable fields — strips server-managed keys the schemas reject.
const EDITABLE: Array<keyof CorrelationRule> = ['name', 'enabled', 'match', 'trigger', 'actions'];
const cleanPayload = (r: Partial<CorrelationRule>): Partial<CorrelationRule> => {
  const o: any = {};
  for (const k of EDITABLE) if ((r as any)[k] !== undefined) o[k] = (r as any)[k];
  return o;
};

// Compact Any/All selector for a match section. 'all' = the entity must have
// seen every listed value within the window (co-occurrence); 'any' = one is
// enough (volume).
const ModeToggle: React.FC<{ idPrefix: string; value: MatchMode; onChange: (m: MatchMode) => void }> = ({
  idPrefix,
  value,
  onChange,
}) => (
  <EuiButtonGroup
    legend="Match mode"
    buttonSize="compressed"
    idSelected={`${idPrefix}-${value}`}
    options={[
      { id: `${idPrefix}-any`, label: 'Any of' },
      { id: `${idPrefix}-all`, label: 'All of' },
    ]}
    onChange={(id) => onChange(id.endsWith('-all') ? 'all' : 'any')}
  />
);

export const RulesView: React.FC<Props> = ({ apiService, onToast }) => {
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<Partial<CorrelationRule> | null>(null);
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<CorrelationRulePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<CorrelationRule | null>(null);
  const [analysts, setAnalysts] = useState<string[]>([]);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiService.fetchRules();
      setRules(res?.rules || []);
    } catch (e: any) {
      onToast('Failed to load rules', 'danger', e?.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    apiService.fetchUsers().then(setAnalysts).catch(() => setAnalysts([]));
  }, [load]);

  const toggleEnabled = async (rule: CorrelationRule) => {
    try {
      await apiService.updateRule(rule.id, { enabled: !rule.enabled });
      setRules((prev) => prev.map((r) => (r.id === rule.id ? { ...r, enabled: !r.enabled } : r)));
      onToast(rule.enabled ? 'Rule disabled' : 'Rule enabled', 'success');
    } catch (e: any) {
      onToast('Failed to update rule', 'danger', e?.body?.message || e.message);
    }
  };

  // Mirrors the server's validateRule for an inline reason before a round trip.
  const localValidate = (r: Partial<CorrelationRule>): string | null => {
    if (!r.name?.trim()) return 'Give the rule a name.';
    const a = r.actions || ({} as any);
    const t = r.trigger || ({} as any);
    const hasAction = !!a.createCase || !!a.setStatus || !!(a.assignTo && String(a.assignTo).trim());
    if (!hasAction) return 'Pick at least one action: create case, set status, or assign to an analyst.';
    if (t.type === 'burst' && !t.entity) return 'Choose an entity for the burst trigger to group by.';
    if (a.createCase && t.type !== 'burst') return 'Create case requires the burst trigger.';
    return null;
  };

  const save = async () => {
    if (!editing) return;
    const err = localValidate(editing);
    if (err) {
      onToast(err, 'danger');
      return;
    }
    try {
      setSaving(true);
      const payload = { ...cleanPayload(editing), name: editing.name!.trim() };
      if ((editing as any).id) await apiService.updateRule((editing as any).id, payload);
      else await apiService.createRule(payload);
      onToast('Rule saved', 'success');
      setEditing(null);
      setPreview(null);
      await load();
    } catch (e: any) {
      onToast('Failed to save rule', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  const runPreview = async () => {
    if (!editing) return;
    try {
      setPreviewing(true);
      const res = await apiService.previewRule({ ...cleanPayload(editing), lookbackHours: 24 } as any);
      setPreview(res);
    } catch (e: any) {
      onToast('Preview failed', 'danger', e?.body?.message || e.message);
    } finally {
      setPreviewing(false);
    }
  };

  const doDelete = async () => {
    if (!confirmDelete) return;
    try {
      await apiService.deleteRule(confirmDelete.id);
      onToast('Rule deleted', 'success');
      setConfirmDelete(null);
      await load();
    } catch (e: any) {
      onToast('Failed to delete rule', 'danger', e?.body?.message || e.message);
    }
  };

  const columns = [
    {
      field: 'enabled',
      name: 'On',
      width: '52px',
      render: (_e: boolean, r: CorrelationRule) => (
        <EuiSwitch showLabel={false} label="enabled" checked={r.enabled} onChange={() => toggleEnabled(r)} compressed />
      ),
    },
    { field: 'name', name: 'Name', sortable: true, width: '22%' },
    {
      name: 'Does',
      render: (r: CorrelationRule) => {
        const a = r.actions || ({} as any);
        const chips: React.ReactNode[] = [];
        if (a.createCase)
          chips.push(
            <EuiBadge key="c" color="primary">
              Open {a.caseSeverity} case
            </EuiBadge>
          );
        if (a.setStatus)
          chips.push(
            <EuiBadge key="s" color="hollow">
              Set {statusLabel(a.setStatus)}
            </EuiBadge>
          );
        if (a.assignTo)
          chips.push(
            <EuiBadge key="a" color="hollow">
              Assign {a.assignTo}
            </EuiBadge>
          );
        return (
          <EuiFlexGroup gutterSize="xs" wrap responsive={false}>
            {chips.map((c, i) => (
              <EuiFlexItem grow={false} key={i}>
                {c}
              </EuiFlexItem>
            ))}
          </EuiFlexGroup>
        );
      },
    },
    {
      name: 'When',
      render: (r: CorrelationRule) => {
        const t = r.trigger || ({ type: 'per_alert' } as any);
        return (
          <EuiText size="xs">
            {t.type === 'burst'
              ? `≥${t.threshold} in ${t.windowMinutes}m per ${ENTITY_LABEL[t.entity || 'agent']}`
              : 'each matching alert'}
            {r.match?.minLevel != null ? ` · level ≥${r.match.minLevel}` : ''}
            {r.match?.ruleIds?.length ? ` · ${r.match.ruleIdsMode === 'all' ? 'all' : 'any'} of ${r.match.ruleIds.length} id(s)` : ''}
          </EuiText>
        );
      },
    },
    { field: 'matchCount', name: 'Fired', width: '70px', render: (n: number) => n || 0 },
    { field: 'lastFired', name: 'Last fired', width: '110px', render: (v: string | null) => (v ? formatRelative(v) : '—') },
    {
      name: 'Actions',
      width: '90px',
      actions: [
        {
          name: 'Edit',
          description: 'Edit',
          type: 'icon',
          icon: 'pencil',
          onClick: (r: CorrelationRule) => {
            setEditing(normalizeForEdit(r));
            setPreview(null);
          },
        },
        { name: 'Delete', description: 'Delete', type: 'icon', icon: 'trash', color: 'danger', onClick: (r: CorrelationRule) => setConfirmDelete(r) },
      ],
    },
  ];

  const upd = (patch: Partial<CorrelationRule>) => setEditing((e) => ({ ...e, ...patch }));
  const updMatch = (patch: Partial<CorrelationRule['match']>) => setEditing((e) => ({ ...e, match: { ...(e?.match || {}), ...patch } }));
  const updTrigger = (patch: Partial<CorrelationRule['trigger']>) =>
    setEditing((e) => ({ ...e, trigger: { ...(e?.trigger || { type: 'per_alert' }), ...patch } as any }));
  const updActions = (patch: Partial<CorrelationRule['actions']>) =>
    setEditing((e) => ({ ...e, actions: { ...(e?.actions || { createCase: false }), ...patch } as any }));

  const a = editing?.actions || ({ createCase: false } as any);
  const t = editing?.trigger || ({ type: 'per_alert' } as any);
  const isBurst = t.type === 'burst';
  const anyAllNote = editing?.match?.ruleIdsMode === 'all' || editing?.match?.ruleGroupsMode === 'all' || editing?.match?.agentNamesMode === 'all';

  return (
    <div>
      <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
        <EuiFlexItem>
          <EuiText size="s" color="subdued">
            Automation rules act on alerts as they arrive. Match which alerts apply, choose a trigger (every matching
            alert, or a burst on one entity), then one or more actions: open a case, set a status (auto-close routine
            noise), and/or assign to an analyst. Case creation is de-duplicated per rule and entity and rate-limited.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" iconType="plusInCircle" fill onClick={() => { setEditing(emptyRule()); setPreview(null); }}>
            New rule
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />

      {rules.length === 0 && !loading ? (
        <EuiEmptyPrompt
          iconType="indexRollupApp"
          titleSize="xs"
          title={<h3>No automation rules yet</h3>}
          body={<p>Create a rule to auto-open cases from repeated alerts, auto-close routine noise, or auto-assign — e.g. "3+ authentication failures on one host within 10 minutes → open a high case and assign to Alice".</p>}
          actions={<EuiButton size="s" fill onClick={() => setEditing(emptyRule())}>New rule</EuiButton>}
        />
      ) : (
        <EuiBasicTable items={rules} itemId="id" columns={columns as any} loading={loading} />
      )}

      {editing && (
        <EuiFlyout onClose={() => setEditing(null)} size="m" aria-labelledby="rule-editor">
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size="s">
              <h2>{(editing as any).id ? 'Edit rule' : 'New automation rule'}</h2>
            </EuiTitle>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <EuiFormRow label="Name" fullWidth>
              <EuiFieldText fullWidth value={editing.name || ''} onChange={(e) => upd({ name: e.target.value })} placeholder="Auth failures per host" />
            </EuiFormRow>

            <EuiSpacer size="s" />
            <EuiTitle size="xxs"><h4>Match conditions</h4></EuiTitle>
            <EuiText size="xs" color="subdued">Which alerts this rule applies to. All specified conditions must hold (AND). Leave blank to skip.</EuiText>
            <EuiSpacer size="s" />

            <EuiFormRow
              label="Rule groups"
              fullWidth
              labelAppend={<ModeToggle idPrefix="grp" value={editing.match?.ruleGroupsMode || 'any'} onChange={(m) => updMatch({ ruleGroupsMode: m })} />}
            >
              <EuiComboBox
                fullWidth
                placeholder="e.g. authentication_failed, pam"
                selectedOptions={toOpts(editing.match?.ruleGroups)}
                onChange={(sel) => updMatch({ ruleGroups: sel.map((s) => s.label) })}
                onCreateOption={(v) => updMatch({ ruleGroups: [...(editing.match?.ruleGroups || []), v] })}
              />
            </EuiFormRow>
            <EuiFormRow
              label="Rule IDs"
              fullWidth
              labelAppend={<ModeToggle idPrefix="rid" value={editing.match?.ruleIdsMode || 'any'} onChange={(m) => updMatch({ ruleIdsMode: m })} />}
            >
              <EuiComboBox
                fullWidth
                placeholder="e.g. 5710, 5716"
                selectedOptions={toOpts(editing.match?.ruleIds)}
                onChange={(sel) => updMatch({ ruleIds: sel.map((s) => s.label) })}
                onCreateOption={(v) => updMatch({ ruleIds: [...(editing.match?.ruleIds || []), v] })}
              />
            </EuiFormRow>
            <EuiFormRow
              label="Agents"
              fullWidth
              labelAppend={<ModeToggle idPrefix="agt" value={editing.match?.agentNamesMode || 'any'} onChange={(m) => updMatch({ agentNamesMode: m })} />}
            >
              <EuiComboBox
                fullWidth
                placeholder="Any agent"
                selectedOptions={toOpts(editing.match?.agentNames)}
                onChange={(sel) => updMatch({ agentNames: sel.map((s) => s.label) })}
                onCreateOption={(v) => updMatch({ agentNames: [...(editing.match?.agentNames || []), v] })}
              />
            </EuiFormRow>
            <EuiFormRow label="Min level">
              <EuiFieldNumber
                style={{ width: 120 }}
                min={0}
                max={16}
                value={editing.match?.minLevel ?? ''}
                onChange={(e) => updMatch({ minLevel: e.target.value === '' ? undefined : Number(e.target.value) })}
              />
            </EuiFormRow>
            {anyAllNote && (
              <EuiText size="xs" color="subdued">
                <strong>All of</strong> means the same entity must trigger <em>every</em> listed value within the window
                (co-occurrence) — e.g. rule 5510 <em>and</em> 5516 on one host — not just any one. It applies to the burst
                trigger below.
              </EuiText>
            )}

            <EuiSpacer size="m" />
            <EuiTitle size="xxs"><h4>Trigger</h4></EuiTitle>
            <EuiSpacer size="xs" />
            <EuiButtonGroup
              legend="Trigger"
              buttonSize="compressed"
              idSelected={isBurst ? 'trig-burst' : 'trig-per'}
              options={[
                { id: 'trig-per', label: 'Every matching alert' },
                { id: 'trig-burst', label: 'A burst on one entity' },
              ]}
              onChange={(id) => {
                if (id === 'trig-burst') updTrigger({ type: 'burst', entity: t.entity || 'agent', windowMinutes: t.windowMinutes || 10, threshold: t.threshold || 3 });
                else {
                  updTrigger({ type: 'per_alert' });
                  if (a.createCase) updActions({ createCase: false });
                }
              }}
            />
            {isBurst && (
              <>
                <EuiSpacer size="m" />
                <EuiFormRow label="Group alerts by" fullWidth helpText="The entity that ties a burst together.">
                  <EuiSelect
                    fullWidth
                    options={CORRELATION_ENTITIES.map((e) => ({ value: e, text: ENTITY_LABEL[e] }))}
                    value={t.entity}
                    onChange={(e) => updTrigger({ entity: e.target.value as any })}
                  />
                </EuiFormRow>
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem>
                    <EuiFormRow label="Threshold" helpText="Alerts needed.">
                      <EuiFieldNumber min={2} value={t.threshold} onChange={(e) => updTrigger({ threshold: Number(e.target.value) })} />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="Window (min)">
                      <EuiFieldNumber min={1} value={t.windowMinutes} onChange={(e) => updTrigger({ windowMinutes: Number(e.target.value) })} />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </>
            )}

            <EuiSpacer size="m" />
            <EuiTitle size="xxs"><h4>Actions</h4></EuiTitle>
            <EuiText size="xs" color="subdued">
              Pick at least one. {isBurst ? 'Status/assignment apply to the alerts in a firing burst.' : 'Status/assignment apply to every matching alert.'}
            </EuiText>
            <EuiSpacer size="s" />

            <EuiFlexGroup gutterSize="m" responsive={false}>
              <EuiFlexItem>
                <EuiFormRow label="Set status" helpText="Auto-close routine noise, or move to In progress.">
                  <EuiSelect
                    options={[{ value: '', text: 'No change' }, ...ALERT_STATUSES.map((s) => ({ value: s, text: statusLabel(s) }))]}
                    value={a.setStatus || ''}
                    onChange={(e) => updActions({ setStatus: (e.target.value || null) as any })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiFormRow label="Assign to" helpText="Route matching alerts (and any case) to an analyst.">
                  <EuiSelect
                    options={[{ value: '', text: '— No assignment —' }, ...analysts.map((u) => ({ value: u, text: u }))]}
                    value={a.assignTo || ''}
                    onChange={(e) => updActions({ assignTo: (e.target.value || null) as any })}
                  />
                </EuiFormRow>
              </EuiFlexItem>
            </EuiFlexGroup>

            {isBurst && (
              <>
                <EuiSpacer size="s" />
                <EuiPanel color={a.createCase ? 'primary' : 'subdued'} paddingSize="m" hasShadow={false} hasBorder>
                  <EuiSwitch label="Open a case for the burst" checked={!!a.createCase} onChange={(e) => updActions({ createCase: e.target.checked })} />
                  {a.createCase && (
                    <>
                      <EuiSpacer size="m" />
                      <EuiFormRow label="Case severity">
                        <EuiSelect
                          style={{ maxWidth: 220 }}
                          options={CASE_SEVERITIES.map((s) => ({ value: s, text: s.charAt(0).toUpperCase() + s.slice(1) }))}
                          value={a.caseSeverity}
                          onChange={(e) => updActions({ caseSeverity: e.target.value as any })}
                        />
                      </EuiFormRow>
                    </>
                  )}
                </EuiPanel>
              </>
            )}

            <EuiSpacer size="m" />
            <EuiButton size="s" iconType="inspect" onClick={runPreview} isLoading={previewing}>
              Dry run (last 24h)
            </EuiButton>
            {preview && (
              <>
                <EuiSpacer size="s" />
                {preview.triggerType === 'burst' ? (
                  <EuiCallOut
                    size="s"
                    color={preview.triggeringEntities.length > 0 ? 'primary' : 'success'}
                    iconType="inspect"
                    title={`Over the last 24h: ${preview.matchingAlerts.toLocaleString()} matching alerts; ${preview.triggeringEntities.length} ${preview.triggeringEntities.length === 1 ? 'entity would' : 'entities would'} fire${a.createCase ? ` (${preview.wouldOpenCases} would open a case)` : ''}`}
                  >
                    {preview.triggeringEntities.slice(0, 8).map((te) => (
                      <EuiBadge key={te.entity} color="hollow" style={{ marginRight: 4 }}>
                        {te.entity} ({te.count})
                      </EuiBadge>
                    ))}
                    {preview.triggeringEntities.length === 0 && 'No entity crossed the threshold in the last 24h.'}
                    <EuiSpacer size="xs" />
                    <EuiText size="xs" color="subdued">
                      Approximate — counts matches over the lookback, not a strict sliding window. Live evaluation uses the
                      exact {t.windowMinutes}-minute window.
                    </EuiText>
                  </EuiCallOut>
                ) : (
                  <EuiCallOut
                    size="s"
                    color={preview.matchingAlerts > 0 ? 'primary' : 'success'}
                    iconType="inspect"
                    title={`Over the last 24h: ${preview.matchingAlerts.toLocaleString()} matching alert${preview.matchingAlerts === 1 ? '' : 's'} would be acted on`}
                  >
                    <EuiText size="xs" color="subdued">
                      Each matching alert gets this rule's actions ({[a.setStatus ? `set ${statusLabel(a.setStatus)}` : null, a.assignTo ? `assign ${a.assignTo}` : null].filter(Boolean).join(', ') || 'none selected'}) as it arrives.
                    </EuiText>
                  </EuiCallOut>
                )}
              </>
            )}
          </EuiFlyoutBody>
          <EuiFlyoutFooter>
            <EuiFlexGroup justifyContent="spaceBetween">
              <EuiFlexItem grow={false}>
                <EuiButton onClick={() => setEditing(null)}>Cancel</EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton fill onClick={save} isLoading={saving}>
                  Save rule
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutFooter>
        </EuiFlyout>
      )}

      {confirmDelete && (
        <EuiConfirmModal
          title={`Delete "${confirmDelete.name}"?`}
          onCancel={() => setConfirmDelete(null)}
          onConfirm={doDelete}
          cancelButtonText="Cancel"
          confirmButtonText="Delete"
          buttonColor="danger"
        >
          <p>Existing cases this rule opened are kept. New alerts will no longer be acted on by it.</p>
        </EuiConfirmModal>
      )}
    </div>
  );
};
