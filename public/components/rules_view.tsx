import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonGroup,
  EuiButtonIcon,
  EuiCallOut,
  EuiCheckbox,
  EuiCodeBlock,
  EuiComboBox,
  EuiConfirmModal,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
  EuiToolTip,
  EuiEmptyPrompt,
  EuiStat,
  EuiLink,
} from '@elastic/eui';
import {
  ALERT_STATUSES,
  CASE_SEVERITIES,
  CorrelationEntity,
  CorrelationEntityExpression,
  CorrelationEntityPredicate,
  CorrelationRule,
  CorrelationRuleConcurrency,
  CorrelationRuleCreateRequest,
  CorrelationRulePreview,
  CorrelationRulePreviewRequest,
  CorrelationRuleRevision,
  MatchMode,
} from '../../common';
import { formatRelative, statusLabel } from '../design';
import { AlertsApiService, AutomationDlqItem, AutomationHealth, AutomationSettings } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

type Stage = 'basics' | 'match' | 'trigger' | 'actions' | 'safety' | 'preview' | 'history';

type EditorRule = Partial<CorrelationRule>;

const STAGES: Array<{ id: Stage; label: string }> = [
  { id: 'basics', label: '1. Basics' },
  { id: 'match', label: '2. Match' },
  { id: 'trigger', label: '3. Trigger' },
  { id: 'actions', label: '4. Actions' },
  { id: 'safety', label: '5. Safety' },
  { id: 'history', label: 'History' },
  { id: 'preview', label: '6. Preview' },
];

const ENTITY_LABEL: Record<string, string> = {
  srcip: 'Source IP',
  dstip: 'Destination IP',
  user: 'Source user',
  dstuser: 'Destination user',
  process: 'Process',
  srcport: 'Source port',
  dstport: 'Destination port',
};

const ENTITY_OPTIONS = (['srcip', 'dstip', 'srcport', 'dstport', 'user', 'dstuser', 'process'] as CorrelationEntity[])
  .map((entity) => ({ value: entity, text: ENTITY_LABEL[entity] }));
const ADMIN_DOCS = 'https://documentation.wazuh.com/current/user-manual/user-administration/index.html';
const ADMIN_HELP = 'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control automation administration.';
const MAX_ENTITY_GROUPS = 5;
const MAX_ENTITY_PREDICATES = 5;
let nextLocalId = 0;
const localId = (prefix: string) => `${prefix}-${Date.now()}-${++nextLocalId}`;
const emptyExpression = (): CorrelationEntityExpression => ({ version: 1, groups: [] });
const legacyExpression = (rule: any): CorrelationEntityExpression => rule.trigger?.entityExpression || (rule.trigger?.entity || rule.entity ? {
  version: 1,
  groups: [{ id: localId('group'), order: 0, predicates: [{ id: localId('predicate'), order: 0, entity: rule.trigger?.entity || rule.entity, operator: 'exists' }] }],
} : emptyExpression());

const normalizeForEdit = (rule: any): EditorRule => {
  const trigger = rule.trigger?.type
    ? { ...rule.trigger, entityExpression: legacyExpression(rule) }
    : rule.entity
    ? { type: 'burst', entityExpression: legacyExpression(rule), windowMinutes: rule.windowMinutes, threshold: rule.threshold }
    : { type: 'per_alert', entityExpression: emptyExpression() };
  const period = trigger.type === 'burst' ? Number(trigger.windowMinutes || 10) : 0;
  const match = (trigger.type === 'per_alert'
    ? { ...(rule.match || {}), ruleGroupsMode: 'any', ruleIdsMode: 'any', agentNamesMode: 'any' }
    : rule.match || {}) as CorrelationRule['match'];
  return {
    ...rule,
    enabled: rule.enabled === true,
    revision: Number(rule.revision || 1),
    priority: Number(rule.priority ?? 100),
    sortOrder: Number(rule.sortOrder ?? 0),
    processingMode: rule.processingMode || 'continue',
    match,
    schemaVersion: 2,
    trigger: {
      ...trigger,
      routing: trigger.routing || 'separate_by_group',
      cooldown: trigger.cooldown || { durationMinutes: period },
      rearm: trigger.rearm || (trigger.type === 'burst'
        ? { type: 'after_quiet_period', quietPeriodMinutes: period }
        : { type: 'immediate', quietPeriodMinutes: 0 }),
    },
    actions: {
      createCase: !!(rule.actions?.createCase ?? rule.entity),
      caseSeverity: rule.actions?.caseSeverity ?? rule.caseSeverity ?? 'medium',
      setStatus: rule.actions?.setStatus ?? null,
      assignTo: rule.actions?.assignTo ?? null,
    },
    preconditions: {
      statuses: rule.preconditions?.statuses,
      assignment: rule.preconditions?.assignment || 'unassigned',
    },
    safety: {
      acknowledgeMatchAll: rule.safety?.acknowledgeMatchAll === true,
      ...(rule.safety?.maxActionsPerRun == null ? {} : { maxActionsPerRun: rule.safety.maxActionsPerRun }),
      ...(rule.safety?.maxCasesPerRun == null ? {} : { maxCasesPerRun: rule.safety.maxCasesPerRun }),
      ...(rule.safety?.rateLimit == null ? {} : { rateLimit: rule.safety.rateLimit }),
    },
  };
};

const emptyRule = (): EditorRule => ({
  name: '',
  enabled: false,
  priority: 100,
  sortOrder: 0,
  processingMode: 'continue',
  match: {},
  schemaVersion: 2,
  trigger: {
    type: 'per_alert',
    entityExpression: emptyExpression(),
    routing: 'separate_by_group',
    cooldown: { durationMinutes: 0 },
    rearm: { type: 'immediate', quietPeriodMinutes: 0 },
  },
  actions: { createCase: false, caseSeverity: 'medium', setStatus: null, assignTo: null },
  preconditions: { assignment: 'unassigned' },
  safety: { acknowledgeMatchAll: false },
});

const EDITABLE: Array<keyof CorrelationRule> = [
  'name',
  'enabled',
  'priority',
  'sortOrder',
  'processingMode',
  'match',
  'trigger',
  'actions',
  'preconditions',
  'safety',
];
const cleanPayload = (rule: EditorRule): Partial<CorrelationRule> => {
  const payload: any = {};
  for (const key of EDITABLE) if ((rule as any)[key] !== undefined) payload[key] = (rule as any)[key];
  return payload;
};

const toOpts = (values?: string[]) => (values || []).map((label) => ({ label }));
const concurrencyOf = (rule: Pick<CorrelationRule, 'revision' | 'if_seq_no' | 'if_primary_term'>): CorrelationRuleConcurrency => ({
  revision: rule.revision,
  if_seq_no: rule.if_seq_no,
  if_primary_term: rule.if_primary_term,
});

const isConflict = (error: any) =>
  error?.body?.statusCode === 409 || error?.statusCode === 409 || error?.response?.status === 409;

const ModeToggle: React.FC<{
  idPrefix: string;
  value: MatchMode;
  isBurst: boolean;
  onChange: (mode: MatchMode) => void;
}> = ({ idPrefix, value, isBurst, onChange }) => (
  <EuiToolTip content={isBurst ? 'Any matches one listed value; All requires co-occurrence on the same entity.' : 'All is unavailable for per-alert rules because one alert cannot provide entity-window co-occurrence.'}>
    <span>
      <EuiButtonGroup
        legend="Match mode"
        buttonSize="compressed"
        idSelected={`${idPrefix}-${isBurst ? value : 'any'}`}
        options={[
          { id: `${idPrefix}-any`, label: 'Any of' },
          { id: `${idPrefix}-all`, label: 'All of', isDisabled: !isBurst },
        ]}
        onChange={(id) => onChange(id.endsWith('-all') && isBurst ? 'all' : 'any')}
      />
    </span>
  </EuiToolTip>
);

export const RulesView: React.FC<Props> = ({ apiService, onToast }) => {
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [canAdminister, setCanAdminister] = useState(false);
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [editing, setEditing] = useState<EditorRule | null>(null);
  const [stage, setStage] = useState<Stage>('basics');
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<CorrelationRulePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [previewFingerprint, setPreviewFingerprint] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<CorrelationRule | null>(null);
  const [analysts, setAnalysts] = useState<string[]>([]);
  const [revisions, setRevisions] = useState<CorrelationRuleRevision[]>([]);
  const [revisionsLoading, setRevisionsLoading] = useState(false);
  const [rollingBack, setRollingBack] = useState<number | null>(null);
  const [confirmRollback, setConfirmRollback] = useState<number | null>(null);
  const [automation, setAutomation] = useState<AutomationHealth | null>(null);
  const [automationError, setAutomationError] = useState<string | null>(null);
  const [automationLoading, setAutomationLoading] = useState(true);
  const [automationSettings, setAutomationSettings] = useState<AutomationSettings | null>(null);
  const [savingAutomation, setSavingAutomation] = useState(false);
  const [dlqItems, setDlqItems] = useState<AutomationDlqItem[]>([]);
  const [dlqCursors, setDlqCursors] = useState<Array<string | undefined>>([undefined]);
  const [dlqPage, setDlqPage] = useState(0);
  const [dlqNextCursor, setDlqNextCursor] = useState<string | null>(null);
  const [dlqLoading, setDlqLoading] = useState(false);
  const [mutatingDlq, setMutatingDlq] = useState<string | null>(null);
  const healthGeneration = useRef(0);

  const loadAutomationHealth = useCallback(async () => {
    const generation = ++healthGeneration.current;
    setAutomationLoading(true);
    setAutomationError(null);
    try {
      const [health, settings] = await Promise.all([
        apiService.fetchAutomationQueue(),
        apiService.fetchAutomationSettings(),
      ]);
      if (generation !== healthGeneration.current) return;
      setAutomation(health);
      setAutomationSettings(settings);
    } catch (error: any) {
      if (generation === healthGeneration.current) setAutomationError(error?.body?.message || error.message);
    } finally {
      if (generation === healthGeneration.current) setAutomationLoading(false);
    }
  }, [apiService]);

  const loadDlqPage = useCallback(async (page: number, cursor?: string) => {
    try {
      setDlqLoading(true);
      const result = await apiService.fetchAutomationDlq(25, cursor);
      setDlqItems(result.items || []);
      setDlqPage(page);
      setDlqNextCursor(result.nextCursor);
    } catch (error: any) {
      onToast('Failed to load automation dead letters', 'danger', error?.body?.message || error.message);
    } finally {
      setDlqLoading(false);
    }
  }, [apiService, onToast]);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiService.fetchRules();
      setRules((response?.rules || []).map((rule) => normalizeForEdit(rule) as CorrelationRule));
    } catch (error: any) {
      onToast('Failed to load rules', 'danger', error?.body?.message || error.message);
    } finally {
      setLoading(false);
    }
  }, [apiService, onToast]);

  useEffect(() => {
    load();
    apiService.fetchUsers().then(setAnalysts).catch(() => setAnalysts([]));
    apiService
      .fetchSystemCapabilities()
      .then((capabilities: any) => setCanAdminister(Boolean(capabilities?.isPluginAdmin)))
      .catch(() => setCanAdminister(false))
      .then(() => setCapabilitiesLoaded(true));
    loadAutomationHealth();
    loadDlqPage(0);
    return () => { healthGeneration.current += 1; };
  }, [apiService, load, loadAutomationHealth, loadDlqPage]);

  const retryDlqEvent = async (eventId: string) => {
    try {
      setMutatingDlq(eventId);
      await apiService.retryAutomationDlqEvent(eventId);
      onToast('Automation event queued for retry', 'success', eventId);
      await loadAutomationHealth();
      await loadDlqPage(dlqPage, dlqCursors[dlqPage]);
    } catch (error: any) {
      onToast('Automation retry failed', 'danger', error?.body?.message || error.message);
    } finally {
      setMutatingDlq(null);
    }
  };

  const resolveDlqEvent = async (item: AutomationDlqItem) => {
    try {
      setMutatingDlq(item.id);
      await apiService.resolveAutomationDlqEvent(item.id);
      onToast('Dead letter resolved', 'success', item.event_id);
      await loadAutomationHealth();
      await loadDlqPage(dlqPage, dlqCursors[dlqPage]);
    } catch (error: any) {
      onToast('Failed to resolve dead letter', 'danger', error?.body?.message || error.message);
    } finally {
      setMutatingDlq(null);
    }
  };

  const saveQueueSettings = async (settings: AutomationSettings) => {
    if (!canAdminister) return;
    try {
      setSavingAutomation(true);
      const saved = await apiService.saveAutomationSettings(settings);
      setAutomationSettings(saved);
      await loadAutomationHealth();
      onToast(saved.paused ? 'Automation queue paused' : 'Automation queue resumed', 'success');
    } catch (error: any) {
      onToast('Failed to update automation queue', 'danger', error?.body?.message || error.message);
    } finally {
      setSavingAutomation(false);
    }
  };

  const fingerprint = (rule: EditorRule) => JSON.stringify(cleanPayload({ ...rule, enabled: false }));
  const isMatchAll = (rule: EditorRule) => {
    const match = rule.match || {};
    return !match.ruleGroups?.length && !match.ruleIds?.length && !match.agentNames?.length && match.minLevel == null;
  };

  const normalizedPredicateValue = (predicate: CorrelationEntityPredicate) => {
    if (predicate.operator === 'exists') return '';
    const value = String(predicate.value || '').trim();
    if (predicate.entity === 'user' || predicate.entity === 'dstuser' || predicate.entity === 'process') return value.toLowerCase();
    if (predicate.entity === 'srcport' || predicate.entity === 'dstport') {
      return /^\d+$/.test(value) && Number(value) <= 65535 ? String(Number(value)) : '';
    }
    if (predicate.entity === 'srcip' || predicate.entity === 'dstip') {
      const ipv4 = value.split('.');
      if (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) return ipv4.map(Number).join('.');
      if (value.includes(':') && /^[0-9a-f:]+$/i.test(value)) return value.toLowerCase();
      return '';
    }
    return value;
  };

  const expressionErrors = (rule: EditorRule): string[] => {
    const groups = rule.trigger?.entityExpression?.groups || [];
    const predicates = groups.reduce<CorrelationEntityPredicate[]>((all, group) => all.concat(group.predicates || []), []);
    const errors: string[] = [];
    if (groups.length > MAX_ENTITY_GROUPS) errors.push('Use no more than five OR groups.');
    if (predicates.length > MAX_ENTITY_PREDICATES) errors.push('Use no more than five entity predicates in total.');
    groups.forEach((group, index) => {
      if (!group.predicates.length) errors.push(`Group ${index + 1} needs at least one predicate.`);
    });
    const seen = new Set<string>();
    predicates.forEach((predicate) => {
      const normalized = normalizedPredicateValue(predicate);
      if (predicate.operator === 'equals' && !normalized) errors.push(`${ENTITY_LABEL[predicate.entity]} needs a valid, non-blank value.`);
      const key = `${predicate.entity}:${predicate.operator}:${normalized}`;
      if (seen.has(key)) errors.push(`Duplicate predicate: ${ENTITY_LABEL[predicate.entity]} ${predicate.operator === 'exists' ? 'exists' : `equals ${normalized}`}.`);
      seen.add(key);
    });
    return Array.from(new Set(errors));
  };

  const ruleErrors = (rule: EditorRule): string[] => {
    const errors = expressionErrors(rule);
    if (!rule.name?.trim()) errors.unshift('Give the rule a name.');
    const actions = rule.actions || ({} as any);
    const trigger = rule.trigger || ({} as any);
    if (!actions.createCase && !actions.setStatus && !(actions.assignTo && String(actions.assignTo).trim())) errors.push('Pick at least one action: create case, set status, or assign to an analyst.');
    if (trigger.type === 'burst') {
      if (!Number.isInteger(trigger.threshold) || trigger.threshold < 2 || trigger.threshold > 1000) errors.push('Burst threshold must be an integer from 2 to 1,000.');
      if (!Number.isInteger(trigger.windowMinutes) || trigger.windowMinutes < 1 || trigger.windowMinutes > 1440) errors.push('Burst window must be an integer from 1 to 1,440 minutes.');
      if (!Number.isInteger(trigger.cooldown?.durationMinutes) || trigger.cooldown.durationMinutes < 1 || trigger.cooldown.durationMinutes > 10080) errors.push('Burst cooldown must be an integer from 1 to 10,080 minutes.');
      if (!Number.isInteger(trigger.rearm?.quietPeriodMinutes) || trigger.rearm.quietPeriodMinutes < 1 || trigger.rearm.quietPeriodMinutes > 10080) errors.push('Quiet period must be an integer from 1 to 10,080 minutes.');
    }
    if (isMatchAll(rule) && !rule.safety?.acknowledgeMatchAll) errors.push('Acknowledge that this rule matches every alert.');
    if (rule.enabled && previewFingerprint !== fingerprint(rule)) errors.push('Preview the current rule successfully before enabling it.');
    return Array.from(new Set(errors));
  };

  const localValidate = (rule: EditorRule): string | null => {
    return ruleErrors(rule)[0] || null;
  };

  const update = (patch: Partial<EditorRule>) => setEditing((current) => (current ? { ...current, ...patch } : current));
  const updateMatch = (patch: Partial<CorrelationRule['match']>) =>
    setEditing((current) =>
      current
        ? {
            ...current,
            match: { ...(current.match || {}), ...patch },
            safety: { ...(current.safety || { acknowledgeMatchAll: false }), acknowledgeMatchAll: false },
          }
        : current
    );
  const updateTrigger = (patch: Partial<CorrelationRule['trigger']>) =>
    setEditing((current) =>
      current ? { ...current, trigger: { ...(current.trigger || { type: 'per_alert' }), ...patch } as any } : current
    );
  const updateExpression = (expression: CorrelationEntityExpression) => updateTrigger({ entityExpression: expression });
  const addEntityGroup = () => {
    const expression = editing?.trigger?.entityExpression || emptyExpression();
    if (expression.groups.length >= MAX_ENTITY_GROUPS) return;
    updateExpression({ ...expression, groups: [...expression.groups, { id: localId('group'), order: expression.groups.length, predicates: [] }] });
  };
  const removeEntityGroup = (groupId: string) => {
    const groups = (editing?.trigger?.entityExpression?.groups || []).filter((group) => group.id !== groupId)
      .map((group, order) => ({ ...group, order }));
    updateExpression({ version: 1, groups });
  };
  const addPredicate = (groupId: string) => {
    const expression = editing?.trigger?.entityExpression || emptyExpression();
    const total = expression.groups.reduce((count, group) => count + group.predicates.length, 0);
    if (total >= MAX_ENTITY_PREDICATES) return;
    updateExpression({ ...expression, groups: expression.groups.map((group) => group.id === groupId ? {
      ...group,
      predicates: [...group.predicates, { id: localId('predicate'), order: group.predicates.length, entity: 'srcip', operator: 'equals', value: '' }],
    } : group) });
  };
  const updatePredicate = (groupId: string, predicateId: string, patch: Partial<CorrelationEntityPredicate>) => {
    const expression = editing?.trigger?.entityExpression || emptyExpression();
    updateExpression({ ...expression, groups: expression.groups.map((group) => group.id === groupId ? {
      ...group,
      predicates: group.predicates.map((predicate) => predicate.id === predicateId ? { ...predicate, ...patch } : predicate),
    } : group) });
  };
  const removePredicate = (groupId: string, predicateId: string) => {
    const expression = editing?.trigger?.entityExpression || emptyExpression();
    updateExpression({ ...expression, groups: expression.groups.map((group) => group.id === groupId ? {
      ...group,
      predicates: group.predicates.filter((predicate) => predicate.id !== predicateId).map((predicate, order) => ({ ...predicate, order })),
    } : group) });
  };
  const updateActions = (patch: Partial<CorrelationRule['actions']>) =>
    setEditing((current) =>
      current ? { ...current, actions: { ...(current.actions || { createCase: false }), ...patch } as any } : current
    );

  const updatePreconditions = (patch: Partial<NonNullable<CorrelationRule['preconditions']>>) =>
    setEditing((current) =>
      current ? { ...current, preconditions: { ...(current.preconditions || {}), ...patch } } : current
    );
  const updateSafety = (patch: Partial<NonNullable<CorrelationRule['safety']>>) =>
    setEditing((current) =>
      current
        ? {
            ...current,
            safety: { ...(current.safety || { acknowledgeMatchAll: false }), ...patch },
          }
        : current
    );

  const loadRevisions = async (id: string) => {
    try {
      setRevisionsLoading(true);
      const all: CorrelationRuleRevision[] = [];
      let page = 1;
      while (page) {
        const response = await apiService.fetchRuleRevisions(id, page, 100);
        all.push(...response.revisions);
        page = response.nextPage || 0;
      }
      setRevisions(all);
    } catch (error: any) {
      setRevisions([]);
      onToast('Failed to load rule history', 'danger', error?.body?.message || error.message);
    } finally {
      setRevisionsLoading(false);
    }
  };

  const refreshAfterConflict = async (id: string, keepEditor: boolean) => {
    await load();
    if (keepEditor) {
      try {
        const current = await apiService.fetchRule(id);
        setEditing(normalizeForEdit(current));
        setPreview(null);
        setPreviewFingerprint(null);
        loadRevisions(id);
      } catch (error) {
        setEditing(null);
      }
    }
    onToast('Rule changed on the server', 'primary', 'The latest version was loaded. Review it before trying again.');
  };

  const openEditor = (rule?: CorrelationRule) => {
    setEditing(rule ? normalizeForEdit(rule) : emptyRule());
    setStage('basics');
    setPreview(null);
    setPreviewFingerprint(null);
    setRevisions([]);
    if (rule) loadRevisions(rule.id);
  };

  const toggleEnabled = async (rule: CorrelationRule) => {
    if (!canAdminister) return;
    if (!rule.enabled) {
      openEditor(rule);
      setStage('preview');
      onToast('Preview required before activation', 'primary');
      return;
    }
    try {
      const updated = await apiService.updateRule(rule.id, { enabled: false }, concurrencyOf(rule));
      setRules((current) => current.map((item) => (item.id === rule.id ? updated : item)));
      onToast('Rule disabled', 'success');
    } catch (error: any) {
      if (isConflict(error)) {
        await refreshAfterConflict(rule.id, false);
        return;
      }
      onToast('Failed to update rule', 'danger', error?.body?.message || error.message);
    }
  };

  const runPreview = async () => {
    if (!editing || !canAdminister) return;
    if (!editing.id || !editing.revision) {
      onToast('Save the disabled draft before previewing it', 'primary');
      return;
    }
    const validationRule = { ...editing, enabled: false };
    const error = localValidate(validationRule);
    if (error) {
      onToast(error, 'danger');
      return;
    }
    try {
      setPreviewing(true);
      const result = await apiService.previewRule({
        ...cleanPayload(editing),
        id: editing.id,
        revision: editing.revision,
        enabled: false,
        lookbackHours: 24,
      } as CorrelationRulePreviewRequest);
      setPreview(result);
      setPreviewFingerprint(fingerprint(editing));
    } catch (error: any) {
      setPreview(null);
      setPreviewFingerprint(null);
      onToast('Preview failed', 'danger', error?.body?.message || error.message);
    } finally {
      setPreviewing(false);
    }
  };

  const save = async () => {
    if (!editing || !canAdminister) return;
    const error = localValidate(editing);
    if (error) {
      onToast(error, 'danger');
      return;
    }
    try {
      setSaving(true);
      const payload = {
        ...cleanPayload(editing),
        name: editing.name!.trim(),
        ...(!editing.id ? { enabled: false } : {}),
      };
      if (editing.id) await apiService.updateRule(editing.id, payload, concurrencyOf(editing as CorrelationRule));
      else await apiService.createRule(payload as CorrelationRuleCreateRequest);
      onToast(editing.id && editing.enabled ? 'Rule saved and enabled' : 'Draft rule saved', 'success');
      setEditing(null);
      await load();
    } catch (error: any) {
      if (editing.id && isConflict(error)) {
        await refreshAfterConflict(editing.id, true);
        return;
      }
      onToast('Failed to save rule', 'danger', error?.body?.message || error.message);
    } finally {
      setSaving(false);
    }
  };

  const doDelete = async () => {
    if (!confirmDelete || !canAdminister) return;
    try {
      await apiService.deleteRule(confirmDelete.id, concurrencyOf(confirmDelete));
      onToast('Rule deleted', 'success');
      setConfirmDelete(null);
      await load();
    } catch (error: any) {
      if (isConflict(error)) {
        setConfirmDelete(null);
        await refreshAfterConflict(confirmDelete.id, false);
        return;
      }
      onToast('Failed to delete rule', 'danger', error?.body?.message || error.message);
    }
  };

  const rollback = async (targetRevision: number) => {
    if (!editing?.id || !canAdminister) return;
    try {
      setRollingBack(targetRevision);
      const updated = await apiService.rollbackRule(
        editing.id,
        targetRevision,
        concurrencyOf(editing as CorrelationRule)
      );
      setEditing(normalizeForEdit(updated));
      setPreview(null);
      setPreviewFingerprint(null);
      await load();
      await loadRevisions(updated.id);
      onToast(`Rolled back to revision ${targetRevision}`, 'success');
    } catch (error: any) {
      if (isConflict(error)) {
        await refreshAfterConflict(editing.id, true);
        return;
      }
      onToast('Failed to roll back rule', 'danger', error?.body?.message || error.message);
    } finally {
      setRollingBack(null);
    }
  };

  const columns = [
    {
      field: 'enabled',
      name: 'State',
      width: '76px',
      render: (_enabled: boolean, rule: CorrelationRule) => (
        <EuiToolTip content={canAdminister ? (rule.enabled ? 'Disable rule' : 'Open preview before enabling') : ADMIN_HELP}>
          <span>
            <EuiSwitch
              showLabel={false}
              label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.name}`}
              checked={rule.enabled}
              disabled={!canAdminister}
              onChange={() => toggleEnabled(rule)}
              compressed
            />
          </span>
        </EuiToolTip>
      ),
    },
    { field: 'name', name: 'Rule', sortable: true, render: (name: string, rule: any) => <div className="wamRuleIdentity"><strong>{name}</strong><EuiText size="xs" color="subdued">Revision {rule.revision} · priority {rule.priority ?? 100} / order {rule.sortOrder ?? 0}<br />Owner: {rule.created_by || 'Unavailable'}</EuiText></div> },
    {
      name: 'Trigger',
      render: (rule: CorrelationRule) => {
        const trigger = rule.trigger || ({ type: 'per_alert' } as any);
        const groups = trigger.entityExpression?.groups?.length || 0;
        return trigger.type === 'burst'
          ? `>=${trigger.threshold} in ${trigger.windowMinutes}m · ${groups} entity group${groups === 1 ? '' : 's'}`
          : `Every matching alert · ${groups || 'no'} entity group${groups === 1 ? '' : 's'}`;
      },
    },
    {
      name: 'Actions',
      render: (rule: CorrelationRule) => {
        const actions = rule.actions || ({} as any);
        return [actions.createCase ? `Case (${actions.caseSeverity})` : null, actions.setStatus ? `Status: ${statusLabel(actions.setStatus)}` : null, actions.assignTo ? `Assign: ${actions.assignTo}` : null].filter(Boolean).join(', ') || 'None';
      },
    },
    { field: 'lastFired', name: 'Last fired', render: (value: string | null) => value ? formatRelative(value) : 'Never' },
    {
      name: 'Manage',
      width: '84px',
      render: (rule: CorrelationRule) => (
        <EuiFlexGroup gutterSize="xs" responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiToolTip content={canAdminister ? 'Edit rule' : ADMIN_HELP}><span><EuiButtonIcon iconType="pencil" aria-label={`Edit ${rule.name}`} disabled={!canAdminister} onClick={() => openEditor(rule)} /></span></EuiToolTip>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiToolTip content={canAdminister ? 'Delete rule' : ADMIN_HELP}><span><EuiButtonIcon iconType="trash" color="danger" aria-label={`Delete ${rule.name}`} disabled={!canAdminister} onClick={() => setConfirmDelete(rule)} /></span></EuiToolTip>
          </EuiFlexItem>
        </EuiFlexGroup>
      ),
    },
  ];

  const actions = editing?.actions || ({ createCase: false } as any);
  const trigger = editing?.trigger || ({ type: 'per_alert' } as any);
  const isBurst = trigger.type === 'burst';
  const previewIsCurrent = !!editing && previewFingerprint === fingerprint(editing);
  const editorStages = editing?.id ? STAGES : STAGES.filter((item) => item.id !== 'history');
  const currentStageIndex = editorStages.findIndex((item) => item.id === stage);
  const automationPaused = automation?.paused === true;
  const expression = trigger.entityExpression || emptyExpression();
  const predicateCount = expression.groups.reduce((count, group) => count + group.predicates.length, 0);
  const currentErrors = editing ? ruleErrors(editing) : [];
  const expressionSummary = expression.groups.length ? expression.groups.map((group) => `(${group.predicates.map((predicate) => {
    const value = predicate.operator === 'exists' ? 'is present' : `equals "${normalizedPredicateValue(predicate) || '...'}"`;
    return `${ENTITY_LABEL[predicate.entity]} ${value}`;
  }).join(' AND ') || 'add a predicate'})`).join(' OR ') : 'Any entity values (no trigger predicates)';

  const matchField = (label: string, key: 'ruleGroups' | 'ruleIds' | 'agentNames', modeKey: 'ruleGroupsMode' | 'ruleIdsMode' | 'agentNamesMode', placeholder: string) => (
    <EuiFormRow label={label} fullWidth labelAppend={<ModeToggle idPrefix={key} value={(editing?.match?.[modeKey] as MatchMode) || 'any'} isBurst={isBurst} onChange={(mode) => updateMatch({ [modeKey]: mode } as any)} />}>
      <EuiComboBox
        fullWidth
        placeholder={placeholder}
        selectedOptions={toOpts(editing?.match?.[key])}
        onChange={(selected) => updateMatch({ [key]: selected.map((option) => option.label) } as any)}
        onCreateOption={(value) => updateMatch({ [key]: [...(editing?.match?.[key] || []), value] } as any)}
      />
    </EuiFormRow>
  );

  return (
    <div>
      {!capabilitiesLoaded || !canAdminister ? (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="lock"
            title={capabilitiesLoaded ? 'Automation rules are read only for your role' : 'Checking automation permissions'}
          >
            {capabilitiesLoaded && <p>{ADMIN_HELP} Rules and runtime state remain visible, but the editor, preview, queue controls, and every mutation are locked. <EuiLink href={ADMIN_DOCS} target="_blank" external>Manage Wazuh users and roles</EuiLink>.</p>}
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      ) : null}

      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamAutomationHealth">
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
          <EuiFlexItem grow={false}><EuiTitle size="xs"><h3>Automation runtime</h3></EuiTitle></EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiToolTip content={automationPaused ? 'The automation queue is paused. Enabled rules remain enabled, but queued ingestion-time work waits.' : 'Queue processing is running. Individual disabled rules still do not receive new work.'}>
              <EuiBadge color={automationError ? 'warning' : automationPaused ? 'warning' : 'success'}>{automationError ? 'Health unavailable' : automationPaused ? 'Queue paused' : 'Queue running'}</EuiBadge>
            </EuiToolTip>
          </EuiFlexItem>
          <EuiFlexItem grow={false}><EuiButton size="s" iconType="refresh" onClick={() => { loadAutomationHealth(); loadDlqPage(dlqPage, dlqCursors[dlqPage]); }} isLoading={automationLoading || dlqLoading}>Refresh runtime</EuiButton></EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        {automationError ? <EuiCallOut size="s" color="warning" title="Automation health could not be loaded">{automationError}</EuiCallOut> : (
          <EuiFlexGroup gutterSize="s" wrap className="wamAutomationStats">
            <EuiFlexItem><EuiStat titleSize="s" title={automation?.lag ?? '—'} description="Queue lag" /></EuiFlexItem>
            <EuiFlexItem><EuiStat titleSize="s" title={automation?.retries ?? '—'} description="Scheduled retries" titleColor={automation?.retries ? 'warning' : 'default'} /></EuiFlexItem>
            <EuiFlexItem><EuiStat titleSize="s" title={automation?.dlq ?? '—'} description="Dead letters" titleColor={automation?.dlq ? 'danger' : 'success'} /></EuiFlexItem>
            <EuiFlexItem><EuiStat titleSize="s" title={automation?.oldestAgeSeconds == null ? '—' : `${automation.oldestAgeSeconds}s`} description="Oldest queued" /></EuiFlexItem>
          </EuiFlexGroup>
        )}
        {automation && <EuiText size="xs" color="subdued"><p>Queue states: {Object.keys(automation.states || {}).length ? Object.entries(automation.states).map(([state, count]) => `${state} ${count}`).join(' · ') : 'none'}. Admission is {automation.admissionOpen ? 'open' : 'closed'}; deferred: {automation.deferred.toLocaleString()}. Disabling a rule stops new work for that rule. Pausing the queue preserves enabled rules and delays already-admitted ingestion-time work.</p></EuiText>}
        {automationSettings && (
          <EuiPanel paddingSize="s" hasBorder hasShadow={false} className="wamAutomationSettings">
            <EuiFlexGroup gutterSize="m" alignItems="flexEnd" wrap>
              <EuiFlexItem grow={false}>
                <EuiToolTip content={automationSettings.paused ? 'Resume durable queue processing. This is not a historical replay.' : 'Pause queue processing without disabling individual rules.'}>
                  <span><EuiSwitch label="Process automation queue" checked={!automationSettings.paused} disabled={!canAdminister || savingAutomation} onChange={() => saveQueueSettings({ ...automationSettings, paused: !automationSettings.paused })} /></span>
                </EuiToolTip>
              </EuiFlexItem>
              <EuiFlexItem grow={false}><EuiFormRow label="Active backlog cap"><EuiFieldNumber min={1} max={1000000} value={automationSettings.maxBacklog} disabled={!canAdminister} onChange={(event) => setAutomationSettings({ ...automationSettings, maxBacklog: Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
              <EuiFlexItem grow={false}><EuiFormRow label="Deferred cap"><EuiFieldNumber min={1} max={5000000} value={automationSettings.maxDeferred} disabled={!canAdminister} onChange={(event) => setAutomationSettings({ ...automationSettings, maxDeferred: Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
              <EuiFlexItem grow={false}><EuiButton size="s" disabled={!canAdminister || !Number.isInteger(automationSettings.maxBacklog) || automationSettings.maxBacklog < 1 || automationSettings.maxBacklog > 1000000 || !Number.isInteger(automationSettings.maxDeferred) || automationSettings.maxDeferred < 1 || automationSettings.maxDeferred > 5000000} isLoading={savingAutomation} onClick={() => saveQueueSettings(automationSettings)}>Save queue settings</EuiButton></EuiFlexItem>
            </EuiFlexGroup>
          </EuiPanel>
        )}
        <EuiSpacer size="s" />
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s">
          <EuiFlexItem><EuiTitle size="xxs"><h4>Dead-letter queue</h4></EuiTitle></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiText size="xs" color="subdued">Page {dlqPage + 1}</EuiText></EuiFlexItem>
        </EuiFlexGroup>
        {dlqItems.length > 0 && (
          <EuiBasicTable
            items={dlqItems}
            itemId="id"
            loading={dlqLoading}
            columns={[
              { field: 'event_id', name: 'Event' },
              { field: 'stage', name: 'Stage', render: (value: string) => value || 'Unavailable' },
              { field: 'attempts', name: 'Attempts', render: (value: number) => value == null ? 'Unavailable' : value },
              { field: 'error', name: 'Error', render: (value: AutomationDlqItem['error']) => typeof value === 'string' ? value : value?.message || 'Unavailable' },
              { name: 'Actions', render: (item: AutomationDlqItem) => <EuiFlexGroup gutterSize="xs" responsive={false}><EuiFlexItem grow={false}><EuiToolTip content="Return this ingestion-time event to the durable queue with its captured ruleset snapshot."><span><EuiButton size="s" disabled={!canAdminister || mutatingDlq !== null} isLoading={mutatingDlq === item.event_id} onClick={() => retryDlqEvent(item.event_id)}>Retry</EuiButton></span></EuiToolTip></EuiFlexItem><EuiFlexItem grow={false}><EuiToolTip content="Remove this dead letter without executing it. This is not a replay."><span><EuiButton size="s" color="danger" disabled={!canAdminister || mutatingDlq !== null} isLoading={mutatingDlq === item.id} onClick={() => resolveDlqEvent(item)}>Resolve</EuiButton></span></EuiToolTip></EuiFlexItem></EuiFlexGroup> },
            ] as any}
          />
        )}
        {!dlqLoading && dlqItems.length === 0 && <EuiText size="s" color="subdued"><p>No dead letters on this page.</p></EuiText>}
        <EuiFlexGroup justifyContent="flexEnd" gutterSize="s" responsive={false}>
          <EuiFlexItem grow={false}><EuiButton size="s" disabled={dlqPage === 0 || dlqLoading} onClick={() => loadDlqPage(dlqPage - 1, dlqCursors[dlqPage - 1])}>Previous</EuiButton></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiButton size="s" disabled={!dlqNextCursor || dlqLoading} onClick={() => { const cursor = dlqNextCursor || undefined; setDlqCursors((current) => { const next = current.slice(); next[dlqPage + 1] = cursor; return next; }); loadDlqPage(dlqPage + 1, cursor); }}>Next</EuiButton></EuiFlexItem>
        </EuiFlexGroup>
      </EuiPanel>
      <EuiSpacer size="m" />

      <EuiFlexGroup alignItems="center" gutterSize="m">
        <EuiFlexItem>
          <EuiText size="s" color="subdued">
            Rules evaluate incoming alerts in match, trigger, and action stages. New rules remain draft until an administrator previews the current definition and explicitly enables it.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiToolTip content={canAdminister ? 'Create a disabled draft rule' : ADMIN_HELP}>
            <span><EuiButton size="s" iconType="plusInCircle" fill disabled={!canAdminister} onClick={() => openEditor()}>New rule</EuiButton></span>
          </EuiToolTip>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="m" />

      {rules.length === 0 && !loading ? (
        <EuiEmptyPrompt
          iconType="indexRollupApp"
          titleSize="xs"
          title={<h3>No automation rules yet</h3>}
          body={<p>Create a disabled draft, define its scope and supported actions, then preview its exact saved revision before activation.</p>}
          actions={<EuiToolTip content={canAdminister ? 'Create a disabled draft rule' : ADMIN_HELP}><span><EuiButton size="s" fill disabled={!canAdminister} onClick={() => openEditor()}>New rule</EuiButton></span></EuiToolTip>}
        />
      ) : (
        <div style={{ overflowX: 'auto' }}><EuiBasicTable items={rules} itemId="id" columns={columns as any} loading={loading} tableLayout="auto" /></div>
      )}

      {editing && (
        <EuiFlyout onClose={() => setEditing(null)} size="90vw" aria-labelledby="rule-editor" className="wamRuleFlyout">
          <EuiFlyoutHeader hasBorder>
            <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
              <EuiFlexItem>
                <EuiTitle size="s"><h2 id="rule-editor">{editing.id ? `Edit ${editing.name}` : 'New automation rule'}</h2></EuiTitle>
              </EuiFlexItem>
              <EuiFlexItem grow={false}><EuiBadge color={editing.enabled ? 'success' : 'hollow'}>{editing.enabled ? 'Enabled' : 'Draft'}</EuiBadge></EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <div style={{ overflowX: 'auto' }}>
              <EuiTabs size="s">
                {editorStages.map((item) => <EuiTab key={item.id} isSelected={stage === item.id} onClick={() => setStage(item.id)}>{item.label}</EuiTab>)}
              </EuiTabs>
            </div>
            <EuiSpacer size="l" />

            {stage === 'basics' && (
              <>
                <EuiTitle size="xs"><h3>Basics</h3></EuiTitle>
                <EuiText size="s" color="subdued"><p>Name the rule and control activation. New rules are always initialized as disabled drafts.</p></EuiText>
                <EuiSpacer size="m" />
                <EuiFormRow label="Name" fullWidth><EuiFieldText fullWidth value={editing.name || ''} onChange={(event) => update({ name: event.target.value })} placeholder="Authentication failures per host" /></EuiFormRow>
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem><EuiFormRow label="Priority" helpText="Lower priorities run first."><EuiFieldNumber min={0} max={1000} value={editing.priority ?? 100} onChange={(event) => update({ priority: Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
                  <EuiFlexItem><EuiFormRow label="Sort order" helpText="Breaks ties between rules with the same priority."><EuiFieldNumber min={0} max={1000000} value={editing.sortOrder ?? 0} onChange={(event) => update({ sortOrder: Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
                </EuiFlexGroup>
                <EuiPanel paddingSize="m" hasBorder hasShadow={false}>
                  <EuiSwitch
                    label={editing.id ? 'Enabled' : 'Enabled after save'}
                    checked={!!editing.enabled}
                    disabled={!editing.id}
                    onChange={(event) => {
                      if (event.target.checked && !previewIsCurrent) {
                        setStage('preview');
                        onToast('Preview the current definition before enabling', 'primary');
                        return;
                      }
                      update({ enabled: event.target.checked });
                    }}
                  />
                  <EuiText size="xs" color="subdued"><p>{editing.id ? 'Activation is blocked until a successful preview matches the current material definition.' : 'New rules are always saved as disabled drafts. Reopen the saved rule to enable it after preview.'}</p></EuiText>
                </EuiPanel>
              </>
            )}

            {stage === 'match' && (
              <>
                <EuiTitle size="xs"><h3>Match</h3></EuiTitle>
                <EuiText size="s" color="subdued"><p>All populated condition groups must match. Within a group, Any or All controls listed values.</p></EuiText>
                <EuiSpacer size="m" />
                {matchField('Rule groups', 'ruleGroups', 'ruleGroupsMode', 'e.g. authentication_failed, pam')}
                {matchField('Rule IDs', 'ruleIds', 'ruleIdsMode', 'e.g. 5710, 5716')}
                {matchField('Agents', 'agentNames', 'agentNamesMode', 'Any agent')}
                <EuiFormRow label="Minimum level"><EuiFieldNumber min={0} max={16} value={editing.match?.minLevel ?? ''} onChange={(event) => updateMatch({ minLevel: event.target.value === '' ? undefined : Number(event.target.value) })} /></EuiFormRow>
                {!isBurst && <EuiCallOut size="s" color="primary" iconType="iInCircle" title="All-of is disabled for per-alert triggers">All-of means co-occurrence on the same entity within a burst window. Live per-alert evaluation behaves as Any, so the editor does not offer a misleading All selection.</EuiCallOut>}
                {isMatchAll(editing) && (
                  <>
                    <EuiSpacer size="m" />
                     <EuiCallOut size="s" color="warning" iconType="alert" title="This definition matches every alert"><EuiCheckbox id="match-all-ack" label="I understand this rule has no match restrictions" checked={editing.safety?.acknowledgeMatchAll === true} onChange={(event) => updateSafety({ acknowledgeMatchAll: event.target.checked })} /></EuiCallOut>
                  </>
                )}
                <EuiSpacer size="m" />
                <EuiCallOut size="s" color="primary" title="Estimated breadth unavailable">Use Preview for a bounded 24-hour simulation of the exact saved revision.</EuiCallOut>
              </>
            )}

            {stage === 'trigger' && (
              <>
                <EuiTitle size="xs"><h3>Trigger</h3></EuiTitle>
                <EuiText size="s" color="subdued"><p>Predicates are explicitly ANDed inside each card. Cards are ORed. At most five cards and five predicates total are allowed.</p></EuiText>
                <EuiSpacer size="m" />
                <EuiButtonGroup
                  legend="Trigger type"
                  idSelected={isBurst ? 'trigger-burst' : 'trigger-per-alert'}
                  options={[{ id: 'trigger-per-alert', label: 'Every matching alert' }, { id: 'trigger-burst', label: 'Correlated burst' }]}
                  onChange={(id) => {
                    if (id === 'trigger-burst') updateTrigger({
                      type: 'burst', threshold: trigger.threshold || 3, windowMinutes: trigger.windowMinutes || 10,
                      cooldown: { durationMinutes: trigger.cooldown?.durationMinutes || 10 },
                      rearm: { type: 'after_quiet_period', quietPeriodMinutes: trigger.rearm?.quietPeriodMinutes || 10 },
                    });
                    else {
                      updateTrigger({ type: 'per_alert', threshold: undefined, windowMinutes: undefined, cooldown: { durationMinutes: 0 }, rearm: { type: 'immediate', quietPeriodMinutes: 0 } });
                      updateMatch({ ruleGroupsMode: 'any', ruleIdsMode: 'any', agentNamesMode: 'any' });
                    }
                  }}
                />
                <EuiSpacer size="l" />
                <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s">
                  <EuiFlexItem><EuiTitle size="xxs"><h4>Entity expression</h4></EuiTitle><EuiText size="xs" color="subdued">{expression.groups.length}/{MAX_ENTITY_GROUPS} OR groups; {predicateCount}/{MAX_ENTITY_PREDICATES} predicates</EuiText></EuiFlexItem>
                  <EuiFlexItem grow={false}><EuiButton size="s" iconType="plusInCircle" disabled={expression.groups.length >= MAX_ENTITY_GROUPS || predicateCount >= MAX_ENTITY_PREDICATES} onClick={addEntityGroup}>Add OR group</EuiButton></EuiFlexItem>
                </EuiFlexGroup>
                <EuiSpacer size="s" />
                {expression.groups.map((group, groupIndex) => (
                  <React.Fragment key={group.id}>
                    {groupIndex > 0 && <div className="wamRuleOperator"><EuiBadge color="accent">OR</EuiBadge></div>}
                    <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamEntityGroup">
                      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s">
                        <EuiFlexItem><EuiTitle size="xxs"><h4>Group {groupIndex + 1}: all predicates must match (AND)</h4></EuiTitle></EuiFlexItem>
                        <EuiFlexItem grow={false}><EuiButtonIcon iconType="trash" color="danger" aria-label={`Remove group ${groupIndex + 1}`} onClick={() => removeEntityGroup(group.id)} /></EuiFlexItem>
                      </EuiFlexGroup>
                      {group.predicates.map((predicate, predicateIndex) => (
                        <React.Fragment key={predicate.id}>
                          {predicateIndex > 0 && <div className="wamRuleOperator"><EuiBadge color="hollow">AND</EuiBadge></div>}
                          <EuiFlexGroup gutterSize="s" alignItems="flexEnd" className="wamPredicateRow">
                            <EuiFlexItem><EuiFormRow label="Entity"><EuiSelect fullWidth options={ENTITY_OPTIONS} value={predicate.entity} onChange={(event) => updatePredicate(group.id, predicate.id, { entity: event.target.value as CorrelationEntity })} /></EuiFormRow></EuiFlexItem>
                            <EuiFlexItem><EuiFormRow label="Operator"><EuiSelect fullWidth options={[{ value: 'equals', text: 'Equals' }, { value: 'exists', text: 'Is present' }]} value={predicate.operator} onChange={(event) => updatePredicate(group.id, predicate.id, { operator: event.target.value as any, ...(event.target.value === 'exists' ? { value: undefined } : {}) })} /></EuiFormRow></EuiFlexItem>
                            <EuiFlexItem grow={2}><EuiFormRow label="Value" helpText={predicate.operator === 'equals' ? 'Required. Normalized before matching and identity-key construction.' : 'No value required. The observed entity value becomes the identity; missing fields do not match.'}><EuiFieldText fullWidth disabled={predicate.operator === 'exists'} value={predicate.value || ''} placeholder={predicate.entity === 'dstport' ? '22' : 'Required value'} onChange={(event) => updatePredicate(group.id, predicate.id, { value: event.target.value })} /></EuiFormRow></EuiFlexItem>
                            <EuiFlexItem grow={false}><EuiButtonIcon iconType="cross" aria-label={`Remove predicate ${predicateIndex + 1}`} onClick={() => removePredicate(group.id, predicate.id)} /></EuiFlexItem>
                          </EuiFlexGroup>
                        </React.Fragment>
                      ))}
                      <EuiSpacer size="s" />
                      <EuiButton size="s" iconType="plusInCircle" disabled={predicateCount >= MAX_ENTITY_PREDICATES} onClick={() => addPredicate(group.id)}>Add AND predicate</EuiButton>
                    </EuiPanel>
                  </React.Fragment>
                ))}
                {!expression.groups.length && <EuiCallOut size="s" color="primary" title="No entity predicates">Every alert that passes Match qualifies. Add an OR group to require normalized entity values. Agent restrictions belong on Match; Agent may still be referenced here when it is part of the correlation identity.</EuiCallOut>}
                <EuiSpacer size="m" />
                <EuiPanel color="subdued" paddingSize="m" hasShadow={false} className="wamRuleSummary"><EuiText size="s"><strong>Reads as:</strong> {expressionSummary}</EuiText></EuiPanel>
                <EuiSpacer size="s" />
                <EuiToolTip content="IP addresses are canonicalized, ports are numeric (0-65535), and users/processes are lowercased. An absent entity never becomes an 'unknown' bucket. If multiple OR groups match one alert, actions run once while all matching-group provenance is retained."><span className="wamHelpText">Normalization, missing values, and provenance</span></EuiToolTip>
                {expressionErrors(editing).map((error) => <EuiCallOut key={error} size="s" color="danger" iconType="alert" title={error} />)}
                {isBurst && (
                  <>
                    <EuiSpacer size="l" />
                    <EuiFlexGroup gutterSize="m">
                      <EuiFlexItem><EuiFormRow label="Threshold"><EuiFieldNumber min={2} max={1000} value={trigger.threshold} onChange={(event) => updateTrigger({ threshold: Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
                      <EuiFlexItem><EuiFormRow label="Window (minutes)"><EuiFieldNumber min={1} max={1440} value={trigger.windowMinutes} onChange={(event) => updateTrigger({ windowMinutes: Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
                    </EuiFlexGroup>
                    <EuiFormRow label="Case routing" helpText="Applies only when the case action is selected."><EuiSelect fullWidth options={[
                      { value: 'separate_by_group', text: 'Separate by entity group (recommended)' },
                      { value: 'consolidate_overlapping', text: 'Consolidate overlapping bursts' },
                      { value: 'one_per_rule', text: 'One active case per rule (advanced)' },
                    ]} value={trigger.routing || 'separate_by_group'} onChange={(event) => updateTrigger({ routing: event.target.value as any })} /></EuiFormRow>
                    {trigger.routing === 'one_per_rule' && <EuiCallOut size="s" color="warning" title="Advanced routing can mix unrelated activity">All entity groups and values update one active rule case, which can grow large and blur incident boundaries.</EuiCallOut>}
                    <EuiSpacer size="m" />
                    <EuiFlexGroup gutterSize="m">
                      <EuiFlexItem><EuiFormRow label="Cooldown (minutes)" helpText="Suppresses repeated firings for the same resolved group/key."><EuiFieldNumber min={1} max={10080} value={trigger.cooldown?.durationMinutes} onChange={(event) => updateTrigger({ cooldown: { durationMinutes: Number(event.target.value) } })} /></EuiFormRow></EuiFlexItem>
                      <EuiFlexItem><EuiFormRow label="Rearm after quiet (minutes)" helpText="A sustained burst stays disarmed until this quiet period passes."><EuiFieldNumber min={1} max={10080} value={trigger.rearm?.quietPeriodMinutes} onChange={(event) => updateTrigger({ rearm: { type: 'after_quiet_period', quietPeriodMinutes: Number(event.target.value) } })} /></EuiFormRow></EuiFlexItem>
                    </EuiFlexGroup>
                    <EuiText size="xs" color="subdued"><p>Threshold and sliding window apply independently to each resolved OR group/key. Cooldown limits repeated firings; quiet-period rearm prevents a sustained burst from repeatedly creating work. Existing active deduplicated cases may still be extended.</p></EuiText>
                  </>
                )}
                {!isBurst && <EuiCallOut size="s" color="primary" title="Immediate per-alert evaluation">There is no threshold, correlation window, cooldown, or quiet-period control. Each newly ingested alert that passes Match and the entity expression runs once.</EuiCallOut>}
              </>
            )}

            {stage === 'actions' && (
              <>
                <EuiTitle size="xs"><h3>Actions</h3></EuiTitle>
                <EuiText size="s" color="subdued"><p>Choose at least one supported workbench action. No outbound response or webhook actions are available.</p></EuiText>
                <EuiSpacer size="m" />
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem><EuiFormRow label="Set status" helpText="Applies to every matching alert or the alerts in a firing burst."><EuiSelect fullWidth options={[{ value: '', text: 'No change' }, ...ALERT_STATUSES.map((status) => ({ value: status, text: statusLabel(status) }))]} value={actions.setStatus || ''} onChange={(event) => updateActions({ setStatus: (event.target.value || null) as any })} /></EuiFormRow></EuiFlexItem>
                  <EuiFlexItem><EuiFormRow label="Assign to"><EuiSelect fullWidth options={[{ value: '', text: 'No assignment' }, ...analysts.map((analyst) => ({ value: analyst, text: analyst }))]} value={actions.assignTo || ''} onChange={(event) => updateActions({ assignTo: event.target.value || null })} /></EuiFormRow></EuiFlexItem>
                </EuiFlexGroup>
                <EuiPanel color={actions.createCase ? 'primary' : 'subdued'} paddingSize="m" hasBorder hasShadow={false}>
                  <EuiSwitch label="Create or update a deduplicated case" checked={!!actions.createCase} onChange={(event) => updateActions({ createCase: event.target.checked })} />
                  <EuiText size="xs" color="subdued"><p>Later alerts with the same rule and normalized entity-group identity extend the active case. Closed or archived cases are not silently reopened.</p></EuiText>
                  {actions.createCase && <><EuiSpacer size="m" /><EuiFormRow label="Case severity"><EuiSelect options={CASE_SEVERITIES.map((severity) => ({ value: severity, text: severity.charAt(0).toUpperCase() + severity.slice(1) }))} value={actions.caseSeverity} onChange={(event) => updateActions({ caseSeverity: event.target.value as any })} /></EuiFormRow></>}
                </EuiPanel>
                <EuiSpacer size="l" />
                <EuiTitle size="xxs"><h4>Preconditions and processing</h4></EuiTitle>
                <EuiText size="xs" color="subdued"><p>Limit actions to alerts in the expected workflow state, then choose whether lower-priority rules may continue.</p></EuiText>
                <EuiFormRow label="Allowed statuses" helpText="Leave all unchecked to allow every status.">
                  <EuiFlexGroup gutterSize="m" responsive={false} wrap>
                    {ALERT_STATUSES.map((status) => {
                      const selected = editing.preconditions?.statuses || [];
                      return <EuiFlexItem key={status} grow={false}><EuiCheckbox id={`precondition-${status}`} label={statusLabel(status)} checked={selected.includes(status)} onChange={(event) => updatePreconditions({ statuses: event.target.checked ? [...selected, status] : selected.filter((item) => item !== status) })} /></EuiFlexItem>;
                    })}
                  </EuiFlexGroup>
                </EuiFormRow>
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem><EuiFormRow label="Assignment precondition"><EuiSelect fullWidth options={[{ value: 'unassigned', text: 'Only unassigned alerts' }, { value: 'any', text: 'Any assignment' }]} value={editing.preconditions?.assignment || 'unassigned'} onChange={(event) => updatePreconditions({ assignment: event.target.value as any })} /></EuiFormRow></EuiFlexItem>
                  <EuiFlexItem><EuiFormRow label="After this rule"><EuiSelect fullWidth options={[{ value: 'continue', text: 'Continue processing' }, { value: 'stop', text: 'Stop processing' }]} value={editing.processingMode || 'continue'} onChange={(event) => update({ processingMode: event.target.value as any })} /></EuiFormRow></EuiFlexItem>
                </EuiFlexGroup>
              </>
            )}

            {stage === 'safety' && (
              <>
                <EuiTitle size="xs"><h3>Safety</h3></EuiTitle>
                <EuiText size="s" color="subdued"><p>Bound the work a rule may perform in one run and across a time window.</p></EuiText>
                <EuiSpacer size="m" />
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem><EuiFormRow label="Maximum actions per run"><EuiFieldNumber min={1} max={10000} value={editing.safety?.maxActionsPerRun ?? ''} placeholder="No cap" onChange={(event) => updateSafety({ maxActionsPerRun: event.target.value === '' ? undefined : Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
                  <EuiFlexItem><EuiFormRow label="Maximum cases per run"><EuiFieldNumber min={1} max={10000} value={editing.safety?.maxCasesPerRun ?? ''} placeholder="No cap" onChange={(event) => updateSafety({ maxCasesPerRun: event.target.value === '' ? undefined : Number(event.target.value) })} /></EuiFormRow></EuiFlexItem>
                </EuiFlexGroup>
                <EuiPanel paddingSize="m" hasBorder hasShadow={false}>
                  <EuiSwitch label="Rate limit executions" checked={!!editing.safety?.rateLimit} onChange={(event) => updateSafety({ rateLimit: event.target.checked ? { maxExecutions: 100, windowMinutes: 60 } : null as any })} />
                  {editing.safety?.rateLimit && <><EuiSpacer size="m" /><EuiFlexGroup gutterSize="m"><EuiFlexItem><EuiFormRow label="Maximum executions"><EuiFieldNumber min={1} max={100000} value={editing.safety.rateLimit.maxExecutions} onChange={(event) => updateSafety({ rateLimit: { ...editing.safety!.rateLimit!, maxExecutions: Number(event.target.value) } })} /></EuiFormRow></EuiFlexItem><EuiFlexItem><EuiFormRow label="Window (minutes)"><EuiFieldNumber min={1} max={10080} value={editing.safety.rateLimit.windowMinutes} onChange={(event) => updateSafety({ rateLimit: { ...editing.safety!.rateLimit!, windowMinutes: Number(event.target.value) } })} /></EuiFormRow></EuiFlexItem></EuiFlexGroup></>}
                </EuiPanel>
                <EuiSpacer size="m" />
                <EuiCallOut color="primary" iconType="iInCircle" title="Match-all acknowledgment is definition-bound">The acknowledgment is cleared whenever any match condition changes. Match-all rules cannot be previewed or saved until acknowledged again.</EuiCallOut>
              </>
            )}

            {stage === 'preview' && (
              <>
                <EuiTitle size="xs"><h3>Preview and activation</h3></EuiTitle>
                 <EuiText size="s" color="subdued"><p>Save a disabled draft, then run a bounded historical simulation for exact saved revision {editing.revision || '—'}. Preview is read-only: it never mutates historical alerts, cases, queue work, or correlation state.</p></EuiText>
                <EuiSpacer size="m" />
                 <EuiToolTip content={!editing.id ? 'Save the disabled draft first' : canAdminister ? 'Simulate this saved revision over the last 24 hours' : ADMIN_HELP}><span><EuiButton iconType="inspect" onClick={runPreview} isLoading={previewing} disabled={!canAdminister || !editing.id}>Preview last 24 hours</EuiButton></span></EuiToolTip>
                <EuiSpacer size="m" />
                {!preview && <EuiCallOut color="warning" iconType="alert" title="Activation gate not satisfied">A successful preview of this exact definition is required before Enabled can be selected.</EuiCallOut>}
                {preview && !previewIsCurrent && <EuiCallOut color="warning" iconType="alert" title="Preview is stale">The rule changed after this preview. Run it again before activation.</EuiCallOut>}
                {preview && previewIsCurrent && (
                  <EuiCallOut color="success" iconType="check" title={`Preview passed: ${preview.matchingAlerts.toLocaleString()} matching alert${preview.matchingAlerts === 1 ? '' : 's'}`}>
                    <p>Saved revision {editing.revision}; historical interval: last {preview.lookbackHours} hours{preview.triggerType === 'burst' ? `; ${preview.windowMinutes}-minute sliding correlation window` : '; immediate per-alert trigger'}.</p>
                    <p>{preview.triggerType === 'burst' ? `${preview.triggeringEntities.length} resolved groups/keys cross the threshold. ` : ''}{preview.casesCreated ?? preview.wouldOpenCases} cases would be created; {preview.casesExtended || 0} active deduplicated cases would be extended; {preview.statusChanges || 0} status changes and {preview.assignments || 0} assignments are planned.</p>
                    {preview.triggeringEntities.slice(0, 8).map((item) => <EuiBadge key={item.entity} color="hollow" style={{ marginRight: 4 }}>{item.entity} ({item.count})</EuiBadge>)}
                  </EuiCallOut>
                )}
                <EuiSpacer size="m" />
                 <EuiCallOut size="s" color="primary" title="Bounded simulation">Preview uses the live normalized evaluator and runtime planner, including sliding windows, deduplication/routing, preconditions, conflict policy, and safety/rate caps. {preview ? `${(preview.sampledAlerts || 0).toLocaleString()} of ${(preview.totalAlerts ?? preview.sampledAlerts ?? 0).toLocaleString()} candidate alerts sampled in ${preview.queryTimeMs || 0} ms. ${preview.truncated ? 'Results are truncated and do not represent the complete candidate set.' : 'Results were not truncated.'}` : 'The result reports sampled and total candidates plus truncation explicitly.'}</EuiCallOut>
                {preview && <>
                  <EuiSpacer size="m" />
                  <EuiFlexGroup gutterSize="s" wrap className="wamPreviewStats">
                    <EuiFlexItem><EuiStat titleSize="s" title={preview.matchingAlerts.toLocaleString()} description="Matching alerts" /></EuiFlexItem>
                    <EuiFlexItem><EuiStat titleSize="s" title={(preview.missingEntities || 0).toLocaleString()} description={`Missing entities (${((preview.missingEntityRate || 0) * 100).toFixed(1)}%)`} titleColor={preview.missingEntities ? 'warning' : 'default'} /></EuiFlexItem>
                    <EuiFlexItem><EuiStat titleSize="s" title={(preview.skips || 0).toLocaleString()} description="Precondition/planner skips" /></EuiFlexItem>
                    <EuiFlexItem><EuiStat titleSize="s" title={(preview.skippedBySafety || 0).toLocaleString()} description="Skipped by safety caps" titleColor={preview.skippedBySafety ? 'warning' : 'default'} /></EuiFlexItem>
                    <EuiFlexItem><EuiStat titleSize="s" title={(preview.conflicts || []).length.toLocaleString()} description="Conflicts" titleColor={preview.conflicts?.length ? 'warning' : 'default'} /></EuiFlexItem>
                  </EuiFlexGroup>
                  {preview.rateLimited && <EuiCallOut size="s" color="warning" title="Rate cap reached">Some otherwise eligible executions are omitted by the configured rate limit.</EuiCallOut>}
                  {!!preview.conflicts?.length && <EuiCallOut size="s" color="warning" title="Representative conflicts"><EuiCodeBlock language="json" fontSize="s" paddingSize="s" overflowHeight={180} transparentBackground>{JSON.stringify(preview.conflicts.slice(0, 5), null, 2)}</EuiCodeBlock></EuiCallOut>}
                  <EuiSpacer size="m" />
                  <EuiTitle size="xxs"><h4>Representative alerts</h4></EuiTitle>
                  {preview.representativeAlerts?.length ? <div className="wamRepresentativeAlerts">{preview.representativeAlerts.map((alert) => <EuiBadge key={alert.id} color="hollow">{alert.id} · {alert.timestamp || 'timestamp unavailable'}</EuiBadge>)}</div> : <EuiText size="xs" color="subdued"><p>No representative alerts were returned.</p></EuiText>}
                  <EuiText size="xs" color="subdued"><p>Case routing effect: {trigger.routing === 'separate_by_group' ? 'independent active cases per entity group and normalized tuple (recommended)' : trigger.routing === 'consolidate_overlapping' ? 'only bursts with overlapping alert sets in this window are consolidated' : 'all bursts update one active rule case; unrelated activity may mix'}. Preview samples are illustrative; deterministic provenance retains every matching group even when an alert satisfies more than one.</p></EuiText>
                </>}
                <EuiSpacer size="m" />
                <EuiPanel paddingSize="m" hasBorder hasShadow={false}>
                  <EuiSwitch label="Enable after save" checked={!!editing.enabled} disabled={!editing.id || !previewIsCurrent} onChange={(event) => update({ enabled: event.target.checked })} />
                  <EuiText size="xs" color="subdued"><p>{!editing.id ? 'Step 1: save the first disabled draft. Step 2: reopen it and preview its exact saved revision. Step 3: review impact, select Enable after save, then save.' : previewIsCurrent ? 'The exact saved revision passed preview. Review impact, select this switch, then use Save and enable.' : 'Save any edits first, then preview the exact saved revision to unlock activation.'}</p></EuiText>
                </EuiPanel>
              </>
            )}

            {stage === 'history' && editing.id && (
              <>
                <EuiTitle size="xs"><h3>Revision history</h3></EuiTitle>
                <EuiText size="s" color="subdued"><p>Rollback creates a new revision from the selected snapshot; it does not erase history.</p></EuiText>
                <EuiSpacer size="m" />
                <EuiBasicTable
                  items={revisions}
                  loading={revisionsLoading}
                  itemId="revision"
                  columns={[
                    { field: 'revision', name: 'Revision' },
                    { field: 'change_type', name: 'Change' },
                    { field: 'changed_by', name: 'Changed by' },
                    { field: 'changed_at', name: 'Changed', render: (value: string) => formatRelative(value) },
                    { name: 'Action', render: (item: CorrelationRuleRevision) => <EuiButton size="s" disabled={!canAdminister || item.revision === editing.revision || rollingBack !== null} isLoading={rollingBack === item.revision} onClick={() => setConfirmRollback(item.revision)}>Rollback</EuiButton> },
                  ] as any}
                />
              </>
            )}
          </EuiFlyoutBody>
          <EuiFlyoutFooter>
            <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" responsive={false}>
              <EuiFlexItem grow={false}><EuiButton onClick={() => setEditing(null)}>Cancel</EuiButton></EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiFlexGroup gutterSize="s" responsive={false}>
                   {currentStageIndex > 0 && <EuiFlexItem grow={false}><EuiButton onClick={() => setStage(editorStages[currentStageIndex - 1].id)}>Back</EuiButton></EuiFlexItem>}
                    {currentStageIndex < editorStages.length - 1 ? <EuiFlexItem grow={false}><EuiButton fill onClick={() => setStage(editorStages[currentStageIndex + 1].id)}>Next</EuiButton></EuiFlexItem> : <EuiFlexItem grow={false}><EuiToolTip content={currentErrors[0] || (canAdminister ? 'Persist this definition' : ADMIN_HELP)}><span><EuiButton fill onClick={save} isLoading={saving} disabled={!canAdminister || currentErrors.length > 0}>Save {editing.enabled ? 'and enable' : 'draft'}</EuiButton></span></EuiToolTip></EuiFlexItem>}
                </EuiFlexGroup>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutFooter>
        </EuiFlyout>
      )}

      {confirmDelete && canAdminister && (
        <EuiConfirmModal title={`Delete "${confirmDelete.name}"?`} onCancel={() => setConfirmDelete(null)} onConfirm={doDelete} cancelButtonText="Cancel" confirmButtonText="Delete" buttonColor="danger">
          <p>Existing cases are kept. New alerts will no longer be acted on by this rule.</p>
        </EuiConfirmModal>
      )}

      {confirmRollback !== null && editing?.id && canAdminister && (
        <EuiConfirmModal title={`Roll back to revision ${confirmRollback}?`} onCancel={() => setConfirmRollback(null)} onConfirm={() => { const revision = confirmRollback; setConfirmRollback(null); rollback(revision); }} cancelButtonText="Cancel" confirmButtonText="Roll back" buttonColor="danger">
          <p>The selected snapshot will become a new revision. Review and preview the restored definition before leaving it enabled.</p>
        </EuiConfirmModal>
      )}
    </div>
  );
};
