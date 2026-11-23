import React, { useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCode,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  ASSET_CRITICALITIES,
  ASSET_MATCH_KINDS,
  ASSET_MAX_ENTRIES,
  ASSET_MAX_TAGS,
  AssetCriticality,
  AssetEntry,
  AssetMatchKind,
  AssetResolution,
  TARGET_WAZUH_MAJOR,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { ASSET_CRITICALITY_BADGE_COLOR, assetCriticalityLabel } from './asset_badge';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ADMIN_HELP =
  'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control asset administration.';

export const KIND_LABELS: Record<AssetMatchKind, string> = {
  name: 'Agent name (exact)',
  glob: 'Agent name (glob: * and ?)',
  group: 'Agent group',
  label: 'Agent label (4.x, key=value)',
};

const KIND_PLACEHOLDER: Record<AssetMatchKind, string> = {
  name: 'e.g. db-prod-01',
  glob: 'e.g. web-*',
  group: 'e.g. pci',
  label: 'e.g. env=prod',
};

const KIND_OPTIONS = ASSET_MATCH_KINDS.map((kind) => ({ value: kind, text: KIND_LABELS[kind] }));
const CRITICALITY_OPTIONS = ASSET_CRITICALITIES.map((value) => ({ value, text: assetCriticalityLabel(value) }));

/** Lower-case id derived from the match value; unique within the list. */
export function suggestId(value: string, existing: AssetEntry[]): string {
  const base = value.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 56) || 'asset';
  let id = base;
  let n = 2;
  while (existing.some((entry) => entry.id === id)) id = `${base}-${n++}`;
  return id;
}

function newEntry(existing: AssetEntry[]): AssetEntry {
  return { id: suggestId('asset', existing), match: { kind: 'glob', value: '' }, criticality: 'high', tags: [] };
}

function splitCsv(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export const ResolveResult: React.FC<{ result: AssetResolution; input: string }> = ({ result, input }) => {
  if (!result.criticality) {
    return (
      <EuiCallOut size="s" color="primary" iconType="iInCircle" title="No asset entry matches" className="wamAssetTestResult" data-test-subj="wamAssetTestResult">
        <p>
          <EuiCode>{input}</EuiCode> would be synced with no criticality, so automation floors on asset criticality never match it.
        </p>
      </EuiCallOut>
    );
  }
  return (
    <EuiCallOut size="s" color="success" iconType="check" title="Resolved" className="wamAssetTestResult" data-test-subj="wamAssetTestResult">
      <EuiText size="s">
        <p>
          <EuiCode>{input}</EuiCode> resolves to{' '}
          <EuiBadge color={ASSET_CRITICALITY_BADGE_COLOR[result.criticality]} data-test-subj="wamAssetTestCriticality">
            {assetCriticalityLabel(result.criticality)}
          </EuiBadge>{' '}
          via {result.matchedBy} entry <EuiCode>{result.matchedId}</EuiCode>
          {result.tags.length > 0 && (
            <>
              {' '}with tags {result.tags.map((tag) => <EuiBadge key={tag} color="hollow">{tag}</EuiBadge>)}
            </>
          )}
        </p>
      </EuiText>
    </EuiCallOut>
  );
};

export const AssetSettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [loading, setLoading] = useState(true);
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [canAdminister, setCanAdminister] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [assets, setAssets] = useState<AssetEntry[]>([]);
  const [meta, setMeta] = useState<{ updated_at?: string; updated_by?: string }>({});
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editing, setEditing] = useState<AssetEntry | null>(null);
  const [editingOriginalId, setEditingOriginalId] = useState<string | null>(null);
  /** True once the user has typed in the Id field; the id is then never auto-derived from the value. */
  const [idTouched, setIdTouched] = useState(false);
  const [tagsText, setTagsText] = useState('');
  const [testName, setTestName] = useState('');
  const [testGroups, setTestGroups] = useState('');
  const [testLabels, setTestLabels] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ input: string; result: AssetResolution } | null>(null);

  const load = async () => {
    try {
      const res = await apiService.fetchAssetSettings();
      setAssets(res.assets || []);
      setMeta({ updated_at: res.updated_at, updated_by: res.updated_by });
      setLoadError(null);
      setDirty(false);
    } catch (e: any) {
      setLoadError(e?.body?.message || e?.message || 'Failed to load asset settings');
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

  const update = (next: AssetEntry[]) => {
    setAssets(next);
    setDirty(true);
  };

  const openEditor = (entry: AssetEntry, originalId: string | null) => {
    setEditing({ ...entry, match: { ...entry.match }, tags: [...entry.tags] });
    setEditingOriginalId(originalId);
    setIdTouched(originalId !== null);
    setTagsText(entry.tags.join(', '));
  };

  const commitEditor = () => {
    if (!editing) return;
    const draft: AssetEntry = {
      ...editing,
      id: editing.id.trim(),
      match: { kind: editing.match.kind, value: editing.match.value.trim() },
      tags: Array.from(new Set(splitCsv(tagsText))).slice(0, ASSET_MAX_TAGS),
    };
    if (!draft.id || !draft.match.value) {
      onToast('Id and match value are required', 'danger');
      return;
    }
    if (assets.some((entry) => entry.id === draft.id && entry.id !== editingOriginalId)) {
      onToast(`Asset id "${draft.id}" is already used`, 'danger');
      return;
    }
    const exists = editingOriginalId !== null && assets.some((entry) => entry.id === editingOriginalId);
    update(exists ? assets.map((entry) => (entry.id === editingOriginalId ? draft : entry)) : [...assets, draft]);
    setEditing(null);
    setEditingOriginalId(null);
  };

  const move = (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= assets.length) return;
    const next = [...assets];
    [next[index], next[target]] = [next[target], next[index]];
    update(next);
  };

  const save = async () => {
    try {
      setSaving(true);
      const res = await apiService.saveAssetSettings({ assets });
      setAssets(res.assets || []);
      setMeta({ updated_at: res.updated_at, updated_by: res.updated_by });
      setDirty(false);
      onToast('Asset settings saved', 'success', 'Criticality is stamped on alerts as they sync; existing alerts update on their next resync.');
    } catch (e: any) {
      onToast('Failed to save asset settings', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    const name = testName.trim();
    const groups = splitCsv(testGroups);
    const labels = splitCsv(testLabels);
    if (!name && !groups.length && !labels.length) return;
    try {
      setTesting(true);
      const result = await apiService.resolveAsset({ agentName: name || undefined, groups, labels });
      const input = [name, groups.length ? `groups: ${groups.join(', ')}` : '', labels.length ? `labels: ${labels.join(', ')}` : '']
        .filter(Boolean)
        .join(' / ');
      setTestResult({ input, result });
    } catch (e: any) {
      onToast('Test match failed', 'danger', e?.body?.message || e.message);
    } finally {
      setTesting(false);
    }
  };

  if (loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="xl" /></div>;

  const description = (
    <>
      Entries map agents to a business criticality and tags. Every synced alert is stamped with the first matching entry: an exact
      agent name beats a glob, which beats an agent group, which beats a 4.x agent label; inside one kind the entry listed first
      wins. Names and globs are case-insensitive. Agent groups come from Wazuh 5.0 findings directly
      {Number(TARGET_WAZUH_MAJOR) === 5 ? '' : ' and, on Wazuh 4.x, from the Wazuh server API when the wazuhCore plugin is available'}.
      Changing an entry affects alerts on their next sync; it never rewrites history.
    </>
  );

  if (!capabilitiesLoaded || !canAdminister) {
    return (
      <div className="wamSettingsPage wamAssetSettings">
        <SettingsPageHeader title="Asset criticality" description={description} />
        <EuiCallOut
          size="s"
          color={capabilitiesLoaded ? 'warning' : 'primary'}
          iconType="lock"
          title={capabilitiesLoaded ? 'Asset criticality is administered by Wazuh administrators' : 'Checking permissions'}
        >
          {capabilitiesLoaded && <p>{ADMIN_HELP} Analysts still see the criticality badge, filter and automation floors an administrator configured.</p>}
        </EuiCallOut>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="wamSettingsPage wamAssetSettings">
        <SettingsPageHeader title="Asset criticality" description={description} />
        <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load asset settings" data-test-subj="wamAssetLoadError">
          <p>{loadError}</p>
          <EuiButton
            size="s"
            color="danger"
            iconType="refresh"
            data-test-subj="wamAssetRetry"
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
      name: 'Order',
      width: '90px',
      render: (entry: AssetEntry) => {
        const index = assets.indexOf(entry);
        return (
          <EuiFlexGroup gutterSize="none" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="sortUp" aria-label={`Move ${entry.id} up`} disabled={index === 0} onClick={() => move(index, -1)} />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="sortDown" aria-label={`Move ${entry.id} down`} disabled={index === assets.length - 1} onClick={() => move(index, 1)} />
            </EuiFlexItem>
          </EuiFlexGroup>
        );
      },
    },
    { field: 'id', name: 'Id', render: (id: string) => <code data-test-subj={`wamAsset-${id}`}>{id}</code> },
    {
      field: 'match',
      name: 'Match',
      render: (match: AssetEntry['match']) => (
        <span>
          <EuiBadge color="hollow">{match.kind}</EuiBadge> <code>{match.value}</code>
        </span>
      ),
    },
    {
      field: 'criticality',
      name: 'Criticality',
      render: (value: AssetCriticality) => <EuiBadge color={ASSET_CRITICALITY_BADGE_COLOR[value]}>{assetCriticalityLabel(value)}</EuiBadge>,
    },
    {
      field: 'tags',
      name: 'Tags',
      render: (tags: string[]) => (tags || []).map((tag) => <EuiBadge key={tag} color="default">{tag}</EuiBadge>),
    },
    {
      name: 'Actions',
      width: '90px',
      render: (entry: AssetEntry) => (
        <EuiFlexGroup gutterSize="xs" responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButtonIcon iconType="pencil" aria-label={`Edit ${entry.id}`} onClick={() => openEditor(entry, entry.id)} />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonIcon
              iconType="trash"
              color="danger"
              aria-label={`Remove ${entry.id}`}
              data-test-subj={`wamAssetRemove-${entry.id}`}
              onClick={() => update(assets.filter((item) => item.id !== entry.id))}
            />
          </EuiFlexItem>
        </EuiFlexGroup>
      ),
    },
  ];

  return (
    <div className="wamSettingsPage wamAssetSettings" data-test-subj="wamAssetSettings">
      <SettingsPageHeader
        title="Asset criticality"
        description={description}
        actions={
          <EuiButton
            size="s"
            fill
            iconType="plusInCircle"
            disabled={assets.length >= ASSET_MAX_ENTRIES || editing !== null}
            onClick={() => openEditor(newEntry(assets), null)}
            data-test-subj="wamAssetAdd"
          >
            Add asset
          </EuiButton>
        }
      />

      {dirty && (
        <>
          <EuiCallOut size="s" color="warning" iconType="alert" title="Unsaved changes" data-test-subj="wamAssetDirty" />
          <EuiSpacer size="m" />
        </>
      )}

      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamAssetEntriesPanel">
      <EuiTitle size="xs">
        <h4>Entries</h4>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable items={assets} columns={columns} className="wamAssetTable" tableLayout="auto" noItemsMessage="No asset entries yet." />
      <EuiSpacer size="m" />

      <SettingsFormActions
        meta={
          <>
            {assets.length}/{ASSET_MAX_ENTRIES} entries
            {meta.updated_by ? ` · last saved by ${meta.updated_by}` : ''}
          </>
        }
      >
        {dirty ? (
          <EuiButtonEmpty size="s" onClick={() => load()} disabled={saving}>
            Discard
          </EuiButtonEmpty>
        ) : null}
        <EuiButton size="s" fill iconType="save" isLoading={saving} disabled={!dirty || editing !== null} onClick={save} data-test-subj="wamAssetSave">
          Save
        </EuiButton>
      </SettingsFormActions>
      </EuiPanel>

      {editing && (
        <>
          <EuiSpacer size="m" />
          <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamAssetEditor" data-test-subj="wamAssetEditor">
            <EuiForm component="form" onSubmit={(event) => { event.preventDefault(); commitEditor(); }}>
              <EuiFlexGroup gutterSize="m" wrap>
                <EuiFlexItem style={{ minWidth: 200 }}>
                  <EuiFormRow fullWidth label="Id" helpText="Lower-case letters, digits, - and _.">
                    <EuiFieldText fullWidth
                      value={editing.id}
                      onChange={(e) => { setIdTouched(true); setEditing({ ...editing, id: e.target.value.toLowerCase() }); }}
                      data-test-subj="wamAssetEditorId"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 220 }}>
                  <EuiFormRow fullWidth label="Match by">
                    <EuiSelect fullWidth
                      options={KIND_OPTIONS}
                      value={editing.match.kind}
                      onChange={(e) => setEditing({ ...editing, match: { ...editing.match, kind: e.target.value as AssetMatchKind } })}
                      data-test-subj="wamAssetEditorKind"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 220 }}>
                  <EuiFormRow fullWidth label="Value" helpText={editing.match.kind === 'glob' ? 'Only * and ? are wildcards; everything else is literal.' : undefined}>
                    <EuiFieldText fullWidth
                      placeholder={KIND_PLACEHOLDER[editing.match.kind]}
                      value={editing.match.value}
                      onChange={(e) => {
                        const value = e.target.value;
                        // Derive the id from the value only while adding a new entry and the Id field is untouched.
                        const autoId = editingOriginalId === null && !idTouched;
                        setEditing({ ...editing, id: autoId ? suggestId(value, assets) : editing.id, match: { ...editing.match, value } });
                      }}
                      data-test-subj="wamAssetEditorValue"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 160 }}>
                  <EuiFormRow fullWidth label="Criticality">
                    <EuiSelect fullWidth
                      options={CRITICALITY_OPTIONS}
                      value={editing.criticality}
                      onChange={(e) => setEditing({ ...editing, criticality: e.target.value as AssetCriticality })}
                      data-test-subj="wamAssetEditorCriticality"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem style={{ minWidth: 220 }}>
                  <EuiFormRow fullWidth label="Tags" helpText={`Comma separated, at most ${ASSET_MAX_TAGS}.`}>
                    <EuiFieldText fullWidth value={tagsText} onChange={(e) => setTagsText(e.target.value)} placeholder="pci, crown-jewel" data-test-subj="wamAssetEditorTags" />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="s" />
              <SettingsFormActions>
                <EuiButtonEmpty size="s" onClick={() => { setEditing(null); setEditingOriginalId(null); }}>
                  Cancel
                </EuiButtonEmpty>
                <EuiButton size="s" fill type="submit" data-test-subj="wamAssetEditorApply">
                  Apply
                </EuiButton>
              </SettingsFormActions>
            </EuiForm>
          </EuiPanel>
        </>
      )}

      <EuiSpacer size="m" />
      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamAssetTestPanel">
      <EuiTitle size="xs">
        <h4>Test match</h4>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>Runs the saved entries (not unsaved edits) the way the sync job does. Groups and labels are comma separated; labels as key=value.</p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd" wrap>
        <EuiFlexItem style={{ minWidth: 200 }}>
          <EuiFormRow fullWidth label="Agent name" display="rowCompressed">
            <EuiFieldText fullWidth compressed value={testName} onChange={(e) => setTestName(e.target.value)} data-test-subj="wamAssetTestName" />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 200 }}>
          <EuiFormRow fullWidth label="Groups" display="rowCompressed">
            <EuiFieldText fullWidth compressed value={testGroups} onChange={(e) => setTestGroups(e.target.value)} placeholder="default, pci" data-test-subj="wamAssetTestGroups" />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem style={{ minWidth: 200 }}>
          <EuiFormRow fullWidth label="Labels (4.x)" display="rowCompressed">
            <EuiFieldText fullWidth compressed value={testLabels} onChange={(e) => setTestLabels(e.target.value)} placeholder="env=prod" data-test-subj="wamAssetTestLabels" />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiToolTip content={dirty ? 'Save first to test the current list' : undefined}>
            <EuiButton size="s" iconType="play" isLoading={testing} onClick={runTest} data-test-subj="wamAssetTestRun">
              Test match
            </EuiButton>
          </EuiToolTip>
        </EuiFlexItem>
      </EuiFlexGroup>
      {testResult && <ResolveResult result={testResult.result} input={testResult.input} />}
      </EuiPanel>
    </div>
  );
};
