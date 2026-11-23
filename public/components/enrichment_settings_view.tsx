import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCheckboxGroup,
  EuiCode,
  EuiCodeBlock,
  EuiFieldNumber,
  EuiFieldPassword,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiLink,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTextArea,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  CTI_EXPLORER_APP_PATH,
  ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS,
  ENRICHMENT_DEFAULT_TIMEOUT_MS,
  ENRICHMENT_KIND_CAPABILITIES,
  ENRICHMENT_KIND_NEEDS_KEY,
  ENRICHMENT_LOOKUP_TYPES,
  ENRICHMENT_VERDICTS,
  EnrichmentLookupType,
  EnrichmentSourceInput,
  EnrichmentSourceKind,
  EnrichmentTestResponse,
  EnrichmentVerdict,
  TARGET_WAZUH_MAJOR,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ADMIN_HELP =
  'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control enrichment administration.';

const KIND_LABELS: Record<EnrichmentSourceKind, string> = {
  abuseipdb: 'AbuseIPDB',
  misp: 'MISP',
  generic_http: 'Generic HTTP (JSON)',
  wazuh_cti_local: 'Wazuh CTI catalog (local)',
};

// Single source of truth shared with the server validator (common/constants.ts).
const KIND_CAPABILITIES: Record<EnrichmentSourceKind, EnrichmentLookupType[]> = ENRICHMENT_KIND_CAPABILITIES;
const NEEDS_KEY: Record<EnrichmentSourceKind, boolean> = ENRICHMENT_KIND_NEEDS_KEY;

/** The CTI Explorer deep link exists only on 5.0 dashboards; built in the browser so server.basePath is honoured. */
export function ctiExplorerUrl(apiService: Pick<AlertsApiService, 'appUrl'>): string | null {
  return Number(TARGET_WAZUH_MAJOR) === 5 ? apiService.appUrl(CTI_EXPLORER_APP_PATH) : null;
}

const VERDICT_COLORS: Record<EnrichmentVerdict, string> = {
  malicious: 'danger',
  suspicious: 'warning',
  clean: 'success',
  unknown: 'hollow',
};

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'source';
}

function newSource(kind: EnrichmentSourceKind, existing: EnrichmentSourceInput[]): EnrichmentSourceInput {
  const base = slug(KIND_LABELS[kind]);
  let id = base;
  let n = 2;
  while (existing.some((source) => source.id === id)) id = `${base}-${n++}`;
  return {
    id,
    name: KIND_LABELS[kind],
    kind,
    enabled: false,
    supports: [...KIND_CAPABILITIES[kind]],
    cacheTtlSeconds: ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS,
    timeoutMs: ENRICHMENT_DEFAULT_TIMEOUT_MS,
    baseUrl: '',
    urlTemplate: kind === 'generic_http' ? 'https://intel.example.com/api/lookup?type={type}&q={value}' : undefined,
    headers: kind === 'generic_http' ? {} : undefined,
    verdictPath: kind === 'generic_http' ? '/verdict' : undefined,
    scorePath: kind === 'generic_http' ? '' : undefined,
    tagsPath: kind === 'generic_http' ? '' : undefined,
    linkPath: kind === 'generic_http' ? '' : undefined,
    verdictMap: kind === 'generic_http' ? {} : undefined,
    apiKey: '',
  };
}

function headersToText(headers: Record<string, string> | undefined): string {
  return Object.entries(headers || {})
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
}

function textToHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const index = line.indexOf(':');
    if (index <= 0) continue;
    const name = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

function verdictMapToText(map: Record<string, EnrichmentVerdict> | undefined): string {
  return Object.entries(map || {})
    .map(([raw, verdict]) => `${raw}=${verdict}`)
    .join('\n');
}

function textToVerdictMap(text: string): Record<string, EnrichmentVerdict> {
  const out: Record<string, EnrichmentVerdict> = {};
  for (const line of text.split('\n')) {
    const index = line.lastIndexOf('=');
    if (index <= 0) continue;
    const raw = line.slice(0, index).trim();
    const verdict = line.slice(index + 1).trim() as EnrichmentVerdict;
    if (raw && (ENRICHMENT_VERDICTS as readonly string[]).includes(verdict)) out[raw] = verdict;
  }
  return out;
}

/**
 * Strip read-only flags and empty optional strings before a PUT. `apiKey`
 * follows the route contract: '' / absent keeps the stored key, a string
 * replaces it, and `null` (the editor's "Clear saved key") removes it.
 */
export function toPayload(source: EnrichmentSourceInput): EnrichmentSourceInput {
  const { apiKeyConfigured, builtIn, ...rest } = source;
  const out: any = { ...rest };
  for (const key of ['baseUrl', 'urlTemplate', 'verdictPath', 'scorePath', 'tagsPath', 'linkPath']) {
    if (out[key] === '' || out[key] === undefined) delete out[key];
  }
  if (out.headers && Object.keys(out.headers).length === 0) delete out.headers;
  if (out.verdictMap && Object.keys(out.verdictMap).length === 0) delete out.verdictMap;
  if (out.apiKey === '' || out.apiKey === undefined) delete out.apiKey;
  if (out.allowInsecure !== true) delete out.allowInsecure;
  if (source.kind === 'wazuh_cti_local' || source.kind === 'abuseipdb') delete out.baseUrl;
  return out;
}

export const TestResult: React.FC<{ result: EnrichmentTestResponse; appLink?: string | null }> = ({ result, appLink }) => {
  if (result.status === 'error') {
    return (
      <EuiCallOut size="s" color="danger" iconType="alert" title={`${result.sourceName}: test failed`} className="wamEnrichmentTestResult">
        <p>{result.error}</p>
      </EuiCallOut>
    );
  }
  const r = result.result!;
  return (
    <EuiCallOut size="s" color="success" iconType="check" title={`${result.sourceName}: reachable`} className="wamEnrichmentTestResult">
      <EuiText size="s">
        <p>
          Looked up <EuiCode>{result.value}</EuiCode> ({result.type}):{' '}
          <EuiBadge color={VERDICT_COLORS[r.verdict]} className={`wamEnrichmentVerdict--${r.verdict}`}>
            {r.verdict}
          </EuiBadge>
          {r.score !== null && <EuiBadge color="hollow">score {r.score}</EuiBadge>} {r.summary}
          {r.link && (
            <>
              {' '}
              <EuiLink href={r.link} target="_blank" external>
                open
              </EuiLink>
            </>
          )}
          {!r.link && appLink && (
            <>
              {' '}
              <EuiLink href={appLink} target="_blank">
                open CTI Explorer
              </EuiLink>
            </>
          )}
        </p>
      </EuiText>
    </EuiCallOut>
  );
};

export const EnrichmentSettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [loading, setLoading] = useState(true);
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [canAdminister, setCanAdminister] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [encryptionConfigured, setEncryptionConfigured] = useState(true);
  const [egressAllowedHosts, setEgressAllowedHosts] = useState<string[]>([]);
  const [sources, setSources] = useState<EnrichmentSourceInput[]>([]);
  const [savedIds, setSavedIds] = useState<string[]>([]);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editing, setEditing] = useState<EnrichmentSourceInput | null>(null);
  const [addKind, setAddKind] = useState<EnrichmentSourceKind>('abuseipdb');
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, EnrichmentTestResponse>>({});
  const [headersText, setHeadersText] = useState('');
  const [verdictMapText, setVerdictMapText] = useState('');

  const load = async () => {
    try {
      const res = await apiService.fetchEnrichmentSettings();
      setSources(res.sources.map((source) => ({ ...source, apiKey: '' })));
      setSavedIds(res.sources.map((source) => source.id));
      setEncryptionConfigured(res.encryptionConfigured);
      setEgressAllowedHosts(res.egressAllowedHosts || []);
      setLoadError(null);
      setDirty(false);
    } catch (e: any) {
      setLoadError(e?.body?.message || e?.message || 'Failed to load enrichment settings');
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

  const update = (next: EnrichmentSourceInput[]) => {
    setSources(next);
    setDirty(true);
  };

  const openEditor = (source: EnrichmentSourceInput) => {
    // A pending clear (null) or pending new key survives re-opening the editor.
    setEditing({ ...source, apiKey: source.apiKey === undefined ? '' : source.apiKey });
    setHeadersText(headersToText(source.headers));
    setVerdictMapText(verdictMapToText(source.verdictMap));
  };

  const commitEditor = () => {
    if (!editing) return;
    const draft: EnrichmentSourceInput = {
      ...editing,
      headers: editing.kind === 'generic_http' ? textToHeaders(headersText) : undefined,
      verdictMap: editing.kind === 'generic_http' ? textToVerdictMap(verdictMapText) : undefined,
    };
    const exists = sources.some((source) => source.id === draft.id);
    update(exists ? sources.map((source) => (source.id === draft.id ? draft : source)) : [...sources, draft]);
    setEditing(null);
  };

  const save = async () => {
    try {
      setSaving(true);
      const res = await apiService.saveEnrichmentSettings({ sources: sources.map(toPayload) });
      setSources(res.sources.map((source) => ({ ...source, apiKey: '' })));
      setSavedIds(res.sources.map((source) => source.id));
      setEncryptionConfigured(res.encryptionConfigured);
      setDirty(false);
      onToast('Enrichment settings saved', 'success');
    } catch (e: any) {
      onToast('Failed to save enrichment settings', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  const test = async (sourceId: string) => {
    try {
      setTesting(sourceId);
      const res = await apiService.testEnrichmentSource(sourceId);
      setTestResults((prev) => ({ ...prev, [sourceId]: res }));
    } catch (e: any) {
      onToast('Test failed', 'danger', e?.body?.message || e.message);
    } finally {
      setTesting(null);
    }
  };

  const needsKey = useMemo(() => sources.some((source) => NEEDS_KEY[source.kind] || (source.headers && Object.values(source.headers).some((v) => v.includes('{apiKey}')))), [sources]);

  if (loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="xl" /></div>;

  const header = (
    <SettingsPageHeader
      title="Enrichment sources"
      description={
        <>
          Threat-intelligence sources analysts can query for an IP, domain, URL or hash from an alert or case. Verdicts are cached per
          source for the configured time. By default a remote source must be a public HTTPS hostname: the dashboard never follows
          redirects, and refuses <EuiCode>localhost</EuiCode>, IP literals and any host that resolves to a private, loopback or
          link-local address. <EuiCode>WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS</EuiCode> on the wazuh-dashboard service narrows egress:
          once it is set, every source host must be listed, including <EuiCode>api.abuseipdb.com</EuiCode>. Listing a name with a
          local suffix (<EuiCode>.internal</EuiCode>, <EuiCode>.local</EuiCode>, <EuiCode>.home.arpa</EuiCode>) is also the way to
          reach an on-premises receiver on a private network (for example an internal MISP): such a listed name may resolve to a
          private address and may use plain http or a self-signed certificate when the source&apos;s &quot;Insecure transport (lab only)&quot; switch is on. Any other listed host,
          and <EuiCode>localhost</EuiCode> or an IP literal, keeps the public-address rule.
          {egressAllowedHosts.length > 0 ? (
            <>
              {' '}
              Currently allowed hosts: {egressAllowedHosts.map((host) => <EuiCode key={host}>{host}</EuiCode>)}.
            </>
          ) : (
            <> No allowlist is set, so every public HTTPS host is permitted.</>
          )}
        </>
      }
    />
  );

  if (!capabilitiesLoaded || !canAdminister) {
    return (
      <div className="wamSettingsPage wamEnrichmentSettings">
        {header}
        <EuiCallOut
          size="s"
          color={capabilitiesLoaded ? 'warning' : 'primary'}
          iconType="lock"
          title={capabilitiesLoaded ? 'Enrichment sources are administered by Wazuh administrators' : 'Checking permissions'}
        >
          {capabilitiesLoaded && <p>{ADMIN_HELP} Analysts can still run lookups from alerts and cases with the sources an administrator has enabled.</p>}
        </EuiCallOut>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="wamSettingsPage wamEnrichmentSettings">
        {header}
        <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load enrichment settings" data-test-subj="wamEnrichmentLoadError">
          <p>{loadError}</p>
          <EuiButton
            size="s"
            color="danger"
            iconType="refresh"
            data-test-subj="wamEnrichmentRetry"
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
      name: 'Source',
      className: 'wamEnrichmentSourceTable__name',
      render: (name: string, source: EnrichmentSourceInput) => (
        <div className="wamTablePrimary" data-test-subj="wamEnrichmentSourceName">
          <strong title={name}>
            {name}
            {source.builtIn && (
              <>
                {' '}
                <EuiBadge color="hollow">built in</EuiBadge>
              </>
            )}
          </strong>
          <EuiText size="xs" color="subdued" className="wamTableSecondary" title={source.id}>
            <code>{source.id}</code>
          </EuiText>
        </div>
      ),
    },
    { field: 'kind', name: 'Kind', render: (kind: EnrichmentSourceKind) => KIND_LABELS[kind] },
    {
      field: 'supports',
      name: 'Indicators',
      render: (supports: EnrichmentLookupType[] | undefined) => (supports || []).map((type) => <EuiBadge key={type} color="hollow">{type}</EuiBadge>),
    },
    {
      field: 'apiKeyConfigured',
      name: 'Credentials',
      render: (configured: boolean | undefined, source: EnrichmentSourceInput) =>
        source.apiKey === null ? (
          <EuiBadge color="warning">Key cleared (pending save)</EuiBadge>
        ) : source.apiKey ? (
          <EuiBadge color="primary">New key pending save</EuiBadge>
        ) : configured ? (
          <EuiBadge color="success">Configured</EuiBadge>
        ) : NEEDS_KEY[source.kind] ? (
          <EuiBadge color="warning">Not set</EuiBadge>
        ) : (
          <EuiBadge color="hollow">None needed</EuiBadge>
        ),
    },
    {
      field: 'enabled',
      name: 'Enabled',
      render: (enabled: boolean, source: EnrichmentSourceInput) => (
        <EuiSwitch
          label=""
          showLabel={false}
          compressed
          checked={enabled}
          onChange={(e) => update(sources.map((s) => (s.id === source.id ? { ...s, enabled: e.target.checked } : s)))}
          aria-label={`Enable ${source.name}`}
        />
      ),
    },
    {
      name: 'Actions',
      render: (source: EnrichmentSourceInput) => {
        const saved = savedIds.includes(source.id);
        return (
          <EuiFlexGroup gutterSize="xs" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiToolTip content={saved ? 'Look up a benign value through the saved configuration' : 'Save first'}>
                <EuiButtonEmpty size="xs" iconType="play" isLoading={testing === source.id} disabled={!saved || testing !== null} onClick={() => test(source.id)}>
                  Test
                </EuiButtonEmpty>
              </EuiToolTip>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="pencil" aria-label={`Edit ${source.name}`} onClick={() => openEditor(source)} />
            </EuiFlexItem>
            {!source.builtIn && (
              <EuiFlexItem grow={false}>
                <EuiButtonIcon iconType="trash" color="danger" aria-label={`Remove ${source.name}`} onClick={() => update(sources.filter((s) => s.id !== source.id))} />
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
        );
      },
    },
  ];

  const supportsOptions = editing ? KIND_CAPABILITIES[editing.kind].map((type) => ({ id: type, label: type })) : [];
  const supportsSelection: Record<string, boolean> = {};
  for (const type of editing?.supports || []) supportsSelection[type] = true;

  return (
    <div className="wamSettingsPage wamEnrichmentSettings" data-test-subj="wamEnrichmentSettings">
      {header}

      {needsKey && !encryptionConfigured && (
        <>
          <EuiCallOut size="s" title="Encryption key not configured" color="danger" iconType="lock">
            <p>
              Set the <EuiCode>WAZUH_ALERT_MANAGER_ENCRYPTION_KEY</EuiCode> environment variable (32+ characters) for the wazuh-dashboard
              service and restart it before an API key can be saved. Generate one with:
            </p>
            <EuiCodeBlock isCopyable fontSize="s" paddingSize="s">
              openssl rand -base64 32
            </EuiCodeBlock>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}

      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamEnrichmentSourcesPanel">
      <EuiTitle size="xs">
        <h4>Sources</h4>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable className="wamEnrichmentSourceTable" tableLayout="auto" items={sources} columns={columns} rowProps={(source: EnrichmentSourceInput) => ({ 'data-test-subj': `wamEnrichmentSource-${source.id}` })} />
      {Object.values(testResults).map((result) => (
        <TestResult key={result.sourceId} result={result} appLink={result.kind === 'wazuh_cti_local' ? ctiExplorerUrl(apiService) : null} />
      ))}
      <EuiSpacer size="m" />

      <SettingsFormActions
        leading={
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiSelect fullWidth
                compressed
                aria-label="Source kind to add"
                options={(['abuseipdb', 'misp', 'generic_http'] as EnrichmentSourceKind[]).map((kind) => ({ value: kind, text: KIND_LABELS[kind] }))}
                value={addKind}
                onChange={(e) => setAddKind(e.target.value as EnrichmentSourceKind)}
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton size="s" iconType="plusInCircle" onClick={() => openEditor(newSource(addKind, sources))}>
                Add source
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        }
      >
        <EuiButton fill size="s" onClick={save} isLoading={saving} disabled={!dirty || editing !== null} data-test-subj="wamEnrichmentSave">
          Save enrichment settings
        </EuiButton>
      </SettingsFormActions>
      </EuiPanel>

      {editing && (
        <>
          <EuiSpacer size="m" />
          <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamEnrichmentEditor" data-test-subj="wamEnrichmentEditor">
            <EuiTitle size="xs">
              <h4>{sources.some((s) => s.id === editing.id) ? `Edit ${editing.name}` : `New ${KIND_LABELS[editing.kind]} source`}</h4>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiForm>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow fullWidth label="Name">
                    <EuiFieldText fullWidth value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow fullWidth label="Id" helpText="Lower-case letters, digits, - and _. Used in cache keys and lookups.">
                    <EuiFieldText fullWidth
                      value={editing.id}
                      disabled={editing.builtIn || sources.some((s) => s.id === editing.id)}
                      onChange={(e) => setEditing({ ...editing, id: e.target.value.toLowerCase().replace(/\s+/g, '') })}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>

              <EuiFormRow fullWidth label="Enabled">
                <EuiSwitch label={editing.enabled ? 'Enabled' : 'Disabled'} checked={editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />
              </EuiFormRow>

              <EuiFormRow fullWidth label="Indicator types">
                <EuiCheckboxGroup
                  options={supportsOptions}
                  idToSelectedMap={supportsSelection}
                  onChange={(id) => {
                    const current = new Set(editing.supports || []);
                    if (current.has(id as EnrichmentLookupType)) current.delete(id as EnrichmentLookupType);
                    else current.add(id as EnrichmentLookupType);
                    setEditing({ ...editing, supports: KIND_CAPABILITIES[editing.kind].filter((t) => current.has(t)) });
                  }}
                />
              </EuiFormRow>

              {editing.kind === 'misp' && (
                <EuiFormRow fullWidth
                  label="MISP base URL"
                  helpText="Public HTTPS hostname by default (no localhost, no IP literals, no host resolving to a private address). An on-premises MISP on a private network is reachable only under a local-suffix name (.internal, .local, .home.arpa) listed in WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS; plain http or a self-signed certificate additionally needs the 'Insecure transport (lab only)' switch. POST /attributes/restSearch is called with the API key as Authorization."
                >
                  <EuiFieldText fullWidth value={editing.baseUrl || ''} onChange={(e) => setEditing({ ...editing, baseUrl: e.target.value })} placeholder="https://misp.example.org" />
                </EuiFormRow>
              )}

              {editing.kind === 'abuseipdb' && (
                <EuiText size="xs" color="subdued">
                  <p>Calls https://api.abuseipdb.com/api/v2/check (last 90 days). Abuse confidence 75+ is malicious, 25+ suspicious.</p>
                </EuiText>
              )}

              {editing.kind === 'wazuh_cti_local' && (
                <EuiText size="xs" color="subdued">
                  <p>
                    Reads the local Wazuh 5.0 CTI catalog (<EuiCode>wazuh-threatintel-enrichments*</EuiCode>) as the signed-in user; the
                    CTI API is never called. Users need read access to that index (install.sh maps the native-read role). A miss means
                    &quot;not in the catalog&quot;, not &quot;clean&quot;.
                  </p>
                </EuiText>
              )}

              {editing.kind === 'generic_http' && (
                <>
                  <EuiFormRow fullWidth label="URL template" helpText="GET request; {value} and {type} are URL-encoded. Placeholders are allowed in the path and query only.">
                    <EuiFieldText fullWidth value={editing.urlTemplate || ''} onChange={(e) => setEditing({ ...editing, urlTemplate: e.target.value })} />
                  </EuiFormRow>
                  <EuiFormRow fullWidth label="Headers" helpText="One per line, Name: value. A value may contain {apiKey} to insert the stored API key.">
                    <EuiTextArea fullWidth rows={3} value={headersText} onChange={(e) => setHeadersText(e.target.value)} placeholder={'Authorization: Bearer {apiKey}'} />
                  </EuiFormRow>
                  <EuiFlexGroup>
                    <EuiFlexItem>
                      <EuiFormRow fullWidth label="Verdict pointer" helpText="RFC 6901, e.g. /data/verdict">
                        <EuiFieldText fullWidth value={editing.verdictPath || ''} onChange={(e) => setEditing({ ...editing, verdictPath: e.target.value })} />
                      </EuiFormRow>
                    </EuiFlexItem>
                    <EuiFlexItem>
                      <EuiFormRow fullWidth label="Score pointer" helpText="0-100; decides the verdict when no verdict pointer matches">
                        <EuiFieldText fullWidth value={editing.scorePath || ''} onChange={(e) => setEditing({ ...editing, scorePath: e.target.value })} />
                      </EuiFormRow>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                  <EuiFlexGroup>
                    <EuiFlexItem>
                      <EuiFormRow fullWidth label="Tags pointer" helpText="Array of strings">
                        <EuiFieldText fullWidth value={editing.tagsPath || ''} onChange={(e) => setEditing({ ...editing, tagsPath: e.target.value })} />
                      </EuiFormRow>
                    </EuiFlexItem>
                    <EuiFlexItem>
                      <EuiFormRow fullWidth label="Link pointer" helpText="http(s) URL to show analysts">
                        <EuiFieldText fullWidth value={editing.linkPath || ''} onChange={(e) => setEditing({ ...editing, linkPath: e.target.value })} />
                      </EuiFormRow>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                  <EuiFormRow fullWidth label="Verdict map" helpText={`One per line, rawValue=verdict (${ENRICHMENT_VERDICTS.join(' | ')}).`}>
                    <EuiTextArea fullWidth rows={3} value={verdictMapText} onChange={(e) => setVerdictMapText(e.target.value)} placeholder={'bad=malicious\nmaybe=suspicious\ngood=clean'} />
                  </EuiFormRow>
                </>
              )}

              {(editing.kind === 'misp' || editing.kind === 'generic_http') && (
                <EuiFormRow fullWidth
                  label="Insecure transport (lab only)"
                  helpText="Only honoured for hosts listed in WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS on the dashboard service: plain HTTP for any listed host, and a self-signed certificate only for a listed local-suffix name (.internal, .local, .home.arpa, e.g. a lab MISP at https://misp.internal). Every other target must use verified HTTPS."
                >
                  <EuiSwitch
                    label={editing.allowInsecure ? 'Allow plain HTTP / self-signed certificate (lab only)' : 'Verified HTTPS only'}
                    checked={editing.allowInsecure === true}
                    onChange={(e) => setEditing({ ...editing, allowInsecure: e.target.checked })}
                    data-test-subj="wamEnrichmentAllowInsecure"
                  />
                </EuiFormRow>
              )}

              {editing.kind !== 'wazuh_cti_local' && (
                <EuiFormRow fullWidth
                  label="API key"
                  labelAppend={
                    editing.apiKey === null ? (
                      <EuiBadge color="warning">Will be cleared</EuiBadge>
                    ) : editing.apiKeyConfigured ? (
                      <EuiBadge color="success">Configured</EuiBadge>
                    ) : (
                      <EuiBadge color="hollow">Not set</EuiBadge>
                    )
                  }
                  helpText={
                    editing.apiKey === null
                      ? 'The saved key is removed when you save. Paste a new key to replace it instead.'
                      : editing.apiKeyConfigured
                      ? 'Leave blank to keep the currently saved key.'
                      : NEEDS_KEY[editing.kind]
                      ? 'Encrypted at rest; never sent back to the browser.'
                      : 'Optional; only used where a header contains {apiKey}.'
                  }
                >
                  <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
                    <EuiFlexItem>
                      <EuiFieldPassword fullWidth
                        type="dual"
                        value={editing.apiKey || ''}
                        onChange={(e) => setEditing({ ...editing, apiKey: e.target.value })}
                        placeholder={editing.apiKey === null ? 'Saved key will be cleared' : editing.apiKeyConfigured ? '••••••••••••' : 'Paste the API key'}
                      />
                    </EuiFlexItem>
                    {editing.apiKeyConfigured && (
                      <EuiFlexItem grow={false}>
                        {editing.apiKey === null ? (
                          <EuiButtonEmpty size="xs" onClick={() => setEditing({ ...editing, apiKey: '' })} data-test-subj="wamEnrichmentKeepKey">
                            Keep saved key
                          </EuiButtonEmpty>
                        ) : (
                          <EuiButtonEmpty size="xs" color="danger" iconType="cross" onClick={() => setEditing({ ...editing, apiKey: null })} data-test-subj="wamEnrichmentClearKey">
                            Clear saved key
                          </EuiButtonEmpty>
                        )}
                      </EuiFlexItem>
                    )}
                  </EuiFlexGroup>
                </EuiFormRow>
              )}

              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow fullWidth label="Cache verdicts for (seconds)" helpText="60 s to 30 days">
                    <EuiFieldNumber fullWidth value={editing.cacheTtlSeconds ?? ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS} min={60} onChange={(e) => setEditing({ ...editing, cacheTtlSeconds: Number(e.target.value) })} />
                  </EuiFormRow>
                </EuiFlexItem>
                {editing.kind !== 'wazuh_cti_local' && (
                  <EuiFlexItem>
                    <EuiFormRow fullWidth label="Timeout (ms)" helpText="1000 to 30000">
                      <EuiFieldNumber fullWidth value={editing.timeoutMs ?? ENRICHMENT_DEFAULT_TIMEOUT_MS} min={1000} max={30000} onChange={(e) => setEditing({ ...editing, timeoutMs: Number(e.target.value) })} />
                    </EuiFormRow>
                  </EuiFlexItem>
                )}
              </EuiFlexGroup>

              <EuiSpacer size="s" />
              <SettingsFormActions>
                <EuiButtonEmpty size="s" onClick={() => setEditing(null)}>
                  Cancel
                </EuiButtonEmpty>
                <EuiButton size="s" fill onClick={commitEditor} data-test-subj="wamEnrichmentApply">
                  Apply
                </EuiButton>
              </SettingsFormActions>
            </EuiForm>
          </EuiPanel>
        </>
      )}
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>Changes apply after &quot;Save enrichment settings&quot;. Lookup types available: {ENRICHMENT_LOOKUP_TYPES.join(', ')}.</p>
      </EuiText>
    </div>
  );
};
