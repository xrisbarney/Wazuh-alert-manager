import React, { useEffect, useState } from 'react';
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
  EuiComboBox,
  EuiFieldPassword,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
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
  IndexerChannelSummary,
  IndexerChannelWarning,
  IndexerChannelsResponse,
  NOTIFICATIONS_CHANNELS_APP_PATH,
  NOTIFICATION_CHANNEL_ID_PATTERN,
  NOTIFICATION_CHANNEL_KINDS,
  NOTIFICATION_EVENTS,
  NOTIFICATION_MAX_CHANNELS,
  NOTIFICATION_MAX_WEBHOOK_HEADERS,
  NotificationChannelInput,
  NotificationChannelKind,
  NotificationEvent,
  NotificationTestResponse,
  TARGET_WAZUH_MAJOR,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { NotificationOutboxPanel } from './notification_outbox_panel';
import { SettingsFormActions, SettingsPageHeader } from './settings_page';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

const ADMIN_HELP =
  'Your effective Wazuh authorization does not include all_access. OpenSearch Security roles, not SSO/LDAP group names, control notification administration.';

export const KIND_LABELS: Record<NotificationChannelKind, string> = {
  indexer_channel: 'Notifications channel (Slack, Teams, email, webhook, SNS, chime)',
  webhook: 'Direct webhook (signed JSON)',
};

export const KIND_SHORT: Record<NotificationChannelKind, string> = {
  indexer_channel: 'Notifications channel',
  webhook: 'Direct webhook',
};

export const EVENT_LABELS: Record<NotificationEvent, string> = {
  'case.created': 'Case created',
  'case.assigned': 'Case assigned',
  'case.severity_raised': 'Case severity raised',
  'case.closed': 'Case closed',
  'sla.breached': 'SLA breached',
  'sla.escalated': 'SLA escalated',
  'rule.action': 'Automation rule notify action',
  'report.scheduled': 'Scheduled report',
};

/** Human text for a channel warning; the 5.0 placeholder hint is only rendered on a 5.0 build (see `visibleWarnings`). */
export const WARNING_TEXT: Record<IndexerChannelWarning, string> = {
  missing_json_content_type:
    'This webhook channel sets header_params without "Content-Type: application/json", so the indexer delivers text/plain. Add the header in the Notifications app.',
  disabled_placeholder: 'Wazuh 5.0 placeholder channel: it is disabled and carries a placeholder URL. Configure and enable it in the Notifications app before binding it.',
};

/** Warnings a build may show: the placeholder hint exists on 5.0 only, whatever the server sent. */
export function visibleWarnings(warnings: IndexerChannelWarning[] | undefined, wazuhMajor: number): IndexerChannelWarning[] {
  return (warnings || []).filter((warning) => warning !== 'disabled_placeholder' || wazuhMajor === 5);
}

export function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'channel';
}

export function suggestChannelId(name: string, existing: Array<{ id: string }>): string {
  const base = slug(name);
  let id = base;
  let n = 2;
  while (existing.some((channel) => channel.id === id)) id = `${base}-${n++}`.slice(0, 64);
  return id;
}

/**
 * Client-side check of the editor's id field (the server repeats it on PUT):
 * the pattern, and, for a new channel, a collision with a listed id, which
 * would otherwise produce two rows sharing one id until the save is refused.
 */
export function channelIdError(id: string, existing: Array<{ id: string }>, isNew: boolean): string | null {
  if (!NOTIFICATION_CHANNEL_ID_PATTERN.test(id)) return 'Use 1-64 lower-case letters, digits, "-" or "_", starting with a letter or digit.';
  if (isNew && existing.some((channel) => channel.id === id)) return `A channel with id "${id}" already exists.`;
  return null;
}

export function newChannel(kind: NotificationChannelKind, existing: NotificationChannelInput[]): NotificationChannelInput {
  const name = kind === 'webhook' ? 'Direct webhook' : 'Notifications channel';
  const channel: NotificationChannelInput = { id: suggestChannelId(name, existing), name, kind, enabled: true, events: [] };
  if (kind === 'indexer_channel') channel.indexer_channel = { configId: '' };
  else channel.webhook = { url: '', headers: {}, contentType: 'application/json', secret: '' };
  return channel;
}

export function headersToText(headers: Record<string, string> | undefined): string {
  return Object.entries(headers || {})
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
}

export function textToHeaders(text: string): Record<string, string> {
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

/**
 * Strip read-only flags and the other kind's block before a PUT. `webhook.secret`
 * follows the route contract: '' / absent keeps the stored secret, a string
 * replaces it, and `null` (the editor's "Clear saved secret") removes it.
 */
export function toPayload(channel: NotificationChannelInput): NotificationChannelInput {
  const out: NotificationChannelInput = { id: channel.id, name: channel.name, kind: channel.kind, enabled: channel.enabled, events: [...(channel.events || [])] };
  if (channel.kind === 'indexer_channel') {
    out.indexer_channel = { configId: channel.indexer_channel?.configId || '' };
  } else {
    const webhook: any = { url: channel.webhook?.url || '', contentType: 'application/json' };
    const headers = channel.webhook?.headers || {};
    if (Object.keys(headers).length > 0) webhook.headers = headers;
    if (channel.webhook?.allowInsecure === true) webhook.allowInsecure = true;
    if (channel.webhook?.secret === null) webhook.secret = null;
    else if (channel.webhook?.secret) webhook.secret = channel.webhook.secret;
    out.webhook = webhook;
  }
  return out;
}

export function describeTest(result: NotificationTestResponse): { color: 'success' | 'danger'; text: string } {
  if (result.ok) return { color: 'success', text: `Delivered${result.statusCode !== null ? ` (HTTP ${result.statusCode})` : ''} in ${result.durationMs} ms` };
  return { color: 'danger', text: `Failed${result.statusCode !== null ? ` (${result.statusCode})` : ''}: ${result.error || 'unknown error'}` };
}

type ChannelOption = { label: string; value: string; channel: IndexerChannelSummary };

export const NotificationSettingsView: React.FC<Props> = ({ apiService, onToast }) => {
  const [loading, setLoading] = useState(true);
  const [capabilitiesLoaded, setCapabilitiesLoaded] = useState(false);
  const [canAdminister, setCanAdminister] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [channels, setChannels] = useState<NotificationChannelInput[]>([]);
  const [savedIds, setSavedIds] = useState<string[]>([]);
  const [encryptionConfigured, setEncryptionConfigured] = useState(true);
  const [egressAllowedHosts, setEgressAllowedHosts] = useState<string[]>([]);
  const [wazuhMajor, setWazuhMajor] = useState<number>(Number(TARGET_WAZUH_MAJOR));
  const [updatedBy, setUpdatedBy] = useState<string | undefined>(undefined);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editing, setEditing] = useState<NotificationChannelInput | null>(null);
  const [editingIsNew, setEditingIsNew] = useState(false);
  const [headersText, setHeadersText] = useState('');
  const [addKind, setAddKind] = useState<NotificationChannelKind>('indexer_channel');
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, NotificationTestResponse>>({});
  const [indexerChannels, setIndexerChannels] = useState<IndexerChannelsResponse | null>(null);
  const [indexerLoading, setIndexerLoading] = useState(false);

  const applyResponse = (res: any) => {
    setEnabled(res.enabled === true);
    setChannels((res.channels || []).map((channel: NotificationChannelInput) => (channel.kind === 'webhook' ? { ...channel, webhook: { ...channel.webhook!, secret: '' } } : channel)));
    setSavedIds((res.channels || []).map((channel: NotificationChannelInput) => channel.id));
    setEncryptionConfigured(res.encryptionConfigured !== false);
    setEgressAllowedHosts(res.egressAllowedHosts || []);
    if (typeof res.wazuhMajor === 'number') setWazuhMajor(res.wazuhMajor);
    setUpdatedBy(res.updated_by);
    setDirty(false);
  };

  const load = async () => {
    try {
      applyResponse(await apiService.fetchNotificationSettings());
      setLoadError(null);
    } catch (e: any) {
      setLoadError(e?.body?.message || e?.message || 'Failed to load notification settings');
    }
  };

  const loadIndexerChannels = async () => {
    setIndexerLoading(true);
    try {
      setIndexerChannels(await apiService.fetchIndexerChannels());
    } catch (e: any) {
      // The route never answers an error for an access problem; a transport failure is shown inline.
      setIndexerChannels({ channels: [], access: 'unavailable', message: e?.body?.message || e?.message || 'Could not list Notifications channels' });
    } finally {
      setIndexerLoading(false);
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

  const update = (next: NotificationChannelInput[]) => {
    setChannels(next);
    setDirty(true);
  };

  const openEditor = (channel: NotificationChannelInput, isNew: boolean) => {
    setEditing(channel.kind === 'webhook' ? { ...channel, webhook: { ...channel.webhook!, secret: channel.webhook?.secret === undefined ? '' : channel.webhook.secret } } : { ...channel });
    setEditingIsNew(isNew);
    setHeadersText(headersToText(channel.webhook?.headers));
    if (channel.kind === 'indexer_channel' && indexerChannels === null) loadIndexerChannels();
  };

  const commitEditor = () => {
    if (!editing || channelIdError(editing.id, channels, editingIsNew)) return;
    const draft: NotificationChannelInput = editing.kind === 'webhook' ? { ...editing, webhook: { ...editing.webhook!, headers: textToHeaders(headersText) } } : editing;
    // `invalid` is a read-only server flag; an edit is the repair, so drop it.
    delete draft.invalid;
    const exists = channels.some((channel) => channel.id === draft.id);
    update(exists && !editingIsNew ? channels.map((channel) => (channel.id === draft.id ? draft : channel)) : [...channels, draft]);
    setEditing(null);
  };

  const save = async () => {
    try {
      setSaving(true);
      applyResponse(await apiService.saveNotificationSettings({ enabled, channels: channels.map(toPayload) }));
      setTestResults({});
      onToast('Notification settings saved', 'success');
    } catch (e: any) {
      onToast('Failed to save notification settings', 'danger', e?.body?.message || e.message);
    } finally {
      setSaving(false);
    }
  };

  const test = async (channelId: string) => {
    try {
      setTesting(channelId);
      const res = await apiService.testNotificationChannel(channelId);
      setTestResults((prev) => ({ ...prev, [channelId]: res }));
    } catch (e: any) {
      onToast('Test failed', 'danger', e?.body?.message || e.message);
    } finally {
      setTesting(null);
    }
  };

  const channelsAppUrl = apiService.appUrl(NOTIFICATIONS_CHANNELS_APP_PATH);

  if (loading) return <div className="wamSettingsLoading"><EuiLoadingSpinner size="xl" /></div>;

  // The delivery outbox (step 1.2) is visible to every signed-in user, under
  // whichever branch the settings render in; the Retry action is admin-only.
  const outbox = (
    <>
      <EuiSpacer size="m" />
      <NotificationOutboxPanel apiService={apiService} isAdmin={capabilitiesLoaded && canAdminister} onToast={onToast} />
    </>
  );

  const header = (
    <SettingsPageHeader
      title="Notifications"
      description="Bind case, SLA, automation and report events to Notifications channels or signed direct webhooks."
    />
  );

  const deliveryHelp = (
    <EuiText size="s" color="subdued" className="wamNotifDeliveryHelp" data-test-subj="wamNotifDeliveryHelp">
      <p>
        A <strong>Notifications channel</strong> reuses a channel
        of the indexer Notifications plugin (Slack, Microsoft Teams, chime, email, SNS or a webhook, created in the{' '}
        <EuiLink href={channelsAppUrl} target="_blank">
          Notifications app
        </EuiLink>
        ) and is delivered through an on-demand Alerting execution. A <strong>direct webhook</strong> is a signed JSON POST from the
        dashboard server (<EuiCode>x-wam-signature</EuiCode> = HMAC-SHA256 of <EuiCode>&lt;timestamp&gt;.&lt;body&gt;</EuiCode>) for
        receivers that need a signature, sub-minute delivery or a private network reachable only from the dashboard. Receivers of a
        direct webhook must be public HTTPS hostnames unless listed in <EuiCode>WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS</EuiCode>
        {egressAllowedHosts.length > 0 ? (
          <>
            {' '}
            (currently: {egressAllowedHosts.map((host) => <EuiCode key={host}>{host}</EuiCode>)})
          </>
        ) : null}
        .
        {wazuhMajor === 5 && (
          <>
            {' '}
            On Wazuh 5.0 the indexer refuses private receivers for Notifications channels by default (<EuiCode>host_deny_list</EuiCode>);
            use a direct webhook for those or override the list on the indexer.
          </>
        )}
      </p>
    </EuiText>
  );

  if (!capabilitiesLoaded || !canAdminister) {
    return (
      <div className="wamSettingsPage wamNotifSettings">
        {header}
        <EuiCallOut
          size="s"
          color={capabilitiesLoaded ? 'warning' : 'primary'}
          iconType="lock"
          title={capabilitiesLoaded ? 'Notification channels are administered by Wazuh administrators' : 'Checking permissions'}
        >
          {capabilitiesLoaded && (
            <>
              <p>{ADMIN_HELP}</p>
              {!loadError && (
                <p data-test-subj="wamNotifReadOnly">
                  {enabled ? 'Notifications are enabled.' : 'Notifications are disabled.'}{' '}
                  {channels.length === 0
                    ? 'No channels are configured.'
                    : `Configured channels: ${channels.map((channel) => `${channel.name} (${KIND_SHORT[channel.kind]}${channel.enabled ? '' : ', off'})`).join(', ')}.`}
                </p>
              )}
            </>
          )}
        </EuiCallOut>
        {outbox}
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="wamSettingsPage wamNotifSettings">
        {header}
        <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load notification settings" data-test-subj="wamNotifLoadError">
          <p>{loadError}</p>
          <EuiButton
            size="s"
            color="danger"
            iconType="refresh"
            data-test-subj="wamNotifRetry"
            onClick={() => {
              setLoading(true);
              load().finally(() => setLoading(false));
            }}
          >
            Retry
          </EuiButton>
        </EuiCallOut>
        {outbox}
      </div>
    );
  }

  const columns: any[] = [
    {
      field: 'name',
      name: 'Channel',
      render: (name: string, channel: NotificationChannelInput) => (
        <span>
          {name} <code>{channel.id}</code>
        </span>
      ),
    },
    {
      field: 'kind',
      name: 'Kind',
      render: (kind: NotificationChannelKind, channel: NotificationChannelInput) => (
        <span>
          {KIND_SHORT[kind]}
          {kind === 'indexer_channel' && channel.indexer_channel?.configId && (
            <>
              {' '}
              <code>{channel.indexer_channel.configId}</code>
            </>
          )}
          {kind === 'webhook' && (
            <>
              {channel.invalid && (
                <>
                  {' '}
                  <EuiToolTip content={channel.invalid}>
                    <EuiBadge color="danger" iconType="alert" data-test-subj={`wamNotifInvalid-${channel.id}`}>
                      Blocked by egress policy
                    </EuiBadge>
                  </EuiToolTip>
                </>
              )}
              {' '}
              {channel.webhook?.secret === null ? (
                <EuiBadge color="warning">Secret cleared (pending save)</EuiBadge>
              ) : channel.webhook?.secret ? (
                <EuiBadge color="primary">New secret pending save</EuiBadge>
              ) : channel.webhook?.secretConfigured ? (
                <EuiBadge color="success">Signed</EuiBadge>
              ) : (
                <EuiBadge color="warning">Unsigned</EuiBadge>
              )}
            </>
          )}
        </span>
      ),
    },
    {
      field: 'events',
      name: 'Events',
      render: (events: NotificationEvent[] | undefined) =>
        (events || []).length === 0 ? (
          <EuiText size="xs" color="subdued">
            none
          </EuiText>
        ) : (
          <span className="wamNotifEvents">
            {(events || []).map((event) => (
              <EuiBadge key={event} color="hollow">
                {event}
              </EuiBadge>
            ))}
          </span>
        ),
    },
    {
      field: 'enabled',
      name: 'Enabled',
      render: (isEnabled: boolean, channel: NotificationChannelInput) => (
        <EuiSwitch
          label=""
          showLabel={false}
          compressed
          checked={isEnabled}
          onChange={(e) => update(channels.map((c) => (c.id === channel.id ? { ...c, enabled: e.target.checked } : c)))}
          aria-label={`Enable ${channel.name}`}
        />
      ),
    },
    {
      name: 'Actions',
      render: (channel: NotificationChannelInput) => {
        const saved = savedIds.includes(channel.id);
        const result = testResults[channel.id];
        return (
          <EuiFlexGroup gutterSize="xs" responsive={false} alignItems="center">
            <EuiFlexItem grow={false}>
              <EuiToolTip content={saved ? 'Send a fixed test notification through the saved channel as yourself' : 'Save first'}>
                <EuiButtonEmpty
                  size="xs"
                  iconType="play"
                  isLoading={testing === channel.id}
                  disabled={!saved || testing !== null || dirty}
                  onClick={() => test(channel.id)}
                  data-test-subj={`wamNotifTest-${channel.id}`}
                >
                  Test
                </EuiButtonEmpty>
              </EuiToolTip>
            </EuiFlexItem>
            {result && (
              <EuiFlexItem grow={false}>
                <EuiToolTip content={describeTest(result).text}>
                  <EuiBadge color={describeTest(result).color} data-test-subj={`wamNotifTestResult-${channel.id}`}>
                    {result.ok ? 'Delivered' : 'Failed'}
                  </EuiBadge>
                </EuiToolTip>
              </EuiFlexItem>
            )}
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="pencil" aria-label={`Edit ${channel.name}`} onClick={() => openEditor(channel, false)} />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonIcon iconType="trash" color="danger" aria-label={`Remove ${channel.name}`} onClick={() => update(channels.filter((c) => c.id !== channel.id))} />
            </EuiFlexItem>
          </EuiFlexGroup>
        );
      },
    },
  ];

  const eventOptions = NOTIFICATION_EVENTS.map((event) => ({ id: event, label: `${EVENT_LABELS[event]} (${event})` }));
  const eventSelection: Record<string, boolean> = {};
  for (const event of editing?.events || []) eventSelection[event] = true;

  const pickerOptions: ChannelOption[] = (indexerChannels?.channels || []).map((channel) => ({
    label: `${channel.name} (${channel.type}${channel.isEnabled ? '' : ', disabled'})`,
    value: channel.configId,
    channel,
  }));
  const selectedConfigId = editing?.indexer_channel?.configId || '';
  const selectedOption = pickerOptions.find((option) => option.value === selectedConfigId);
  const selectedWarnings = visibleWarnings(selectedOption?.channel.warnings, wazuhMajor);
  const hasWebhookChannels = channels.some((channel) => channel.kind === 'webhook');
  const failedTests = Object.values(testResults).filter((result) => !result.ok);
  const invalidChannels = channels.filter((channel) => channel.invalid);
  const editingIdError = editing ? channelIdError(editing.id, channels, editingIsNew) : null;

  return (
    <div className="wamSettingsPage wamNotifSettings" data-test-subj="wamNotifSettings">
      {header}

      {hasWebhookChannels && !encryptionConfigured && (
        <>
          <EuiCallOut size="s" title="Encryption key not configured" color="danger" iconType="lock">
            <p>
              Set the <EuiCode>WAZUH_ALERT_MANAGER_ENCRYPTION_KEY</EuiCode> environment variable (32+ characters) for the wazuh-dashboard
              service and restart it before a webhook secret can be saved or used. Generate one with:
            </p>
            <EuiCodeBlock isCopyable fontSize="s" paddingSize="s">
              openssl rand -base64 32
            </EuiCodeBlock>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}

      <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamNotifChannelsPanel">
      <EuiTitle size="xs">
        <h4>Channels</h4>
      </EuiTitle>
      <EuiSpacer size="s" />
      {deliveryHelp}
      <EuiSpacer size="m" />
      <EuiFormRow label="Delivery" fullWidth hasChildLabel={false}>
        <EuiSwitch
          label={enabled ? 'Notifications enabled' : 'Notifications disabled (bindings are kept, nothing is sent)'}
          checked={enabled}
          onChange={(e) => {
            setEnabled(e.target.checked);
            setDirty(true);
          }}
          data-test-subj="wamNotifEnabled"
        />
      </EuiFormRow>
      <EuiSpacer size="m" />

      <EuiBasicTable
        className="wamNotifChannelTable"
        items={channels}
        columns={columns}
        rowProps={(channel: NotificationChannelInput) => ({ 'data-test-subj': `wamNotifChannel-${channel.id}` })}
        noItemsMessage="No channels yet. Add a Notifications channel or a direct webhook."
      />
      {invalidChannels.map((channel) => (
        <EuiCallOut key={channel.id} size="s" color="danger" iconType="alert" title={`${channel.id}: disabled by the server`} className="wamNotifTestResult" data-test-subj={`wamNotifInvalidCallout-${channel.id}`}>
          <p>
            {channel.invalid} Edit the receiver URL or remove the channel; the settings cannot be saved until it passes the current{' '}
            <EuiCode>WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS</EuiCode> policy.
          </p>
        </EuiCallOut>
      ))}
      {failedTests.map((result) => (
        <EuiCallOut key={result.channelId} size="s" color="danger" iconType="alert" title={`${result.channelId}: test failed`} className="wamNotifTestResult">
          <p>{describeTest(result).text}</p>
        </EuiCallOut>
      ))}
      <EuiSpacer size="m" />

      <SettingsFormActions
        leading={
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiSelect fullWidth
                compressed
                aria-label="Channel kind to add"
                options={NOTIFICATION_CHANNEL_KINDS.map((kind) => ({ value: kind, text: KIND_LABELS[kind] }))}
                value={addKind}
                onChange={(e) => setAddKind(e.target.value as NotificationChannelKind)}
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton size="s" iconType="plusInCircle" disabled={channels.length >= NOTIFICATION_MAX_CHANNELS} onClick={() => openEditor(newChannel(addKind, channels), true)} data-test-subj="wamNotifAdd">
                Add channel
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        }
        meta={updatedBy ? <>Last saved by {updatedBy}</> : undefined}
      >
        {dirty ? (
          <EuiBadge color="warning" data-test-subj="wamNotifDirty">
            Unsaved changes
          </EuiBadge>
        ) : null}
        <EuiButtonEmpty size="s" disabled={!dirty || saving} onClick={() => load()}>
          Discard
        </EuiButtonEmpty>
        <EuiButton fill size="s" onClick={save} isLoading={saving} disabled={!dirty || editing !== null} data-test-subj="wamNotifSave">
          Save notification settings
        </EuiButton>
      </SettingsFormActions>
      </EuiPanel>

      {editing && (
        <EuiFlyout onClose={() => setEditing(null)} size="m" ownFocus={false} className="wamNotifFlyout" data-test-subj="wamNotifFlyout">
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size="s">
              <h3>{editingIsNew ? `New ${KIND_SHORT[editing.kind].toLowerCase()}` : `Edit ${editing.name}`}</h3>
            </EuiTitle>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <EuiForm>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow fullWidth label="Name">
                    <EuiFieldText fullWidth
                      value={editing.name}
                      onChange={(e) => setEditing({ ...editing, name: e.target.value, id: editingIsNew ? suggestChannelId(e.target.value, channels) : editing.id })}
                      data-test-subj="wamNotifName"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow fullWidth
                    label="Id"
                    helpText="Lower-case letters, digits, - and _. Referenced by automation rules and SLA escalations."
                    isInvalid={Boolean(editingIdError)}
                    error={editingIdError || undefined}
                  >
                    <EuiFieldText fullWidth
                      value={editing.id}
                      disabled={!editingIsNew}
                      isInvalid={Boolean(editingIdError)}
                      onChange={(e) => setEditing({ ...editing, id: e.target.value.toLowerCase().replace(/\s+/g, '') })}
                      data-test-subj="wamNotifId"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>

              <EuiFormRow fullWidth label="Kind">
                <EuiSelect fullWidth
                  options={NOTIFICATION_CHANNEL_KINDS.map((kind) => ({ value: kind, text: KIND_LABELS[kind] }))}
                  value={editing.kind}
                  disabled={!editingIsNew}
                  onChange={(e) => {
                    const kind = e.target.value as NotificationChannelKind;
                    const base = newChannel(kind, channels);
                    setEditing({ ...base, id: editing.id, name: editing.name, enabled: editing.enabled, events: editing.events });
                    if (kind === 'indexer_channel' && indexerChannels === null) loadIndexerChannels();
                  }}
                  data-test-subj="wamNotifKind"
                />
              </EuiFormRow>

              <EuiFormRow fullWidth label="Enabled">
                <EuiSwitch label={editing.enabled ? 'Enabled' : 'Disabled'} checked={editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />
              </EuiFormRow>

              {editing.kind === 'indexer_channel' && (
                <EuiFormRow fullWidth
                  label="Notifications channel"
                  helpText={
                    selectedWarnings.length > 0
                      ? selectedWarnings.map((warning) => WARNING_TEXT[warning]).join(' ')
                      : 'Channels of the indexer Notifications plugin visible to you (needs notifications_read_access). Delivery goes through an on-demand Alerting execution as the dashboard service user.'
                  }
                  isInvalid={selectedWarnings.length > 0}
                >
                  <div>
                    {indexerLoading ? (
                      <EuiLoadingSpinner size="m" />
                    ) : indexerChannels && indexerChannels.access !== 'ok' ? (
                      <EuiCallOut size="s" color="warning" iconType="iInCircle" title={indexerChannels.access === 'forbidden' ? 'Cannot list Notifications channels' : 'Notifications plugin unavailable'} data-test-subj="wamNotifPickerEmpty">
                        <p>
                          {indexerChannels.access === 'forbidden'
                            ? 'Your account lacks the notifications_read_access role, so the channel list is empty. Ask an administrator for the role, or paste the channel id below.'
                            : indexerChannels.message || 'The Notifications plugin is not available on this indexer.'}{' '}
                          <EuiLink href={channelsAppUrl} target="_blank">
                            Open the Notifications app
                          </EuiLink>
                        </p>
                      </EuiCallOut>
                    ) : indexerChannels && indexerChannels.channels.length === 0 ? (
                      <EuiCallOut size="s" color="primary" iconType="iInCircle" title="No Notifications channels yet" data-test-subj="wamNotifPickerEmpty">
                        <p>
                          Create a channel (Slack, Teams, email, webhook, ...) in the{' '}
                          <EuiLink href={channelsAppUrl} target="_blank">
                            Notifications app
                          </EuiLink>{' '}
                          first, then pick it here.
                        </p>
                      </EuiCallOut>
                    ) : (
                      <EuiComboBox<string>
                        singleSelection={{ asPlainText: true }}
                        options={pickerOptions}
                        selectedOptions={selectedOption ? [selectedOption] : selectedConfigId ? [{ label: selectedConfigId, value: selectedConfigId }] : []}
                        onChange={(selected) => setEditing({ ...editing, indexer_channel: { configId: (selected[0] as any)?.value || '' } })}
                        placeholder="Pick a Notifications channel"
                        isClearable
                        data-test-subj="wamNotifChannelPicker"
                      />
                    )}
                    {indexerChannels && indexerChannels.access !== 'ok' && (
                      <>
                        <EuiSpacer size="s" />
                        <EuiFieldText fullWidth
                          value={selectedConfigId}
                          onChange={(e) => setEditing({ ...editing, indexer_channel: { configId: e.target.value.trim() } })}
                          placeholder="Notifications channel config id"
                          aria-label="Notifications channel config id"
                          data-test-subj="wamNotifConfigId"
                        />
                      </>
                    )}
                    {indexerChannels && indexerChannels.access === 'ok' && pickerOptions.some((option) => visibleWarnings(option.channel.warnings, wazuhMajor).length > 0) && (
                      <>
                        <EuiSpacer size="xs" />
                        <EuiText size="xs" color="subdued">
                          <ul className="wamNotifWarningList">
                            {pickerOptions
                              .filter((option) => visibleWarnings(option.channel.warnings, wazuhMajor).length > 0)
                              .map((option) => (
                                <li key={option.value} data-test-subj={`wamNotifWarning-${option.value}`}>
                                  <strong>{option.channel.name}</strong>: {visibleWarnings(option.channel.warnings, wazuhMajor).map((warning) => WARNING_TEXT[warning]).join(' ')}
                                </li>
                              ))}
                          </ul>
                        </EuiText>
                      </>
                    )}
                  </div>
                </EuiFormRow>
              )}

              {editing.kind === 'webhook' && (
                <>
                  <EuiFormRow fullWidth
                    label="Receiver URL"
                    helpText="HTTPS, public hostname by default (no localhost, no IP literals, no host resolving to a private address). A private receiver is reachable only under a local-suffix name (.internal, .local, .home.arpa) listed in WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS; plain http or a self-signed certificate additionally needs the 'Insecure transport (lab only)' switch."
                  >
                    <EuiFieldText fullWidth value={editing.webhook?.url || ''} onChange={(e) => setEditing({ ...editing, webhook: { ...editing.webhook!, url: e.target.value } })} placeholder="https://receiver.example.com/wazuh" data-test-subj="wamNotifUrl" />
                  </EuiFormRow>
                  <EuiFormRow fullWidth
                    label="Signing secret"
                    labelAppend={
                      editing.webhook?.secret === null ? (
                        <EuiBadge color="warning">Will be cleared</EuiBadge>
                      ) : editing.webhook?.secretConfigured ? (
                        <EuiBadge color="success">Configured</EuiBadge>
                      ) : (
                        <EuiBadge color="hollow">Not set</EuiBadge>
                      )
                    }
                    helpText={
                      editing.webhook?.secret === null
                        ? 'The saved secret is removed when you save; deliveries will be unsigned. Paste a new secret to replace it instead.'
                        : editing.webhook?.secretConfigured
                        ? 'Leave blank to keep the currently saved secret. Encrypted at rest; never sent back to the browser.'
                        : 'Shared with the receiver to verify x-wam-signature (sha256=HMAC-SHA256(secret, "<x-wam-timestamp>.<body>")). Without a secret deliveries are unsigned.'
                    }
                  >
                    <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
                      <EuiFlexItem>
                        <EuiFieldPassword fullWidth
                          type="dual"
                          value={editing.webhook?.secret || ''}
                          onChange={(e) => setEditing({ ...editing, webhook: { ...editing.webhook!, secret: e.target.value } })}
                          placeholder={editing.webhook?.secret === null ? 'Saved secret will be cleared' : editing.webhook?.secretConfigured ? '••••••••••••' : 'Paste a shared secret'}
                          data-test-subj="wamNotifSecret"
                        />
                      </EuiFlexItem>
                      {editing.webhook?.secretConfigured && (
                        <EuiFlexItem grow={false}>
                          {editing.webhook?.secret === null ? (
                            <EuiButtonEmpty size="xs" onClick={() => setEditing({ ...editing, webhook: { ...editing.webhook!, secret: '' } })} data-test-subj="wamNotifKeepSecret">
                              Keep saved secret
                            </EuiButtonEmpty>
                          ) : (
                            <EuiButtonEmpty size="xs" color="danger" iconType="cross" onClick={() => setEditing({ ...editing, webhook: { ...editing.webhook!, secret: null } })} data-test-subj="wamNotifClearSecret">
                              Clear saved secret
                            </EuiButtonEmpty>
                          )}
                        </EuiFlexItem>
                      )}
                    </EuiFlexGroup>
                  </EuiFormRow>
                  <EuiFormRow fullWidth
                    label="Extra headers"
                    helpText={`One per line, Name: value (at most ${NOTIFICATION_MAX_WEBHOOK_HEADERS}). Content-Type, Authorization and the x-wam-* headers are set by the plugin and cannot be overridden.`}
                  >
                    <EuiTextArea fullWidth rows={3} value={headersText} onChange={(e) => setHeadersText(e.target.value)} placeholder={'X-Tenant: soc'} data-test-subj="wamNotifHeaders" />
                  </EuiFormRow>
                  <EuiFormRow fullWidth label="Insecure transport (lab only)" helpText="Only honoured for hosts listed in WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS on the dashboard service: plain HTTP for any listed host, and a self-signed certificate only for a listed local-suffix name (.internal, .local, .home.arpa). Every other receiver must use verified HTTPS.">
                    <EuiSwitch
                      label={editing.webhook?.allowInsecure ? 'Allow plain HTTP / self-signed certificate (lab only)' : 'Verified HTTPS only'}
                      checked={editing.webhook?.allowInsecure === true}
                      onChange={(e) => setEditing({ ...editing, webhook: { ...editing.webhook!, allowInsecure: e.target.checked } })}
                      data-test-subj="wamNotifAllowInsecure"
                    />
                  </EuiFormRow>
                </>
              )}

              <EuiFormRow fullWidth label="Events" helpText="Which events reach this channel. A channel with no events is kept but receives nothing.">
                <EuiCheckboxGroup
                  options={eventOptions}
                  idToSelectedMap={eventSelection}
                  onChange={(id) => {
                    const current = new Set(editing.events || []);
                    if (current.has(id as NotificationEvent)) current.delete(id as NotificationEvent);
                    else current.add(id as NotificationEvent);
                    setEditing({ ...editing, events: NOTIFICATION_EVENTS.filter((event) => current.has(event)) });
                  }}
                  data-test-subj="wamNotifEvents"
                />
              </EuiFormRow>
            </EuiForm>
          </EuiFlyoutBody>
          <EuiFlyoutFooter>
            <EuiFlexGroup justifyContent="spaceBetween" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty onClick={() => setEditing(null)} data-test-subj="wamNotifCancel">
                  Cancel
                </EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton
                  fill
                  onClick={commitEditor}
                  disabled={
                    !editing.name.trim() || Boolean(editingIdError) || (editing.kind === 'indexer_channel' ? !selectedConfigId : !(editing.webhook?.url || '').trim())
                  }
                  data-test-subj="wamNotifApply"
                >
                  Apply
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutFooter>
        </EuiFlyout>
      )}
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>
          Changes apply after &quot;Save notification settings&quot;. Delivery through a Notifications channel needs the dashboard service
          user to hold the <EuiCode>wazuh_alert_manager_notify</EuiCode> role (install.sh maps it); a test send runs as you and needs the
          same alerting <EuiCode>monitor/execute</EuiCode> grant.
        </p>
      </EuiText>
      {outbox}
    </div>
  );
};
