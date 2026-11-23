/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NotificationSettingsView, channelIdError, describeTest, newChannel, suggestChannelId, textToHeaders, toPayload, visibleWarnings } from './notification_settings_view';

configure({ testIdAttribute: 'data-test-subj' });

const settings = {
  enabled: true,
  encryptionConfigured: true,
  egressAllowedHosts: ['receiver.internal'],
  wazuhMajor: 4,
  updated_by: 'admin',
  channels: [
    { id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created', 'case.closed'], indexer_channel: { configId: 'abc123' } },
    { id: 'siem-hook', name: 'SIEM webhook', kind: 'webhook', enabled: false, events: ['sla.breached'], webhook: { url: 'https://hooks.example.com/wam', contentType: 'application/json', headers: { 'X-Tenant': 'soc' }, secretConfigured: true } },
  ],
};

const listing = {
  access: 'ok',
  channels: [
    { configId: 'abc123', name: 'SOC', type: 'slack', isEnabled: true, warnings: [] },
    { configId: 'hook-1', name: 'Plain hook', type: 'webhook', isEnabled: true, warnings: ['missing_json_content_type'] },
    { configId: 'default_slack_channel', name: 'default_slack_channel', type: 'slack', isEnabled: false, warnings: ['disabled_placeholder'] },
  ],
};

function apiServiceWith(isPluginAdmin: boolean, stored: any = settings, channels: any = listing) {
  return {
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    fetchNotificationSettings: jest.fn(async () => stored),
    saveNotificationSettings: jest.fn(async (payload: any) => ({ ...stored, ...payload, channels: payload.channels.map((c: any) => (c.kind === 'webhook' ? { ...c, webhook: { ...c.webhook, secret: undefined, secretConfigured: true } } : c)) })),
    fetchIndexerChannels: jest.fn(async () => channels),
    testNotificationChannel: jest.fn(),
    fetchNotificationStatus: jest.fn(async () => ({ enabled: true, tickSeconds: 5, status: null, counts: { pending: 0, sending: 0, sent: 0, failed: 0, dead: 0 } })),
    fetchNotificationOutbox: jest.fn(async () => ({ items: [], next_cursor: null, total: 0 })),
    retryNotification: jest.fn(),
    appUrl: jest.fn((path: string) => `/base${path}`),
  } as any;
}

describe('NotificationSettingsView', () => {
  test('locks the tab for non-administrators with a read-only summary', async () => {
    render(<NotificationSettingsView apiService={apiServiceWith(false)} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText(/administered by Wazuh administrators/)).toBeTruthy());
    expect(screen.queryByTestId('wamNotifSave')).toBeNull();
    expect(screen.getByTestId('wamNotifReadOnly').textContent).toMatch(/Notifications are enabled.*SOC Slack \(Notifications channel\), SIEM webhook \(Direct webhook, off\)/);
  });

  test('lists the channels with kind, events, signed state and the Notifications app link', async () => {
    const api = apiServiceWith(true);
    render(<NotificationSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifChannel-soc-slack')).toBeTruthy());
    expect(screen.getByTestId('wamNotifChannel-soc-slack').textContent).toContain('abc123');
    expect(screen.getByTestId('wamNotifChannel-soc-slack').textContent).toContain('case.created');
    expect(screen.getByTestId('wamNotifChannel-siem-hook').textContent).toContain('Signed');
    expect(screen.getAllByText('Notifications app')[0].closest('a')!.getAttribute('href')).toBe('/base/app/notifications-dashboards#/channels');
    expect(screen.getByText('receiver.internal')).toBeTruthy();
    expect((screen.getByTestId('wamNotifSave') as HTMLButtonElement).disabled).toBe(true);
    // The 5.0 host_deny_list caveat never shows on a 4.x build.
    expect(screen.queryByText(/host_deny_list/)).toBeNull();
  });

  test('an administrator whose settings load fails sees a load error with retry', async () => {
    const api = apiServiceWith(true);
    api.fetchNotificationSettings.mockRejectedValueOnce(Object.assign(new Error('boom'), { body: { message: 'meta index unavailable' } }));
    render(<NotificationSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifLoadError')).toBeTruthy());
    expect(screen.getByText('meta index unavailable')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamNotifRetry'));
    await waitFor(() => expect(screen.getByTestId('wamNotifChannel-soc-slack')).toBeTruthy());
    expect(api.fetchNotificationSettings).toHaveBeenCalledTimes(2);
  });

  test('the picker lists Notifications channels with warnings as help text; the placeholder hint is hidden on 4.x', async () => {
    const api = apiServiceWith(true);
    render(<NotificationSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifChannel-soc-slack')).toBeTruthy());
    fireEvent.click(screen.getByLabelText('Edit SOC Slack'));
    await waitFor(() => expect(screen.getByTestId('wamNotifChannelPicker')).toBeTruthy());
    expect(api.fetchIndexerChannels).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('wamNotifWarning-hook-1').textContent).toMatch(/Content-Type: application\/json/);
    expect(screen.queryByTestId('wamNotifWarning-default_slack_channel')).toBeNull();
    fireEvent.click(screen.getByTestId('wamNotifCancel'));
    expect(screen.queryByTestId('wamNotifFlyout')).toBeNull();
  });

  test('a 403 on the channel listing shows the empty state with the role hint and a manual id field, never a toast', async () => {
    const onToast = jest.fn();
    const api = apiServiceWith(true, settings, { access: 'forbidden', channels: [], message: 'no role' });
    render(<NotificationSettingsView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifAdd')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamNotifAdd'));
    await waitFor(() => expect(screen.getByTestId('wamNotifPickerEmpty')).toBeTruthy());
    expect(screen.getByTestId('wamNotifPickerEmpty').textContent).toMatch(/notifications_read_access/);
    expect(screen.getByTestId('wamNotifPickerEmpty').querySelector('a')!.getAttribute('href')).toBe('/base/app/notifications-dashboards#/channels');
    fireEvent.change(screen.getByTestId('wamNotifConfigId'), { target: { value: 'manual-id' } });
    fireEvent.click(screen.getByTestId('wamNotifApply'));
    expect(screen.getByTestId('wamNotifChannel-notifications-channel').textContent).toContain('manual-id');
    expect(onToast).not.toHaveBeenCalled();
  });

  test('"Clear saved secret" sends webhook.secret: null and a test send shows the result badge', async () => {
    const api = apiServiceWith(true);
    api.testNotificationChannel.mockResolvedValue({ channelId: 'siem-hook', kind: 'webhook', ok: false, statusCode: 500, error: 'Receiver answered HTTP 500', durationMs: 20 });
    render(<NotificationSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifChannel-siem-hook')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamNotifTest-siem-hook'));
    await waitFor(() => expect(screen.getByTestId('wamNotifTestResult-siem-hook')).toBeTruthy());
    expect(screen.getByTestId('wamNotifTestResult-siem-hook').textContent).toBe('Failed');
    expect(screen.getByText(/Receiver answered HTTP 500/)).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Edit SIEM webhook'));
    fireEvent.click(screen.getByTestId('wamNotifClearSecret'));
    expect(screen.getByText('Will be cleared')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamNotifApply'));
    expect(screen.getByTestId('wamNotifChannel-siem-hook').textContent).toContain('Secret cleared');
    expect(screen.getByTestId('wamNotifDirty')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamNotifSave'));
    await waitFor(() => expect(api.saveNotificationSettings).toHaveBeenCalledTimes(1));
    const sent = api.saveNotificationSettings.mock.calls[0][0];
    expect(sent.enabled).toBe(true);
    const hook = sent.channels.find((c: any) => c.id === 'siem-hook');
    expect(hook.webhook).toEqual({ url: 'https://hooks.example.com/wam', contentType: 'application/json', headers: { 'X-Tenant': 'soc' }, secret: null });
    expect(sent.channels.find((c: any) => c.id === 'soc-slack')).toEqual({ id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true, events: ['case.created', 'case.closed'], indexer_channel: { configId: 'abc123' } });
  });

  test('a new channel cannot reuse a listed id or a malformed one: Apply stays disabled with the error on the Id row', async () => {
    const api = apiServiceWith(true);
    render(<NotificationSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifChannel-soc-slack')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamNotifAdd'));
    await waitFor(() => expect(screen.getByTestId('wamNotifApply')).toBeTruthy());
    fireEvent.change(screen.getByTestId('wamNotifId'), { target: { value: 'soc-slack' } });
    expect(screen.getByText(/already exists/)).toBeTruthy();
    expect((screen.getByTestId('wamNotifApply') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByTestId('wamNotifId'), { target: { value: '-bad' } });
    expect(screen.getByText(/lower-case letters/)).toBeTruthy();
    expect((screen.getByTestId('wamNotifApply') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId('wamNotifApply'));
    expect(screen.getAllByTestId('wamNotifChannel-soc-slack')).toHaveLength(1);
    expect(screen.queryByTestId('wamNotifChannel--bad')).toBeNull();
  });

  test('a channel the server flagged invalid shows the egress badge and callout, and the flag is dropped from the PUT payload', async () => {
    const flagged = {
      ...settings,
      channels: [settings.channels[0], { ...settings.channels[1], enabled: false, invalid: 'Channel "SIEM webhook" URL: host "hooks.example.com" is not allowed.' }],
    };
    const api = apiServiceWith(true, flagged);
    render(<NotificationSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifInvalid-siem-hook')).toBeTruthy());
    expect(screen.getByTestId('wamNotifInvalidCallout-siem-hook').textContent).toContain('not allowed');
    expect(toPayload(flagged.channels[1] as any)).not.toHaveProperty('invalid');
  });

  test('helpers: toPayload contract, id suggestion, header parsing, warning visibility, test description', () => {
    expect(channelIdError('soc-slack', [{ id: 'soc-slack' }], true)).toMatch(/already exists/);
    expect(channelIdError('soc-slack', [{ id: 'soc-slack' }], false)).toBeNull();
    expect(channelIdError('Soc Slack', [], true)).toMatch(/lower-case/);
    expect(channelIdError('', [], true)).toMatch(/lower-case/);
    expect(channelIdError('soc_slack-2', [], true)).toBeNull();
    const base: any = { id: 'h', name: 'H', kind: 'webhook', enabled: true, events: ['case.created'], webhook: { url: 'https://x.example/h', contentType: 'application/json', headers: {}, secretConfigured: true } };
    expect(toPayload({ ...base, webhook: { ...base.webhook, secret: '' } }).webhook).toEqual({ url: 'https://x.example/h', contentType: 'application/json' });
    expect(toPayload({ ...base, webhook: { ...base.webhook, secret: 'new', allowInsecure: true } }).webhook).toEqual({ url: 'https://x.example/h', contentType: 'application/json', allowInsecure: true, secret: 'new' });
    expect(toPayload({ ...base, webhook: { ...base.webhook, secret: null } }).webhook!.secret).toBeNull();
    expect(toPayload(base).webhook).not.toHaveProperty('secretConfigured');
    expect(toPayload({ ...base, kind: 'indexer_channel', indexer_channel: { configId: 'c' } })).toEqual({ id: 'h', name: 'H', kind: 'indexer_channel', enabled: true, events: ['case.created'], indexer_channel: { configId: 'c' } });
    expect(suggestChannelId('SOC Slack!', [{ id: 'soc-slack' }])).toBe('soc-slack-2');
    expect(newChannel('webhook', []).webhook).toEqual({ url: '', headers: {}, contentType: 'application/json', secret: '' });
    expect(textToHeaders('X-A: 1\nbad line\n X-B : two: parts ')).toEqual({ 'X-A': '1', 'X-B': 'two: parts' });
    expect(visibleWarnings(['missing_json_content_type', 'disabled_placeholder'], 4)).toEqual(['missing_json_content_type']);
    expect(visibleWarnings(['missing_json_content_type', 'disabled_placeholder'], 5)).toEqual(['missing_json_content_type', 'disabled_placeholder']);
    expect(describeTest({ channelId: 'x', kind: 'webhook', ok: true, statusCode: 204, error: null, durationMs: 9 })).toEqual({ color: 'success', text: 'Delivered (HTTP 204) in 9 ms' });
    expect(describeTest({ channelId: 'x', kind: 'indexer_channel', ok: false, statusCode: 403, error: 'no permissions', durationMs: 9 }).text).toBe('Failed (403): no permissions');
  });
});
