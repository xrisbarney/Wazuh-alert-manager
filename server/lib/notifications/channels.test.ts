import { NOTIFICATIONS_CONFIGS_PATH, channelWarnings, listIndexerChannels, summariseChannel } from './channels';

function clientAnswering(impl: (req: any) => any) {
  return { transport: { request: jest.fn(async (req: any) => impl(req)) } };
}

function config(configId: string, config_type: string, extra: any = {}, is_enabled = true) {
  return { config_id: configId, config: { name: `${configId} name`, config_type, is_enabled, ...extra } };
}

const listing = {
  config_list: [
    config('slack-1', 'slack', { slack: { url: 'https://hooks.slack.com/x' } }),
    config('hook-json', 'webhook', { webhook: { url: 'https://r.example/x', header_params: { 'Content-Type': 'application/json; charset=utf-8', 'X-Key': 'k' } } }),
    config('hook-plain', 'webhook', { webhook: { url: 'https://r.example/y', header_params: { 'X-Key': 'k' } } }),
    config('hook-default', 'webhook', { webhook: { url: 'https://r.example/z' } }),
    config('mail-1', 'email', { email: {} }),
    config('smtp-1', 'smtp_account', {}),
    config('default_slack_channel', 'slack', {}, false),
    { config_id: '', config: { name: 'broken', config_type: 'slack' } },
  ],
};

describe('listIndexerChannels', () => {
  test('lists channel types only, as the given client, with the warnings and a stable order', async () => {
    const client = clientAnswering(() => ({ body: listing }));
    const res = await listIndexerChannels(client, { wazuhMajor: 4 });
    expect(client.transport.request).toHaveBeenCalledWith({
      method: 'GET',
      path: NOTIFICATIONS_CONFIGS_PATH,
      querystring: { config_type: 'slack,chime,webhook,email,microsoft_teams,sns', max_items: 100 },
    });
    expect(res.access).toBe('ok');
    expect(res.channels.map((c) => c.configId)).toEqual(['default_slack_channel', 'hook-default', 'hook-json', 'hook-plain', 'mail-1', 'slack-1']);
    const byId = Object.fromEntries(res.channels.map((c) => [c.configId, c]));
    expect(byId['hook-json']).toEqual({ configId: 'hook-json', name: 'hook-json name', type: 'webhook', isEnabled: true, warnings: [] });
    expect(byId['hook-plain'].warnings).toEqual(['missing_json_content_type']);
    // An empty header map delivers application/json by default on the indexer: no warning.
    expect(byId['hook-default'].warnings).toEqual([]);
    expect(byId['slack-1'].warnings).toEqual([]);
    // The 5.0 placeholder hint never appears on a 4.x build.
    expect(byId['default_slack_channel']).toMatchObject({ isEnabled: false, warnings: [] });
  });

  test('flags disabled default_* placeholders on a 5.0 build only, and only while disabled', async () => {
    const client = clientAnswering(() => ({ body: listing }));
    const res = await listIndexerChannels(client, { wazuhMajor: 5 });
    const placeholder = res.channels.find((c) => c.configId === 'default_slack_channel')!;
    expect(placeholder.warnings).toEqual(['disabled_placeholder']);
    expect(channelWarnings(config('default_slack_channel', 'slack', {}, true), 5)).toEqual([]);
    expect(channelWarnings(config('my_slack', 'slack', {}, false), 5)).toEqual([]);
    expect(channelWarnings(config('default_shuffle_channel', 'webhook', { webhook: { header_params: { 'X-A': '1' } } }, false), 5)).toEqual([
      'missing_json_content_type',
      'disabled_placeholder',
    ]);
  });

  test('403 answers forbidden with an empty list; 404 / no handler answers unavailable; other errors are unavailable with the message', async () => {
    const forbidden = await listIndexerChannels(clientAnswering(() => {
      throw Object.assign(new Error('security_exception'), { meta: { statusCode: 403 } });
    }));
    expect(forbidden).toMatchObject({ access: 'forbidden', channels: [] });
    expect(forbidden.message).toMatch(/notifications_read_access/);

    const missing = await listIndexerChannels(clientAnswering(() => {
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }));
    expect(missing).toMatchObject({ access: 'unavailable', channels: [] });

    const noHandler = await listIndexerChannels(clientAnswering(() => {
      throw Object.assign(new Error('no handler found for uri [/_plugins/_notifications/configs] and method [GET]'), { meta: { statusCode: 400 } });
    }));
    expect(noHandler.access).toBe('unavailable');

    const down = await listIndexerChannels(clientAnswering(() => {
      throw new Error('connect ECONNREFUSED');
    }));
    expect(down).toMatchObject({ access: 'unavailable', channels: [] });
    expect(down.message).toMatch(/ECONNREFUSED/);
  });

  test('summariseChannel tolerates missing names and skips non-channel types', () => {
    expect(summariseChannel({ config_id: 'x', config: { config_type: 'chime', name: '  ' } }, 4)).toEqual({ configId: 'x', name: 'x', type: 'chime', isEnabled: true, warnings: [] });
    expect(summariseChannel({ config_id: 'x', config: { config_type: 'email_group' } }, 4)).toBeNull();
    expect(summariseChannel({ config: { config_type: 'slack' } }, 4)).toBeNull();
    expect(summariseChannel(null, 4)).toBeNull();
  });
});
