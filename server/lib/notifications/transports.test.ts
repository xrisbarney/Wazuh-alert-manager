import { createHmac } from 'crypto';
import { META_INDEX, NOTIFICATIONS_OUTBOX_INDEX } from '../../../common';
import { EgressError } from '../egress/url_policy';
import {
  ALERTING_EXECUTE_PATH,
  buildInlineMonitor,
  parseExecuteResponse,
  resolveMonitorInputIndex,
  sendIndexerChannel,
  sendWebhook,
  signWebhookBody,
  webhookHeaders,
} from './transports';

const hook: any = {
  id: 'siem-hook',
  name: 'SIEM',
  kind: 'webhook',
  enabled: true,
  events: ['case.created'],
  webhook: { url: 'https://hooks.example.com/wam', contentType: 'application/json', headers: { 'X-Tenant': 'soc', 'X-WAM-Delivery': 'spoof' } },
};

const payload = { event: 'case.created', occurred_at: '2026-11-21T12:00:00.000Z', source: 'wazuh-alert-manager', case: { id: 'c1', title: 'T' } };

describe('sendWebhook', () => {
  test('signs "<timestamp>.<body>" with HMAC-SHA256 and sets the plugin headers over operator headers', async () => {
    const fetch = jest.fn(async () => ({ status: 204, headers: {}, bodyText: '', truncated: false as const }));
    const now = new Date('2026-11-21T12:34:56.000Z');
    const res = await sendWebhook({}, hook, 'shh', payload, { fetch, now, deliveryId: 'd-1' });
    expect(res).toMatchObject({ ok: true, statusCode: 204, error: null, deliveryId: 'd-1' });
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = fetch.mock.calls[0] as any[];
    expect(url).toBe('https://hooks.example.com/wam');
    expect(options.method).toBe('POST');
    expect(options.timeoutMs).toBe(10000);
    expect(options.maxResponseBytes).toBe(65536);
    expect(options.allowInsecure).toBe(false);
    const body = JSON.stringify(payload);
    expect(options.body).toBe(body);
    const expected = `sha256=${createHmac('sha256', 'shh').update(`2026-11-21T12:34:56.000Z.${body}`).digest('hex')}`;
    expect(options.headers).toEqual({
      'x-tenant': 'soc',
      'content-type': 'application/json',
      'x-wam-event': 'case.created',
      'x-wam-delivery': 'd-1',
      'x-wam-timestamp': '2026-11-21T12:34:56.000Z',
      'x-wam-signature': expected,
    });
    // Known-answer vector so a receiver implementation can be checked against it.
    expect(signWebhookBody('secret', '2026-01-01T00:00:00.000Z', '{"a":1}')).toBe(
      `sha256=${createHmac('sha256', 'secret').update('2026-01-01T00:00:00.000Z.{"a":1}').digest('hex')}`
    );
  });

  test('without a secret no signature header is sent; operator headers cannot inject one', () => {
    const headers = webhookHeaders({ webhook: { url: 'u', contentType: 'application/json', headers: { 'X-WAM-Signature': 'forged', 'Content-Type': 'text/plain' } } } as any, {
      event: 'test',
      deliveryId: 'd',
      timestamp: 't',
      signature: null,
    });
    expect(headers['x-wam-signature']).toBeUndefined();
    expect(headers['content-type']).toBe('application/json');
  });

  test('non-2xx, egress policy and network failures are results, never throws', async () => {
    const bad = await sendWebhook({}, hook, 's', payload, { fetch: async () => ({ status: 500, headers: {}, bodyText: 'boom', truncated: false as const }) });
    expect(bad).toMatchObject({ ok: false, statusCode: 500, error: 'Receiver answered HTTP 500: boom' });
    const policy = await sendWebhook({}, hook, 's', payload, {
      fetch: async () => {
        throw new EgressError('policy', 'Webhook URL cannot target localhost', { reason: 'host', host: 'localhost' });
      },
    });
    expect(policy).toMatchObject({ ok: false, statusCode: null, error: 'Webhook URL cannot target localhost' });
    const timeout = await sendWebhook({}, hook, 's', payload, {
      fetch: async () => {
        throw new EgressError('timeout', 'Request to hooks.example.com timed out after 10000 ms.');
      },
    });
    expect(timeout.error).toMatch(/timed out/);
    const notHook = await sendWebhook({}, { ...hook, kind: 'indexer_channel', webhook: undefined }, 's', payload, { fetch: jest.fn() });
    expect(notHook.ok).toBe(false);
  });
});

function executeResponse(actionResult: any, triggerExtra: any = {}) {
  return {
    monitor_name: 'wam-notification-x',
    period_start: 1,
    period_end: 2,
    error: null,
    input_results: { results: [{ hits: { total: { value: 0 } } }], error: null },
    trigger_results: { 'trigger-1': { name: 'wam-notify', triggered: true, error: null, action_results: { 'action-1': actionResult }, ...triggerExtra } },
  };
}

const notificationsEvent = (statusCode: string, statusText = 'Success') =>
  JSON.stringify({ event_source: { title: 'x' }, status_list: [{ config_id: 'abc', config_type: 'webhook', delivery_status: { status_code: statusCode, status_text: statusText } }] });

describe('sendIndexerChannel', () => {
  test('executes an inline, disabled query-level monitor whose one action targets the channel with mustache-escaped templates', async () => {
    const client = {
      indices: { exists: jest.fn(async () => ({ body: true })) },
      transport: { request: jest.fn(async (_req: any) => ({ body: executeResponse({ id: 'a', name: 'n', output: { messageId: notificationsEvent('200') }, throttled: false, error: null }) })) },
    };
    const res = await sendIndexerChannel(client, 'abc', { subject: 'Hello {{ctx}}', message: 'Body' }, { deliveryId: 'd-2' });
    expect(res).toMatchObject({ ok: true, statusCode: 200, error: null, deliveryId: 'd-2' });
    expect(client.indices.exists).toHaveBeenCalledWith({ index: NOTIFICATIONS_OUTBOX_INDEX });
    const req = client.transport.request.mock.calls[0]![0];
    expect(req).toMatchObject({ method: 'POST', path: ALERTING_EXECUTE_PATH, querystring: { dryrun: false } });
    const monitor = req.body;
    expect(monitor).toMatchObject({
      type: 'monitor',
      monitor_type: 'query_level_monitor',
      name: 'wam-notification-d-2',
      enabled: false,
      schedule: { period: { interval: 1000, unit: 'DAYS' } },
      inputs: [{ search: { indices: [NOTIFICATIONS_OUTBOX_INDEX], query: { size: 0, query: { match_all: {} } } } }],
    });
    const trigger = monitor.triggers[0].query_level_trigger;
    expect(trigger.condition.script).toEqual({ source: 'return true', lang: 'painless' });
    expect(trigger.actions).toHaveLength(1);
    expect(trigger.actions[0]).toEqual({
      name: 'wam-notification-d-2',
      destination_id: 'abc',
      subject_template: { source: '{{=<% %>=}}Hello {{ctx}}', lang: 'mustache' },
      message_template: { source: 'Body', lang: 'mustache' },
      throttle_enabled: false,
    });
  });

  test('the search input falls back to the meta index while the outbox does not exist (nothing is created)', async () => {
    const client = { indices: { exists: jest.fn(async () => ({ body: false })), create: jest.fn() }, transport: { request: jest.fn(async (_req: any) => ({ body: executeResponse({ error: null }) })) } };
    expect(await resolveMonitorInputIndex(client)).toBe(META_INDEX);
    await sendIndexerChannel(client, 'abc', { subject: 's', message: 'm' });
    expect(client.transport.request.mock.calls[0]![0].body.inputs[0].search.indices).toEqual([META_INDEX]);
    expect(client.indices.create).not.toHaveBeenCalled();
    const failing = { indices: { exists: jest.fn(async () => { throw new Error('403'); }) } };
    expect(await resolveMonitorInputIndex(failing)).toBe(META_INDEX);
    expect(buildInlineMonitor('c', { subject: 's', message: 'm' }, { inputIndex: 'idx', deliveryId: 'd' }).inputs[0].search.indices).toEqual(['idx']);
  });

  test('parses delivery status from the Notifications event, action errors, throttling and top-level errors', () => {
    expect(parseExecuteResponse(executeResponse({ output: { messageId: notificationsEvent('200') }, error: null }))).toEqual({ ok: true, statusCode: 200, error: null });
    expect(parseExecuteResponse(executeResponse({ output: { messageId: notificationsEvent('500', 'Internal Server Error') }, error: null }))).toEqual({
      ok: false,
      statusCode: 500,
      error: 'Internal Server Error',
    });
    expect(parseExecuteResponse(executeResponse({ output: { messageId: notificationsEvent('423', 'The channel is muted') }, error: null }))).toMatchObject({ ok: false, statusCode: 423, error: 'The channel is muted' });
    expect(parseExecuteResponse(executeResponse({ delivery_status: { status_code: 202 }, error: null }))).toEqual({ ok: true, statusCode: 202, error: null });
    expect(parseExecuteResponse(executeResponse({ output: { subject: 's', message: 'm' }, error: null }))).toEqual({ ok: true, statusCode: null, error: null });
    expect(parseExecuteResponse(executeResponse({ error: 'Failed to send notification: 403 Forbidden' }))).toMatchObject({ ok: false, error: expect.stringContaining('403') });
    expect(parseExecuteResponse(executeResponse({ throttled: true, error: null }))).toMatchObject({ ok: false, error: /throttled/ });
    expect(parseExecuteResponse(executeResponse({ error: null }, { error: 'trigger failed' }))).toMatchObject({ ok: false, error: 'trigger failed' });
    expect(parseExecuteResponse({ ...executeResponse({}), error: 'no permissions for [cluster:admin/opendistro/alerting/monitor/execute]' })).toMatchObject({ ok: false, error: /monitor\/execute/ });
    expect(parseExecuteResponse({ trigger_results: {} })).toMatchObject({ ok: false, error: /no trigger results/ });
    // A failed search input (no read on the input index) is named, not reported as "no action was executed".
    expect(parseExecuteResponse({ ...executeResponse({}), input_results: { results: [], error: 'no permissions for [indices:data/read/search] and User [name=kibanaserver]' } })).toEqual({
      ok: false,
      statusCode: null,
      error: 'no permissions for [indices:data/read/search] and User [name=kibanaserver]',
    });
    expect(parseExecuteResponse({ input_results: { results: [], error: { type: 'index_not_found_exception', reason: 'no such index [x]' } }, trigger_results: {} })).toMatchObject({ ok: false, error: 'no such index [x]' });
    expect(parseExecuteResponse(executeResponse(undefined))).toMatchObject({ ok: false });
    expect(parseExecuteResponse(null)).toMatchObject({ ok: false });
  });

  test('a 403 from the transport is a failed result naming the missing grant; a 404 names the plugin', async () => {
    const forbidden = {
      indices: { exists: jest.fn(async () => ({ body: true })) },
      transport: {
        request: jest.fn(async () => {
          throw Object.assign(new Error('security_exception'), { meta: { statusCode: 403, body: { error: { reason: 'no permissions for [cluster:admin/opendistro/alerting/monitor/execute]' } } } });
        }),
      },
    };
    const res = await sendIndexerChannel(forbidden, 'abc', { subject: 's', message: 'm' });
    expect(res).toMatchObject({ ok: false, statusCode: 403 });
    expect(res.error).toMatch(/monitor\/execute/);
    expect(res.error).toMatch(/wazuh_alert_manager_notify/);
    const missing = { indices: { exists: jest.fn(async () => ({ body: true })) }, transport: { request: jest.fn(async () => { throw Object.assign(new Error('nf'), { meta: { statusCode: 404 } }); }) } };
    expect((await sendIndexerChannel(missing, 'abc', { subject: 's', message: 'm' })).error).toMatch(/Alerting plugin is not available/);
    expect((await sendIndexerChannel(missing, '', { subject: 's', message: 'm' })).error).toMatch(/No Notifications channel id/);
  });
});
