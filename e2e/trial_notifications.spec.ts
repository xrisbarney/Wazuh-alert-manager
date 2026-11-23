import { expect, Page, test } from '@playwright/test';
import { API, api, apiRaw, fromSeedRun, indexerRequest, openSettingsSection, pollUntil, seedAlerts, signIn, waitForProjectedAlert } from './helpers';
import { RECEIVER_CONTAINER_HOST, startWebhookReceiver, verifySignature, WebhookReceiver } from './webhook_receiver';

/**
 * Phase 1 bench (PLAN.md 1.5): notifications end to end on a live stack.
 *
 * A local receiver (`webhook_receiver.ts`) stands in for both a direct
 * signed webhook (channel A, `/direct`) and the target of a Notifications
 * webhook channel created on the indexer and bound as `indexer_channel`
 * (channel B, `/indexer`). The bench saves the settings, runs the test sends,
 * creates a case from two seeded alerts and waits for the dispatcher to mark
 * both `case.created` deliveries `sent`, enables a rule with `notify` +
 * `assignTo` and seeds alerts for it, checks the egress policy and an
 * unknown Notifications config id, and drives an SLA escalation whose
 * `notify` names the direct channel (`sla.escalated`).
 *
 * Mutating: it adds its channels to the notification settings document (the
 * operator's channels stay in every write, disabled, so their stored secrets
 * survive; the original document is restored afterwards), creates and deletes
 * a Notifications channel on the indexer (direct HTTPS call with the seeder
 * credentials), creates and deletes a rule, replaces the SLA policy (restored
 * afterwards; like trial_sla.spec.ts every open unassigned high-band alert of
 * the stack is escalated while the 1-minute policy is in force), seeds alerts
 * and creates a case (closed afterwards). Outbox entries
 * of this run stay in `wazuh-alert-manager-v2-notifications` (there is no
 * delete API; ids carry the run's case / rule ids). Needs the Docker stack
 * with `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=<RECEIVER_CONTAINER_HOST>`
 * and `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` on the dashboard service
 * (scripts/dev/e2e-deploy.sh writes both) and the dashboard user mapped to
 * `wazuh_alert_manager_notify` (install.sh / docker/dev/README.md).
 */

const CHANNEL_A = 'wam-e2e-direct';
const CHANNEL_B = 'wam-e2e-indexer';
const CHANNEL_GHOST = 'wam-e2e-ghost';
const SECRET = 'wam-e2e-secret';
const INDEXER_CHANNEL_NAME = 'wam-e2e-channel';
const AGENT_NAME = 'wam-e2e-agent';
const SEEDED_RULE_ID = '930001';
const RULE_NAME = 'WAM e2e notify rule';
const RULE_ASSIGNEE = 'wam-e2e-notify';
const BENCH_CHANNEL_IDS = [CHANNEL_A, CHANNEL_B, CHANNEL_GHOST, 'wam-e2e-private'];
const SLA_BAND = 'high' as const; // the seeder writes rule.level = 10
const SLA_ESCALATION_ID = 'wam-e2e-notify-sla';
const SLA_ESCALATION_NAME = 'WAM e2e notify escalation';
const SLA_ASSIGNEE = 'wam-e2e-sla-notify';
const QUEUE_QUERY = `${API}/alerts?from_offset=0&size=50&sortField=@timestamp&sortDirection=desc&agentNames=${AGENT_NAME}`;
/** Dispatcher tick is 5 s; a webhook send has a 10-s deadline and the first retry waits 30 s. */
const DELIVERY_BUDGET_MS = 90_000;

const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;

test.describe.configure({ mode: 'serial' });

test.describe('trial: notifications (direct webhook, Notifications channel, outbox, rule notify)', () => {
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 to run the mutating notifications bench.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  let page: Page;
  let receiver: WebhookReceiver;
  let savedSettings: { enabled: boolean; channels: any[] } | null = null;
  let savedPolicy: { targets: any; escalations: any[] } | null = null;
  let indexerConfigId = '';
  let caseId = '';
  let ruleId = '';
  let seededIds: string[] = [];

  const directChannel = () => ({
    id: CHANNEL_A,
    name: 'WAM e2e direct webhook',
    kind: 'webhook',
    enabled: true,
    events: ['case.created', 'case.closed', 'rule.action', 'sla.escalated'],
    webhook: { url: `${receiver.containerBaseUrl}/direct`, secret: SECRET, allowInsecure: true },
  });
  const indexerChannel = () => ({
    id: CHANNEL_B,
    name: 'WAM e2e Notifications channel',
    kind: 'indexer_channel',
    enabled: true,
    events: ['case.created'],
    indexer_channel: { configId: indexerConfigId },
  });

  /**
   * The operator's channels, disabled, as every write of the bench carries
   * them: a webhook channel left out of a PUT loses its stored secret (the
   * write path keeps a secret only for an element that stays in the list and
   * sends `secret: ''`), so they are never removed, only switched off.
   */
  const baseChannels = () => (savedSettings?.channels || []).map((channel: any) => ({ ...channel, enabled: false }));
  const benchIds = (channels: any[]) => channels.map((channel: any) => channel.id).filter((id: string) => BENCH_CHANNEL_IDS.includes(id));
  /** Write the settings document: the operator's channels (disabled) plus the bench's `channels`. */
  const putSettings = (channels: any[]) => api(page, 'PUT', `${API}/notifications/settings`, { enabled: true, channels: [...baseChannels(), ...channels] });

  /** The outbox entry of `channelId` targeting `targetId` for `event`, once it is `sent`. */
  const waitForSent = (event: string, channelId: string, targetId: string) =>
    pollUntil(
      page,
      async () => {
        const result = await api(page, 'GET', `${API}/notifications/outbox?event=${event}&channelId=${channelId}&limit=50`);
        return (result.items || []).find((item: any) => item.target_id === targetId && item.status === 'sent') || null;
      },
      { label: `outbox ${event} -> ${channelId} for ${targetId} sent`, timeoutMs: DELIVERY_BUDGET_MS, pollMs: 3_000 }
    );

  const ruleTokens = async (id: string) => {
    const rule = await api(page, 'GET', `${API}/rules/${encodeURIComponent(id)}`);
    return { revision: rule.revision, if_seq_no: rule.if_seq_no, if_primary_term: rule.if_primary_term };
  };

  test.beforeAll(async ({ browser }) => {
    // signIn alone waits up to 3 x 60 s on a slow stack; Playwright's default hook budget is 30 s.
    test.setTimeout(120_000);
    receiver = await startWebhookReceiver();
    page = await browser.newPage();
    await signIn(page, username!, password!);
  });

  test.afterAll(async () => {
    // Settings first: with the bench channels gone (or notifications
    // disabled) the case close and the alert closes below enqueue nothing,
    // so the run leaves no pending entry behind.
    let restoreError: string | null = null;
    if (savedSettings) {
      try {
        await api(page, 'PUT', `${API}/notifications/settings`, savedSettings);
      } catch (e) {
        restoreError = `could not restore the notification settings: ${String(e)}`;
        console.warn(restoreError);
        // Leave nothing pointed at the receiver (it closes below): keep the
        // operator's channels (secrets kept, original flags) without the
        // bench's, or, failing that, switch notifications off entirely.
        try {
          await api(page, 'PUT', `${API}/notifications/settings`, { enabled: savedSettings.enabled, channels: savedSettings.channels.filter((channel: any) => !channel.invalid) });
        } catch (e2) {
          console.warn(`fallback restore failed too: ${String(e2)}`);
          await api(page, 'PUT', `${API}/notifications/settings`, { enabled: false, channels: [] });
        }
      }
    }
    try {
      if (savedPolicy) await api(page, 'PUT', `${API}/sla/policy`, savedPolicy);
    } catch (e) {
      console.warn(`could not restore the SLA policy: ${String(e)}`);
    }
    try {
      if (ruleId) {
        const tokens = await ruleTokens(ruleId);
        const query = new URLSearchParams({ revision: String(tokens.revision), if_seq_no: String(tokens.if_seq_no), if_primary_term: String(tokens.if_primary_term) });
        await api(page, 'DELETE', `${API}/rules/${encodeURIComponent(ruleId)}?${query.toString()}`);
      }
    } catch (e) {
      console.warn(`could not delete the notify rule: ${String(e)}`);
    }
    try {
      if (caseId) await api(page, 'POST', `${API}/cases/${encodeURIComponent(caseId)}/close`, { excludeAlertIds: [] });
    } catch (e) {
      console.warn(`could not close the case: ${String(e)}`);
    }
    try {
      // The rule's and the escalation's alerts plus everything else the run seeded.
      const ids = new Set<string>(seededIds);
      for (const assignee of [RULE_ASSIGNEE, SLA_ASSIGNEE]) {
        const assigned = await api(page, 'GET', `${API}/alerts?from_offset=0&size=500&statuses=open,in_progress&assignedTo=${assignee}`);
        for (const hit of assigned?.hits?.hits || []) ids.add(hit._id as string);
      }
      if (ids.size) await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: Array.from(ids), status: 'closed' });
    } catch (e) {
      console.warn(`could not close the seeded alerts: ${String(e)}`);
    }
    try {
      if (indexerConfigId) {
        const deleted = await indexerRequest('DELETE', `/_plugins/_notifications/configs/${encodeURIComponent(indexerConfigId)}`);
        if (!deleted.ok) console.warn(`could not delete the Notifications channel ${indexerConfigId}: ${JSON.stringify(deleted.body)}`);
      }
    } catch (e) {
      console.warn(`could not delete the Notifications channel: ${String(e)}`);
    }
    await receiver?.close();
    await page?.close();
    // Reported red rather than silently leaving a stack with changed settings.
    if (restoreError) throw new Error(restoreError);
  });

  test('direct webhook channel saves, its test send is signed and the Settings tab shows it delivered', async () => {
    test.setTimeout(120_000);
    const current = await api(page, 'GET', `${API}/notifications/settings`);
    expect(current.redacted, 'the e2e user must be a plugin administrator').toBeFalsy();
    expect(current.encryptionConfigured, 'dashboard service needs WAZUH_ALERT_MANAGER_ENCRYPTION_KEY (scripts/dev/e2e-deploy.sh)').toBe(true);
    expect(
      current.egressAllowedHosts,
      `dashboard service must allowlist the receiver host ${RECEIVER_CONTAINER_HOST} (see scripts/dev/e2e-deploy.sh / WAM_E2E_STUB_HOST)`
    ).toContain(RECEIVER_CONTAINER_HOST);
    const operatorChannels = (current.channels || []).filter((channel: any) => !BENCH_CHANNEL_IDS.includes(channel.id));
    // A channel the read flags `invalid` (its URL no longer passes the egress
    // policy) would make every write of the bench a 400; the bench refuses to
    // run rather than drop it (and its secret) from the document.
    expect(
      operatorChannels.filter((channel: any) => channel.invalid).map((channel: any) => channel.id),
      'the stack has notification channels flagged invalid; fix or remove them before running the bench'
    ).toEqual([]);
    // `secret: ''` keeps the stored secret for an element that stays in the list.
    savedSettings = {
      enabled: current.enabled === true,
      channels: operatorChannels.map(({ invalid, ...channel }: any) =>
        channel.webhook?.secretConfigured ? { ...channel, webhook: { ...channel.webhook, secret: '' } } : channel
      ),
    };

    const saved = await putSettings([directChannel()]);
    expect(benchIds(saved.channels)).toEqual([CHANNEL_A]);
    for (const channel of savedSettings.channels) {
      // The operator's channels are still there, switched off, secrets kept.
      const kept = saved.channels.find((entry: any) => entry.id === channel.id);
      expect(kept, `operator channel ${channel.id} kept`).toMatchObject({ enabled: false });
      if (channel.webhook?.secret === '') expect(kept.webhook.secretConfigured).toBe(true);
    }
    const stored = saved.channels.find((channel: any) => channel.id === CHANNEL_A);
    expect(stored).toMatchObject({ kind: 'webhook', enabled: true });
    // Events are stored in the canonical NOTIFICATION_EVENTS order.
    expect([...stored.events].sort()).toEqual(['case.closed', 'case.created', 'rule.action', 'sla.escalated']);
    expect(stored.webhook).toMatchObject({ url: `${receiver.containerBaseUrl}/direct`, secretConfigured: true, allowInsecure: true, contentType: 'application/json' });
    expect(stored.webhook.secret).toBeUndefined();

    const before = receiver.byPath('/direct').length;
    const result = await api(page, 'POST', `${API}/notifications/test/${CHANNEL_A}`);
    expect(result, JSON.stringify(result)).toMatchObject({ channelId: CHANNEL_A, kind: 'webhook', ok: true, statusCode: 200, error: null });
    const delivered = await receiver.waitFor((request) => request.path === '/direct' && request.headers['x-wam-event'] === 'test', 15_000, 'direct test send');
    expect(receiver.byPath('/direct').length).toBe(before + 1);
    expect(delivered.method).toBe('POST');
    expect(String(delivered.headers['content-type'])).toMatch(/^application\/json/);
    expect(delivered.headers['x-wam-signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(delivered.headers['x-wam-timestamp']).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(delivered.headers['x-wam-delivery']).toBeTruthy();
    expect(verifySignature(delivered, SECRET), 'x-wam-signature must verify against the channel secret').toBe(true);
    expect(verifySignature(delivered, 'wrong-secret')).toBe(false);
    expect(delivered.json).toMatchObject({ event: 'test', source: 'wazuh-alert-manager', case: null });
    expect(delivered.json.message).toContain(CHANNEL_A);

    // Settings > Notifications lists the channel and its UI test passes.
    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'notifications');
    const row = page.locator(`[data-test-subj="wamNotifChannel-${CHANNEL_A}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toContainText('WAM e2e direct webhook');
    await row.locator(`[data-test-subj="wamNotifTest-${CHANNEL_A}"]`).click();
    const badge = row.locator(`[data-test-subj="wamNotifTestResult-${CHANNEL_A}"]`);
    await expect(badge).toBeVisible({ timeout: 30_000 });
    await expect(badge).toHaveText('Delivered');
    await receiver.waitFor((request) => request.path === '/direct' && receiver.byPath('/direct').length >= before + 2, 15_000, 'UI test send');
  });

  test('a Notifications webhook channel is listed, binds as indexer_channel and its test send reaches the receiver', async () => {
    test.setTimeout(120_000);
    const created = await indexerRequest('POST', '/_plugins/_notifications/configs', {
      config: {
        name: INDEXER_CHANNEL_NAME,
        description: 'WAM e2e: Notifications webhook channel pointing at the local receiver',
        config_type: 'webhook',
        is_enabled: true,
        webhook: { url: `${receiver.containerBaseUrl}/indexer`, header_params: { 'Content-Type': 'application/json' } },
      },
    });
    expect(created.ok, JSON.stringify(created.body)).toBe(true);
    indexerConfigId = created.body.config_id;
    expect(indexerConfigId).toBeTruthy();

    // The Notifications config index is not refreshed on write: the new
    // config becomes searchable (and so listable) a few seconds later.
    const summary = await pollUntil(
      page,
      async () => {
        const listed = await api(page, 'GET', `${API}/notifications/channels`);
        expect(listed.access, JSON.stringify(listed)).toBe('ok');
        return (listed.channels || []).find((channel: any) => channel.configId === indexerConfigId) || null;
      },
      { label: `picker lists Notifications config ${indexerConfigId}`, timeoutMs: 30_000, pollMs: 2_000 }
    );
    expect(summary).toMatchObject({ name: INDEXER_CHANNEL_NAME, type: 'webhook', isEnabled: true, warnings: [] });

    const saved = await putSettings([directChannel(), indexerChannel()]);
    expect(benchIds(saved.channels)).toEqual([CHANNEL_A, CHANNEL_B]);
    expect(saved.channels.find((channel: any) => channel.id === CHANNEL_B)).toMatchObject({ kind: 'indexer_channel', enabled: true, events: ['case.created'], indexer_channel: { configId: indexerConfigId } });
    // The direct channel's secret survived the re-save (the PUT carried the plaintext again).
    expect(saved.channels.find((channel: any) => channel.id === CHANNEL_A).webhook.secretConfigured).toBe(true);

    const before = receiver.byPath('/indexer').length;
    const result = await api(page, 'POST', `${API}/notifications/test/${CHANNEL_B}`);
    expect(result, JSON.stringify(result)).toMatchObject({ channelId: CHANNEL_B, kind: 'indexer_channel', ok: true, error: null });
    expect(result.statusCode).toBe(200);
    const delivered = await receiver.waitFor((request) => request.path === '/indexer' && request.body.includes('Test notification'), 20_000, 'indexer channel test send');
    expect(receiver.byPath('/indexer').length).toBeGreaterThanOrEqual(before + 1);
    expect(delivered.method).toBe('POST');
    expect(String(delivered.headers['content-type'])).toMatch(/^application\/json/);
    // The Notifications plugin posts the rendered message text as the body
    // (no WAM signature headers: the indexer is the sender).
    expect(delivered.body).toContain(CHANNEL_B);
    expect(delivered.headers['x-wam-signature']).toBeUndefined();
  });

  test('creating a case from seeded alerts delivers case.created through both channels and the outbox records it', async () => {
    test.setTimeout(420_000);
    const seed = seedAlerts({ count: 2 });
    const fromRun = fromSeedRun(seed.run);
    await waitForProjectedAlert(page, fromRun, { agentName: AGENT_NAME });
    const alertIds = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter(fromRun);
        return rows.length === 2 ? rows.map((row: any) => row._id as string) : null;
      },
      { label: 'both seeded alerts projected', timeoutMs: 180_000, pollMs: 5_000 }
    );
    seededIds.push(...alertIds);

    const created = await api(page, 'POST', `${API}/cases`, { title: `WAM e2e notifications ${seed.run}`, severity: 'high', alertIds });
    caseId = created.id;
    expect(caseId).toMatch(/^case-/);

    const sentA = await waitForSent('case.created', CHANNEL_A, caseId);
    const sentB = await waitForSent('case.created', CHANNEL_B, caseId);
    for (const entry of [sentA, sentB]) {
      expect(entry.id).toMatch(new RegExp(`^case:case\\.created:${caseId}:`));
      expect(entry).toMatchObject({ target_type: 'case', target_id: caseId, status: 'sent', last_error: null });
      expect(entry.attempts).toBeGreaterThanOrEqual(1);
      expect(entry.sent_at).toBeTruthy();
    }
    expect(sentA.channel_kind).toBe('webhook');
    expect(sentB.channel_kind).toBe('indexer_channel');
    expect(sentA.delivery).toMatchObject({ transport: 'webhook', statusCode: 200 });
    // The inline monitor's delivery_status is recorded on the outbox doc.
    expect(sentB.delivery).toMatchObject({ transport: 'indexer_channel', statusCode: 200 });
    expect(sentB.delivery.deliveryId).toBeTruthy();

    const direct = await receiver.waitFor((request) => request.path === '/direct' && request.json?.event === 'case.created' && request.json?.case?.id === caseId, 15_000, 'direct case.created');
    expect(direct.headers['x-wam-event']).toBe('case.created');
    expect(direct.headers['x-wam-delivery']).toBe(sentA.delivery.deliveryId);
    expect(verifySignature(direct, SECRET)).toBe(true);
    expect(direct.json.case).toMatchObject({ id: caseId, title: `WAM e2e notifications ${seed.run}`, severity: 'high', status: 'open', alert_count: 2 });
    expect(direct.json.case.link).toContain(`case=${caseId}`);
    const viaIndexer = await receiver.waitFor((request) => request.path === '/indexer' && request.body.includes(caseId), 15_000, 'indexer case.created');
    expect(viaIndexer.body).toContain('Case created');
    expect(viaIndexer.body).toContain(`WAM e2e notifications ${seed.run}`);

    // The administrator's single-entry read carries the payload that was sent.
    const stored = await api(page, 'GET', `${API}/notifications/outbox/${encodeURIComponent(sentA.id)}`);
    expect(stored.payload).toMatchObject({ event: 'case.created', case: { id: caseId } });
    expect(JSON.stringify(stored.payload)).toBe(direct.body);

    // The outbox panel (Settings > Notifications) shows both rows as Sent.
    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'notifications');
    const outbox = page.locator('[data-test-subj="wamNotifOutbox"]');
    await expect(outbox).toBeVisible({ timeout: 30_000 });
    for (const entry of [sentA, sentB]) {
      const row = outbox.locator(`[data-test-subj="wamNotifOutboxRow-${entry.id}"]`);
      await expect(row).toBeVisible({ timeout: 30_000 });
      await expect(row.locator('[data-test-subj="wamNotifOutboxStatusBadge"]')).toHaveText('Sent');
      await expect(row.locator('[data-test-subj="wamNotifOutboxEvent"]')).toHaveText('case.created');
      await expect(row.locator('[data-test-subj="wamNotifOutboxChannel"]')).toContainText(entry.channel_id);
    }
  });

  test('a rule with notify + assignTo fires on newly ingested alerts and the receiver gets rule.action with the assignee', async () => {
    test.setTimeout(480_000);
    // Rules are created disabled, previewed, then enabled (the activation gate).
    const definition = {
      name: RULE_NAME,
      enabled: false,
      match: { ruleIds: [SEEDED_RULE_ID], agentNames: [AGENT_NAME] },
      trigger: {
        type: 'per_alert',
        entityExpression: { version: 1, groups: [] },
        routing: 'one_per_rule',
        cooldown: { durationMinutes: 0 },
        rearm: { type: 'immediate', quietPeriodMinutes: 0 },
      },
      actions: { createCase: false, assignTo: RULE_ASSIGNEE, notify: { channelIds: [CHANNEL_A] } },
      preconditions: { statuses: ['open'], assignment: 'unassigned' },
      safety: { maxActionsPerRun: 25 },
    };
    const ghost = await apiRaw(page, 'POST', `${API}/rules`, { ...definition, actions: { ...definition.actions, notify: { channelIds: ['no-such-channel'] } } });
    expect(ghost.status, ghost.text).toBe(400);
    // OSD error payloads keep only message + attributes (core response adapter).
    expect(JSON.parse(ghost.text).attributes?.unknownChannelIds).toEqual(['no-such-channel']);

    const created = await api(page, 'POST', `${API}/rules`, definition);
    ruleId = created.id;
    expect(created).toMatchObject({ enabled: false, revision: 1, actions: { assignTo: RULE_ASSIGNEE, notify: { channelIds: [CHANNEL_A] } } });

    const preview = await api(page, 'POST', `${API}/rules/preview`, { ...definition, id: ruleId, revision: created.revision, lookbackHours: 1 });
    expect(preview.mode).toBe('historical_read_only');
    expect(preview.token).toBeTruthy();

    const tokens = await ruleTokens(ruleId);
    const enabled = await api(page, 'PUT', `${API}/rules/${encodeURIComponent(ruleId)}`, { enabled: true, ...tokens });
    expect(enabled.enabled).toBe(true);

    // Ingestion-time evaluation: seed after the rule is live.
    const seed = seedAlerts({ count: 2 });
    const fromRun = fromSeedRun(seed.run);
    const assigned = await waitForProjectedAlert(page, (hit) => fromRun(hit) && hit._source?.assigned_to === RULE_ASSIGNEE, { agentName: AGENT_NAME, timeoutMs: 300_000 });
    seededIds.push(assigned._id);
    const alertId = assigned._id;

    const entry = await pollUntil(
      page,
      async () => {
        const result = await api(page, 'GET', `${API}/notifications/outbox?event=rule.action&channelId=${CHANNEL_A}&limit=50`);
        return (result.items || []).find((item: any) => item.id === `notify:${ruleId}:${alertId}:${CHANNEL_A}` && item.status === 'sent') || null;
      },
      { label: `outbox notify:${ruleId}:${alertId}:${CHANNEL_A} sent`, timeoutMs: DELIVERY_BUDGET_MS, pollMs: 3_000 }
    );
    expect(entry).toMatchObject({ event: 'rule.action', channel_kind: 'webhook', target_type: 'alert', target_id: alertId, last_error: null });

    const delivered = await receiver.waitFor((request) => request.path === '/direct' && request.json?.event === 'rule.action' && request.json?.alert?.id === alertId, 15_000, 'rule.action delivery');
    expect(delivered.headers['x-wam-event']).toBe('rule.action');
    expect(verifySignature(delivered, SECRET)).toBe(true);
    expect(delivered.json.rule).toMatchObject({ id: ruleId, name: RULE_NAME });
    expect(delivered.json.actions).toMatchObject({ assignee: RULE_ASSIGNEE });
    expect(delivered.json.alert).toMatchObject({ id: alertId, rule: { id: SEEDED_RULE_ID }, agent: { name: AGENT_NAME }, assigned_to: RULE_ASSIGNEE });

    // The second seeded alert fires too (one outbox entry per rule, alert and channel).
    const secondId = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter((row: any) => fromRun(row) && row._id !== alertId);
        return rows.length === 1 && rows[0]._source?.assigned_to === RULE_ASSIGNEE ? (rows[0]._id as string) : null;
      },
      { label: 'second seeded alert assigned by the rule', timeoutMs: 180_000, pollMs: 5_000 }
    );
    seededIds.push(secondId);
    await pollUntil(
      page,
      async () => {
        const result = await api(page, 'GET', `${API}/notifications/outbox?event=rule.action&channelId=${CHANNEL_A}&limit=50`);
        return (result.items || []).find((item: any) => item.id === `notify:${ruleId}:${secondId}:${CHANNEL_A}` && item.status === 'sent') || null;
      },
      { label: 'second rule.action entry sent', timeoutMs: DELIVERY_BUDGET_MS, pollMs: 3_000 }
    );
    // Two alerts, one channel: exactly two rule.action entries for this rule.
    const all = await api(page, 'GET', `${API}/notifications/outbox?event=rule.action&channelId=${CHANNEL_A}&limit=200`);
    expect((all.items || []).filter((item: any) => item.id.startsWith(`notify:${ruleId}:`)).length).toBe(2);
  });

  test('negative: a private receiver URL is refused by the egress policy and an unknown Notifications config id fails its test send', async () => {
    test.setTimeout(120_000);
    const privateUrl = await apiRaw(page, 'PUT', `${API}/notifications/settings`, {
      enabled: true,
      channels: [...baseChannels(), directChannel(), indexerChannel(), { id: 'wam-e2e-private', name: 'Private LAN', kind: 'webhook', enabled: true, events: ['case.created'], webhook: { url: 'http://10.1.2.3/x', allowInsecure: true } }],
    });
    expect(privateUrl.status, privateUrl.text).toBe(400);
    expect(privateUrl.text).toMatch(/10\.1\.2\.3|private|IP literal|not an allowed/i);
    // Nothing was written: the two bench channels are still the document.
    const unchanged = await api(page, 'GET', `${API}/notifications/settings`);
    expect(benchIds(unchanged.channels)).toEqual([CHANNEL_A, CHANNEL_B]);

    const ghost = { id: CHANNEL_GHOST, name: 'WAM e2e ghost config', kind: 'indexer_channel', enabled: true, events: [], indexer_channel: { configId: 'wam-e2e-no-such-config' } };
    const saved = await putSettings([directChannel(), indexerChannel(), ghost]);
    expect(saved.channels.find((channel: any) => channel.id === CHANNEL_GHOST)).toMatchObject({ kind: 'indexer_channel', enabled: true, indexer_channel: { configId: 'wam-e2e-no-such-config' } });

    const result = await api(page, 'POST', `${API}/notifications/test/${CHANNEL_GHOST}`);
    expect(result).toMatchObject({ channelId: CHANNEL_GHOST, kind: 'indexer_channel', ok: false });
    expect(result.error, JSON.stringify(result)).toBeTruthy();
    expect(result.durationMs).toBeGreaterThanOrEqual(0);

    const missing = await apiRaw(page, 'POST', `${API}/notifications/test/wam-e2e-not-saved`);
    expect(missing.status).toBe(404);

    // The UI surfaces the failure as a badge, not a crash.
    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'notifications');
    const row = page.locator(`[data-test-subj="wamNotifChannel-${CHANNEL_GHOST}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.locator(`[data-test-subj="wamNotifTest-${CHANNEL_GHOST}"]`).click();
    await expect(row.locator(`[data-test-subj="wamNotifTestResult-${CHANNEL_GHOST}"]`)).toHaveText('Failed', { timeout: 30_000 });
    await expect(page.locator('[data-test-subj="wamNotifSettings"]')).toBeVisible();
  });

  test('an SLA escalation whose notify names the direct channel delivers sla.escalated and the outbox records it', async () => {
    test.setTimeout(480_000);
    expect(ruleId, 'previous step creates the notify rule').not.toBe('');
    // The rule assigns every seeded alert at ingestion, which would defeat an
    // `unassigned` escalation: disable it first.
    const tokens = await ruleTokens(ruleId);
    const disabled = await api(page, 'PUT', `${API}/rules/${encodeURIComponent(ruleId)}`, { enabled: false, ...tokens });
    expect(disabled.enabled).toBe(false);

    // Same shape as trial_sla.spec.ts: 1-minute targets for the seeded band
    // and one alert escalation at 50 % (= 30 s) on unassigned alerts, here
    // with `notify: [CHANNEL_A]`.
    const current = await api(page, 'GET', `${API}/sla/policy`);
    expect(current.policy.targets).toHaveProperty(SLA_BAND);
    savedPolicy = { targets: current.policy.targets, escalations: current.policy.escalations || [] };
    const saved = await api(page, 'PUT', `${API}/sla/policy`, {
      targets: { ...current.policy.targets, [SLA_BAND]: { resolveMinutes: 1, assignMinutes: 1 } },
      escalations: [
        ...(current.policy.escalations || []).filter((entry: any) => entry.id !== SLA_ESCALATION_ID),
        {
          id: SLA_ESCALATION_ID,
          name: SLA_ESCALATION_NAME,
          target: 'alert',
          thresholdPercent: 50,
          condition: 'unassigned',
          actions: { assignTo: SLA_ASSIGNEE, notify: [CHANNEL_A] },
          enabled: true,
        },
      ],
    });
    expect(saved.policy.escalations.find((entry: any) => entry.id === SLA_ESCALATION_ID)).toMatchObject({ actions: { assignTo: SLA_ASSIGNEE, notify: [CHANNEL_A] } });

    const seed = seedAlerts({ count: 1 });
    const fromRun = fromSeedRun(seed.run);
    const projected = await waitForProjectedAlert(page, fromRun, { agentName: AGENT_NAME });
    seededIds.push(projected._id);
    const alertId = projected._id;

    // The scanner ticks every 60 s; the alert is eligible 30 s after @timestamp.
    const escalated = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter((row: any) => row._id === alertId);
        return rows.find((hit: any) => (hit._source?.sla?.escalated || []).includes(SLA_ESCALATION_ID)) || null;
      },
      { label: 'the seeded alert escalated', timeoutMs: 240_000, pollMs: 10_000 }
    );
    expect(escalated._source.assigned_to).toBe(SLA_ASSIGNEE);

    const outboxId = `sla:sla.escalated:alert:${alertId}:${SLA_ESCALATION_ID}:${CHANNEL_A}`;
    const entry = await pollUntil(
      page,
      async () => {
        const result = await api(page, 'GET', `${API}/notifications/outbox?event=sla.escalated&channelId=${CHANNEL_A}&limit=50`);
        return (result.items || []).find((item: any) => item.id === outboxId && item.status === 'sent') || null;
      },
      { label: `outbox ${outboxId} sent`, timeoutMs: DELIVERY_BUDGET_MS, pollMs: 3_000 }
    );
    expect(entry).toMatchObject({ event: 'sla.escalated', channel_kind: 'webhook', target_type: 'alert', target_id: alertId, last_error: null });
    expect(entry.delivery).toMatchObject({ transport: 'webhook', statusCode: 200 });

    const delivered = await receiver.waitFor((request) => request.path === '/direct' && request.json?.event === 'sla.escalated' && request.json?.alert?.id === alertId, 15_000, 'sla.escalated delivery');
    expect(delivered.headers['x-wam-event']).toBe('sla.escalated');
    expect(delivered.headers['x-wam-delivery']).toBe(entry.delivery.deliveryId);
    expect(verifySignature(delivered, SECRET)).toBe(true);
    expect(delivered.json.escalation).toMatchObject({ id: SLA_ESCALATION_ID, name: SLA_ESCALATION_NAME });
    expect(delivered.json.alert).toMatchObject({ id: alertId, agent: { name: AGENT_NAME }, assigned_to: SLA_ASSIGNEE });
  });
});
