import { expect, Page, test } from '@playwright/test';
import { API, api, apiRaw, applyQueueFilters, fromSeedRun, openAlertFlyout, openSettingsSection, pollUntil, queueRow, queueRowCell, seedAlerts, signIn } from './helpers';

/**
 * Phase 3 bench (PLAN.md 3.5): SLA targets, due timestamps, breach history and
 * escalation auto-assign on a live stack.
 *
 * The seeder writes `rule.level = 10` (e2e/seed_alerts.py), which is the
 * `high` band of common/severity.ts (7-11), so the bench sets a 1-minute
 * resolve and assign target for `high` plus one alert escalation at 50 % of
 * the resolve target (= 30 s) on unassigned alerts. The scanner ticks every
 * 60 s (`wazuh_alert_manager.sla.escalation.tickSeconds`), so after at most
 * two ticks a seeded alert is both escalated (assigned to `wam-e2e-sla`,
 * `sla.escalated` marker, `sla_escalated` history row) and breached
 * (`sla.breached_at`, one `sla_breached` history row).
 *
 * Mutating: it replaces the SLA policy (restored afterwards; every open
 * unassigned high-band alert of the stack breaches and is escalated while the
 * 1-minute policy is in force, so afterAll closes every alert the escalation
 * assigned to `wam-e2e-sla`, not only the seeded ones) and seeds alerts.
 */

const AGENT_NAME = 'wam-e2e-agent';
const SEEDED_BAND = 'high' as const;
const ESCALATION_ID = 'wam-e2e-sla';
const ESCALATION_NAME = 'WAM e2e escalation';
const ESCALATION_ASSIGNEE = 'wam-e2e-sla';
const QUEUE_QUERY = `${API}/alerts?from_offset=0&size=50&sortField=@timestamp&sortDirection=desc&agentNames=${AGENT_NAME}`;
const MINUTE_MS = 60_000;

const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;

test.describe.configure({ mode: 'serial' });

test.describe('trial: SLA targets, breach and escalation', () => {
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 to run the mutating SLA bench.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  let page: Page;
  let savedPolicy: { targets: any; escalations: any[] } | null = null;
  let seededIds: string[] = [];
  let seededHits: any[] = [];
  let escalatedId = '';

  test.beforeAll(async ({ browser }) => {
    // signIn alone waits up to 3 x 60 s on a slow stack; Playwright's default hook budget is 30 s.
    test.setTimeout(120_000);
    page = await browser.newPage();
    await signIn(page, username!, password!);
  });

  test.afterAll(async () => {
    try {
      if (savedPolicy) await api(page, 'PUT', `${API}/sla/policy`, savedPolicy);
    } catch (e) {
      console.warn(`could not restore the SLA policy: ${String(e)}`);
    }
    try {
      // Close the seeded alerts and everything the 1-minute escalation
      // auto-assigned meanwhile so nothing of this run stays in the breached set.
      const assigned = await api(page, 'GET', `${API}/alerts?from_offset=0&size=500&statuses=open,in_progress&assignedTo=${ESCALATION_ASSIGNEE}`);
      const ids = Array.from(new Set([...seededIds, ...((assigned?.hits?.hits || []).map((hit: any) => hit._id as string))]));
      if (ids.length) await api(page, 'POST', `${API}/alerts/bulk-update`, { ids, status: 'closed' });
    } catch (e) {
      console.warn(`could not close the escalated alerts: ${String(e)}`);
    }
    await page?.close();
  });

  test('the policy defaults are served; a 1-minute policy with one escalation saves and shows in Settings > SLA', async () => {
    test.setTimeout(120_000);
    const current = await api(page, 'GET', `${API}/sla/policy`);
    expect(current.defaults.targets).toMatchObject({
      critical: { resolveMinutes: 60, assignMinutes: 15 },
      high: { resolveMinutes: 240, assignMinutes: 60 },
      medium: { resolveMinutes: 1440, assignMinutes: 360 },
      low: { resolveMinutes: 4320, assignMinutes: 1080 },
    });
    expect(current.policy.targets).toHaveProperty(SEEDED_BAND);
    savedPolicy = { targets: current.policy.targets, escalations: current.policy.escalations || [] };

    const policy = {
      targets: { ...current.policy.targets, [SEEDED_BAND]: { resolveMinutes: 1, assignMinutes: 1 } },
      escalations: [
        ...(current.policy.escalations || []).filter((entry: any) => entry.id !== ESCALATION_ID),
        {
          id: ESCALATION_ID,
          name: ESCALATION_NAME,
          target: 'alert',
          thresholdPercent: 50,
          condition: 'unassigned',
          actions: { assignTo: ESCALATION_ASSIGNEE, comment: 'SLA escalation {{escalation}} on {{id}}' },
          enabled: true,
        },
      ],
    };
    const saved = await api(page, 'PUT', `${API}/sla/policy`, policy);
    expect(saved.policy.targets[SEEDED_BAND]).toEqual({ resolveMinutes: 1, assignMinutes: 1 });
    expect(saved.policy.escalations.find((entry: any) => entry.id === ESCALATION_ID)).toMatchObject({
      name: ESCALATION_NAME,
      target: 'alert',
      thresholdPercent: 50,
      condition: 'unassigned',
      enabled: true,
      actions: { assignTo: ESCALATION_ASSIGNEE },
    });
    expect(saved.updated_by).toBe(username);
    const reread = await api(page, 'GET', `${API}/sla/policy`);
    expect(reread.policy.targets[SEEDED_BAND]).toEqual({ resolveMinutes: 1, assignMinutes: 1 });

    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'sla');
    const targets = page.locator('[data-test-subj="wamSlaTargets"]');
    await expect(targets).toBeVisible({ timeout: 30_000 });
    await expect(page.locator(`[data-test-subj="wamSla-${SEEDED_BAND}-resolveMinutes"]`)).toHaveValue('1');
    await expect(page.locator(`[data-test-subj="wamSla-${SEEDED_BAND}-assignMinutes"]`)).toHaveValue('1');
    const row = page.locator(`[data-test-subj="wamSlaEscalation-${ESCALATION_ID}"]`);
    await expect(row).toBeVisible();
    await expect(row).toContainText(ESCALATION_NAME);
    await expect(row).toContainText('50% of resolve target');
    await expect(row).toContainText(ESCALATION_ASSIGNEE);
  });

  test('seeded alerts are projected with due dates one minute after @timestamp and the queue shows the Due column', async () => {
    test.setTimeout(360_000);
    const seed = seedAlerts({ count: 2 });
    const fromRun = fromSeedRun(seed.run);
    // The seeder stamps now+2s plus a per-doc offset, so the second record may
    // only land on the next sync tick: wait for both.
    seededHits = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter(fromRun);
        return rows.length === 2 ? rows : null;
      },
      { label: 'both seeded alerts projected', timeoutMs: 180_000, pollMs: 5_000 }
    );
    seededIds = seededHits.map((hit: any) => hit._id as string);

    for (const hit of seededHits) {
      const source = hit._source;
      expect(source.rule?.level).toBe(10);
      const timestamp = Date.parse(source['@timestamp']);
      expect(Number.isFinite(timestamp)).toBe(true);
      expect(typeof source.reporting?.sla_due_at).toBe('string');
      expect(typeof source.reporting?.assign_due_at).toBe('string');
      expect(Date.parse(source.reporting.sla_due_at) - timestamp).toBe(MINUTE_MS);
      expect(Date.parse(source.reporting.assign_due_at) - timestamp).toBe(MINUTE_MS);
      // The escalation scanner may already have auto-assigned the alert (eligible 30 s after
      // @timestamp under the 1-minute policy); test 3 asserts the assignment itself.
      expect([null, ESCALATION_ASSIGNEE]).toContain(source.assigned_to ?? null);
    }

    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    const row = queueRow(page, seededIds[0]);
    await expect(row).toBeVisible({ timeout: 60_000 });
    const due = queueRowCell(page, seededIds[0], '[data-test-subj="wamAlertDue"]');
    await expect(due).toBeVisible();
    // One minute after the seed the countdown is either still running or
    // already overdue; either way it is a dated cell, never the "-" of an
    // undated record.
    await expect(due).toHaveAttribute('data-sla-state', /^(on_track|due_soon|breached)$/);
    await expect(due.locator('.wamSlaDue__text')).toHaveText(/(\d+m left|\d+m overdue|due in)/);
  });

  test('the scanner escalates (auto-assign + sla_escalated) and then breaches the alert exactly once', async () => {
    test.setTimeout(480_000);
    expect(seededIds.length, 'previous step seeds the alerts').toBe(2);
    const fromRun = (hit: any) => seededIds.includes(hit._id);
    const readSeeded = async () => ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter(fromRun);

    const escalated = await pollUntil(
      page,
      async () => {
        const rows = await readSeeded();
        return rows.find((hit: any) => (hit._source?.sla?.escalated || []).includes(ESCALATION_ID)) || null;
      },
      { label: 'a seeded alert escalated', timeoutMs: 180_000, pollMs: 10_000 }
    );
    escalatedId = escalated._id;
    expect(escalated._source.assigned_to).toBe(ESCALATION_ASSIGNEE);
    expect(escalated._source.status).toBe('in_progress');
    const history: any[] = escalated._source.history || [];
    const escalationRows = history.filter((entry) => entry.action === 'sla_escalated');
    expect(escalationRows).toHaveLength(1);
    expect(escalationRows[0]).toMatchObject({ from: ESCALATION_ID, to: ESCALATION_NAME });
    expect(history.some((entry) => entry.action === 'assignment_change' && entry.to === ESCALATION_ASSIGNEE)).toBe(true);
    expect(history.some((entry) => entry.action === 'comment_added')).toBe(true);

    const breached = await pollUntil(
      page,
      async () => {
        const rows = await readSeeded();
        const hit = rows.find((row: any) => row._id === escalatedId);
        return hit?._source?.sla?.breached_at ? hit : null;
      },
      { label: 'the escalated alert breached', timeoutMs: 180_000, pollMs: 10_000 }
    );
    expect(Number.isFinite(Date.parse(breached._source.sla.breached_at))).toBe(true);
    const breachRows = (breached._source.history || []).filter((entry: any) => entry.action === 'sla_breached');
    expect(breachRows).toHaveLength(1);
    expect(breachRows[0].to).toBe(breached._source.reporting.sla_due_at);
    // The marker is applied once: a later tick must not re-apply the escalation.
    expect((breached._source.history || []).filter((entry: any) => entry.action === 'sla_escalated')).toHaveLength(1);

    // Breached quick filter + badge in the queue.
    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    await page.locator('[data-test-subj="wamSlaFilter-breached"]').click();
    await applyQueueFilters(page);
    const row = queueRow(page, escalatedId);
    await expect(row).toBeVisible({ timeout: 60_000 });
    const due = queueRowCell(page, escalatedId, '[data-test-subj="wamAlertDue"]');
    await expect(due).toHaveAttribute('data-sla-state', 'breached');
    await expect(due.locator('[data-test-subj="wamAlertDueBadge"]')).toHaveText('Breached');

    // Flyout: "Escalated" line with the escalation name, both history rows.
    const flyout = await openAlertFlyout(page, escalatedId);
    const escalatedLine = flyout.locator('[data-test-subj="wamAlertFlyoutEscalated"]');
    await expect(escalatedLine).toBeVisible({ timeout: 30_000 });
    await expect(escalatedLine).toContainText('Escalated');
    await expect(escalatedLine).toContainText(ESCALATION_NAME, { timeout: 30_000 });
    await expect(flyout.locator('[data-test-subj="wamAlertFlyoutDueBadge"]')).toHaveText('Breached');
    await flyout.locator('[data-test-subj="wamAlertNav-history"]').click();
    await expect(flyout).toContainText('applied an SLA escalation');
    await expect(flyout).toContainText('SLA breached (resolve target passed)');
  });

  test('report metrics for the last hour count the breach and the escalation', async () => {
    test.setTimeout(120_000);
    expect(escalatedId, 'previous step escalates an alert').not.toBe('');
    const to = new Date();
    const from = new Date(to.getTime() - 60 * MINUTE_MS);
    const metrics = await api(page, 'GET', `${API}/reports/metrics?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`);
    expect(metrics.slaCurrentlyBreached.alerts).toBeGreaterThanOrEqual(1);
    expect(metrics.slaCurrentlyBreached.byBand[SEEDED_BAND]).toBeGreaterThanOrEqual(1);
    expect(metrics.slaBreachesInPeriod.alerts).toBeGreaterThanOrEqual(1);
    expect(metrics.slaEscalationsInPeriod.total).toBeGreaterThanOrEqual(1);
    expect(metrics.slaEscalationsInPeriod.byEscalation).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: ESCALATION_ID, name: ESCALATION_NAME })])
    );
  });

  test('an administrator can run the due-date backfill and read its finished run', async () => {
    test.setTimeout(180_000);
    const started = await apiRaw(page, 'POST', `${API}/sla/backfill`);
    expect([200, 202], started.text.slice(0, 300)).toContain(started.status);
    const startedStatus = JSON.parse(started.text).status;
    expect(['running', 'skipped', 'completed', 'partial']).toContain(startedStatus.status);

    const finished = await pollUntil(
      page,
      async () => {
        const status = (await api(page, 'GET', `${API}/sla/backfill`))?.status;
        return status && status.finished_at && status.status !== 'running' ? status : null;
      },
      { label: 'backfill run finished', timeoutMs: 120_000, pollMs: 3_000 }
    );
    expect(['completed', 'partial']).toContain(finished.status);
    expect(finished.failures).toBe(0);
    expect(finished.error ?? null).toBeNull();
    expect(Number.isFinite(Date.parse(finished.started_at))).toBe(true);
  });
});
