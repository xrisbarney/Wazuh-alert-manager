import { expect, Page, test } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as path from 'path';

const API = '/api/wazuh_alert_manager';

function emitAutomationFixtures() {
  const vagrantDir = process.env.WAM_E2E_VAGRANT_DIR || path.resolve(process.cwd(), '..', '..', 'wazuh414-vagrant');
  const remote = [
    'cd /home/vagrant/wazuh-alert-manager-src',
    'set -a',
    '. ./.env.e2e.local',
    'set +a',
    'export WAM_USER="$WAM_E2E_USERNAME" WAM_PW="$WAM_E2E_PASSWORD"',
    'python3 e2e/seed_alerts.py',
  ].join(' && ');
  execFileSync('vagrant', ['ssh', '-c', remote], { cwd: vagrantDir, stdio: 'pipe', timeout: 120_000 });
}

async function signIn(page: Page) {
  await page.goto('/app/wazuh-alert-manager');
  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(process.env.WAM_E2E_USERNAME!);
    await page.locator('[data-test-subj="password"]').fill(process.env.WAM_E2E_PASSWORD!);
    await page.locator('[data-test-subj="submit"]').click();
  }
  await expect(page).toHaveURL(/\/app\/wazuh-alert-manager/, { timeout: 60_000 });
  await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 60_000 });
}

async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json', 'osd-xsrf': 'wam-e2e' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${JSON.stringify(payload)}`);
    return payload;
  }, { method, path, body });
}

async function openAutomation(page: Page) {
  await page.getByRole('tab', { name: 'Settings' }).click();
  await page.getByRole('tab', { name: 'Automation rules' }).click();
  await expect(page.getByRole('button', { name: 'New rule' }).first()).toBeVisible({ timeout: 60_000 });
}

async function cleanupNamedRules(page: Page, names: string[]) {
  const result: any = await api(page, 'GET', `${API}/rules?size=100`);
  for (const rule of result.rules || []) {
    if (!names.includes(rule.name)) continue;
    const query = new URLSearchParams({
      revision: String(rule.revision),
      if_seq_no: String(rule.if_seq_no),
      if_primary_term: String(rule.if_primary_term),
    });
    await api(page, 'DELETE', `${API}/rules/${encodeURIComponent(rule.id)}?${query}`);
  }
}

async function saveDraft(page: Page, name: string, kind: 'immediate' | 'burst' | 'complex') {
  await page.getByRole('button', { name: 'New rule' }).first().click();
  const flyout = page.locator('.wamRuleFlyout');
  await expect(flyout.getByRole('heading', { name: 'New automation rule' })).toBeVisible();
  await flyout.getByLabel('Name').fill(name);

  await flyout.getByRole('tab', { name: '2. Match' }).click();
  await flyout.getByLabel('Minimum level').fill('0');

  await flyout.getByRole('tab', { name: '3. Trigger' }).click();
  if (kind !== 'immediate') await flyout.getByText('Correlated burst', { exact: true }).click();
  await flyout.getByRole('button', { name: 'Add OR group' }).click();
  await flyout.getByRole('button', { name: 'Add AND predicate' }).click();
  await flyout.getByLabel('Value').fill(kind === 'immediate' ? '203.0.113.77' : '203.0.113.88');

  if (kind === 'burst') {
    await flyout.getByRole('button', { name: 'Add OR group' }).click();
    await flyout.getByRole('button', { name: 'Add AND predicate' }).last().click();
    await flyout.getByLabel('Value').nth(1).fill('203.0.113.89');
  }

  if (kind === 'complex') {
    await flyout.getByRole('button', { name: 'Add AND predicate' }).click();
    const entities = flyout.getByLabel('Entity');
    await entities.nth(1).selectOption('dstport');
    await flyout.getByLabel('Value').nth(1).fill('22');
    await flyout.getByRole('button', { name: 'Add OR group' }).click();
    await flyout.getByRole('button', { name: 'Add AND predicate' }).last().click();
    await flyout.getByLabel('Value').nth(2).fill('203.0.113.89');
  }

  if (kind !== 'immediate') {
    await flyout.getByLabel('Threshold').fill('2');
    await flyout.getByLabel('Window (minutes)').fill('10');
    await flyout.getByLabel('Cooldown (minutes)').fill('2');
    await flyout.getByLabel('Rearm after quiet (minutes)').fill('2');
    await flyout.getByLabel('Case routing').selectOption(kind === 'complex' ? 'consolidate_overlapping' : 'separate_by_group');
  }

  await flyout.getByRole('tab', { name: '4. Actions' }).click();
  await flyout.getByLabel('Set status').selectOption('in_progress');
  await flyout.getByLabel('Create or update a deduplicated case').check();
  await flyout.getByLabel('Case severity').selectOption(kind === 'complex' ? 'critical' : 'high');
  await flyout.getByText('Open', { exact: true }).last().click();
  await flyout.getByLabel('Assignment precondition').selectOption('any');
  await flyout.getByLabel('After this rule').selectOption(kind === 'complex' ? 'stop' : 'continue');

  await flyout.getByRole('tab', { name: '5. Safety' }).click();
  await flyout.getByLabel('Maximum actions per run').fill('25');
  await flyout.getByLabel('Maximum cases per run').fill('10');
  await flyout.getByLabel('Rate limit executions').check();
  await flyout.getByLabel('Maximum executions').fill('100');
  await flyout.getByLabel('Window (minutes)').fill('60');

  await flyout.getByRole('tab', { name: '6. Preview' }).click();
  await flyout.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByText('Draft rule saved', { exact: true })).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: 'Dismiss toast' }).click();
  await expect(page.getByText(name, { exact: true })).toBeVisible({ timeout: 60_000 });
}

async function previewAndEnable(page: Page, name: string) {
  // Re-enter from the persisted list, matching the documented draft -> reopen
  // activation workflow and avoiding any transient post-save animation state.
  await page.reload();
  const editButton = page.getByRole('button', { name: `Edit ${name}` });
  await expect(editButton).toBeEnabled({ timeout: 60_000 });
  await editButton.click();
  const flyout = page.locator('.wamRuleFlyout');
  await expect(flyout.getByRole('tab', { name: '6. Preview' })).toBeVisible({ timeout: 60_000 });
  await flyout.getByRole('tab', { name: '6. Preview' }).click();
  await flyout.getByRole('button', { name: 'Preview last 24 hours' }).click();
  await expect(flyout.getByText(/Preview passed:/)).toBeVisible({ timeout: 120_000 });
  await flyout.getByLabel('Enable after save').check();
  await flyout.getByRole('button', { name: 'Save and enable' }).click();
  await expect(page.getByText('Rule saved and enabled', { exact: true })).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: 'Dismiss toast' }).click();
}

test.describe('full workbench UI bench', () => {
  test.skip(process.env.WAM_E2E_MUTATING !== '1', 'Set WAM_E2E_MUTATING=1 for the disposable full UI bench.');

  test('automation edit control opens the saved rule wizard', async ({ page }) => {
    await signIn(page);
    await openAutomation(page);
    const name = 'E2E immediate entity rule';
    const rules: any = await api(page, 'GET', `${API}/rules?size=100`);
    const rule = rules.rules.find((item: any) => item.name === name);
    test.skip(!rule, 'Run the automation matrix once to leave its retry fixture.');
    console.log(`WAM_RULE_PROBE=${JSON.stringify({ id: rule.id, revision: rule.revision, trigger: rule.trigger, actions: rule.actions })}`);
    const editButton = page.getByRole('button', { name: `Edit ${name}` });
    await expect(editButton).toBeEnabled({ timeout: 60_000 });
    await editButton.click();
    await expect(page.locator('.wamRuleFlyout')).toBeVisible({ timeout: 30_000 });
  });

  test('manual case creation, evidence, comments, graph, and close work through the UI', async ({ page }) => {
    test.setTimeout(300_000);
    await signIn(page);
    const title = `E2E manual case ${Date.now()}`;

    const firstRow = page.locator('.wamAlertTable tbody tr').first();
    await expect(firstRow).toBeVisible({ timeout: 60_000 });
    await firstRow.locator('input[type="checkbox"]').check();
    await page.getByRole('button', { name: 'Create case from selected' }).click();
    await page.getByLabel('Title').fill(title);
    await page.getByLabel('Description').fill('Created through the release browser bench');
    await page.getByLabel('Severity').selectOption('high');
    await page.getByRole('button', { name: 'Create case', exact: true }).click();
    await expect(page.getByText('Case created', { exact: true })).toBeVisible({ timeout: 60_000 });

    const flyout = page.locator('.wamCaseFlyout');
    await expect(flyout.getByText(title, { exact: true })).toBeVisible();

    await flyout.getByRole('tab', { name: 'Comments' }).click();
    await flyout.getByPlaceholder('Add a comment...').fill('E2E analyst investigation note');
    await flyout.getByRole('button', { name: 'Add comment' }).click();
    await expect(flyout.getByText('E2E analyst investigation note')).toBeVisible({ timeout: 30_000 });

    await flyout.getByRole('tab', { name: /Linked Alerts/ }).click();
    const holdButton = flyout.getByRole('button', { name: 'Set evidence hold' }).first();
    await expect(holdButton).toBeVisible({ timeout: 30_000 });
    await holdButton.click();
    await page.getByLabel('Hold reason').fill('E2E preservation check');
    await page.getByRole('button', { name: 'Place hold' }).click();
    await expect(flyout.getByText('Held', { exact: true })).toBeVisible({ timeout: 30_000 });
    await flyout.getByRole('button', { name: 'Release evidence hold' }).first().click();

    await flyout.getByRole('tab', { name: 'Attack Graph' }).click();
    await expect(flyout.getByText('Entity relationships and MITRE ATT&CK context derived from this case\'s linked alerts.')).toBeVisible({ timeout: 60_000 });
    await flyout.getByText('Alert timeline', { exact: true }).click();
    await expect(flyout.getByRole('heading', { name: 'Alert chronology' })).toBeVisible();

    await flyout.getByRole('tab', { name: 'Overview' }).click();
    await flyout.getByText('In progress', { exact: true }).last().click();
    await expect(page.getByText('Case set to In progress', { exact: true })).toBeVisible({ timeout: 30_000 });
    await flyout.getByText('Closed', { exact: true }).last().click();
    await page.getByRole('button', { name: /Close case/ }).last().click();
    await expect(page.getByText('Case closed', { exact: true })).toBeVisible({ timeout: 60_000 });
  });

  test('case table title link opens the selected case details', async ({ page }) => {
    test.setTimeout(120_000);
    await signIn(page);
    const alerts: any = await api(page, 'GET', `${API}/alerts?from_offset=0&size=1`);
    const alertId = alerts.hits?.hits?.[0]?._id;
    expect(alertId).toBeTruthy();
    const title = `E2E row-open case ${Date.now()}`;
    const created: any = await api(page, 'POST', `${API}/cases`, {
      title, description: 'Case row activation regression fixture', severity: 'medium', alertIds: [alertId], assignedTo: null,
    });

    await page.getByRole('tab', { name: 'Cases' }).click();
    await page.getByPlaceholder('Search by title/description').fill(title);
    await page.getByRole('button', { name: 'Refresh' }).click();
    const caseControl = page.getByRole('button', { name: title, exact: true });
    await expect(caseControl).toBeVisible({ timeout: 60_000 });
    await caseControl.click();
    await expect(page.locator('.wamCaseFlyout').getByText(title, { exact: true })).toBeVisible({ timeout: 60_000 });

    const closed: any = await api(page, 'POST', `${API}/cases/${encodeURIComponent(created.id)}/close`, { excludeAlertIds: [] });
    expect(closed.caseClosed).toBe(true);
  });

  test('case severity and assignee filters support multi-select combinations', async ({ page }) => {
    test.setTimeout(180_000);
    await signIn(page);
    const alerts: any = await api(page, 'GET', `${API}/alerts?from_offset=0&size=2`);
    const alertIds = (alerts.hits?.hits || []).map((hit: any) => hit._id);
    expect(alertIds.length).toBeGreaterThanOrEqual(2);
    const marker = `E2E case filters ${Date.now()}`;
    const high: any = await api(page, 'POST', `${API}/cases`, {
      title: `${marker} high assigned`, severity: 'high', alertIds: [alertIds[0]], assignedTo: 'admin',
    });
    const low: any = await api(page, 'POST', `${API}/cases`, {
      title: `${marker} low unassigned`, severity: 'low', alertIds: [alertIds[1]], assignedTo: null,
    });

    const assigned: any = await api(page, 'GET', `${API}/cases?status=open,in_progress&severity=high&assignedTo=admin&q=${encodeURIComponent(marker)}`);
    expect(assigned.cases.map((item: any) => item.id)).toEqual([high.id]);
    const unassigned: any = await api(page, 'GET', `${API}/cases?status=open,in_progress&assignedTo=__unassigned__&q=${encodeURIComponent(marker)}`);
    expect(unassigned.cases.map((item: any) => item.id)).toEqual([low.id]);

    await page.getByRole('tab', { name: 'Cases' }).click();
    await page.getByPlaceholder('Search by title/description').fill(marker);
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText(`${marker} high assigned`, { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(`${marker} low unassigned`, { exact: true })).toBeVisible();

    const severity = page.getByLabel('Filter cases by severity');
    await severity.click();
    await page.getByRole('option', { name: 'High', exact: true }).click();
    await expect(page.getByText(`${marker} high assigned`, { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(`${marker} low unassigned`, { exact: true })).toHaveCount(0);
    await severity.click();
    await page.getByRole('option', { name: 'Low', exact: true }).click();
    await expect(page.getByText(`${marker} low unassigned`, { exact: true })).toBeVisible({ timeout: 60_000 });

    const assignee = page.getByLabel('Filter cases by assignee');
    await assignee.click();
    await page.getByRole('option', { name: 'admin', exact: true }).click();
    await expect(page.getByText(`${marker} high assigned`, { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(`${marker} low unassigned`, { exact: true })).toHaveCount(0);

    for (const caseId of [high.id, low.id]) {
      const closed: any = await api(page, 'POST', `${API}/cases/${encodeURIComponent(caseId)}/close`, { excludeAlertIds: [] });
      expect(closed.caseClosed).toBe(true);
    }
  });

  test('automation editor supports immediate, burst, boolean entities, actions, safety, preview, and activation', async ({ page }) => {
    test.setTimeout(600_000);
    const names = ['E2E immediate entity rule', 'E2E burst entity rule', 'E2E complex boolean draft'];
    await signIn(page);
    await openAutomation(page);
    await cleanupNamedRules(page, names);
    await page.getByRole('button', { name: 'Refresh runtime' }).click();

    await saveDraft(page, names[0], 'immediate');
    await previewAndEnable(page, names[0]);
    await saveDraft(page, names[1], 'burst');
    await previewAndEnable(page, names[1]);
    await saveDraft(page, names[2], 'complex');

    const result: any = await api(page, 'GET', `${API}/rules?size=100`);
    const immediate = result.rules.find((rule: any) => rule.name === names[0]);
    const burst = result.rules.find((rule: any) => rule.name === names[1]);
    const complex = result.rules.find((rule: any) => rule.name === names[2]);
    expect(immediate).toEqual(expect.objectContaining({ enabled: true, trigger: expect.objectContaining({ type: 'per_alert' }) }));
    expect(immediate.actions).toEqual(expect.objectContaining({ createCase: true, setStatus: 'in_progress' }));
    expect(burst).toEqual(expect.objectContaining({ enabled: true, trigger: expect.objectContaining({ type: 'burst', threshold: 2, routing: 'separate_by_group' }) }));
    expect(complex.trigger.entityExpression.groups).toHaveLength(2);
    expect(complex.trigger.entityExpression.groups[0].predicates).toHaveLength(2);
    expect(complex.processingMode).toBe('stop');
    expect(complex.safety.rateLimit).toEqual({ maxExecutions: 100, windowMinutes: 60 });
    console.log('WAM_E2E_AUTOMATION_RULES_READY=1');
  });

  test('ingestion-time automation deduplicates immediate work and routes burst groups separately', async ({ page }) => {
    test.setTimeout(420_000);
    await signIn(page);

    const configured: any = await api(page, 'GET', `${API}/rules?size=100`);
    for (const name of ['E2E immediate entity rule', 'E2E burst entity rule']) {
      expect(configured.rules.find((rule: any) => rule.name === name && rule.enabled)).toBeTruthy();
    }
    emitAutomationFixtures();

    const findCases = async (name: string) => {
      const result: any = await api(page, 'GET', `${API}/cases?status=open,in_progress&size=100&q=${encodeURIComponent(name)}`);
      return (result.cases || []).filter((item: any) => item.title === `${name}: automated incident`);
    };

    await expect.poll(async () => {
      const cases = await findCases('E2E immediate entity rule');
      return cases.length === 1 ? cases[0].alert_ids.length : 0;
    }, {
      timeout: 300_000,
      intervals: [5_000, 10_000, 15_000],
      message: 'The immediate rule should create one active case and deduplicate both newly ingested .77 alerts into it.',
    }).toBeGreaterThanOrEqual(2);
    await expect.poll(async () => {
      const cases = await findCases('E2E burst entity rule');
      return cases.length === 2 && cases.every((item: any) => item.alert_ids.length >= 2);
    }, {
      timeout: 300_000,
      intervals: [5_000, 10_000, 15_000],
      message: 'The two burst entity groups should each create their own case with the threshold evidence linked.',
    }).toBe(true);

    const immediate = (await findCases('E2E immediate entity rule'))[0];
    const bursts = await findCases('E2E burst entity rule');
    expect(immediate.alert_ids.length).toBeGreaterThanOrEqual(2);
    expect(bursts.every((item: any) => item.alert_ids.length >= 2)).toBe(true);
    expect(new Set(bursts.map((item: any) => item.correlation_key)).size).toBe(2);

    await page.getByRole('tab', { name: 'Cases' }).click();
    await page.getByPlaceholder('Search by title/description').fill('E2E burst entity rule');
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText('E2E burst entity rule: automated incident', { exact: true })).toHaveCount(2, { timeout: 60_000 });
    await page.getByRole('button', { name: 'E2E burst entity rule: automated incident', exact: true }).first().click();
    await expect(page.locator('.wamCaseFlyout').getByRole('tab', { name: /Linked Alerts/ })).toBeVisible({ timeout: 60_000 });

    // Disable/delete fixtures after observing their effects; existing cases remain
    // as auditable closed work and no future incoming alert is affected.
    await cleanupNamedRules(page, ['E2E immediate entity rule', 'E2E burst entity rule', 'E2E complex boolean draft']);
    for (const caseDoc of [immediate, ...bursts]) {
      const result: any = await api(page, 'POST', `${API}/cases/${encodeURIComponent(caseDoc.id)}/close`, { excludeAlertIds: [] });
      expect(result.caseClosed).toBe(true);
    }
    console.log(`WAM_E2E_AUTOMATION_OUTCOME=${JSON.stringify({ immediateAlerts: immediate.alert_ids.length, burstCases: bursts.length, burstAlerts: bursts.map((item: any) => item.alert_ids.length) })}`);
  });

  test('automation ingestion diagnostics expose every pipeline boundary', async ({ page }) => {
    await signIn(page);
    const [health, queue, rules, alerts77, alerts88, immediateCases, burstCases] = await Promise.all([
      api(page, 'GET', `${API}/system/health`),
      api(page, 'GET', `${API}/system/automation/queue`),
      api(page, 'GET', `${API}/rules?size=100`),
      api(page, 'GET', `${API}/alerts?from_offset=0&size=20&q=${encodeURIComponent('data.srcip:"203.0.113.77"')}`),
      api(page, 'GET', `${API}/alerts?from_offset=0&size=20&q=${encodeURIComponent('data.srcip:"203.0.113.88" OR data.srcip:"203.0.113.89"')}`),
      api(page, 'GET', `${API}/cases?size=100&q=${encodeURIComponent('E2E immediate entity rule')}`),
      api(page, 'GET', `${API}/cases?size=100&q=${encodeURIComponent('E2E burst entity rule')}`),
    ]);
    console.log(`WAM_AUTOMATION_DIAGNOSTICS=${JSON.stringify({
      sync: health.sync,
      counts: health.counts,
      automation: health.automation,
      queue,
      rules: rules.rules.filter((rule: any) => rule.name.startsWith('E2E ')).map((rule: any) => ({ name: rule.name, enabled: rule.enabled, revision: rule.revision, lastFiredAt: rule.lastFiredAt, counters: rule.counters })),
      alert77Total: alerts77.total,
      alert77States: alerts77.hits?.hits?.reduce((states: Record<string, number>, hit: any) => {
        const status = hit._source?.status || 'unknown';
        states[status] = (states[status] || 0) + 1;
        return states;
      }, {}),
      alert88Total: alerts88.total,
      alert88States: alerts88.hits?.hits?.reduce((states: Record<string, number>, hit: any) => {
        const status = hit._source?.status || 'unknown';
        states[status] = (states[status] || 0) + 1;
        return states;
      }, {}),
      immediateCases: immediateCases.cases.map((item: any) => ({ id: item.id, status: item.status, alertCount: item.alert_ids?.length || 0 })),
      burstCases: burstCases.cases.map((item: any) => ({ id: item.id, status: item.status, alertCount: item.alert_ids?.length || 0, correlationKey: item.correlation_key })),
    })}`);
  });

  test('settings, reports, AI configuration state, and about diagnostics render from the UI', async ({ page }) => {
    test.setTimeout(300_000);
    await signIn(page);
    await page.getByRole('tab', { name: 'Settings' }).click();

    await page.getByRole('tab', { name: 'Background sync' }).click();
    await expect(page.getByRole('heading', { name: 'Background alert sync' })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByLabel('Sync interval')).toBeVisible();

    await page.getByRole('tab', { name: 'AI analysis' }).click();
    await expect(page.getByRole('heading', { name: 'AI Analysis Integration' })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByLabel('Provider')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save AI settings' })).toBeVisible();

    await page.getByRole('tab', { name: 'Storage & lifecycle' }).click();
    await expect(page.getByText('Automatic rollover', { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole('button', { name: 'Roll alert generation' })).toBeVisible();

    await page.getByRole('tab', { name: 'About' }).click();
    await expect(page.getByText(/Browser build ID/i)).toBeVisible({ timeout: 60_000 });

    await page.goto('/app/wazuhAlertManagerReporting');
    await expect(page.getByRole('heading', { name: 'Reporting' })).toBeVisible({ timeout: 120_000 });
    await expect(page.getByText(/alerts occurred in this cohort/)).toBeVisible({ timeout: 180_000 });
    for (const tab of ['Workload', 'Performance', 'Cases by analyst', 'Leaderboard', 'Overview']) {
      await page.getByRole('tab', { name: tab, exact: true }).click();
      await expect(page.getByRole('tab', { name: tab, exact: true })).toHaveAttribute('aria-selected', 'true');
    }

    await page.goto('/app/wazuh-alert-manager');
    await expect(page.getByRole('tab', { name: 'Alerts' })).toBeVisible({ timeout: 120_000 });
    await page.getByRole('button', { name: /^Open details for / }).first().click();
    const alertFlyout = page.locator('.wamAlertFlyout');
    await alertFlyout.getByRole('tab', { name: 'Comments' }).click();
    await expect(alertFlyout.getByPlaceholder('Add a comment...')).toBeVisible();
    await alertFlyout.getByRole('button', { name: 'Close' }).click().catch(() => undefined);
  });
});
