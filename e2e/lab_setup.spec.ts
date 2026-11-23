import { expect, Locator, Page, test } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { API, api, applyQueueFilters, isPrivateIp, openAlertFlyout, openCaseFlyout, openSettingsSection, pickQuickTimeRange, pollUntil, queueRowCheckbox, setQueueQuery, signIn } from './helpers';

/**
 * Live-lab configuration tour (PLAN.md 9.3). Drives the plugin against the
 * lab of steps 9.1 (Vagrant agent `wam-lab-agent`) and 9.2 (MISP on
 * `https://misp.internal:8445` from the dashboard container) exactly as an
 * operator would, in one serial browser session, and writes numbered
 * screenshots to `runtime-evidence/browser/lab/NN-<name>.png` so they read
 * as a walkthrough:
 *
 *   01 sign-in, 02 Settings > Enrichment start, 03 AbuseIPDB source created,
 *   04 its Test result, 05 MISP source created, 06 its Test result,
 *   07 Settings > Notifications as configured, 08 alert queue filtered to the
 *   lab agent (last 24 h), 09 one lab alert's Overview with the Indicators
 *   block, 10 its Enrichment tab after "Lookup all" with the AbuseIPDB and
 *   MISP verdicts, 11 the queue selection + "Create case from selected",
 *   12 case Indicators, 13 case Attack graph, 14 case Timeline.
 *
 * Gated on `WAM_E2E_LAB=1` and `WAM_E2E_MUTATING=1` (it writes the enrichment
 * settings document). The API keys come from `.env.e2e.local`
 * (`WAM_E2E_ABUSEIPDB_KEY`, `WAM_E2E_MISP_KEY`, loaded by playwright.config.ts);
 * they are typed into the key field and never printed, asserted or captured
 * (the key field is masked on screenshots). Optional: `WAM_E2E_SLOWMO=<ms>`
 * slows every action for a headed run, `WAM_E2E_LAB_GENERATE=1` lets the spec
 * run `lab/agent/generate.sh` through `vagrant ssh` when the queue holds no
 * lab alert in the last 24 h (otherwise it fails and says so).
 *
 * Re-runnable: the previous run's numbered captures are deleted first, the
 * two lab sources are removed (by name) before they are created again, and a
 * case titled `Lab: wam-lab-agent activity` is reused when one is open (the
 * create-case modal is still shown and captured, then cancelled). The lab
 * sources are left in place at the end: they are the point of the tour.
 * Traces and videos are off for this file: a trace kept on failure would
 * carry the typed keys in its `fill` action params.
 */

const ABUSEIPDB_NAME = 'AbuseIPDB (lab)';
const ABUSEIPDB_ID = 'abuseipdb-lab';
const MISP_NAME = 'MISP (lab)';
const MISP_ID = 'misp-lab';
const MISP_BASE_URL = 'https://misp.internal:8445';
const LAB_AGENT = 'wam-lab-agent';
const LAB_QUERY = `agent.name:"${LAB_AGENT}"`;
const CASE_TITLE = `Lab: ${LAB_AGENT} activity`;
const MAX_CASE_ALERTS = 10;
const LAB_ALERTS_QUERY = `${API}/alerts?from_offset=0&size=200&sortField=@timestamp&sortDirection=desc&agentNames=${LAB_AGENT}&from=now-24h&to=now`;

const evidenceDir = path.resolve(process.cwd(), 'runtime-evidence', 'browser', 'lab');
const lab = process.env.WAM_E2E_LAB === '1';
const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;
const abuseIpDbKey = process.env.WAM_E2E_ABUSEIPDB_KEY || '';
const mispKey = process.env.WAM_E2E_MISP_KEY || '';
const slowMo = Number(process.env.WAM_E2E_SLOWMO || 0);

if (Number.isFinite(slowMo) && slowMo > 0) test.use({ launchOptions: { slowMo } });
// The keys are typed with locator.fill(): a trace or video kept on failure
// would carry them in its action params, so neither is recorded for this file.
test.use({ trace: 'off', video: 'off' });

test.describe.configure({ mode: 'serial' });

test.describe('lab tour: enrichment sources, lab alerts, case indicators, attack graph', () => {
  test.skip(!lab, 'Set WAM_E2E_LAB=1 to run the live-lab configuration tour.');
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 as well: the tour writes the enrichment settings.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');
  test.skip(!abuseIpDbKey || !mispKey, 'Set WAM_E2E_ABUSEIPDB_KEY and WAM_E2E_MISP_KEY in .env.e2e.local (lab/misp/bootstrap.sh writes the MISP key).');

  let page: Page;
  /** Alert chosen for the flyout steps and the ids linked to the case. */
  let pickedAlert: { id: string; reason: string } | null = null;
  let labAlertIds: string[] = [];
  let caseId = '';
  let caseReused = false;
  /** Outcome of each Test button, recorded in the test annotations (never the keys). */
  const verdicts: Record<string, string> = {};

  test.beforeAll(async ({ browser }) => {
    fs.mkdirSync(evidenceDir, { recursive: true });
    // Drop the previous run's numbered captures so the folder only holds this walkthrough.
    for (const f of fs.readdirSync(evidenceDir)) if (/^\d{2}-.*\.png$/.test(f)) fs.rmSync(path.join(evidenceDir, f));
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    for (const [name, outcome] of Object.entries(verdicts)) test.info().annotations.push({ type: name, description: outcome });
    await page?.close();
  });

  test('01 sign in as the administrator', async () => {
    await signIn(page, username!, password!);
    await shot(page, '01-signed-in');
  });

  test('02 Settings > Enrichment starting state (lab sources removed when present)', async () => {
    test.setTimeout(120_000);
    const current = await api(page, 'GET', `${API}/enrichment/settings`);
    expect(current.egressAllowedHosts, 'dashboard allow list must carry api.abuseipdb.com and misp.internal (scripts/dev/e2e-deploy.sh)').toEqual(
      expect.arrayContaining(['api.abuseipdb.com', 'misp.internal'])
    );
    expect(current.encryptionConfigured, 'WAZUH_ALERT_MANAGER_ENCRYPTION_KEY must be set on the dashboard service').toBe(true);
    const kept = (current.sources || []).filter((source: any) => !isLabSource(source));
    if (kept.length !== (current.sources || []).length) {
      await api(page, 'PUT', `${API}/enrichment/settings`, { sources: kept });
    }

    await page.goto('/app/wazuh-alert-manager?tab=settings');
    const section = await openSettingsSection(page, 'enrichment');
    await expect(section.locator('.wamEnrichmentSourceTable')).toBeVisible({ timeout: 60_000 });
    await expect(section.locator(`[data-test-subj="wamEnrichmentSource-${ABUSEIPDB_ID}"]`)).toHaveCount(0);
    await expect(section.locator(`[data-test-subj="wamEnrichmentSource-${MISP_ID}"]`)).toHaveCount(0);
    await shot(page, '02-settings-enrichment-start');
  });

  test('03 create the AbuseIPDB source and save', async () => {
    test.setTimeout(120_000);
    const section = page.locator('[data-test-subj="wamSettingsPage-enrichment"]');
    const editor = await openSourceEditor(page, 'abuseipdb');
    await editor.getByLabel('Name', { exact: true }).fill(ABUSEIPDB_NAME);
    await editor.getByLabel('Id', { exact: true }).fill(ABUSEIPDB_ID);
    await enableSource(editor);
    await expect(editor.getByRole('checkbox', { name: 'ip', exact: true })).toBeChecked();
    const keyField = editor.locator('input.euiFieldPassword');
    await keyField.fill(abuseIpDbKey);
    await shot(page, '03-abuseipdb-source-editor', { mask: [keyField] });
    await editor.locator('[data-test-subj="wamEnrichmentApply"]').click();
    await saveEnrichment(page);
    const row = section.locator(`[data-test-subj="wamEnrichmentSource-${ABUSEIPDB_ID}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toContainText(ABUSEIPDB_NAME);
    await expect(row).toContainText('Configured');
    await shot(page, '03-abuseipdb-source-saved');
  });

  test('04 Test the AbuseIPDB source', async () => {
    test.setTimeout(120_000);
    const outcome = await testSource(page, ABUSEIPDB_ID, ABUSEIPDB_NAME);
    await shot(page, '04-abuseipdb-test-result');
    verdicts['abuseipdb-test'] = outcome.text;
    if (outcome.ok) return;
    if (/quota|rate limit|too many|HTTP 429|HTTP 401|HTTP 403|unauthori[sz]ed|invalid.*key|key.*invalid|subscription|daily limit/i.test(outcome.text)) {
      // Spec: a quota or auth failure is recorded and the tour continues with MISP.
      console.warn(`AbuseIPDB test failed with a quota/auth error; continuing: ${outcome.text}`);
      return;
    }
    throw new Error(`AbuseIPDB test failed: ${outcome.text}`);
  });

  test('05 create the MISP source (misp.internal, self-signed allowed) and save', async () => {
    test.setTimeout(120_000);
    const section = page.locator('[data-test-subj="wamSettingsPage-enrichment"]');
    const editor = await openSourceEditor(page, 'misp');
    await editor.getByLabel('Name', { exact: true }).fill(MISP_NAME);
    await editor.getByLabel('Id', { exact: true }).fill(MISP_ID);
    await enableSource(editor);
    // ip / domain / hash on, url off.
    for (const type of ['ip', 'domain', 'hash']) await setIndicatorType(editor, type, true);
    await setIndicatorType(editor, 'url', false);
    await editor.getByLabel('MISP base URL', { exact: true }).fill(MISP_BASE_URL);
    const insecure = editor.locator('[data-test-subj="wamEnrichmentAllowInsecure"]');
    if (!(await insecure.isChecked())) await insecure.click();
    await expect(insecure).toBeChecked();
    const keyField = editor.locator('input.euiFieldPassword');
    await keyField.fill(mispKey);
    await shot(page, '05-misp-source-editor', { mask: [keyField] });
    await editor.locator('[data-test-subj="wamEnrichmentApply"]').click();
    await saveEnrichment(page);
    const row = section.locator(`[data-test-subj="wamEnrichmentSource-${MISP_ID}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toContainText(MISP_NAME);
    await expect(row).toContainText('Configured');
    for (const type of ['ip', 'domain', 'hash']) await expect(row).toContainText(type);
    await shot(page, '05-misp-source-saved');
  });

  test('06 Test the MISP source', async () => {
    test.setTimeout(120_000);
    const outcome = await testSource(page, MISP_ID, MISP_NAME);
    await shot(page, '06-misp-test-result');
    verdicts['misp-test'] = outcome.text;
    expect(outcome.ok, `MISP test failed: ${outcome.text}`).toBe(true);
  });

  test('07 Settings > Notifications as configured (no changes)', async () => {
    test.setTimeout(120_000);
    const section = await openSettingsSection(page, 'notifications');
    await expect(section).toBeVisible();
    await page.waitForTimeout(1_000);
    await shot(page, '07-settings-notifications');
  });

  test('08 alert queue filtered to the lab agent over the last 24 hours', async () => {
    test.setTimeout(420_000);
    let rows = await listLabAlerts(page);
    if (!rows.length) {
      if (process.env.WAM_E2E_LAB_GENERATE !== '1') {
        throw new Error(
          `No ${LAB_AGENT} alert in the last 24 h. Run \`cd lab/agent && vagrant ssh -c 'sudo bash /vagrant/generate.sh'\` (or set WAM_E2E_LAB_GENERATE=1 to let the tour do it) and retry.`
        );
      }
      generateLabEvents();
      rows = await pollUntil(page, async () => {
        const fresh = await listLabAlerts(page);
        return fresh.length ? fresh : null;
      }, { label: `${LAB_AGENT} alerts after generate.sh`, timeoutMs: 300_000, pollMs: 5_000 });
    }
    labAlertIds = rows.slice(0, MAX_CASE_ALERTS).map((row) => row._id);

    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    await setQueueQuery(page, LAB_QUERY);
    await pickQuickTimeRange(page, 'Last 24 hours');
    await applyQueueFilters(page);
    const summary = page.locator('[data-test-subj="wamAlertResultSummary"]');
    await expect(summary).toHaveText(/Showing 1-\d+ of [1-9][\d,]* alerts/, { timeout: 120_000 });
    // The agent name is in the Agent / IP cell, not the row's anchor cell
    // (the queue is an EuiDataGrid and has no row element, 13.1).
    await expect(page.locator('.wamAlertCell').filter({ hasText: LAB_AGENT }).first()).toBeVisible();
    await shot(page, '08-queue-lab-agent');
  });

  test('09 open a lab alert with an indicator and capture the Overview Indicators block', async () => {
    test.setTimeout(180_000);
    const rows = await listLabAlerts(page);
    pickedAlert = pickAlert(rows);
    expect(pickedAlert, 'a lab alert carrying at least one lookupable indicator').not.toBeNull();
    verdicts['picked-alert'] = `${pickedAlert!.id} (${pickedAlert!.reason})`;

    const flyout = await openAlertFlyout(page, pickedAlert!.id);
    await expect(flyout.locator('[data-test-subj="wamAlertFlyoutMeta"]')).toBeVisible({ timeout: 60_000 });
    await flyout.getByRole('button', { name: 'Expand to full screen' }).click();
    const indicators = flyout.locator('[data-test-subj="wamAlertIndicators"]');
    await expect(indicators).toBeVisible({ timeout: 60_000 });
    await expect(indicators.locator('[data-test-subj="wamIndicatorGroups"]')).toBeVisible();
    await indicators.scrollIntoViewIfNeeded();
    await shotElement(flyout, '09-alert-overview-indicators');
  });

  test('10 Enrichment tab: Lookup all returns an AbuseIPDB and a MISP verdict row', async () => {
    test.setTimeout(240_000);
    const flyout = page.locator('.wamAlertFlyout');
    await flyout.locator('[data-test-subj="wamAlertNav-enrichment"]').click();
    const panel = flyout.locator('[data-test-subj="wamEnrichmentPanel"]');
    await expect(panel).toBeVisible({ timeout: 30_000 });
    const lookupAll = panel.locator('[data-test-subj="wamEnrichmentLookupAll"]');
    await expect(lookupAll).toBeEnabled({ timeout: 30_000 });
    await lookupAll.click();
    const badges = panel.locator('[data-test-subj="wamEnrichmentBadges"]');
    await expect(badges.filter({ hasText: ABUSEIPDB_NAME }).first()).toBeVisible({ timeout: 180_000 });
    await expect(badges.filter({ hasText: MISP_NAME }).first()).toBeVisible({ timeout: 180_000 });
    await expect(lookupAll).toBeEnabled({ timeout: 120_000 });
    const observed = (await badges.allInnerTexts()).map((text) => text.replace(/\s+/g, ' ').trim());
    verdicts['alert-enrichment'] = observed.join(' | ');
    expect(observed.some((text) => text.includes(ABUSEIPDB_NAME))).toBe(true);
    expect(observed.some((text) => text.includes(MISP_NAME))).toBe(true);
    await shotElement(flyout, '10-alert-enrichment-verdicts');
    await flyout.getByRole('button', { name: 'Collapse' }).click();
    await flyout.locator('[data-test-subj="wamAlertFlyoutClose"]').click();
    await expect(flyout).toBeHidden({ timeout: 30_000 });
  });

  test('11 select the lab alerts and create (or reuse) the lab case', async () => {
    test.setTimeout(240_000);
    expect(labAlertIds.length, 'step 08 lists the lab alerts').toBeGreaterThan(0);
    const existing = await findOpenCase(page, CASE_TITLE);

    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    await setQueueQuery(page, LAB_QUERY);
    await pickQuickTimeRange(page, 'Last 24 hours');
    await applyQueueFilters(page);
    await expect(page.locator('[data-test-subj="wamAlertResultSummary"]')).toHaveText(/Showing 1-\d+ of [1-9]/, { timeout: 120_000 });
    const rows = page.locator('.wamAlertRow');
    const count = Math.min(await rows.count(), MAX_CASE_ALERTS);
    const selected: string[] = [];
    for (let i = 0; i < count; i += 1) {
      const alertId = (await rows.nth(i).getAttribute('data-alert-id')) || '';
      await queueRowCheckbox(page, alertId).check();
      selected.push(alertId);
    }
    expect(selected.every(Boolean)).toBe(true);
    labAlertIds = selected;
    await expect(page.getByRole('button', { name: 'Create case from selected' })).toBeVisible();
    await shot(page, '11-queue-selection');

    // The modal is shown (and captured) on every run; it is only submitted when no open lab case exists.
    await page.getByRole('button', { name: 'Create case from selected' }).click();
    const modal = page.locator('.wamCreateCaseModal');
    await expect(modal).toBeVisible();
    await modal.locator('[data-test-subj="wamCreateCaseTitle"]').fill(CASE_TITLE);
    await modal.getByLabel('Description').fill(`Activity generated by lab/agent/generate.sh on ${LAB_AGENT}.`);
    await shot(page, '11-create-case-modal');
    if (existing) {
      caseReused = true;
      caseId = existing.id;
      await modal.getByRole('button', { name: 'Cancel' }).click();
      await expect(modal).toBeHidden();
      const missing = selected.filter((id) => !(existing.alert_ids || []).includes(id));
      if (missing.length) await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: missing, caseId });
    } else {
      await modal.locator('[data-test-subj="wamCreateCaseSubmit"]').click();
      await expect(page).toHaveURL(/[?&]case=case-[0-9a-f]+/, { timeout: 60_000 });
      caseId = new URL(page.url()).searchParams.get('case') || '';
    }
    expect(caseId).toMatch(/^case-/);
    let caseDoc = (await api(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}`)).case;
    // The alert enriched in step 10 is not always among the newest rows the
    // queue page shows: link it too so the case carries its stored verdicts.
    if (pickedAlert && !(caseDoc.alert_ids || []).includes(pickedAlert.id)) {
      await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: [pickedAlert.id], caseId });
      caseDoc = (await api(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}`)).case;
    }
    expect(caseDoc.title).toBe(CASE_TITLE);
    expect(caseDoc.alert_ids).toEqual(expect.arrayContaining([...selected, ...(pickedAlert ? [pickedAlert.id] : [])]));
    verdicts['case'] = `${caseId} (${caseReused ? 'reused' : 'created'}, ${caseDoc.alert_ids.length} linked alerts)`;
  });

  test('12 case Indicators: aggregated indicators with verdict hints', async () => {
    test.setTimeout(180_000);
    const flyout = await openCaseFlyout(page, caseId);
    await expect(flyout.locator('[data-test-subj="wamCaseFlyoutTitle"]')).toContainText(CASE_TITLE, { timeout: 60_000 });
    await flyout.getByRole('button', { name: 'Expand to full screen' }).click();
    await flyout.locator('[data-test-subj="wamCaseNav-indicators"]').click();
    const tab = flyout.locator('[data-test-subj="wamCaseIndicators"]');
    await expect(tab).toBeVisible();
    await expect(tab.locator('.wamIndicatorTable tbody tr').first()).toBeVisible({ timeout: 60_000 });
    await expect(tab).toContainText(/[1-9]\d* indicator\(s\) across [1-9]\d* linked alerts/, { timeout: 60_000 });
    // "(refreshing...)" stays on after a successful load (case_flyout.tsx: the
    // effect's own `setIndicatorsStale(false)` cancels the `.finally` that
    // clears `indicatorsLoading`), so the rows, not that label, are awaited.
    // The stored verdicts of step 10 show as hints on the aggregated rows ...
    const hinted = tab.locator('[data-test-subj="wamEnrichmentBadges"]');
    await expect(hinted.first()).toBeVisible({ timeout: 30_000 });
    await expect(hinted.filter({ hasText: MISP_ID }).first()).toBeVisible({ timeout: 30_000 });
    // ... and "Lookup all" asks both lab sources about every aggregated indicator.
    const lookupAll = tab.locator('[data-test-subj="wamCaseIndicatorsLookupAll"]');
    await expect(lookupAll).toBeEnabled({ timeout: 30_000 });
    await lookupAll.click();
    await expect(hinted.filter({ hasText: MISP_NAME }).first()).toBeVisible({ timeout: 180_000 });
    await expect(lookupAll).toBeEnabled({ timeout: 180_000 });
    verdicts['case-indicators'] = (await hinted.allInnerTexts()).map((t) => t.replace(/\s+/g, ' ').trim()).join(' | ');
    await shotElement(flyout, '12-case-indicators');
  });

  test('13 case Attack graph', async () => {
    test.setTimeout(180_000);
    const flyout = page.locator('.wamCaseFlyout');
    await flyout.locator('[data-test-subj="wamCaseNav-attack-path"]').click();
    const graph = flyout.locator('.wamAg');
    await expect(graph).toBeVisible({ timeout: 60_000 });
    await expect(graph.locator('.wamAg__panel').first()).toBeVisible({ timeout: 120_000 });
    await page.waitForTimeout(1_500);
    await shotElement(flyout, '13-case-attack-graph');
  });

  test('14 case Timeline', async () => {
    test.setTimeout(180_000);
    const flyout = page.locator('.wamCaseFlyout');
    await flyout.locator('[data-test-subj="wamCaseNav-timeline"]').click();
    const timeline = flyout.locator('[data-test-subj="wamCaseTimeline"]');
    await expect(timeline).toBeVisible({ timeout: 60_000 });
    await expect(timeline.locator('.wamCaseTimelineRow').first()).toBeVisible({ timeout: 60_000 });
    await shotElement(flyout, '14-case-timeline');
  });
});

function isLabSource(source: any): boolean {
  return source?.name === ABUSEIPDB_NAME || source?.name === MISP_NAME || source?.id === ABUSEIPDB_ID || source?.id === MISP_ID;
}

/** Full-page screenshot into the lab evidence directory; `mask` hides secret fields. */
async function shot(page: Page, name: string, options: { mask?: Locator[] } = {}) {
  await settle(page);
  // A full-page capture taken while scrolled paints the sticky header mid-image.
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(200);
  await page.screenshot({ path: path.join(evidenceDir, `${name}.png`), fullPage: true, mask: options.mask });
}

/** Element screenshot (expanded flyouts) into the lab evidence directory. */
async function shotElement(target: Locator, name: string) {
  await settle(target.page());
  await target.screenshot({ path: path.join(evidenceDir, `${name}.png`) });
}

/** Dismiss toasts and park the pointer so tooltips and toasts do not cover the capture. */
async function settle(page: Page) {
  await page.mouse.move(0, 0);
  const closers = page.locator('.euiToast [aria-label="Dismiss toast"]');
  for (let i = await closers.count(); i > 0; i -= 1) await closers.first().click({ timeout: 2_000 }).catch(() => undefined);
  await expect(page.locator('.euiToast')).toHaveCount(0, { timeout: 15_000 }).catch(() => undefined);
  await page.waitForTimeout(300);
}

/** Pick the kind in the "Add source" select, click it and return the editor panel. */
async function openSourceEditor(page: Page, kind: 'abuseipdb' | 'misp') {
  const section = page.locator('[data-test-subj="wamSettingsPage-enrichment"]');
  await section.getByRole('combobox', { name: 'Source kind to add' }).selectOption(kind);
  await section.getByRole('button', { name: 'Add source' }).click();
  const editor = section.locator('[data-test-subj="wamEnrichmentEditor"]');
  await expect(editor).toBeVisible();
  return editor;
}

/** The editor's Enabled switch (a new source starts disabled). */
async function enableSource(editor: Locator) {
  const toggle = editor.getByRole('switch', { name: /^(Enabled|Disabled)$/ });
  if ((await toggle.getAttribute('aria-checked')) !== 'true') await toggle.click();
  await expect(toggle).toHaveAttribute('aria-checked', 'true');
}

/** EUI hides the checkbox input itself (the label is the click target): toggle an indicator type by its label. */
async function setIndicatorType(editor: Locator, type: string, checked: boolean) {
  const box = editor.getByRole('checkbox', { name: type, exact: true });
  if ((await box.isChecked()) !== checked) await editor.locator(`label[for="${type}"]`).click();
  await expect(box).toBeChecked({ checked });
}

/** Click "Save enrichment settings" and wait for the button to settle (it is disabled again once nothing is dirty). */
async function saveEnrichment(page: Page) {
  const save = page.locator('[data-test-subj="wamEnrichmentSave"]');
  await expect(save).toBeEnabled();
  await save.click();
  await expect(save).toBeDisabled({ timeout: 60_000 });
}

/** Press a source row's Test button and return the callout outcome (title + text, which never contains a key). */
async function testSource(page: Page, sourceId: string, sourceName: string): Promise<{ ok: boolean; text: string }> {
  const section = page.locator('[data-test-subj="wamSettingsPage-enrichment"]');
  const row = section.locator(`[data-test-subj="wamEnrichmentSource-${sourceId}"]`);
  await expect(row).toBeVisible({ timeout: 30_000 });
  const button = row.getByRole('button', { name: 'Test' });
  await expect(button).toBeEnabled({ timeout: 30_000 });
  await button.click();
  const result = section.locator('.wamEnrichmentTestResult', { hasText: `${sourceName}:` });
  await expect(result).toBeVisible({ timeout: 90_000 });
  const text = (await result.innerText()).replace(/\s+/g, ' ').trim();
  const ok = text.includes(`${sourceName}: reachable`);
  if (!ok && /egress|allow ?list|allowed hosts|not permitted|refused|policy|private address|must use https/i.test(text)) {
    throw new Error(`${sourceName} test was refused by the egress policy: ${text}`);
  }
  return { ok, text };
}

interface LabAlertRow {
  _id: string;
  _source: any;
}

async function listLabAlerts(page: Page): Promise<LabAlertRow[]> {
  const result = await api(page, 'GET', LAB_ALERTS_QUERY);
  return (result?.hits?.hits || []).filter((row: any) => row?._source?.agent?.name === LAB_AGENT);
}

/**
 * The alert the flyout steps open: the newest one whose `data.srcip` /
 * `data.dstip` is a public address; failing that (the stock 4.14 auditd
 * decoder leaves `data.dstip` empty, see lab/README.md) the newest one with a
 * syscheck hash, which MISP holds; failing that the newest one with any IP.
 */
function pickAlert(rows: LabAlertRow[]): { id: string; reason: string } | null {
  const ipOf = (row: LabAlertRow, field: 'srcip' | 'dstip') => String(row._source?.data?.[field] || '').trim();
  const publicIp = rows.find((row) => (['srcip', 'dstip'] as const).some((field) => ipOf(row, field) && !isPrivateIp(ipOf(row, field))));
  if (publicIp) return { id: publicIp._id, reason: `public ip ${ipOf(publicIp, 'dstip') || ipOf(publicIp, 'srcip')}` };
  const hashed = rows.find((row) => row._source?.syscheck?.sha256_after);
  if (hashed) return { id: hashed._id, reason: `syscheck sha256 ${String(hashed._source.syscheck.sha256_after).slice(0, 12)}... (no public IP in any lab alert)` };
  const anyIp = rows.find((row) => ipOf(row, 'srcip') || ipOf(row, 'dstip'));
  if (anyIp) return { id: anyIp._id, reason: `private ip ${ipOf(anyIp, 'srcip') || ipOf(anyIp, 'dstip')} (no public IP or hash in any lab alert)` };
  return null;
}

async function findOpenCase(page: Page, title: string): Promise<{ id: string; alert_ids: string[] } | null> {
  // The route feeds `q` to a query_string: a raw `Lab: ...` title would parse `Lab` as a field, so the phrase is quoted against `title`.
  const q = `title:"${title.replace(/"/g, '\\"')}"`;
  const result = await api(page, 'GET', `${API}/cases?from_offset=0&size=50&q=${encodeURIComponent(q)}&status=open,in_progress`);
  const hit = (result?.cases || []).find((row: any) => row?.title === title);
  if (!hit) return null;
  const doc = (await api(page, 'GET', `${API}/cases/${encodeURIComponent(hit.id)}`)).case;
  return { id: hit.id, alert_ids: doc?.alert_ids || [] };
}

/** Run lab/agent/generate.sh inside the Vagrant VM (only with WAM_E2E_LAB_GENERATE=1). */
function generateLabEvents() {
  const cwd = path.resolve(process.cwd(), 'lab', 'agent');
  console.log(`generating lab events through vagrant ssh in ${cwd}`);
  execFileSync('vagrant', ['ssh', '-c', 'sudo bash /vagrant/generate.sh'], { cwd, stdio: 'inherit', timeout: 600_000 });
}
