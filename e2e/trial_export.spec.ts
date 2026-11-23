import { expect, Page, test } from '@playwright/test';
import { API, api, apiRaw, fromSeedRun, openCaseFlyout, openSettingsSection, parseCsvLine, pollUntil, seedAlerts, signIn } from './helpers';

/**
 * Phase 5 bench (PLAN.md 5.5): the alerts CSV export (route + "Export CSV"
 * download), the case report in HTML and Markdown (route + "Report" popover),
 * case attachments (link + small file through the routes, the file row in the
 * Attachments tab) and scheduled summaries (a daily schedule, run-now, the
 * stored Markdown, the Settings > Reports row).
 *
 * Mutating: seeds alerts (their formula assignee is cleared afterwards),
 * creates a case with attachments and rewrites the report schedules
 * (restored afterwards). Seeded documents carry
 * `rule.description = "Synthetic WAM 100k scenario UI"` and `agent.name =
 * wam-e2e-agent` (e2e/seed_alerts.py).
 */

const AGENT_NAME = 'wam-e2e-agent';
const SEEDED_RULE_DESCRIPTION = 'Synthetic WAM 100k scenario UI';
const SCHEDULE_ID = 'wam-e2e-daily';
const SCHEDULE_NAME = 'WAM e2e daily summary';
const FILE_NAME = 'wam-e2e-note.txt';
const FILE_BODY = 'WAM e2e attachment body\nline two\n';
/** An assignee that a spreadsheet would run as a formula unless the export guards it. */
const FORMULA_ASSIGNEE = '=HYPERLINK("https://example.com")';
/** The leaders `csvEscape` prefixes with a quote (server/lib/http_download.ts FORMULA_LEADERS). */
const FORMULA_LEADER = /^[=+\-@\t\r]/;
const QUEUE_QUERY = `${API}/alerts?from_offset=0&size=50&sortField=@timestamp&sortDirection=desc&agentNames=${AGENT_NAME}`;

const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;

test.describe.configure({ mode: 'serial' });

test.describe('trial: export, report and attachments', () => {
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 to run the mutating export bench.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  let page: Page;
  let seededIds: string[] = [];
  let seedRun = '';
  let caseId = '';
  let caseTitle = '';
  let formulaCaseId = '';
  let fileAttachmentId = '';
  let savedSchedules: any[] | null = null;

  test.beforeAll(async ({ browser }) => {
    // signIn alone waits up to 3 x 60 s on a slow stack; Playwright's default hook budget is 30 s.
    test.setTimeout(120_000);
    page = await browser.newPage();
    await signIn(page, username!, password!);
  });

  test.afterAll(async () => {
    try {
      if (savedSchedules) await api(page, 'PUT', `${API}/reports/schedules`, { schedules: savedSchedules });
    } catch (e) {
      console.warn(`could not restore report schedules: ${String(e)}`);
    }
    // The formula assignee is a test fixture: clear it so it does not stay on
    // the queue's first row (and in the wiki screenshots) after the run.
    try {
      if (seededIds.length) await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: seededIds, assignedTo: null });
    } catch (e) {
      console.warn(`could not clear the seeded alerts' assignee: ${String(e)}`);
    }
    await page?.close();
  });

  test('alerts CSV export has the header, the seeded rows and formula-guarded cells', async () => {
    test.setTimeout(360_000);
    const seed = seedAlerts({ count: 3 });
    seedRun = seed.run;
    const fromRun = fromSeedRun(seed.run);
    // The seeder stamps now+2s plus a per-doc offset, so the last record may
    // only land on the next sync tick: wait for all three.
    seededIds = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter(fromRun);
        return rows.length === 3 ? rows.map((row: any) => row._id as string) : null;
      },
      { label: 'three seeded alerts projected', timeoutMs: 180_000, pollMs: 5_000 }
    );

    // Give one seeded alert an assignee that starts with a formula leader so
    // the export's csvEscape guard (server/lib/http_download.ts) is exercised
    // on a real cell; the route accepts any string and the alert is test-owned.
    const assigned = await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: [seededIds[0]], assignedTo: FORMULA_ASSIGNEE });
    expect(assigned).toMatchObject({ requested: 1, updated: 1 });

    const exported = await apiRaw(page, 'GET', `${API}/alerts/export.csv?agentNames=${AGENT_NAME}`);
    expect(exported.status, exported.text.slice(0, 300)).toBe(200);
    expect(exported.headers['content-type']).toMatch(/^text\/csv/);
    expect(exported.headers['content-disposition']).toMatch(/^attachment; filename="wam-alerts-\d{4}-\d{2}-\d{2}\.csv"/);

    const lines = exported.text.split(/\r?\n/).filter((line) => line.length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(4);
    const header = parseCsvLine(lines[0]);
    expect(header.slice(0, 5)).toEqual(['id', 'timestamp', 'status', 'assignee', 'severity']);
    expect(header).toEqual(expect.arrayContaining(['rule.description', 'agent.name', 'data.srcip', 'case_id']));
    const rows = lines.slice(1).map(parseCsvLine);
    expect(rows.length).toBeGreaterThanOrEqual(3);
    const idColumn = header.indexOf('id');
    const agentColumn = header.indexOf('agent.name');
    const assigneeColumn = header.indexOf('assignee');
    const descriptionColumn = header.indexOf('rule.description');
    const exportedIds = new Set(rows.map((row) => row[idColumn]));
    for (const id of seededIds) expect(exportedIds.has(id), `seeded alert ${id} is in the export`).toBe(true);
    for (const row of rows) {
      expect(row.length).toBe(header.length);
      expect(row[agentColumn]).toBe(AGENT_NAME);
      for (const cell of row) expect(FORMULA_LEADER.test(cell), `cell ${JSON.stringify(cell)} must not start with a formula leader`).toBe(false);
    }
    const seededRow = rows.find((row) => row[idColumn] === seededIds[0])!;
    expect(seededRow[descriptionColumn]).toBe(SEEDED_RULE_DESCRIPTION);
    expect(seededRow[assigneeColumn]).toBe(`'${FORMULA_ASSIGNEE}`);

    // The "Export CSV" button hands the browser a .csv download.
    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    const button = page.locator('[data-test-subj="wamExportAlertsCsv"]');
    await expect(button).toBeVisible({ timeout: 60_000 });
    const downloadPromise = page.waitForEvent('download', { timeout: 60_000 });
    await button.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^wam-alerts-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  test('case report in HTML and Markdown names the case and a linked alert; the Report popover lists three actions', async () => {
    test.setTimeout(180_000);
    expect(seededIds.length, 'previous step seeds the alerts this case links').toBe(3);
    caseTitle = `WAM e2e export ${seedRun}`;
    const created = await api(page, 'POST', `${API}/cases`, {
      title: caseTitle,
      severity: 'medium',
      alertIds: seededIds.slice(0, 2),
    });
    caseId = created.id;
    expect(caseId).toMatch(/^case-/);

    const html = await apiRaw(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/report?format=html&inline=1`);
    expect(html.status, html.text.slice(0, 300)).toBe(200);
    expect(html.headers['content-type']).toMatch(/^text\/html/);
    expect(html.headers['content-disposition']).toMatch(/^inline/);
    expect(html.headers['content-security-policy']).toContain("default-src 'none'");
    expect(html.text).toContain(caseTitle);
    expect(html.text).toContain(SEEDED_RULE_DESCRIPTION);
    expect(html.text).toContain(seededIds[0]);

    const markdown = await apiRaw(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/report?format=markdown`);
    expect(markdown.status, markdown.text.slice(0, 300)).toBe(200);
    expect(markdown.headers['content-disposition']).toMatch(/^attachment; filename="wam-case-.*\.md"/);
    const heading = markdown.text.split(/\r?\n/)[0];
    expect(heading.startsWith('# ')).toBe(true);
    expect(heading).toContain(caseTitle);
    expect(markdown.text).toContain(SEEDED_RULE_DESCRIPTION);

    const flyout = await openCaseFlyout(page, caseId);
    await flyout.locator('[data-test-subj="wamCaseReportButton"]').click();
    const menu = page.locator('.wamCaseReportMenu');
    await expect(menu).toBeVisible();
    await expect(menu.locator('[data-test-subj="wamCaseReportMarkdown"]')).toContainText('Download Markdown');
    await expect(menu.locator('[data-test-subj="wamCaseReportHtml"]')).toContainText('Download HTML');
    await expect(menu.locator('[data-test-subj="wamCaseReportPrint"]')).toContainText('Print / PDF');
    await page.keyboard.press('Escape');
  });

  test('attachments: a link and a small file are listed, the file downloads, the link is removed', async () => {
    test.setTimeout(180_000);
    expect(caseId, 'previous step creates the case').toMatch(/^case-/);
    const base = `${API}/cases/${encodeURIComponent(caseId)}/attachments`;

    const link = await api(page, 'POST', base, { kind: 'link', name: 'WAM e2e runbook', url: 'https://example.com/wam-e2e/runbook' });
    expect(link.attachment).toMatchObject({ kind: 'link', name: 'WAM e2e runbook', url: 'https://example.com/wam-e2e/runbook' });
    const file = await api(page, 'POST', base, {
      kind: 'file',
      name: FILE_NAME,
      contentType: 'text/plain',
      dataBase64: Buffer.from(FILE_BODY, 'utf8').toString('base64'),
    });
    expect(file.attachment).toMatchObject({ kind: 'file', name: FILE_NAME, content_type: 'text/plain', size: Buffer.byteLength(FILE_BODY, 'utf8') });
    expect(file.attachment.data).toBeUndefined();
    fileAttachmentId = file.attachment.id;

    const listed = await api(page, 'GET', base);
    expect(listed.total).toBe(2);
    expect(listed.attachments.map((item: any) => item.id).sort()).toEqual([link.attachment.id, fileAttachmentId].sort());
    for (const item of listed.attachments) expect(item.data).toBeUndefined();

    const download = await apiRaw(page, 'GET', `${base}/${encodeURIComponent(fileAttachmentId)}/download`);
    expect(download.status, download.text.slice(0, 300)).toBe(200);
    expect(download.headers['content-type']).toMatch(/^text\/plain/);
    expect(download.headers['content-disposition']).toMatch(new RegExp(`^attachment; filename="${FILE_NAME}"`));
    expect(download.headers['x-content-type-options']).toBe('nosniff');
    expect(download.text).toBe(FILE_BODY);

    // A link has no bytes to download.
    const linkDownload = await apiRaw(page, 'GET', `${base}/${encodeURIComponent(link.attachment.id)}/download`);
    expect(linkDownload.status, linkDownload.text.slice(0, 300)).toBe(404);
    expect(linkDownload.text).toContain('Attachment not found');

    const removed = await api(page, 'DELETE', `${base}/${encodeURIComponent(link.attachment.id)}`);
    expect(removed.deleted).toBe(true);
    const after = await api(page, 'GET', base);
    expect(after.total).toBe(1);
    expect(after.attachments[0]).toMatchObject({ id: fileAttachmentId, kind: 'file', name: FILE_NAME });

    const flyout = await openCaseFlyout(page, caseId);
    await flyout.locator('[data-test-subj="wamCaseNav-attachments"]').click();
    const tab = flyout.locator('[data-test-subj="wamCaseAttachments"]');
    await expect(tab).toBeVisible();
    const row = tab.locator(`[data-test-subj="wamAttachmentRow-${fileAttachmentId}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    // EuiLink appends a screen-reader "(opens in a new tab or window)" suffix.
    await expect(row.locator('[data-test-subj="wamAttachmentDownload"]')).toContainText(FILE_NAME);
    await expect(tab.locator('[data-test-subj^="wamAttachmentRow-"]')).toHaveCount(1);
  });

  test('cases CSV export lists both run cases, guards a formula title and the Export CSV button downloads', async () => {
    test.setTimeout(180_000);
    expect(caseId, 'the report step creates the first case').toMatch(/^case-/);
    const formulaTitle = `=WAM e2e formula ${seedRun}`;
    const formulaCase = await api(page, 'POST', `${API}/cases`, { title: formulaTitle, severity: 'low' });
    formulaCaseId = formulaCase.id;
    expect(formulaCaseId).toMatch(/^case-/);

    // `q` is a query_string over the case documents; the run marker is a token
    // of both titles, so the export is scoped to this run's two cases.
    const exported = await apiRaw(page, 'GET', `${API}/cases/export.csv?q=${encodeURIComponent(seedRun)}`);
    expect(exported.status, exported.text.slice(0, 300)).toBe(200);
    expect(exported.headers['content-type']).toMatch(/^text\/csv/);
    expect(exported.headers['content-disposition']).toMatch(/^attachment; filename="wam-cases-\d{4}-\d{2}-\d{2}\.csv"/);

    const lines = exported.text.split(/\r?\n/).filter((line) => line.length > 0);
    const header = parseCsvLine(lines[0]);
    expect(header.slice(0, 5)).toEqual(['id', 'title', 'status', 'severity', 'assignee']);
    const rows = lines.slice(1).map(parseCsvLine);
    const idColumn = header.indexOf('id');
    const titleColumn = header.indexOf('title');
    for (const row of rows) {
      expect(row.length).toBe(header.length);
      for (const cell of row) expect(FORMULA_LEADER.test(cell), `cell ${JSON.stringify(cell)} must not start with a formula leader`).toBe(false);
    }
    const exportedIds = rows.map((row) => row[idColumn]);
    expect(exportedIds).toEqual(expect.arrayContaining([caseId, formulaCaseId]));
    expect(rows.find((row) => row[idColumn] === caseId)![titleColumn]).toBe(caseTitle);
    expect(rows.find((row) => row[idColumn] === formulaCaseId)![titleColumn]).toBe(`'${formulaTitle}`);

    await page.goto('/app/wazuh-alert-manager?tab=cases');
    const button = page.locator('[data-test-subj="wamExportCasesCsv"]');
    await expect(button).toBeVisible({ timeout: 60_000 });
    const downloadPromise = page.waitForEvent('download', { timeout: 60_000 });
    await button.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^wam-cases-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  test('a daily report schedule runs now, stores its Markdown and shows in Settings > Reports', async () => {
    test.setTimeout(180_000);
    const current = await api(page, 'GET', `${API}/reports/schedules`);
    savedSchedules = (current.schedules || []).filter((entry: any) => entry.id !== SCHEDULE_ID);
    const schedule = { id: SCHEDULE_ID, name: SCHEDULE_NAME, cadence: 'daily', hourUtc: 8, rangeDays: 1, channelIds: [], enabled: true };
    const saved = await api(page, 'PUT', `${API}/reports/schedules`, { schedules: [...savedSchedules!, schedule] });
    const persisted = saved.schedules.find((entry: any) => entry.id === SCHEDULE_ID);
    expect(persisted).toMatchObject({ name: SCHEDULE_NAME, cadence: 'daily', hourUtc: 8, rangeDays: 1, enabled: true });
    expect(saved.nextSlots[SCHEDULE_ID]).toMatch(/T08:00:00/);

    const ran = await api(page, 'POST', `${API}/reports/schedules/${SCHEDULE_ID}/run-now`);
    expect(ran.run).toMatchObject({ schedule_id: SCHEDULE_ID, triggered_by: username });
    expect(ran.run.markdown_bytes).toBeGreaterThan(0);
    expect(ran.run.markdown).toBeUndefined();

    const lastRun = await api(page, 'GET', `${API}/reports/schedules/${SCHEDULE_ID}/last-run`);
    expect(lastRun.run).toMatchObject({ schedule_id: SCHEDULE_ID, slot: ran.run.slot, generated_at: ran.run.generated_at });

    const markdown = await apiRaw(page, 'GET', `${API}/reports/schedules/${SCHEDULE_ID}/last-run.md`);
    expect(markdown.status, markdown.text.slice(0, 300)).toBe(200);
    expect(markdown.headers['content-disposition']).toMatch(new RegExp(`^attachment; filename="wam-report-${SCHEDULE_ID}-.*\\.md"`));
    expect(markdown.text.startsWith(`# ${SCHEDULE_NAME}`)).toBe(true);

    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'reports');
    const row = page.locator(`[data-test-subj="wamReportSchedule-${SCHEDULE_ID}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toContainText(SCHEDULE_NAME);
    await expect(page.locator(`[data-test-subj="wamReportScheduleDownload-${SCHEDULE_ID}"]`)).toBeVisible();
  });
});
