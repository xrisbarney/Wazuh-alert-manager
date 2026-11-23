import { expect, Page, test } from '@playwright/test';
import { API, api, collapseOsdNav, openAlertFlyout, openCaseFlyout, openSettingsSection, signIn } from './helpers';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Documentation screenshots (steps 8.5 and 10.4). Every page and flyout is
 * captured twice, on the light and on the dark dashboard theme, into
 * `<WAM_DOC_EVIDENCE_DIR>/<light|dark>/` (default
 * `runtime-evidence/browser/ui-polish-5`); the light set is then copied over
 * `wiki/images/*.png` by hand (same file names).
 *
 * The run uses a 1920x1080 viewport with the dashboard's own side navigation
 * collapsed (`collapseOsdNav`); the two queues are captured a second time at
 * 1280x800 (`*-1280.png`) to prove the 10.2 "no horizontal scroll" layout.
 * Step 10.4 adds: the case flyout with its section nav collapsed
 * (`case-nav-collapsed.png`, the toggle is restored afterwards), the settings
 * nav rail (`settings-nav.png`), the Reporting export menu open
 * (`reporting-export-menu.png`), the server-rendered HTML export opened as a
 * page (`reporting-export-html.png`, `format=html&inline=1`) and, when the
 * Phase 9 lab case `Lab: wam-lab-agent activity` is still open on the stack,
 * its Indicators section (`case-indicators.png`) and the Enrichment tab of one
 * of its alerts (`alert-enrichment.png`); both are skipped with a note when the
 * case is gone. Step 11.3 adds: the alert flyout with its new section rail
 * collapsed (`alert-nav-collapsed.png`, restored afterwards), the settings
 * nav collapsed (`settings-nav-collapsed.png`, restored), and the lab case's
 * Assets section with its agent row expanded (`case-assets.png`, the header
 * summary line above it); on a 4.x build the SCA chip must read `not indexed
 * on 4.x` next to the Configuration Assessment link, which is followed once
 * per run to prove the Wazuh app opens for that agent. Step 13.3 adds the
 * `EuiDataGrid` controls of the alert queue (`queue-column-selector.png`,
 * `queue-column-resized.png`, `queue-density-compact.png` and
 * `queue-columns-restored.png`); the grid's layout preferences are put back
 * with the toolbar's Reset layout button afterwards.
 *
 * The theme is switched through the dashboard's Advanced settings
 * (`theme:darkMode`, the same `POST /api/opensearch-dashboards/settings`
 * call Dashboards Management > Advanced settings makes) and restored to its
 * previous value at the end, also when a capture fails. Switching the global
 * theme changes it for every user of the target dashboard while the spec
 * runs, so the spec also needs the `WAM_E2E_MUTATING=1` guard, and it skips
 * when `theme:darkMode` is pinned by `uiSettings.overrides` (the POST would
 * return 400 and nothing could be restored).
 */
const evidenceRoot = path.resolve(
  process.cwd(),
  process.env.WAM_DOC_EVIDENCE_DIR || path.join('runtime-evidence', 'browser', 'ui-polish-5')
);
const THEMES = ['light', 'dark'] as const;
type Theme = typeof THEMES[number];

/** Default capture size; the queues are also captured at the narrow size. */
const DOC_VIEWPORT = { width: 1920, height: 1080 };
const QUEUE_VIEWPORTS = [
  { width: 1280, height: 800, suffix: '-1280' },
  { width: 1920, height: 1080, suffix: '' },
];

/** Title of the Phase 9 lab case (`e2e/lab_setup.spec.ts`), captured when still open. */
const LAB_CASE_TITLE = `Lab: ${process.env.WAM_LAB_AGENT || 'wam-lab-agent'} activity`;
/** How many of the lab case's alerts are opened looking for one with enrichment rows. */
const LAB_ALERT_PROBES = 8;
/** Wazuh major of the target build (`GET /system/version`), read once after sign-in. */
let TARGET_WAZUH_MAJOR = 4;
/** The Configuration Assessment link is followed once per run (first theme), not per theme. */
let scaLinkFollowed = false;

/**
 * The operator's `theme:darkMode` override (`value` undefined = dashboard
 * default) and whether `uiSettings.overrides` in opensearch_dashboards.yml
 * pins it (then the settings API refuses to change it).
 */
async function readDarkMode(page: Page): Promise<{ value: boolean | undefined; isOverridden: boolean }> {
  const payload = await api(page, 'GET', '/api/opensearch-dashboards/settings');
  const setting = payload?.settings?.['theme:darkMode'];
  const value = setting?.userValue;
  return { value: typeof value === 'boolean' ? value : undefined, isOverridden: setting?.isOverridden === true };
}

/** Write (or with `undefined` clear) the `theme:darkMode` advanced setting; no navigation. */
async function writeDarkMode(page: Page, value: boolean | undefined) {
  await api(page, 'POST', '/api/opensearch-dashboards/settings', { changes: { 'theme:darkMode': value === undefined ? null : value } });
}

/** Reload the workbench so the page picks up the current theme setting. */
async function reloadWorkbench(page: Page) {
  await page.goto('/app/wazuh-alert-manager?tab=alerts');
  await expect(page.getByRole('heading', { name: /(Alert|Finding) queue/ })).toBeVisible({ timeout: 120_000 });
}

/** Dark theme = light body text (the body background itself is transparent). */
async function isDarkTheme(page: Page) {
  return page.evaluate(() => {
    const [r, g, b] = (getComputedStyle(document.body).color.match(/\d+/g) || ['0', '0', '0']).map(Number);
    return (r + g + b) / 3 > 128;
  });
}

function captureInto(theme: Theme) {
  const dir = path.join(evidenceRoot, theme);
  fs.mkdirSync(dir, { recursive: true });
  return {
    dir,
    page: async (page: Page, name: string, options: { fullPage?: boolean } = {}) => {
      await page.screenshot({ path: path.join(dir, name), fullPage: options.fullPage ?? true });
    },
    element: async (page: Page, selector: string, name: string) => {
      await page.locator(selector).screenshot({ path: path.join(dir, name) });
    },
  };
}

/** The open lab case (same quoted-title query as `lab_setup.spec.ts#findOpenCase`), or null when it is gone. */
async function findLabCase(page: Page): Promise<{ id: string; alert_ids: string[] } | null> {
  const q = `title:"${LAB_CASE_TITLE.replace(/"/g, '\\"')}"`;
  const result = await api(page, 'GET', `${API}/cases?from_offset=0&size=50&q=${encodeURIComponent(q)}&status=open,in_progress`);
  const hit = (result?.cases || []).find((row: any) => row?.title === LAB_CASE_TITLE);
  if (!hit) return null;
  const doc = (await api(page, 'GET', `${API}/cases/${encodeURIComponent(hit.id)}`)).case;
  return { id: hit.id, alert_ids: doc?.alert_ids || [] };
}

async function waitForAlertQueue(page: Page) {
  await expect(page.getByRole('heading', { name: /(Alert|Finding) queue/ })).toBeVisible({ timeout: 120_000 });
  await expect(page.locator('[data-test-subj="wamAlertResultSummary"]')).toHaveText(/Showing 1-\d+ of [1-9][\d,]* (alerts|findings)/, { timeout: 180_000 });
}

async function openCaseQueue(page: Page) {
  await page.getByRole('tab', { name: 'Cases' }).click();
  await expect(page.getByRole('heading', { name: 'Case queue' })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText(/[1-9][\d,]* cases?/, { exact: true })).toBeVisible({ timeout: 180_000 });
}

/** Column hidden and shown again by the 13.3 grid captures (visible by default). */
const GRID_HIDDEN_COLUMN = 'Assigned to';

/**
 * Step 13.3: the alert queue's `EuiDataGrid` controls - the column selector
 * open, a column dragged wider, the density popover resting on compact, and
 * the hidden column still hidden after a reload (the preferences come back
 * from `wam.alertsGrid.*` in localStorage). The toolbar's Reset layout button
 * restores the defaults at the end, so the run leaves the queue as it found
 * it. These captures are evidence only; they are not copied into the wiki.
 */
async function captureQueueGrid(page: Page, capture: ReturnType<typeof captureInto>) {
  await page.setViewportSize(DOC_VIEWPORT);
  await page.goto('/app/wazuh-alert-manager?tab=alerts');
  await waitForAlertQueue(page);
  const grid = page.locator('[data-test-subj="wamAlertQueueGrid"]');
  const headerCell = (label: string) => grid.locator('.euiDataGridHeaderCell').filter({ hasText: label });

  // Column selector open, then `Assigned to` switched off from it.
  await grid.locator('[data-test-subj="dataGridColumnSelectorButton"]').click();
  const selector = page.locator('[data-test-subj="dataGridColumnSelectorPopover"]');
  await expect(selector).toBeVisible({ timeout: 30_000 });
  await capture.page(page, 'queue-column-selector.png', { fullPage: false });
  // The popover's panel is portalled out of the anchor `selector` resolves to,
  // so the switches are reached from the page, not from inside it.
  await page.getByRole('switch', { name: GRID_HIDDEN_COLUMN, exact: true }).click();
  await expect(headerCell(GRID_HIDDEN_COLUMN)).toHaveCount(0, { timeout: 30_000 });
  await page.keyboard.press('Escape');
  // `selector` is the popover's anchor, which stays in the DOM; the panel
  // closing is what makes the portalled switches go away.
  await expect(page.getByRole('switch', { name: GRID_HIDDEN_COLUMN, exact: true })).toBeHidden({ timeout: 30_000 });

  // Drag the Rule column's resize handle 160px to the right.
  const resizer = headerCell('Rule').first().locator('[data-test-subj="dataGridColumnResizer"]');
  const widthOf = async () => (await headerCell('Rule').first().boundingBox())?.width ?? 0;
  const before = await widthOf();
  const handle = await resizer.boundingBox();
  expect(handle, 'the Rule column has a resize handle').toBeTruthy();
  await page.mouse.move(handle!.x + handle!.width / 2, handle!.y + handle!.height / 2);
  await page.mouse.down();
  await page.mouse.move(handle!.x + handle!.width / 2 + 160, handle!.y + handle!.height / 2, { steps: 12 });
  await page.mouse.up();
  await expect.poll(widthOf, { timeout: 30_000 }).toBeGreaterThan(before + 100);
  // The width as actually dragged. The reload check below is made against
  // this, not against `before + 100`: the stored width is restored verbatim,
  // so an exact comparison proves the persistence, while a lower bound would
  // also be met by any other re-flex of the one unsized column.
  const afterDrag = await widthOf();
  await capture.page(page, 'queue-column-resized.png', { fullPage: false });

  // Density popover, resting on the compact default.
  await grid.locator('[data-test-subj="wamGridDensity"]').click();
  await expect(page.locator('[data-test-subj="wamGridDensity-compact"]')).toBeVisible({ timeout: 30_000 });
  await capture.page(page, 'queue-density-compact.png', { fullPage: false });
  await page.keyboard.press('Escape');

  // The hidden column and the dragged width survive a reload.
  await page.reload();
  await waitForAlertQueue(page);
  await expect(headerCell(GRID_HIDDEN_COLUMN)).toHaveCount(0, { timeout: 60_000 });
  const restored = await widthOf();
  expect(Math.abs(restored - afterDrag), `restored Rule width ${restored} != dragged width ${afterDrag}`).toBeLessThan(5);
  await capture.page(page, 'queue-columns-restored.png', { fullPage: false });

  // Reset layout: the column comes back and the width goes to the default.
  await grid.locator('[data-test-subj="wamGridReset"]').click();
  await expect(headerCell(GRID_HIDDEN_COLUMN)).toHaveCount(1, { timeout: 30_000 });
}

async function captureTheme(page: Page, theme: Theme) {
  const capture = captureInto(theme);

  // Both queues at 1280x800 and 1920x1080 (10.2 layout proof); the 1920
  // captures keep the wiki file names.
  for (const viewport of QUEUE_VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    await waitForAlertQueue(page);
    await capture.page(page, `workbench-alert-queue${viewport.suffix}.png`);
    await openCaseQueue(page);
    await capture.page(page, `workbench-case-queue${viewport.suffix}.png`);
  }
  await page.setViewportSize(DOC_VIEWPORT);

  // 13.3: the grid toolbar of the alert queue.
  await captureQueueGrid(page, capture);

  // Alert flyout.
  await page.goto('/app/wazuh-alert-manager?tab=alerts');
  await waitForAlertQueue(page);
  await page.getByRole('button', { name: /^Open details for / }).first().click();
  const alertFlyout = page.locator('.wamAlertFlyout');
  await expect(alertFlyout.locator('[data-test-subj="wamAlertFlyoutMeta"]')).toBeVisible({ timeout: 120_000 });
  await expect(alertFlyout.locator('[data-test-subj="wamAlertNav-overview"]')).toBeVisible({ timeout: 60_000 });
  await alertFlyout.getByRole('button', { name: 'Expand to full screen' }).click();
  await expect(alertFlyout.locator('.wamMetaList').first()).toBeVisible({ timeout: 60_000 });
  // 11.1: the alert flyout carries the case flyout's section rail; captured
  // expanded (the wiki's alert-flyout.png) and collapsed, then restored.
  const alertNavColumn = alertFlyout.locator('.wamAlertNavColumn');
  const alertNavToggle = alertFlyout.locator('[data-test-subj="wamAlertNavToggle"]');
  await expect(alertNavToggle).toBeVisible({ timeout: 30_000 });
  await expect(alertNavColumn).not.toHaveClass(/wamAlertNavColumn--collapsed/);
  await capture.element(page, '.wamAlertFlyout', 'alert-flyout.png');
  await alertNavToggle.click();
  await expect(alertNavColumn).toHaveClass(/wamAlertNavColumn--collapsed/, { timeout: 10_000 });
  await capture.element(page, '.wamAlertFlyout', 'alert-nav-collapsed.png');
  await alertNavToggle.click();
  await expect(alertNavColumn).not.toHaveClass(/wamAlertNavColumn--collapsed/, { timeout: 10_000 });
  await alertFlyout.getByRole('button', { name: 'Collapse', exact: true }).click();
  await alertFlyout.locator('[data-test-subj="wamAlertFlyoutClose"]').click();
  await expect(alertFlyout).toBeHidden({ timeout: 30_000 });

  // Case flyout sections (nav expanded), then the nav collapsed and restored.
  await openCaseQueue(page);
  await page.getByRole('button', { name: /^Open details for / }).first().click();
  const caseFlyout = page.locator('.wamCaseFlyout');
  await expect(caseFlyout.locator('[data-test-subj="wamCaseNav-overview"]')).toBeVisible({ timeout: 120_000 });
  await caseFlyout.getByRole('button', { name: 'Expand to full screen' }).click();
  await expect(caseFlyout.locator('[data-test-subj="wamCaseOverview"]')).toBeVisible({ timeout: 60_000 });
  const navColumn = caseFlyout.locator('.wamCaseNavColumn');
  const navToggle = caseFlyout.locator('[data-test-subj="wamCaseNavToggle"]');
  await expect(navToggle).toBeVisible({ timeout: 30_000 });
  await expect(navColumn).not.toHaveClass(/wamCaseNavColumn--collapsed/);
  await capture.element(page, '.wamCaseFlyout', 'case-overview.png');
  await navToggle.click();
  await expect(navColumn).toHaveClass(/wamCaseNavColumn--collapsed/, { timeout: 10_000 });
  await capture.element(page, '.wamCaseFlyout', 'case-nav-collapsed.png');
  await navToggle.click();
  await expect(navColumn).not.toHaveClass(/wamCaseNavColumn--collapsed/, { timeout: 10_000 });
  await caseFlyout.locator('[data-test-subj="wamCaseNav-alerts"]').click();
  await expect(caseFlyout.getByRole('columnheader', { name: 'Evidence' })).toBeVisible({ timeout: 120_000 });
  await capture.element(page, '.wamCaseFlyout', 'case-linked-evidence.png');
  await caseFlyout.locator('[data-test-subj="wamCaseNav-attack-path"]').click();
  await expect(caseFlyout.getByRole('heading', { name: 'Kill-chain phases' })).toBeVisible({ timeout: 180_000 });
  await capture.element(page, '.wamCaseFlyout', 'case-attack-graph.png');
  await caseFlyout.getByText('Alert timeline', { exact: true }).click({ force: true });
  await expect(caseFlyout.getByRole('radio', { name: 'Alert timeline', exact: true })).toBeChecked();
  await capture.element(page, '.wamCaseFlyout', 'case-alert-timeline.png');
  await caseFlyout.locator('[data-test-subj="wamCaseNav-tasks"]').click();
  await expect(caseFlyout.locator('[data-test-subj="wamCaseSection-tasks"]')).toBeVisible({ timeout: 60_000 });
  await capture.element(page, '.wamCaseFlyout', 'case-tasks.png');
  await caseFlyout.locator('[data-test-subj="wamCaseNav-timeline"]').click();
  await expect(caseFlyout.locator('[data-test-subj="wamCaseSection-timeline"]')).toBeVisible({ timeout: 60_000 });
  await capture.element(page, '.wamCaseFlyout', 'case-timeline.png');
  await caseFlyout.getByRole('button', { name: 'Collapse', exact: true }).click();
  await caseFlyout.locator('[data-test-subj="wamCaseFlyoutClose"]').click();
  await expect(caseFlyout).toBeHidden({ timeout: 30_000 });

  // Settings pages (and the settings nav rail on its own).
  await page.getByRole('tab', { name: 'Settings' }).click();
  await openSettingsSection(page, 'automation');
  await expect(page.getByRole('button', { name: 'New rule' }).first()).toBeEnabled({ timeout: 180_000 });
  await capture.page(page, 'automation-rules.png');
  await capture.element(page, '.wamSettingsNavColumn', 'settings-nav.png');
  // 11.2: the settings nav collapses to the same 48px rail; captured on the
  // page so the rail is seen beside its content, then restored.
  const settingsNavColumn = page.locator('.wamSettingsNavColumn');
  const settingsNavToggle = page.locator('[data-test-subj="wamSettingsNavToggle"]');
  await expect(settingsNavToggle).toBeVisible({ timeout: 30_000 });
  await expect(settingsNavColumn).not.toHaveClass(/wamSettingsNavColumn--collapsed/);
  await settingsNavToggle.click();
  await expect(settingsNavColumn).toHaveClass(/wamSettingsNavColumn--collapsed/, { timeout: 10_000 });
  await expect(page.locator('[data-test-subj="wamSettingsNav-automation"]')).toBeVisible({ timeout: 10_000 });
  await capture.page(page, 'settings-nav-collapsed.png');
  await settingsNavToggle.click();
  await expect(settingsNavColumn).not.toHaveClass(/wamSettingsNavColumn--collapsed/, { timeout: 10_000 });

  await page.getByRole('button', { name: 'New rule' }).first().click();
  const ruleFlyout = page.locator('.wamRuleFlyout');
  await ruleFlyout.getByRole('tab', { name: '3. Trigger' }).click();
  await ruleFlyout.getByRole('button', { name: 'Add OR group' }).click();
  await ruleFlyout.getByRole('button', { name: 'Add AND predicate' }).click();
  await ruleFlyout.getByLabel('Operator').selectOption('exists');
  await capture.page(page, 'automation-trigger-entities.png');
  await ruleFlyout.getByRole('button', { name: 'Cancel' }).click();
  await expect(ruleFlyout).toBeHidden({ timeout: 30_000 });

  await openSettingsSection(page, 'task-lists');
  await expect(page.getByRole('heading', { name: 'Task lists' }).first()).toBeVisible({ timeout: 120_000 });
  await capture.page(page, 'settings-task-lists.png');

  await openSettingsSection(page, 'notifications');
  await expect(page.getByRole('heading', { name: 'Notifications' }).first()).toBeVisible({ timeout: 120_000 });
  await capture.page(page, 'settings-notifications.png');

  await openSettingsSection(page, 'storage');
  await expect(page.getByRole('heading', { name: 'Storage and lifecycle' })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText('Automatic rollover', { exact: true })).toBeVisible({ timeout: 180_000 });
  await capture.page(page, 'storage-lifecycle.png');

  // Reporting, its export menu, and the HTML export as a page of its own.
  await page.goto('/app/wazuhAlertManagerReporting');
  await expect(page.getByRole('heading', { name: 'Reporting' })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText(/alerts occurred in this cohort/)).toBeVisible({ timeout: 180_000 });
  await capture.page(page, 'reporting.png');
  const exportButton = page.locator('[data-test-subj="wamReportExport"]');
  await expect(exportButton).toBeEnabled({ timeout: 60_000 });
  await exportButton.click();
  await expect(page.locator('[data-test-subj="wamReportExport-pdf"]')).toBeVisible({ timeout: 10_000 });
  // The popover is positioned against the viewport, so this one is not a full-page capture.
  await capture.page(page, 'reporting-export-menu.png', { fullPage: false });
  await page.keyboard.press('Escape');
  await expect(page.locator('[data-test-subj="wamReportExport-pdf"]')).toBeHidden({ timeout: 10_000 });

  const exportTab = await page.context().newPage();
  try {
    await exportTab.setViewportSize(DOC_VIEWPORT);
    await exportTab.goto(`${API}/reports/export?format=html&inline=1&from=now-7d&to=now`);
    await expect(exportTab.locator('.wam-report-header h1')).toBeVisible({ timeout: 120_000 });
    await exportTab.screenshot({ path: path.join(capture.dir, 'reporting-export-html.png'), fullPage: true });
  } finally {
    await exportTab.close();
  }

  // Phase 9 lab case: Indicators section and one alert's Enrichment tab (10.5 a).
  const labCase = await findLabCase(page);
  if (!labCase) {
    console.warn(`lab case "${LAB_CASE_TITLE}" is not open on the stack: case-indicators.png and alert-enrichment.png skipped (${theme})`);
    return;
  }
  const labFlyout = await openCaseFlyout(page, labCase.id);
  await expect(labFlyout.locator('[data-test-subj="wamCaseFlyoutTitle"]')).toContainText(LAB_CASE_TITLE, { timeout: 60_000 });
  await labFlyout.getByRole('button', { name: 'Expand to full screen' }).click();
  await labFlyout.locator('[data-test-subj="wamCaseNav-indicators"]').click();
  const indicators = labFlyout.locator('[data-test-subj="wamCaseIndicators"]');
  await expect(indicators).toBeVisible({ timeout: 30_000 });
  await expect(indicators.locator('.wamIndicatorTable tbody tr').first()).toBeVisible({ timeout: 60_000 });
  await expect(indicators.locator('[data-test-subj="wamCaseIndicatorsRefresh"]')).toBeEnabled({ timeout: 60_000 });
  await capture.element(page, '.wamCaseFlyout', 'case-indicators.png');

  // 11.4 / 11.5: the header summary line ("1 agent" + counts) and the Assets
  // section; the lab case has one agent, so its row is expanded by default
  // and the chips show the 4.x SCA wording with the Configuration Assessment link.
  await expect(labFlyout.locator('[data-test-subj="wamCaseAssetSummaryAgents"]')).toHaveText(/^\d+ agents?$/, { timeout: 30_000 });
  await labFlyout.locator('[data-test-subj="wamCaseNav-assets"]').click();
  const assets = labFlyout.locator('[data-test-subj="wamCaseAssets"]');
  await expect(assets).toBeVisible({ timeout: 30_000 });
  const assetRows = assets.locator('[data-test-subj^="wamCaseAssetRow-"]');
  await expect(assetRows.first()).toBeVisible({ timeout: 30_000 });
  if ((await assetRows.count()) > 1 || (await assets.locator('[data-test-subj="wamCaseAssetContext"]').count()) === 0) {
    await assets.locator('[data-test-subj^="wamCaseAssetRowToggle-"]').first().click();
  }
  const assetContext = assets.locator('[data-test-subj="wamCaseAssetContext"]').first();
  await expect(assetContext).toBeVisible({ timeout: 30_000 });
  await expect(assetContext.locator('[data-test-subj="wamAssetContextChip-os"]')).toBeVisible({ timeout: 60_000 });
  const scaChip = assetContext.locator('[data-test-subj="wamAssetContextChip-sca"]');
  const scaLink = assetContext.locator('[data-test-subj="wamAssetContextLinkSca"]');
  if (TARGET_WAZUH_MAJOR === 4) {
    await expect(scaChip).toContainText('not indexed on 4.x', { timeout: 30_000 });
    await expect(scaLink).toBeVisible({ timeout: 30_000 });
    await expect(assetContext.locator('[data-test-subj="wamAssetContextLinkHygiene"]')).toBeVisible();
    await expect(assetContext.locator('[data-test-subj="wamAssetContextLinkVuln"]')).toBeVisible();
  }
  await capture.element(page, '.wamCaseFlyout', 'case-assets.png');
  if (TARGET_WAZUH_MAJOR === 4 && !scaLinkFollowed) {
    // Once per run: the link opens the Wazuh app's Configuration Assessment
    // module for the row's agent in a new tab.
    scaLinkFollowed = true;
    const agentId = ((await labFlyout.locator('[data-test-subj^="wamCaseAssetRowId-"]').first().textContent().catch(() => '')) || '')
      .replace(/[^0-9]/g, '') || '001';
    const href = (await scaLink.getAttribute('href')) || '';
    expect(href).toContain('/app/configuration-assessment');
    expect(href).toContain(`agentId=${agentId}`);
    const [popup] = await Promise.all([page.context().waitForEvent('page', { timeout: 30_000 }), scaLink.click()]);
    try {
      await popup.waitForLoadState('domcontentloaded', { timeout: 60_000 });
      expect(popup.url()).toContain('/app/configuration-assessment');
      expect(popup.url()).toContain(`agentId=${agentId}`);
      await expect(popup.locator('body')).not.toContainText('Application Not Found', { timeout: 10_000 });
      await expect(popup.getByText(/Configuration Assessment|wam-lab-agent/i).first()).toBeVisible({ timeout: 120_000 });
    } finally {
      await popup.close();
    }
  }
  await labFlyout.getByRole('button', { name: 'Collapse', exact: true }).click();
  await labFlyout.locator('[data-test-subj="wamCaseFlyoutClose"]').click();
  await expect(labFlyout).toBeHidden({ timeout: 30_000 });

  // The first linked alert whose Enrichment tab lists indicator rows (one
  // carrying stored verdicts is preferred: lab_setup step 10 looked one up).
  let fallback: string | null = null;
  let chosen: string | null = null;
  for (const alertId of labCase.alert_ids.slice(0, LAB_ALERT_PROBES)) {
    const flyout = await openAlertFlyout(page, alertId);
    await expect(flyout.locator('[data-test-subj="wamAlertFlyoutMeta"]')).toBeVisible({ timeout: 60_000 });
    await flyout.locator('[data-test-subj="wamAlertNav-enrichment"]').click();
    const panel = flyout.locator('[data-test-subj="wamEnrichmentPanel"]');
    await expect(panel).toBeVisible({ timeout: 30_000 });
    const rows = panel.locator('.wamEnrichmentTable tbody tr');
    await rows.first().waitFor({ state: 'visible', timeout: 5_000 }).catch(() => undefined);
    if ((await rows.count()) === 0) continue;
    if (!fallback) fallback = alertId;
    if ((await panel.locator('[data-test-subj="wamEnrichmentBadges"]').count()) > 0) {
      chosen = alertId;
      break;
    }
  }
  chosen = chosen || fallback;
  if (!chosen) {
    console.warn(`no alert of the lab case lists enrichment rows: alert-enrichment.png skipped (${theme})`);
    return;
  }
  const enrichmentFlyout = await openAlertFlyout(page, chosen);
  await expect(enrichmentFlyout.locator('[data-test-subj="wamAlertFlyoutMeta"]')).toBeVisible({ timeout: 60_000 });
  await enrichmentFlyout.getByRole('button', { name: 'Expand to full screen' }).click();
  await enrichmentFlyout.locator('[data-test-subj="wamAlertNav-enrichment"]').click();
  const enrichmentPanel = enrichmentFlyout.locator('[data-test-subj="wamEnrichmentPanel"]');
  await expect(enrichmentPanel.locator('.wamEnrichmentTable tbody tr').first()).toBeVisible({ timeout: 30_000 });
  await capture.element(page, '.wamAlertFlyout', 'alert-enrichment.png');
  await enrichmentFlyout.getByRole('button', { name: 'Collapse', exact: true }).click();
  await enrichmentFlyout.locator('[data-test-subj="wamAlertFlyoutClose"]').click();
  await expect(enrichmentFlyout).toBeHidden({ timeout: 30_000 });
}

test('capture documentation screenshots in light and dark mode', async ({ page }) => {
  test.skip(process.env.WAM_DOC_SCREENSHOTS !== '1', 'Set WAM_DOC_SCREENSHOTS=1 to refresh public documentation images.');
  test.skip(process.env.WAM_E2E_MUTATING !== '1', 'Set WAM_E2E_MUTATING=1: the capture switches the global theme:darkMode setting.');
  test.setTimeout(1_500_000);
  await page.setViewportSize(DOC_VIEWPORT);
  await signIn(page, process.env.WAM_E2E_USERNAME!, process.env.WAM_E2E_PASSWORD!);
  await expect(page.getByRole('heading', { name: /(Alert|Finding) queue/ })).toBeVisible({ timeout: 120_000 });
  // The dashboard's own side menu stays collapsed for every capture (the init
  // script the helper installs keeps it so across navigations).
  await collapseOsdNav(page);
  // The SCA assertions branch on the build's Wazuh line, so the version read
  // must succeed: a swallowed failure would run the 4.x-only checks on a 5.0 build.
  const version: any = await api(page, 'GET', `${API}/system/version`);
  expect(version?.targetWazuhMajor, 'system/version reports targetWazuhMajor').toBeTruthy();
  TARGET_WAZUH_MAJOR = Number(version.targetWazuhMajor) || 4;

  const previous = await readDarkMode(page);
  test.skip(previous.isOverridden, 'theme:darkMode is overridden in opensearch_dashboards.yml (uiSettings.overrides); it cannot be switched or restored.');
  try {
    for (const theme of THEMES) {
      await writeDarkMode(page, theme === 'dark');
      await reloadWorkbench(page);
      expect(await isDarkTheme(page), `${theme} theme active`).toBe(theme === 'dark');
      await captureTheme(page, theme);
    }
  } finally {
    // Restore through the API alone: a page.goto here would mask the capture
    // failure when the page or context is already gone.
    try {
      await writeDarkMode(page, previous.value);
    } catch (error) {
      console.error(`theme:darkMode could not be restored to ${String(previous.value)}: ${(error as Error).message}`);
    }
  }
  await reloadWorkbench(page);
  expect(await isDarkTheme(page)).toBe(previous.value === true);
});
