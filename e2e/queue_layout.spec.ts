import { expect, Page, test } from '@playwright/test';
import { API, api, collapseOsdNav, pollUntil, queueRow, queueRowCell, signIn } from './helpers';

/**
 * Queue layout bench (PLAN.md 10.2): at 1280x800 and 1920x1080, with the
 * dashboard's side navigation collapsed, neither queue table scrolls
 * sideways, and the Actions column's expand button of an alert linked to a
 * case with an 80-character title is hit-testable (the long title truncates
 * inside the Case column instead of covering the button).
 *
 * Mutating: links one existing open alert to a case created here with the
 * 80-character title; `afterAll` unlinks the alert again and closes the case
 * (cases cannot be deleted through the plugin API; the close excludes the
 * alert, which keeps its status).
 */

const RUN = Date.now().toString(36);
const CASE_TITLE = `WAM e2e queue layout ${RUN} `.padEnd(80, 'x').slice(0, 80);
const VIEWPORTS = [
  { width: 1280, height: 800 },
  { width: 1920, height: 1080 },
];

const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;

test.describe.configure({ mode: 'serial' });

/** `scrollWidth` / `clientWidth` of a queue's scrolling wrapper (`.wamQueueTable`) and its table's width. */
async function tableOverflow(page: Page, tableClass: string) {
  const wrapper = page.locator(`.${tableClass}`).first();
  await expect(wrapper).toBeVisible({ timeout: 60_000 });
  return wrapper.evaluate((node) => ({
    scrollWidth: node.scrollWidth,
    clientWidth: node.clientWidth,
    // Both queues are EuiDataGrids (13.1, 13.2): the widest element is the
    // grid content.
    tableWidth: (node.querySelector('.euiDataGrid__content') || node.querySelector('table'))?.scrollWidth ?? 0,
  }));
}

/** True when the element at the centre of `locator` is the element itself or one of its descendants. */
async function isHitTestable(locator: ReturnType<Page['locator']>): Promise<{ ok: boolean; covering: string }> {
  await locator.scrollIntoViewIfNeeded();
  return locator.evaluate((node) => {
    const box = node.getBoundingClientRect();
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    const ok = hit === node || (hit != null && node.contains(hit));
    const describe = (element: Element | null) =>
      element ? `${element.tagName.toLowerCase()}.${String(element.className).replace(/\s+/g, '.')}` : 'nothing';
    return { ok, covering: ok ? '' : describe(hit) };
  });
}

test.describe('queue layout at 1280 and 1920 with the dashboard nav collapsed', () => {
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 to run the queue layout bench (it links one alert to a long-titled case).');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  let page: Page;
  let alertId = '';
  let caseId = '';

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await signIn(page, username!, password!);

    // One open alert of the default queue window (last 24 h, open / in
    // progress) becomes the linked alert; the title is exactly 80 characters.
    const listed = await api(
      page,
      'GET',
      `${API}/alerts?from_offset=0&size=1&sortField=@timestamp&sortDirection=desc&statuses=open&from=now-24h&to=now`
    );
    const hit = listed?.hits?.hits?.[0];
    expect(hit, 'the stack needs at least one open alert in the last 24 h (seed_alerts.py)').toBeTruthy();
    alertId = hit._id;
    expect(CASE_TITLE.length).toBe(80);
    const created = await api(page, 'POST', `${API}/cases`, { title: CASE_TITLE, severity: 'low', alertIds: [alertId] });
    caseId = created.id;
    expect(caseId).toMatch(/^case-/);
  });

  test.afterAll(async () => {
    try {
      if (caseId && alertId) await api(page, 'PUT', `${API}/cases/${encodeURIComponent(caseId)}`, { removeAlertIds: [alertId] });
    } catch (e) {
      console.warn(`could not unlink the alert: ${String(e)}`);
    }
    try {
      if (caseId) {
        await api(page, 'POST', `${API}/cases/${encodeURIComponent(caseId)}/close`, {
          excludeAlertIds: alertId ? [alertId] : [],
          disposition: 'undetermined',
          closureReason: 'queue_layout.spec.ts fixture',
        });
      }
    } catch (e) {
      console.warn(`could not close the fixture case: ${String(e)}`);
    }
    await page?.close();
  });

  for (const viewport of VIEWPORTS) {
    test(`${viewport.width}x${viewport.height}: both queues fit and the expand button of the long-case alert is not covered`, async () => {
      test.setTimeout(180_000);
      await page.setViewportSize(viewport);
      await page.goto('/app/wazuh-alert-manager?tab=alerts');
      await collapseOsdNav(page);

      // Alert queue: no horizontal scroll on the wrapper, the table no wider than it.
      const alerts = await tableOverflow(page, 'wamAlertTable');
      expect(alerts.scrollWidth, `alert queue scrollWidth ${alerts.scrollWidth} > clientWidth ${alerts.clientWidth}`).toBeLessThanOrEqual(alerts.clientWidth + 1);
      // `tableOverflow` falls back to 0 when it finds no grid content, which
      // would make the width comparison pass on a queue that never rendered.
      expect(alerts.tableWidth, 'the alert grid content must have been measured').toBeGreaterThan(0);
      expect(alerts.tableWidth).toBeLessThanOrEqual(alerts.clientWidth + 1);
      // ... and not short of it either: the 13.1/13.2 defect 13.3 fixed was
      // EUI's `useDefaultColumnWidth` counting the hidden columns, collapsing
      // the flexible Rule column to its 100px floor and leaving ~750px of the
      // panel empty. Only an upper bound would have passed that.
      expect(alerts.tableWidth, 'the alert grid must fill its panel').toBeGreaterThan(alerts.clientWidth - 48);

      // The linked alert's row: the badge truncates but keeps the full title,
      // ends before the expand button, and the button is hit-testable.
      const row = queueRow(page, alertId);
      await expect(row).toBeVisible({ timeout: 60_000 });
      const badge = queueRowCell(page, alertId, '[data-test-subj="wamAlertCaseBadge"]');
      await pollUntil(page, async () => ((await badge.getAttribute('title').catch(() => null)) === CASE_TITLE ? true : null), {
        label: 'case title resolved on the badge',
        timeoutMs: 60_000,
      });
      const badgeBox = (await badge.boundingBox())!;
      const expand = queueRowCell(page, alertId, '[data-test-subj="wamAlertExpand"]');
      await expect(expand).toBeVisible();
      const expandBox = (await expand.boundingBox())!;
      expect(badgeBox.x + badgeBox.width, 'the case badge must end before the expand button starts').toBeLessThanOrEqual(expandBox.x);
      const hit = await isHitTestable(expand);
      expect(hit.ok, `expand button covered by ${hit.covering}`).toBe(true);

      // Case queue: same wrapper check, and the Created by column is gone.
      await page.getByRole('tab', { name: 'Cases' }).click();
      await expect(page.getByRole('heading', { name: 'Case queue' })).toBeVisible({ timeout: 60_000 });
      const cases = await tableOverflow(page, 'wamCaseTable');
      expect(cases.scrollWidth, `case queue scrollWidth ${cases.scrollWidth} > clientWidth ${cases.clientWidth}`).toBeLessThanOrEqual(cases.clientWidth + 1);
      expect(cases.tableWidth, 'the case grid content must have been measured').toBeGreaterThan(0);
      expect(cases.tableWidth).toBeLessThanOrEqual(cases.clientWidth + 1);
      expect(cases.tableWidth, 'the case grid must fill its panel').toBeGreaterThan(cases.clientWidth - 48);
      // Created by is not a default column any more; it is one of the two the
      // column selector can add (13.2).
      const headers = await page.locator('.wamCaseTable .euiDataGridHeaderCell').allTextContents();
      // An empty header list would make the next assertion vacuous.
      expect(headers.length, 'the case grid header must have rendered').toBeGreaterThan(5);
      expect(headers.map((text) => text.trim())).not.toContain('Created by');
    });
  }
});
