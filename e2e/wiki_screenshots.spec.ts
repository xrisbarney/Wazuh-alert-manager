import { expect, Page, test } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const output = path.resolve(process.cwd(), 'wiki', 'images');

async function signIn(page: Page) {
  await page.goto('/app/wazuh-alert-manager');
  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(process.env.WAM_E2E_USERNAME!);
    await page.locator('[data-test-subj="password"]').fill(process.env.WAM_E2E_PASSWORD!);
    await page.locator('[data-test-subj="submit"]').click();
  }
  await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 120_000 });
}

async function capture(page: Page, name: string) {
  await page.screenshot({ path: path.join(output, name), fullPage: true });
}

async function captureElement(page: Page, selector: string, name: string) {
  await page.locator(selector).screenshot({ path: path.join(output, name) });
}

test('capture public wiki screenshots', async ({ page }) => {
  test.skip(process.env.WAM_DOC_SCREENSHOTS !== '1', 'Set WAM_DOC_SCREENSHOTS=1 to refresh public documentation images.');
  test.setTimeout(300_000);
  fs.mkdirSync(output, { recursive: true });
  await page.setViewportSize({ width: 1600, height: 1050 });
  await signIn(page);

  await expect(page.getByText(/Showing 1-20 of [1-9][\d,]* alerts/)).toBeVisible({ timeout: 180_000 });
  await capture(page, 'workbench-alert-queue.png');

  await page.getByRole('tab', { name: 'Cases' }).click();
  await expect(page.getByRole('heading', { name: 'Case queue' })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText(/[1-9][\d,]* cases?/, { exact: true })).toBeVisible({ timeout: 180_000 });
  await capture(page, 'workbench-case-queue.png');

  await page.getByRole('button', { name: /^Open details for / }).first().click();
  const caseFlyout = page.locator('.wamCaseFlyout');
  await expect(caseFlyout.getByRole('tab', { name: 'Overview' })).toBeVisible({ timeout: 120_000 });
  await caseFlyout.getByRole('button', { name: 'Expand to full screen' }).click();
  await captureElement(page, '.wamCaseFlyout', 'case-overview.png');
  await caseFlyout.getByRole('tab', { name: /^Linked Alerts/ }).click();
  await expect(caseFlyout.getByRole('columnheader', { name: 'Evidence' })).toBeVisible({ timeout: 120_000 });
  await captureElement(page, '.wamCaseFlyout', 'case-linked-evidence.png');
  await caseFlyout.getByRole('tab', { name: 'Attack Graph' }).click();
  await expect(caseFlyout.getByRole('heading', { name: 'Kill-chain phases' })).toBeVisible({ timeout: 180_000 });
  await captureElement(page, '.wamCaseFlyout', 'case-attack-graph.png');
  await caseFlyout.getByText('Alert timeline', { exact: true }).click({ force: true });
  await expect(caseFlyout.getByRole('button', { name: 'Alert timeline', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await captureElement(page, '.wamCaseFlyout', 'case-alert-timeline.png');
  await caseFlyout.getByRole('button', { name: 'Collapse' }).click();
  await caseFlyout.getByRole('button', { name: 'Close' }).click().catch(() => undefined);

  await page.getByRole('tab', { name: 'Settings' }).click();
  await expect(page.getByRole('tab', { name: 'Automation rules' })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole('button', { name: 'New rule' }).first()).toBeEnabled({ timeout: 180_000 });
  await capture(page, 'automation-rules.png');

  await page.getByRole('button', { name: 'New rule' }).first().click();
  const flyout = page.locator('.wamRuleFlyout');
  await flyout.getByRole('tab', { name: '3. Trigger' }).click();
  await flyout.getByRole('button', { name: 'Add OR group' }).click();
  await flyout.getByRole('button', { name: 'Add AND predicate' }).click();
  await flyout.getByLabel('Operator').selectOption('exists');
  await capture(page, 'automation-trigger-entities.png');
  await flyout.getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('tab', { name: 'Storage & lifecycle' }).click();
  await expect(page.getByRole('heading', { name: 'Storage and lifecycle' })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText('Automatic rollover', { exact: true })).toBeVisible({ timeout: 180_000 });
  await capture(page, 'storage-lifecycle.png');

  await page.goto('/app/wazuhAlertManagerReporting');
  await expect(page.getByRole('heading', { name: 'Reporting' })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText(/alerts occurred in this cohort/)).toBeVisible({ timeout: 180_000 });
  await capture(page, 'reporting.png');
});
