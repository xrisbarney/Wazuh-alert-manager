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

test('capture public wiki screenshots', async ({ page }) => {
  test.skip(process.env.WAM_DOC_SCREENSHOTS !== '1', 'Set WAM_DOC_SCREENSHOTS=1 to refresh public documentation images.');
  test.setTimeout(300_000);
  fs.mkdirSync(output, { recursive: true });
  await page.setViewportSize({ width: 1600, height: 1050 });
  await signIn(page);

  await capture(page, 'workbench-alert-queue.png');

  await page.getByRole('tab', { name: 'Cases' }).click();
  await expect(page.getByRole('heading', { name: 'Case queue' })).toBeVisible({ timeout: 60_000 });
  await capture(page, 'workbench-case-queue.png');

  await page.getByRole('tab', { name: 'Settings' }).click();
  await expect(page.getByRole('tab', { name: 'Automation rules' })).toBeVisible({ timeout: 60_000 });
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
  await capture(page, 'storage-lifecycle.png');

  await page.goto('/app/wazuhAlertManagerReporting');
  await expect(page.getByRole('heading', { name: 'Reporting' })).toBeVisible({ timeout: 120_000 });
  await capture(page, 'reporting.png');
});
