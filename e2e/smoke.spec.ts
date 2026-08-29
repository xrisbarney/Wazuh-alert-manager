import { expect, test } from '@playwright/test';

test('admin can sign in and open Wazuh Alert Manager', async ({ page }) => {
  test.setTimeout(180_000);
  const username = process.env.WAM_E2E_USERNAME;
  const password = process.env.WAM_E2E_PASSWORD;

  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  await page.goto('/app/wazuh-alert-manager');

  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(username!);
    await page.locator('[data-test-subj="password"]').fill(password!);
    await page.locator('[data-test-subj="submit"]').click();
  }

  await expect(page).toHaveURL(/\/app\/wazuh-alert-manager/, { timeout: 60_000 });
  await expect(page.locator('body')).toContainText(/Wazuh alert manager/i, { timeout: 60_000 });

  const header = page.locator('.wamWorkbenchHeader');
  await expect(header).toBeVisible();
  const headerContrast = await page.evaluate(() => {
    const parse = (value: string) => (value.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    const luminance = (rgb: number[]) => {
      const channels = rgb.map((value) => {
        const normalized = value / 255;
        return normalized <= 0.03928 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    };
    const heading = document.querySelector('.wamWorkbenchHeader h1') as HTMLElement;
    const container = document.querySelector('.wamWorkbenchHeader') as HTMLElement;
    const foreground = luminance(parse(getComputedStyle(heading).color));
    const background = luminance(parse(getComputedStyle(container).backgroundColor));
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
  });
  expect(headerContrast).toBeGreaterThanOrEqual(4.5);
  await page.evaluate(() => window.scrollTo(0, 800));
  await page.waitForTimeout(250);
  expect((await header.boundingBox())!.y).toBeLessThanOrEqual(70);
  await page.evaluate(() => window.scrollTo(0, 0));

  const alertStats = page.locator('.wamQueueStats');
  await expect(alertStats).toBeVisible();
  await page.getByRole('button', { name: 'Hide summary' }).click();
  await expect(alertStats).toBeHidden();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Show summary' })).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: 'Show summary' }).click();
  await expect(alertStats).toBeVisible();

  await page.getByRole('tab', { name: 'Cases' }).click();
  await expect(page.getByRole('heading', { name: 'Case queue' })).toBeVisible();
  await expect(page.locator('.wamQueueStats')).toBeVisible();
  await page.getByRole('button', { name: 'Hide summary' }).click();
  await expect(page.locator('.wamQueueStats')).toBeHidden();
  await page.getByRole('button', { name: 'Show summary' }).click();

  await page.getByRole('tab', { name: 'Settings' }).click();
  await page.getByRole('tab', { name: 'Storage & lifecycle' }).click();
  await expect(page.getByText('Automatic rollover', { exact: true })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText('Maximum generation age', { exact: false })).toBeVisible();
  await expect(page.getByText('Alert retention (days)', { exact: false })).toBeVisible();
  await expect(page.getByText('Activity retention (days)', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Roll evidence generation' })).toBeVisible();
  await expect(page.getByText('Evidence generations', { exact: true })).toBeVisible();
});
