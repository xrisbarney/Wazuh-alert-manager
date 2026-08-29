import { expect, test } from '@playwright/test';

test('toast remains above an open alert flyout', async ({ page }) => {
  test.skip(process.env.WAM_E2E_MUTATING !== '1', 'Set WAM_E2E_MUTATING=1 for the reversible UI mutation.');
  test.setTimeout(120_000);
  await page.goto('/app/wazuh-alert-manager');
  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(process.env.WAM_E2E_USERNAME!);
    await page.locator('[data-test-subj="password"]').fill(process.env.WAM_E2E_PASSWORD!);
    await page.locator('[data-test-subj="submit"]').click();
  }
  await expect(page).toHaveURL(/\/app\/wazuh-alert-manager/, { timeout: 60_000 });

  const openDetails = page.getByRole('button', { name: /^Open details for / }).first();
  await openDetails.waitFor({ state: 'visible', timeout: 60_000 });
  await openDetails.evaluate((button: HTMLElement) => button.click());
  const flyout = page.locator('.wamAlertFlyout');
  await expect(flyout).toBeVisible();
  await flyout.getByText('In progress', { exact: true }).last().click();
  const toast = page.locator('.wamGlobalToasts');
  await expect(toast).toBeVisible();
  const toastZ = await toast.evaluate((node) => Number(getComputedStyle(node).zIndex));
  const flyoutZ = await flyout.evaluate((node) => Number(getComputedStyle(node).zIndex) || 0);
  expect(toastZ).toBeGreaterThan(flyoutZ);

  // Restore the disposable status mutation before leaving the test.
  await flyout.getByText('Open', { exact: true }).last().click();
});
