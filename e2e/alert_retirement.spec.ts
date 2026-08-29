import { expect, test } from '@playwright/test';

async function call(page: any, method: string, path: string, body?: any) {
  return page.evaluate(async ({ method, path, body }: any) => {
    const response = await fetch(path, {
      method, credentials: 'same-origin',
      headers: { 'content-type': 'application/json', 'osd-xsrf': 'wam-e2e' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${JSON.stringify(payload)}`);
    return payload;
  }, { method, path, body });
}

test('alert generation can retire and restore without touching native Wazuh indices', async ({ page }) => {
  test.skip(process.env.WAM_E2E_MUTATING !== '1', 'Set WAM_E2E_MUTATING=1 for the storage bench.');
  test.setTimeout(600_000);
  await page.goto('/app/wazuh-alert-manager');
  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(process.env.WAM_E2E_USERNAME!);
    await page.locator('[data-test-subj="password"]').fill(process.env.WAM_E2E_PASSWORD!);
    await page.locator('[data-test-subj="submit"]').click();
  }
  await expect(page).toHaveURL(/\/app\/wazuh-alert-manager/, { timeout: 60_000 });

  const before = await call(page, 'GET', '/api/wazuh_alert_manager/system/health');
  const source = before.generations.alerts.find((item: any) => item.isWriteIndex)?.index;
  expect(source).toBeTruthy();
  await call(page, 'POST', '/api/wazuh_alert_manager/system/rollover', { family: 'alerts' });
  const plan = await call(page, 'POST', '/api/wazuh_alert_manager/system/retirement/plan', { retiringIndex: source });
  expect(plan.retiringIndex).toBe(source);
  expect(plan.totalDocuments).toBeGreaterThanOrEqual(0);
  const retired = await call(page, 'POST', '/api/wazuh_alert_manager/system/retirement/execute', {
    retiringIndex: source, confirmation: source,
  });
  expect(retired.retiringIndex).toBe(source);

  const archived = await call(page, 'GET', '/api/wazuh_alert_manager/system/health');
  expect(archived.generations.archivedAlerts.some((item: any) => item.index === source)).toBe(true);
  const restored = await call(page, 'POST', '/api/wazuh_alert_manager/system/retirement/restore', {
    index: source, confirmation: `RESTORE ${source}`,
  });
  expect(restored).toEqual(expect.objectContaining({ index: source }));
  expect(restored.restored + restored.alreadyLive).toBeGreaterThanOrEqual(plan.totalDocuments);
  console.log(`WAM_E2E_RETIRED_ALERT_INDEX=${source}`);
});
