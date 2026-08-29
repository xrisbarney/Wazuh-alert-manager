import { expect, test } from '@playwright/test';

async function signIn(page: any) {
  await page.goto('/app/wazuh-alert-manager');
  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(process.env.WAM_E2E_USERNAME!);
    await page.locator('[data-test-subj="password"]').fill(process.env.WAM_E2E_PASSWORD!);
    await page.locator('[data-test-subj="submit"]').click();
  }
  await expect(page).toHaveURL(/\/app\/wazuh-alert-manager/, { timeout: 60_000 });
}

async function api(page: any, method: string, path: string, body?: any) {
  return page.evaluate(async ({ method, path, body }: any) => {
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

test('case, evidence, graph, close, reporting, and lifecycle APIs work together', async ({ page }) => {
  test.skip(process.env.WAM_E2E_MUTATING !== '1', 'Set WAM_E2E_MUTATING=1 for the disposable lifecycle bench.');
  test.setTimeout(180_000);
  await signIn(page);

  const alerts = await api(page, 'GET', '/api/wazuh_alert_manager/alerts?from_offset=0&size=1');
  const alertId = alerts?.hits?.hits?.[0]?._id;
  expect(alertId).toBeTruthy();

  const marker = `E2E lifecycle ${Date.now()}`;
  const created = await api(page, 'POST', '/api/wazuh_alert_manager/cases', {
    title: marker, description: 'Disposable release bench fixture', severity: 'high', alertIds: [alertId], assignedTo: null,
  });
  expect(created.id).toMatch(/^case-/);

  const opened = await api(page, 'GET', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}`);
  expect(opened.case.alert_ids).toContain(alertId);
  expect(opened.evidence.evidence.some((item: any) => item.alert_id === alertId)).toBe(true);

  const beforeRollover = await api(page, 'GET', '/api/wazuh_alert_manager/system/health');
  const caseSourceGeneration = beforeRollover.generations.cases.find((item: any) => item.isWriteIndex)?.index;
  const evidenceSourceGeneration = beforeRollover.generations.evidence.find((item: any) => item.isWriteIndex)?.index;
  expect(caseSourceGeneration).toBeTruthy();
  expect(evidenceSourceGeneration).toBeTruthy();
  await api(page, 'POST', '/api/wazuh_alert_manager/system/rollover', { family: 'cases' });
  await api(page, 'POST', '/api/wazuh_alert_manager/system/rollover', { family: 'evidence' });

  const updated = await api(page, 'PUT', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}`, {
    status: 'in_progress', addAlertIds: [], removeAlertIds: [],
  });
  expect(updated.status).toBe('in_progress');

  const held = await api(page, 'PUT', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}/evidence/${encodeURIComponent(alertId)}/hold`, {
    reason: 'E2E hold and release validation',
  });
  expect(held.hold_reason).toContain('E2E');
  const released = await api(page, 'DELETE', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}/evidence/${encodeURIComponent(alertId)}/hold`);
  expect(released.hold_reason).toBeNull();

  const graph = await api(page, 'GET', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}/attack-path`);
  expect(graph).toEqual(expect.objectContaining({ truncated: false, limit: 5000 }));

  const closed = await api(page, 'POST', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}/close`, { excludeAlertIds: [] });
  expect(closed.caseClosed).toBe(true);
  expect(closed.failedAlertIds).toEqual([]);

  const afterClose = await api(page, 'GET', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}`);
  expect(afterClose.case.status).toBe('closed');

  const to = new Date(Date.now() + 60_000).toISOString();
  const from = new Date(Date.now() - 7 * 86400000).toISOString();
  const report = await api(page, 'GET', `/api/wazuh_alert_manager/reports/metrics?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  expect(report.exact).toBe(true);
  expect(report.caseBasis).toBe('exact_cohort');

  await api(page, 'POST', '/api/wazuh_alert_manager/system/evidence-retirement/execute', {
    index: evidenceSourceGeneration, confirmation: evidenceSourceGeneration,
  });
  const casePlan = await api(page, 'POST', '/api/wazuh_alert_manager/system/cases/retirement/plan', {
    retiringIndex: caseSourceGeneration,
  });
  expect(casePlan.retiringIndex).toBe(caseSourceGeneration);
  await api(page, 'POST', '/api/wazuh_alert_manager/system/cases/retirement/execute', {
    retiringIndex: caseSourceGeneration, confirmation: caseSourceGeneration,
  });

  const afterRetirement = await api(page, 'GET', `/api/wazuh_alert_manager/cases/${encodeURIComponent(created.id)}`);
  expect(afterRetirement.case.status).toBe('closed');
  const health = await api(page, 'GET', '/api/wazuh_alert_manager/system/health');
  expect(health.generations.evidence.length).toBeGreaterThan(0);
  expect(health.generations.cases.length).toBeGreaterThan(0);
  expect(health.generations.archivedEvidenceRelationships.some((item: any) => item.index === evidenceSourceGeneration)).toBe(true);
  expect(health.generations.archivedCases.some((item: any) => item.index === caseSourceGeneration)).toBe(true);
  console.log(`WAM_E2E_CASE_ID=${created.id}`);
});
