import { expect, test } from '@playwright/test';
import { fromSeedRun, seedAlerts, signIn, waitForProjectedAlert } from './helpers';

// Proves the seeding path: write test-owned alerts into the indexer and wait
// for the sync job to project one of them into the workbench.
test('seeded alert is projected into the alert queue', async ({ page }) => {
  test.skip(process.env.WAM_E2E_MUTATING !== '1', 'Set WAM_E2E_MUTATING=1 to seed fixtures.');
  test.setTimeout(300_000);
  const username = process.env.WAM_E2E_USERNAME;
  const password = process.env.WAM_E2E_PASSWORD;
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  const seed = seedAlerts({ count: 3 });
  expect(seed.seeded).toBe(3);
  expect(seed.index).toBe('wazuh-alerts-4.x-wam-e2e');

  await signIn(page, username!, password!);
  const hit = await waitForProjectedAlert(page, fromSeedRun(seed.run), { agentName: 'wam-e2e-agent' });
  expect(hit._source.source_index).toBe(seed.index);
  expect(hit._source.agent?.name).toBe('wam-e2e-agent');
  console.log(`WAM_E2E_SEEDED_ALERT ${hit._id}`);
});
