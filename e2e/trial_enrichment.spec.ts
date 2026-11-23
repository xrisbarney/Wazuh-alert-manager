import { expect, Page, test } from '@playwright/test';
import { API, api, fromSeedRun, openAlertFlyout, openCaseFlyout, openSettingsSection, pollUntil, seedAlerts, seedFindingsV5, signIn, waitForProjectedAlert } from './helpers';
import { EnrichmentStub, STUB_CONTAINER_HOST, startEnrichmentStub } from './stubs/enrichment_stub';

/**
 * Phase 6 bench (PLAN.md 6.6): a generic HTTP enrichment source against a
 * local stub, an analyst lookup from the alert flyout with the stored verdict
 * showing as a queue badge, asset criticality stamped on freshly synced
 * alerts (plus the asset-context chips' no-inventory state for the synthetic
 * agent), the case Indicators tab aggregating the seeded source IPs, and, on
 * a 5.0 stack (`WAM_E2E_PROFILE=wazuh5`), a seeded `wazuh.threat.enrichments[]`
 * hit projected to `threat.matches[]` and shown as an indicator verdict hint.
 *
 * Mutating: it rewrites the enrichment and asset settings documents (restored
 * afterwards), seeds alerts and creates a case. Needs the Docker stack with
 * `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=<STUB_CONTAINER_HOST>` on the
 * dashboard service (`host.docker.internal` unless `WAM_E2E_STUB_HOST`
 * overrides it; scripts/dev/e2e-deploy.sh writes the default).
 */

const STUB_SOURCE_ID = 'wam-e2e-stub';
const ASSET_ENTRY_ID = 'wam-e2e-agent';
const AGENT_NAME = 'wam-e2e-agent';
const SEEDED_SRCIP = '203.0.113.77';
const QUEUE_QUERY = `${API}/alerts?from_offset=0&size=50&sortField=@timestamp&sortDirection=desc&agentNames=${AGENT_NAME}`;

const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;

test.describe.configure({ mode: 'serial' });

test.describe('trial: enrichment and assets', () => {
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 to run the mutating enrichment bench.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  let page: Page;
  let stub: EnrichmentStub;
  let savedEnrichmentSources: any[] | null = null;
  let savedAssets: any[] | null = null;
  let enrichedAlertId = '';
  let criticalRun = '';
  let criticalAlertIds: string[] = [];
  let caseId = '';

  test.beforeAll(async ({ browser }) => {
    stub = await startEnrichmentStub();
    page = await browser.newPage();
    await signIn(page, username!, password!);
  });

  test.afterAll(async () => {
    try {
      if (savedEnrichmentSources) await api(page, 'PUT', `${API}/enrichment/settings`, { sources: savedEnrichmentSources });
    } catch (e) {
      console.warn(`could not restore enrichment settings: ${String(e)}`);
    }
    try {
      if (savedAssets) await api(page, 'PUT', `${API}/assets/settings`, { assets: savedAssets });
    } catch (e) {
      console.warn(`could not restore asset settings: ${String(e)}`);
    }
    await stub?.close();
    await page?.close();
  });

  test('generic HTTP source against the local stub is saved and answers a test lookup', async () => {
    test.setTimeout(120_000);
    const current = await api(page, 'GET', `${API}/enrichment/settings`);
    savedEnrichmentSources = (current.sources || []).filter((source: any) => source.id !== STUB_SOURCE_ID);
    expect(
      current.egressAllowedHosts,
      `dashboard service must allowlist the stub host ${STUB_CONTAINER_HOST} (see scripts/dev/e2e-deploy.sh / WAM_E2E_STUB_HOST)`
    ).toContain(STUB_CONTAINER_HOST);

    const stubSource = {
      id: STUB_SOURCE_ID,
      name: 'WAM e2e stub',
      kind: 'generic_http',
      enabled: true,
      supports: ['ip'],
      urlTemplate: stub.urlTemplate,
      verdictPath: '/verdict',
      scorePath: '/score',
      tagsPath: '/tags',
      allowInsecure: true,
      cacheTtlSeconds: 60,
      timeoutMs: 5000,
    };
    const saved = await api(page, 'PUT', `${API}/enrichment/settings`, { sources: [...savedEnrichmentSources!, stubSource] });
    const persisted = saved.sources.find((source: any) => source.id === STUB_SOURCE_ID);
    expect(persisted).toMatchObject({ kind: 'generic_http', enabled: true, allowInsecure: true, urlTemplate: stub.urlTemplate });

    const probe = await api(page, 'POST', `${API}/enrichment/test/${STUB_SOURCE_ID}`);
    expect(probe.status, JSON.stringify(probe)).toBe('ok');
    expect(probe.result?.verdict).toBe('malicious');
    await stub.waitForRequests(1, 10_000);

    // The settings tab lists the source.
    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'enrichment');
    const row = page.locator(`[data-test-subj="wamEnrichmentSource-${STUB_SOURCE_ID}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toContainText('WAM e2e stub');
  });

  test('lookup from the alert flyout stores a malicious verdict and the queue shows the badge', async () => {
    test.setTimeout(360_000);
    const seed = seedAlerts({ count: 2 });
    const hit = await waitForProjectedAlert(page, fromSeedRun(seed.run), { agentName: AGENT_NAME });
    enrichedAlertId = hit._id;
    expect(hit._source.data?.srcip).toBe(SEEDED_SRCIP);

    const flyout = await openAlertFlyout(page, enrichedAlertId);
    await flyout.locator('[data-test-subj="wamAlertNav-enrichment"]').click();
    const panel = flyout.locator('[data-test-subj="wamEnrichmentPanel"]');
    await expect(panel).toBeVisible();
    const ipRow = panel.locator('tr', { hasText: SEEDED_SRCIP }).first();
    await expect(ipRow).toBeVisible();
    const before = stub.requests.length;
    await ipRow.locator('[data-test-subj="wamEnrichmentLookup"]').click();
    const badges = ipRow.locator('[data-test-subj="wamEnrichmentBadges"]');
    await expect(badges).toBeVisible({ timeout: 30_000 });
    await expect(badges).toContainText(/malicious/);
    await expect(badges).toContainText(/90/);
    await expect(ipRow.locator('[data-test-subj="wamEnrichmentLookupError"]')).toHaveCount(0);

    const asked = await stub.waitForRequests(before + 1, 10_000);
    const last = asked[asked.length - 1];
    expect(last.query).toMatchObject({ type: 'ip', value: SEEDED_SRCIP });

    // Stored on the record, not only in the session.
    const stored = await pollUntil(
      page,
      async () => {
        const result = await api(page, 'GET', QUEUE_QUERY);
        const record = (result?.hits?.hits || []).find((row: any) => row._id === enrichedAlertId);
        return record?._source?.enrichment?.worst_verdict === 'malicious' ? record : null;
      },
      { label: 'stored enrichment verdict' }
    );
    expect(stored._source.enrichment.items.some((item: any) => item.source === STUB_SOURCE_ID && item.verdict === 'malicious')).toBe(true);

    // After a reload the queue row of THIS record (not a stale one from an
    // earlier run) carries the badge and the flyout shows the stored verdict.
    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    const flagged = queueRow(page, enrichedAlertId);
    await expect(flagged).toBeVisible({ timeout: 60_000 });
    await expect(queueRowCell(page, enrichedAlertId, '[data-test-subj="wamEnrichmentQueueBadge"]')).toHaveText('malicious');

    const reopened = await openAlertFlyout(page, enrichedAlertId);
    await reopened.locator('[data-test-subj="wamAlertNav-enrichment"]').click();
    const storedRow = reopened.locator('[data-test-subj="wamEnrichmentPanel"] tr', { hasText: SEEDED_SRCIP }).first();
    await expect(storedRow.locator('[data-test-subj="wamEnrichmentBadges"]')).toContainText(/malicious/);
  });

  test('asset criticality is stamped on newly synced alerts and the Assets tab resolves the agent', async () => {
    test.setTimeout(360_000);
    const current = await api(page, 'GET', `${API}/assets/settings`);
    savedAssets = (current.assets || []).filter((entry: any) => entry.id !== ASSET_ENTRY_ID);
    const entry = { id: ASSET_ENTRY_ID, match: { kind: 'name', value: AGENT_NAME }, criticality: 'critical', tags: ['e2e'] };
    const saved = await api(page, 'PUT', `${API}/assets/settings`, { assets: [...savedAssets!, entry] });
    expect(saved.assets.find((item: any) => item.id === ASSET_ENTRY_ID)).toMatchObject({ criticality: 'critical' });

    const resolved = await api(page, 'GET', `${API}/assets/resolve?agentName=${AGENT_NAME}`);
    expect(resolved).toMatchObject({ criticality: 'critical', matchedId: ASSET_ENTRY_ID, matchedBy: 'name' });

    const seed = seedAlerts({ count: 2 });
    criticalRun = seed.run;
    const fromRun = fromSeedRun(seed.run);
    const hit = await waitForProjectedAlert(page, (row) => fromRun(row) && row._source?.asset?.criticality === 'critical', { agentName: AGENT_NAME });
    expect(hit._source.asset).toMatchObject({ criticality: 'critical', tags: ['e2e'], matched_id: ASSET_ENTRY_ID });
    // The seeder stamps now+2s plus a per-doc offset, so the second record may
    // only land on the next sync tick: wait for both instead of reading once.
    criticalAlertIds = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter(fromRun);
        return rows.length === 2 && rows.every((row: any) => row._source?.asset?.criticality === 'critical') ? rows.map((row: any) => row._id) : null;
      },
      { label: 'both critical alerts projected', timeoutMs: 180_000, pollMs: 5_000 }
    );

    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    const criticalRow = queueRow(page, criticalAlertIds[0]);
    await expect(criticalRow).toBeVisible({ timeout: 60_000 });
    const criticalBadge = queueRowCell(page, criticalAlertIds[0], '[data-test-subj="wamAssetQueueBadge"]');
    await expect(criticalBadge).toHaveText('Critical');
    await expect(criticalBadge).toHaveAttribute('data-criticality', 'critical');

    // Asset-context chips: the synthetic agent has no inventory in the native
    // states indices (and SCA has no state index on 4.x), so every chip must
    // show a no-data / no-access / n/a state, never a value or a read error.
    const flyout = await openAlertFlyout(page, criticalAlertIds[0]);
    const chips = flyout.locator('[data-test-subj="wamAlertAssetContext"] [data-test-subj^="wamAssetContextChip-"]');
    await expect(flyout.locator('[data-test-subj="wamAssetContextLoading"]')).toHaveCount(0, { timeout: 30_000 });
    await expect(flyout.locator('[data-test-subj="wamAssetContextFailed"]')).toHaveCount(0);
    await expect(chips).toHaveCount(5);
    for (const key of ['os', 'ips', 'ports', 'cves', 'sca']) {
      const chip = flyout.locator(`[data-test-subj="wamAssetContextChip-${key}"]`);
      await expect(chip).toBeVisible();
      await expect(chip).toHaveAttribute('data-status', /^(no_data|no_access|not_available)$/);
    }

    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'assets');
    await expect(page.locator(`[data-test-subj="wamAsset-${ASSET_ENTRY_ID}"]`)).toBeVisible({ timeout: 30_000 });
    await page.locator('[data-test-subj="wamAssetTestName"]').fill(AGENT_NAME);
    await page.locator('[data-test-subj="wamAssetTestRun"]').click();
    const result = page.locator('[data-test-subj="wamAssetTestResult"]');
    await expect(result).toBeVisible({ timeout: 30_000 });
    await expect(result.locator('[data-test-subj="wamAssetTestCriticality"]')).toHaveText('Critical');
    await expect(result).toContainText(ASSET_ENTRY_ID);
  });

  test('case Indicators tab aggregates the seeded source IP over both alerts', async () => {
    test.setTimeout(180_000);
    expect(criticalAlertIds.length, 'previous step seeds the alerts this case links').toBe(2);
    const created = await api(page, 'POST', `${API}/cases`, {
      title: `WAM e2e indicators ${criticalRun}`,
      severity: 'high',
      alertIds: criticalAlertIds,
    });
    caseId = created.id;
    expect(caseId).toMatch(/^case-/);

    const indicators = await api(page, 'GET', `${API}/cases/${caseId}/indicators`);
    const ip = (indicators.indicators || []).find((item: any) => item.type === 'ip' && item.value === SEEDED_SRCIP);
    expect(ip, JSON.stringify(indicators).slice(0, 500)).toBeTruthy();
    expect(ip.count).toBe(2);
    expect([...ip.alert_ids].sort()).toEqual([...criticalAlertIds].sort());

    const flyout = await openCaseFlyout(page, caseId);
    await flyout.locator('[data-test-subj="wamCaseNav-indicators"]').click();
    const tab = flyout.locator('[data-test-subj="wamCaseIndicators"]');
    await expect(tab).toBeVisible();
    const row = tab.locator('tr', { hasText: SEEDED_SRCIP }).first();
    await expect(row).toBeVisible({ timeout: 30_000 });
    await expect(row).toContainText(/203\.0\.113\./);
    await expect(row.getByRole('cell', { name: '2', exact: true })).toHaveCount(1);
    await expect(tab.locator('[data-test-subj="wamCaseIndicatorsCopyAll"]')).toBeVisible();
  });

  test('5.0: a seeded wazuh.threat.enrichments[] hit is projected and shown as an indicator verdict hint', async () => {
    test.skip(process.env.WAM_E2E_PROFILE !== 'wazuh5', 'Set WAM_E2E_PROFILE=wazuh5 on a Wazuh 5.0 stack (plugin-owned findings stream).');
    test.setTimeout(360_000);
    const seed = seedFindingsV5({ count: 2, severity: 'high' });
    expect(seed.threat_ip).toBe(SEEDED_SRCIP);
    const hit = await waitForProjectedAlert(
      page,
      (row) => row._source?.rule?.id === seed.rule_id && row._source?.data?.srcip === seed.threat_ip,
      { agentName: AGENT_NAME }
    );
    expect(hit._source.asset?.groups).toEqual(expect.arrayContaining(seed.agent_groups));
    const match = (hit._source.threat?.matches || []).find((item: any) => item.indicator?.name === seed.threat_ip);
    expect(match, JSON.stringify(hit._source.threat)).toMatchObject({
      source: 'wazuh5_engine',
      verdict: 'malicious',
      matched_field: 'source.ip',
      indicator: { type: 'ipv4-addr', provider: 'wam-e2e', feed: 'wam-e2e-feed', confidence: 'high' },
    });

    const flyout = await openAlertFlyout(page, hit._id);
    const ipRow = flyout.locator('[data-test-subj="wamIndicatorGroup-ip"] .wamIndicatorRow', { hasText: seed.threat_ip }).first();
    await expect(ipRow).toBeVisible({ timeout: 30_000 });
    await expect(ipRow.locator('.wamIndicatorHints')).toContainText(/malicious/);
  });
});

/**
 * The queue row rendering one projected record. The alert queue is an
 * EuiDataGrid (PLAN.md 13.1) and renders no row element: `.wamAlertRow` is
 * the row's anchor cell and every cell of the row carries `data-alert-id`.
 */
function queueRow(page: Page, alertId: string) {
  return page.locator(`.wamAlertRow[data-alert-id="${alertId}"]`);
}

/** One element inside that row, in whichever of its cells it is rendered. */
function queueRowCell(page: Page, alertId: string, selector: string) {
  return page.locator(`.wamAlertCell[data-alert-id="${alertId}"] ${selector}`);
}
