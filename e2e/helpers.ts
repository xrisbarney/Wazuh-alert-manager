import { expect, Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as https from 'https';
import * as path from 'path';

export const API = '/api/wazuh_alert_manager';

/** Sign in through the dashboard login form (no-op when already signed in). */
export async function signIn(page: Page, username: string, password: string) {
  await page.goto('/app/wazuh-alert-manager');
  if (page.url().includes('/app/login')) {
    await page.locator('[data-test-subj="user-name"]').waitFor({ state: 'visible', timeout: 60_000 });
    await page.locator('[data-test-subj="user-name"]').fill(username);
    await page.locator('[data-test-subj="password"]').fill(password);
    await page.locator('[data-test-subj="submit"]').click();
  }
  await expect(page).toHaveURL(/\/app\/wazuh-alert-manager/, { timeout: 60_000 });
  await expect(page.locator('body')).toContainText(/Wazuh alert manager/i, { timeout: 60_000 });
}

/**
 * Call a plugin (or dashboard) route from inside the browser session. OSD
 * rejects every mutating request without the `osd-xsrf` header, and
 * `credentials: 'same-origin'` reuses the signed-in cookie.
 */
export async function api(page: Page, method: string, path: string, body?: any): Promise<any> {
  return page.evaluate(async ({ method, path, body }: { method: string; path: string; body?: any }) => {
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

export interface SeedResult {
  /** Documents written by the seeder. */
  seeded: number;
  /** Test-owned source index (never a native Wazuh index). */
  index: string;
  /** Seeder run marker; seeded doc ids are `wam-e2e-<run>-<n>`. */
  run: string;
}

function parseSeedOutput(stdout: string): SeedResult {
  const line = stdout.split(/\r?\n/).reverse().find((item) => item.trim().startsWith('{'));
  if (!line) throw new Error(`seed_alerts.py printed no JSON summary:\n${stdout}`);
  return JSON.parse(line) as SeedResult;
}

/**
 * Seed fresh 4.x-shaped alerts into the plugin-owned test index.
 *
 * `WAM_E2E_SEED=local` runs `e2e/seed_alerts.py` on this machine against
 * `WAM_SEED_URL` (default `https://localhost:9200`) with
 * `WAM_SEED_USERNAME`/`WAM_SEED_PASSWORD` (default: the e2e credentials).
 * Otherwise the seeder runs on the 4.x Vagrant lab through `vagrant ssh`.
 */
export function seedAlerts(options: { count?: number } = {}): SeedResult {
  const count = options.count;
  if (process.env.WAM_E2E_SEED === 'local') {
    const repoRoot = path.resolve(__dirname, '..');
    const password = process.env.WAM_SEED_PASSWORD || process.env.WAM_E2E_PASSWORD;
    if (!password) throw new Error('Set WAM_SEED_PASSWORD (or WAM_E2E_PASSWORD) in .env.e2e.local for local seeding');
    const args = ['-I', path.join('e2e', 'seed_alerts.py'), ...(count ? ['--count', String(count)] : [])];
    const stdout = execFileSync(process.env.WAM_SEED_PYTHON || 'python', args, {
      cwd: repoRoot,
      stdio: 'pipe',
      timeout: 120_000,
      env: {
        ...process.env,
        WAM_INDEXER: process.env.WAM_SEED_URL || 'https://localhost:9200',
        WAM_USER: process.env.WAM_SEED_USERNAME || process.env.WAM_E2E_USERNAME || 'admin',
        WAM_PW: password,
      },
    }).toString();
    return parseSeedOutput(stdout);
  }
  const vagrantDir = process.env.WAM_E2E_VAGRANT_DIR || path.resolve(process.cwd(), '..', '..', 'wazuh414-vagrant');
  const remote = [
    'cd /home/vagrant/wazuh-alert-manager-src',
    'set -a',
    '. ./.env.e2e.local',
    'set +a',
    'export WAM_USER="$WAM_E2E_USERNAME" WAM_PW="$WAM_E2E_PASSWORD"',
    `python3 e2e/seed_alerts.py${count ? ` --count ${count}` : ''}`,
  ].join(' && ');
  const stdout = execFileSync('vagrant', ['ssh', '-c', remote], { cwd: vagrantDir, stdio: 'pipe', timeout: 120_000 }).toString();
  return parseSeedOutput(stdout);
}

export interface SeedFindingsResult {
  seeded: number;
  findings_stream: string;
  findings_index: string;
  events_index: string;
  severity: string;
  run: string;
  /** `wazuh.rule.id` every finding of this run carries (`wam-e2e-<run>-rule`). */
  rule_id: string;
  /** Source IP whose findings carry a seeded `wazuh.threat.enrichments[]` hit. */
  threat_ip: string;
  agent_groups: string[];
}

/**
 * Seed Wazuh 5.0-shaped findings into the plugin-owned test streams
 * (`e2e/seed_findings_v5.py`). `WAM_E2E_SEED=local` runs it on this machine
 * against `WAM_SEED_URL`; otherwise it runs on the 5.0 Vagrant lab through
 * `vagrant ssh` (same command as `full_ui.spec.ts`).
 */
export function seedFindingsV5(options: { count?: number; severity?: string } = {}): SeedFindingsResult {
  const args = [...(options.count ? ['--count', String(options.count)] : []), ...(options.severity ? ['--severity', options.severity] : [])];
  const parse = (stdout: string) => {
    const line = stdout.split(/\r?\n/).reverse().find((item) => item.trim().startsWith('{'));
    if (!line) throw new Error(`seed_findings_v5.py printed no JSON summary:\n${stdout}`);
    return JSON.parse(line) as SeedFindingsResult;
  };
  if (process.env.WAM_E2E_SEED === 'local') {
    const repoRoot = path.resolve(__dirname, '..');
    const password = process.env.WAM_SEED_PASSWORD || process.env.WAM_E2E_PASSWORD;
    if (!password) throw new Error('Set WAM_SEED_PASSWORD (or WAM_E2E_PASSWORD) in .env.e2e.local for local seeding');
    const stdout = execFileSync(process.env.WAM_SEED_PYTHON || 'python', ['-I', path.join('e2e', 'seed_findings_v5.py'), ...args], {
      cwd: repoRoot,
      stdio: 'pipe',
      timeout: 120_000,
      env: {
        ...process.env,
        WAM_INDEXER: process.env.WAM_SEED_URL || 'https://localhost:9200',
        WAM_USER: process.env.WAM_SEED_USERNAME || process.env.WAM_E2E_USERNAME || 'admin',
        WAM_PW: password,
      },
    }).toString();
    return parse(stdout);
  }
  const vagrantDir = process.env.WAM_E2E_VAGRANT_DIR || path.resolve(process.cwd(), '..', '..', 'wazuh-vagrant');
  const remote = [
    'cd /home/vagrant/wam-tools',
    "export WAM_PW=$(sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2- | sed -e 's/^\"//' -e 's/\"$//')",
    'export WAM_INDEXER=https://localhost:9200',
    `python3 e2e/seed_findings_v5.py${args.length ? ` ${args.join(' ')}` : ''}`,
  ].join(' && ');
  const stdout = execFileSync('vagrant', ['ssh', '-c', remote], { cwd: vagrantDir, stdio: 'pipe', timeout: 120_000 }).toString();
  return parse(stdout);
}

export interface ProjectedAlertHit {
  _id: string;
  _source: any;
}

/**
 * Poll `GET /alerts` until a projected record satisfies `predicate`. The sync
 * job runs on a fixed interval (30-60 s), so the default budget covers two
 * ticks plus the seeder's small future timestamp offset.
 */
export async function waitForProjectedAlert(
  page: Page,
  predicate: (hit: ProjectedAlertHit) => boolean,
  options: { timeoutMs?: number; pollMs?: number; agentName?: string; size?: number } = {}
): Promise<ProjectedAlertHit> {
  const timeoutMs = options.timeoutMs ?? 180_000;
  const pollMs = options.pollMs ?? 5_000;
  const query = new URLSearchParams({
    from_offset: '0',
    size: String(options.size ?? 100),
    sortField: '@timestamp',
    sortDirection: 'desc',
  });
  if (options.agentName) query.set('agentNames', options.agentName);
  const deadline = Date.now() + timeoutMs;
  let lastTotal: any = null;
  while (Date.now() < deadline) {
    const result = await api(page, 'GET', `${API}/alerts?${query.toString()}`);
    const hits: ProjectedAlertHit[] = result?.hits?.hits || [];
    lastTotal = result?.hits?.total;
    const match = hits.find((hit) => predicate(hit));
    if (match) return match;
    await page.waitForTimeout(pollMs);
  }
  throw new Error(`No projected alert matched within ${timeoutMs} ms (last total: ${JSON.stringify(lastTotal)})`);
}

/** Predicate for records projected from a `seedAlerts()` run. */
export function fromSeedRun(run: string) {
  const prefix = `wam-e2e-${run}-`;
  return (hit: ProjectedAlertHit) => String(hit._source?.source_id || '').startsWith(prefix);
}

/** Open the workbench with one alert's flyout showing (the app honours `?alert=`). */
export async function openAlertFlyout(page: Page, alertId: string) {
  await page.goto(`/app/wazuh-alert-manager?tab=alerts&alert=${encodeURIComponent(alertId)}`);
  const flyout = page.locator('.wamAlertFlyout');
  await expect(flyout).toBeVisible({ timeout: 60_000 });
  return flyout;
}

/** Open the workbench on the Cases tab with one case's flyout showing (`?case=`). */
export async function openCaseFlyout(page: Page, caseId: string) {
  await page.goto(`/app/wazuh-alert-manager?tab=cases&case=${encodeURIComponent(caseId)}`);
  const flyout = page.locator('.wamCaseFlyout');
  await expect(flyout).toBeVisible({ timeout: 60_000 });
  return flyout;
}

/** Poll `probe` until it returns a non-null value; throws after `timeoutMs`. */
export async function pollUntil<T>(
  page: Page,
  probe: () => Promise<T | null | undefined | false>,
  options: { timeoutMs?: number; pollMs?: number; label?: string } = {}
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const pollMs = options.pollMs ?? 2_000;
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const value = await probe();
      if (value) return value as T;
    } catch (e) {
      lastError = e;
    }
    await page.waitForTimeout(pollMs);
  }
  throw new Error(`${options.label || 'condition'} not met within ${timeoutMs} ms${lastError ? `: ${String(lastError)}` : ''}`);
}

export interface RawApiResponse {
  status: number;
  ok: boolean;
  /** Response headers, lower-cased names. */
  headers: Record<string, string>;
  /** Body as text (downloads such as CSV, Markdown, HTML and attachment files). */
  text: string;
}

/**
 * Like `api()` but for routes that answer with a file rather than JSON: the
 * body comes back as text together with the status and headers, and a non-2xx
 * answer is returned, not thrown, so a test can assert on it.
 */
export async function apiRaw(page: Page, method: string, path: string, body?: any): Promise<RawApiResponse> {
  return page.evaluate(async ({ method, path, body }: { method: string; path: string; body?: any }) => {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json', 'osd-xsrf': 'wam-e2e' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    return { status: response.status, ok: response.ok, headers, text: await response.text() };
  }, { method, path, body });
}

/** Split one CSV record (RFC 4180 quoting, as the server's `toCsvLine` writes it) into cells. */
export function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (quoted) {
      if (char === '"' && line[i + 1] === '"') { current += '"'; i += 1; }
      else if (char === '"') quoted = false;
      else current += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { cells.push(current); current = ''; }
    else current += char;
  }
  cells.push(current);
  return cells;
}

/**
 * The alert queue is an `EuiDataGrid` (PLAN.md 13.1), which is virtualized and
 * renders no row element at all: a row is its set of cells, each carrying
 * `data-alert-id` and `.wamAlertCell`, and the first visible column's cell is
 * the row anchor (`.wamAlertRow`, which also carries the severity band).
 *
 * `queueRow` is that anchor - a single element, so it can be awaited and
 * asserted on; anything rendered in another cell of the same row is reached
 * with `queueRowCell`.
 */
export function queueRow(page: Page, alertId: string) {
  return page.locator(`.wamAlertRow[data-alert-id="${alertId}"]`);
}

/** One element inside the queue row of `alertId`, in whichever cell it is rendered. */
export function queueRowCell(page: Page, alertId: string, selector: string) {
  return page.locator(`.wamAlertCell[data-alert-id="${alertId}"] ${selector}`);
}

/** The selection checkbox of the queue row of `alertId`. */
export function queueRowCheckbox(page: Page, alertId: string) {
  return queueRowCell(page, alertId, 'input[type="checkbox"]').first();
}

/**
 * The case queue is the same grid (PLAN.md 13.2): every cell of a row carries
 * `data-case-id` and `.wamCaseQueueCell`, and the Title cell is the row anchor
 * (`.wamCaseRow`, which also carries the severity band).
 */
export function caseQueueRow(page: Page, caseId: string) {
  return page.locator(`.wamCaseRow[data-case-id="${caseId}"]`);
}

/** One element inside the case queue row of `caseId`, in whichever cell it is rendered. */
export function caseQueueRowCell(page: Page, caseId: string, selector: string) {
  return page.locator(`.wamCaseQueueCell[data-case-id="${caseId}"] ${selector}`);
}

/** Apply the queue's pending filters (the filter bar's "Apply" button). */
export async function applyQueueFilters(page: Page) {
  await page.locator('.wamQueryRow__apply button').click();
}

export interface IndexerResponse {
  status: number;
  ok: boolean;
  body: any;
}

/**
 * Call the indexer REST API directly over HTTPS (never through the dashboard's
 * `/api/console/proxy`), the way the local seeders do: `WAM_SEED_URL`
 * (default `https://localhost:9200`) with `WAM_SEED_USERNAME` /
 * `WAM_SEED_PASSWORD` (default: the e2e credentials). The dev stack's
 * certificate is self-signed, so verification is off. A non-2xx answer is
 * returned, not thrown.
 */
export function indexerRequest(method: string, path: string, body?: any): Promise<IndexerResponse> {
  const base = process.env.WAM_SEED_URL || 'https://localhost:9200';
  const username = process.env.WAM_SEED_USERNAME || process.env.WAM_E2E_USERNAME || 'admin';
  const password = process.env.WAM_SEED_PASSWORD || process.env.WAM_E2E_PASSWORD;
  if (!password) throw new Error('Set WAM_SEED_PASSWORD (or WAM_E2E_PASSWORD) in .env.e2e.local for indexer calls');
  const url = new URL(path, base);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise<IndexerResponse>((resolve, reject) => {
    const request = https.request(
      url,
      {
        method,
        rejectUnauthorized: false,
        headers: {
          authorization: `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`,
          ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: any = text;
          try {
            parsed = text ? JSON.parse(text) : null;
          } catch (e) {
            parsed = text;
          }
          const status = response.statusCode || 0;
          resolve({ status, ok: status >= 200 && status < 300, body: parsed });
        });
      }
    );
    request.on('error', reject);
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

/** Settings section ids: the `?settingsTab=` values and the `wamSettingsNav-<id>` side-nav items (step 8.3). */
export type SettingsSectionId =
  | 'automation'
  | 'task-lists'
  | 'sla'
  | 'notifications'
  | 'ai'
  | 'enrichment'
  | 'assets'
  | 'reports'
  | 'sync'
  | 'storage'
  | 'about';

/**
 * Open one settings section through the grouped side nav. The workbench must
 * already be on the Settings tab (`?tab=settings` or the Settings tab clicked);
 * resolves to the page column of that section.
 */
export async function openSettingsSection(page: Page, id: SettingsSectionId) {
  const item = page.locator(`[data-test-subj="wamSettingsNav-${id}"]`);
  await expect(item).toBeVisible({ timeout: 60_000 });
  await item.click();
  await expect(item).toHaveClass(/isSelected/, { timeout: 30_000 });
  const section = page.locator(`[data-test-subj="wamSettingsPage-${id}"]`);
  await expect(section).toBeVisible({ timeout: 30_000 });
  return section;
}

/**
 * Collapse the dashboard's own side navigation (step 10.2 layout checks). OSD
 * keeps the collapsible nav docked while `localStorage['core.chrome.isLocked']`
 * is `true`; the helper clears that flag for every later navigation, reloads,
 * and closes the nav if it is still open. Safe to call when the nav is
 * already collapsed or the chrome has no toggle.
 */
export async function collapseOsdNav(page: Page) {
  await page.addInitScript(() => {
    try { window.localStorage.setItem('core.chrome.isLocked', 'false'); } catch (e) { /* storage blocked */ }
  });
  await page.evaluate(() => {
    try { window.localStorage.setItem('core.chrome.isLocked', 'false'); } catch (e) { /* storage blocked */ }
  });
  await page.reload();
  await expect(page.locator('body')).toContainText(/Wazuh alert manager/i, { timeout: 60_000 });
  const nav = page.locator('[data-test-subj="collapsibleNav"]');
  if (await nav.isVisible().catch(() => false)) {
    const undock = nav.locator('[data-test-subj="collapsible-nav-lock"]');
    if (await undock.isVisible().catch(() => false)) await undock.click();
    const toggle = page.locator('[data-test-subj="toggleNavButton"]').first();
    if ((await nav.isVisible().catch(() => false)) && (await toggle.isVisible().catch(() => false))) await toggle.click();
    await expect(nav).toBeHidden({ timeout: 10_000 });
  }
}

/** RFC1918 / loopback / link-local / CGNAT / ULA address (IPv4 or IPv6), i.e. not something a public TI source can judge. */
export function isPrivateIp(value: string): boolean {
  const v = value.trim().toLowerCase();
  // IPv4-mapped IPv6 (`::ffff:10.0.2.77`, what the sshd decoder emits on dual-stack hosts): judge the IPv4 part.
  const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIp(mapped[1]);
  if (v.includes(':')) return v === '::1' || v.startsWith('fe80:') || /^f[cd]/.test(v) || v === '::';
  const parts = v.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

/** Type a Lucene query into the alert queue's search field (not applied until `applyQueueFilters`). */
export async function setQueueQuery(page: Page, query: string) {
  const input = page.getByRole('searchbox', { name: 'Lucene alert query' });
  await expect(input).toBeVisible({ timeout: 60_000 });
  await input.fill(query);
}

/** Pick one of the queue's quick time ranges by its label (e.g. "Last 24 hours"). */
export async function pickQuickTimeRange(page: Page, label: string) {
  const button = page.locator('.wamTimeRangeButton');
  await expect(button).toBeVisible({ timeout: 60_000 });
  if ((await button.innerText()).trim() === label) return; // already selected (the popover toggles on click)
  const popover = page.locator('.wamTimePopover');
  for (let attempt = 0; attempt < 3 && !(await popover.isVisible()); attempt += 1) {
    await button.click();
    await popover.waitFor({ state: 'visible', timeout: 3_000 }).catch(() => undefined);
  }
  await popover.getByRole('button', { name: label, exact: true }).click();
  await expect(button).toContainText(label);
}
