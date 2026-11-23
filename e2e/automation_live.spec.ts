import { expect, Locator, Page, test } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import * as os from 'os';
import * as path from 'path';
import { API, api, applyQueueFilters, indexerRequest, openAlertFlyout, openSettingsSection, pickQuickTimeRange, pollUntil, setQueueQuery, signIn } from './helpers';

/**
 * Phase 12 bench (PLAN.md 12.1 / 12.2): automation rules proven on LIVE
 * device data, driven through the plugin UI the way an analyst would.
 *
 * Nothing here seeds alerts: every record the rules act on comes from the
 * enrolled lab agent (`lab/agent` on 4.x, `lab/agent5` on 5.0), whose events
 * are produced by the lab generator run over `vagrant ssh -c` from
 * `WAM_LAB_DIR` (command `WAM_LAB_GENERATE`). Everything the bench does, it
 * does by clicking the UI, and every assertion reads the UI. The only direct
 * API calls are the three the step allows, each marked `ALLOWED API CALL`:
 *   1. the alert status/assignee snapshot taken before any rule is enabled
 *      (`GET /alerts`, saved to `<out>/snapshot.json`) and its restore
 *      (`POST /alerts/bulk-update`) when `WAM_AUTOMATION_REVERT=1`;
 *   2. the read-only `_count` cross-check behind scenario D;
 *   3. the stdlib HTTPS receiver scenario G starts on this host.
 *
 * Owner decision (PLAN.md Phase 12 preamble): nothing is reverted. The rules
 * stay enabled and every case, task list, channel binding and asset entry
 * the bench creates stays on the stack for inspection; every artefact is
 * named with the prefix `Automation test:`. A revert exists only behind
 * `WAM_AUTOMATION_REVERT=1`.
 *
 * Gates: `WAM_AUTOMATION_LIVE=1` and `WAM_E2E_MUTATING=1`. Base URL and
 * credentials come from `WAM_E2E_URL` / `WAM_E2E_USERNAME` /
 * `WAM_E2E_PASSWORD` (4.x: `.env.e2e.local`; 5.0: `source
 * scripts/dev/env-5.0.sh`). Evidence lands in `WAM_DOC_EVIDENCE_DIR`
 * (default `runtime-evidence/automation-live/<line>/`): screenshots,
 * `snapshot.json`, `results.json` and `REPORT.md` (written by `afterAll`).
 */

const PREFIX = 'Automation test:';
const RULE_NAMES = {
  A: `${PREFIX} A per-alert triage`,
  B: `${PREFIX} B burst case`,
  C: `${PREFIX} C cooccurrence all`,
  D: `${PREFIX} D min level band`,
  E: `${PREFIX} E asset criticality high`,
  E2: `${PREFIX} E asset criticality critical`,
  F: `${PREFIX} F auto-close noise`,
  G: `${PREFIX} G notify only`,
  H: `${PREFIX} H lifecycle`,
};
const TASK_LIST_NAME = `${PREFIX} triage`;
const TASK_TITLES = ['Confirm the source address', 'Check the account for lockout', 'Record the outcome'];
const CHANNEL_NAME = `${PREFIX} webhook`;
const CHANNEL_ID = 'automation-test-webhook';
const CHANNEL_SECRET = 'automation-test-secret';
const ASSET_ID = 'automation-test-lab-agent';
const ASSET_TAG = 'lab';
const RECEIVER_HOST = process.env.WAM_E2E_STUB_HOST || 'host.docker.internal';
const RECEIVER_PORT = Number(process.env.WAM_E2E_WEBHOOK_PORT || 18443);
const RECEIVER_PATH = '/automation';
/** 12.2: pin the receiver's transport (`http` | `https`) to the one the saved channel URL carries on a rerun. */
const RECEIVER_TRANSPORT = process.env.WAM_E2E_WEBHOOK_TRANSPORT as 'http' | 'https' | undefined;
/** Preferred assignees, first one the Assign-to select offers wins (`WAM_AUTOMATION_ASSIGNEE` overrides). */
const ASSIGNEE_PREFERENCE = [process.env.WAM_AUTOMATION_ASSIGNEE, 'automation-test', 'wazuh-manager', 'admin'].filter(Boolean) as string[];
const ASSIGNEE_E_PREFERENCE = [process.env.WAM_AUTOMATION_ASSIGNEE_E, 'automation-test', 'admin', 'wazuh-manager'].filter(Boolean) as string[];
const MIN_LEVEL = 7;
/** Sync interval is 60 s by default, the generator takes ~1-2 min; alerts arrive over a few ticks. */
const SYNC_BUDGET_MS = 8 * 60_000;

const live = process.env.WAM_AUTOMATION_LIVE === '1' && process.env.WAM_E2E_MUTATING === '1';
const revert = process.env.WAM_AUTOMATION_REVERT === '1';
/** Re-run of single scenarios (`--grep`) against a stack that already holds this run's artefacts: keeps the rules and merges the earlier results.json. */
const keepExisting = process.env.WAM_AUTOMATION_KEEP_EXISTING === '1';
/**
 * Step 12.3: `WAM_AUTOMATION_SCENARIOS=G,generator-1` runs only the listed scenario ids (setup always
 * runs); a bare letter selects that scenario's `rule-<letter>` and `<letter>_...` tests.
 */
const selectedScenarios = (process.env.WAM_AUTOMATION_SCENARIOS || '').split(',').map((value) => value.trim()).filter(Boolean);
const scenarioSelected = (id: string) =>
  !selectedScenarios.length || selectedScenarios.some((wanted) => wanted === id || id === `rule-${wanted}` || id.startsWith(`${wanted}_`));
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;
const repoRoot = path.resolve(__dirname, '..');

type AlertStatus = 'open' | 'in_progress' | 'closed';

/** Identifiers of one Wazuh line (PLAN.md Phase 12 preamble). */
interface LineProfile {
  line: '4' | '5';
  agent: string;
  /** Rule group of a failed authentication. */
  failedAuthGroup: string;
  /** Rule group of a sudo (E / E2 match). */
  sudoGroup: string;
  /** Rule ids of sudo and failed su (C: `ruleIds [sudo, su]` mode all). */
  sudoRuleId: string;
  suRuleId: string;
  /** Noisiest benign group (F) and, on 5.0, the informational rule ids inside it. */
  benignGroup: string;
  benignRuleIds: string[];
  /** FIM group (G, one event per generator run). */
  fimGroup: string;
  /** Source address of the generator's sshd failures (second VM address). */
  srcip: string;
  srcuser: string;
  /** How the queue is asked for the >= 7 band: numeric level on 4.x, labels on 5.0. */
  highBand: { levelMin?: number; labels?: string[] };
}

interface SnapshotAlert {
  id: string;
  status: AlertStatus;
  assigned_to: string | null;
  case_id: string | null;
  timestamp: string;
  agent: string | null;
  rule_id: string | null;
  groups: string[];
  level: number | null;
  severity_label: string | null;
  srcip: string | null;
  srcuser: string | null;
  process: string | null;
  asset_criticality: string | null;
}

interface ScenarioResult {
  id: string;
  title: string;
  pass: boolean | null;
  reason: string;
  counts: Record<string, number | string | null>;
  ids: Record<string, string | null>;
  notes: string[];
  wallMs: number;
}

interface ReceivedRequest {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: any;
  at: string;
}

interface Receiver {
  transport: 'https' | 'http';
  port: number;
  url: string;
  requests: ReceivedRequest[];
  close(): Promise<void>;
}

const state = {
  ready: false,
  outDir: '',
  profile: null as LineProfile | null,
  buildLine: '',
  snapshot: [] as SnapshotAlert[],
  snapshotAt: '',
  assignee: '',
  assigneeE: '',
  receiver: null as Receiver | null,
  assetSavedAt: '',
  generatorRuns: [] as Array<{ run: number; startedAt: string; finishedAt: string; summary: string }>,
  /** Queue total (lab agent, last 1 hour, every status) right before each generator run. */
  baselineTotals: [] as number[],
  ruleIds: {} as Record<string, string | null>,
  caseIds: {} as Record<string, string | null>,
  results: [] as ScenarioResult[],
  defects: [] as string[],
};

let page: Page;

const result = (id: string, title: string): ScenarioResult => {
  let entry = state.results.find((item) => item.id === id);
  if (!entry) {
    entry = { id, title, pass: null, reason: '', counts: {}, ids: {}, notes: [], wallMs: 0 };
    state.results.push(entry);
  }
  return entry;
};

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const outPath = (name: string) => path.join(state.outDir, name);
/** Playwright restarts the worker after a failed test, so the bench state is persisted per scenario and restored in `beforeAll`. */
const STATE_POINTER = path.resolve(repoRoot, 'runtime-evidence', 'automation-live', '.current-run.json');
const RECEIVER_LOG = 'receiver-requests.jsonl';

function saveState() {
  if (!state.outDir) return;
  const { receiver, ...rest } = state;
  fs.writeFileSync(outPath('state.json'), JSON.stringify({ ...rest, receiverTransport: receiver?.transport ?? null, runnerPid: process.ppid }, null, 2));
  fs.mkdirSync(path.dirname(STATE_POINTER), { recursive: true });
  fs.writeFileSync(STATE_POINTER, JSON.stringify({ outDir: state.outDir, runnerPid: process.ppid, savedAt: new Date().toISOString() }));
}

async function restoreState() {
  try {
    const pointer = JSON.parse(fs.readFileSync(STATE_POINTER, 'utf8'));
    if (pointer.runnerPid !== process.ppid) return;
    const saved = JSON.parse(fs.readFileSync(path.join(pointer.outDir, 'state.json'), 'utf8'));
    const { receiverTransport, runnerPid, ...rest } = saved;
    Object.assign(state, rest, { receiver: null });
    if (receiverTransport && state.ready) state.receiver = await startReceiver(receiverTransport);
    console.log(`bench state restored after a worker restart (${state.results.length} scenario results so far)`);
  } catch (e) {
    // no pointer / another run: start fresh
  }
}

/**
 * 12.2 review: the pointer's runner when it is another live process, i.e. a concurrent bench against the
 * same stack and evidence directory (one overwrote the live 4.14 run's snapshot.json on 2026-11-22), else null.
 */
function otherRunner(): { runnerPid: number; outDir: string } | null {
  let pid = 0;
  let outDir = '';
  try {
    const pointer = JSON.parse(fs.readFileSync(STATE_POINTER, 'utf8'));
    pid = Number(pointer.runnerPid) || 0;
    outDir = String(pointer.outDir || '');
    if (!pid || pid === process.ppid) return null;
    process.kill(pid, 0);
    return { runnerPid: pid, outDir };
  } catch (e: any) {
    // no pointer, or the runner is gone (ESRCH); a live process of another user answers EPERM
    return e?.code === 'EPERM' ? { runnerPid: pid, outDir } : null;
  }
}

/** `WAM_AUTOMATION_KEEP_EXISTING=1` rerun: a test rule the earlier run created stays as saved (12.2: every rule, not only G). */
async function keptExistingRule(name: string, entry: ScenarioResult): Promise<boolean> {
  if (!keepExisting) return false;
  await openAutomation();
  if (!(await ruleRow(name).count())) return false;
  entry.notes.push(`rule ${name} already present from an earlier run; kept as saved`);
  await expect(ruleRow(name).getByRole('switch')).toHaveAttribute('aria-checked', 'true', { timeout: 60_000 });
  return true;
}

/** Every request the receiver saw, from its on-disk log (survives worker restarts). */
function receiverRequests(): ReceivedRequest[] {
  try {
    return fs.readFileSync(outPath(RECEIVER_LOG), 'utf8').split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as ReceivedRequest);
  } catch (e) {
    return [];
  }
}

async function shot(name: string) {
  if (!state.outDir) return;
  try {
    await page.screenshot({ path: outPath(`${name}.png`), fullPage: true });
  } catch (e) {
    console.warn(`screenshot ${name} failed: ${String(e)}`);
  }
}

async function dismissToasts() {
  for (let i = 0; i < 10; i += 1) {
    const button = page.getByRole('button', { name: 'Dismiss toast' }).first();
    if (!(await button.isVisible().catch(() => false))) break;
    await button.click().catch(() => undefined);
    await page.waitForTimeout(150);
  }
}

/** The `.euiFormRow` whose label reads exactly `label` (scoped to `scope`). */
function formRow(scope: Locator | Page, label: string): Locator {
  return scope.locator('.euiFormRow', { has: page.locator('label', { hasText: new RegExp(`^${escapeRegExp(label)}$`) }) });
}

/** Add values to an `EuiComboBox` (typed + Enter creates or selects the matching pill). */
async function addComboValues(row: Locator, values: string[]) {
  const input = row.locator('.euiComboBox input').first();
  for (const value of values) {
    await input.click();
    await input.fill(value);
    await input.press('Enter');
    await expect(row.locator('.euiComboBoxPill', { hasText: value })).toBeVisible({ timeout: 10_000 });
  }
}

/** Pick an option of an `EuiComboBox` by its label from the options list (no custom option). */
async function pickComboOption(input: Locator, text: string) {
  await input.click();
  await input.fill(text);
  await page.locator('[role="option"]', { hasText: text }).first().click();
}

async function openSettings(id: Parameters<typeof openSettingsSection>[1]) {
  await page.goto('/app/wazuh-alert-manager?tab=settings');
  await expect(page.locator('body')).toContainText(/Wazuh alert manager/i, { timeout: 60_000 });
  return openSettingsSection(page, id);
}

async function openAutomation() {
  await openSettings('automation');
  await expect(page.getByRole('button', { name: 'New rule' }).first()).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('.wamAutomationRulesPanel .euiBasicTable, [data-test-subj="wamRulesEmpty"]').first()).toBeVisible({ timeout: 60_000 });
}

/** The rules table row of `name`. */
function ruleRow(name: string): Locator {
  return page.locator('.wamAutomationRulesPanel tr.euiTableRow', { has: page.locator('.wamRuleIdentity strong', { hasText: new RegExp(`^${escapeRegExp(name)}$`) }) });
}

interface RuleDefinition {
  name: string;
  priority?: number;
  match: {
    ruleGroups?: string[];
    ruleGroupsMode?: 'any' | 'all';
    ruleIds?: string[];
    ruleIdsMode?: 'any' | 'all';
    agentNames?: string[];
    minLevel?: number;
    minAssetCriticality?: 'low' | 'medium' | 'high' | 'critical';
  };
  trigger:
    | { type: 'per_alert' }
    | {
        type: 'burst';
        predicates: Array<{ entity: string; operator: 'exists' | 'equals'; value?: string }>;
        threshold: number;
        windowMinutes: number;
        routing: 'separate_by_group' | 'consolidate_overlapping' | 'one_per_rule';
        cooldownMinutes: number;
        quietMinutes: number;
      };
  actions: {
    setStatus?: AlertStatus;
    disposition?: string;
    assignTo?: string;
    createCase?: boolean;
    caseSeverity?: 'low' | 'medium' | 'high' | 'critical';
    taskList?: string;
    notifyChannels?: string[];
  };
  preconditions?: { statuses?: AlertStatus[]; assignment?: 'unassigned' | 'any' };
  processingMode?: 'continue' | 'stop';
}

/** Fill the rule editor stage by stage and save the disabled draft (Settings > Automation rules must be open). */
async function createDraft(definition: RuleDefinition, shotName: string) {
  // The rules API accepts duplicate names; a second draft with the same name would break every row locator.
  if (await ruleRow(definition.name).count()) throw new Error(`a rule named "${definition.name}" already exists; delete it through Settings > Automation rules first`);
  await page.getByRole('button', { name: 'New rule' }).first().click();
  const flyout = page.locator('.wamRuleFlyout');
  await expect(flyout.getByRole('heading', { name: 'New automation rule' })).toBeVisible({ timeout: 30_000 });

  // 1. Basics
  await formRow(flyout, 'Name').locator('input').fill(definition.name);
  if (definition.priority !== undefined) await formRow(flyout, 'Priority').locator('input').fill(String(definition.priority));

  // 3. Trigger first: the match-mode toggles (All of) are only offered for bursts.
  await flyout.getByRole('tab', { name: '3. Trigger' }).click();
  if (definition.trigger.type === 'burst') {
    await flyout.getByText('Correlated burst', { exact: true }).click();
    await flyout.getByRole('button', { name: 'Add OR group' }).click();
    for (let index = 0; index < definition.trigger.predicates.length; index += 1) {
      const predicate = definition.trigger.predicates[index];
      await flyout.getByRole('button', { name: 'Add AND predicate' }).click();
      await formRow(flyout, 'Entity').nth(index).locator('select').selectOption(predicate.entity);
      await formRow(flyout, 'Operator').nth(index).locator('select').selectOption(predicate.operator);
      if (predicate.operator === 'equals') await formRow(flyout, 'Value').nth(index).locator('input').fill(predicate.value || '');
    }
    await formRow(flyout, 'Threshold').locator('input').fill(String(definition.trigger.threshold));
    await formRow(flyout, 'Window (minutes)').locator('input').fill(String(definition.trigger.windowMinutes));
    await formRow(flyout, 'Case routing').locator('select').selectOption(definition.trigger.routing);
    await formRow(flyout, 'Cooldown (minutes)').locator('input').fill(String(definition.trigger.cooldownMinutes));
    await formRow(flyout, 'Rearm after quiet (minutes)').locator('input').fill(String(definition.trigger.quietMinutes));
  }

  // 2. Match
  await flyout.getByRole('tab', { name: '2. Match' }).click();
  if (definition.match.ruleGroups?.length) await addComboValues(formRow(flyout, 'Rule groups'), definition.match.ruleGroups);
  if (definition.match.ruleGroupsMode === 'all') await formRow(flyout, 'Rule groups').getByText('All of', { exact: true }).click();
  if (definition.match.ruleIds?.length) await addComboValues(formRow(flyout, 'Rule IDs'), definition.match.ruleIds);
  if (definition.match.ruleIdsMode === 'all') await formRow(flyout, 'Rule IDs').getByText('All of', { exact: true }).click();
  if (definition.match.agentNames?.length) await addComboValues(formRow(flyout, 'Agents'), definition.match.agentNames);
  if (definition.match.minLevel !== undefined) await formRow(flyout, 'Minimum level').locator('input').fill(String(definition.match.minLevel));
  if (definition.match.minAssetCriticality) await flyout.locator('[data-test-subj="wamRuleMinAssetCriticality"]').selectOption(definition.match.minAssetCriticality);

  // 4. Actions
  await flyout.getByRole('tab', { name: '4. Actions' }).click();
  if (definition.actions.setStatus) {
    await formRow(flyout, 'Set status').locator('select').selectOption(definition.actions.setStatus);
    if (definition.actions.setStatus === 'closed' && definition.actions.disposition) {
      await flyout.locator('[data-test-subj="wamRuleDisposition"]').selectOption(definition.actions.disposition);
    }
  }
  if (definition.actions.assignTo) await formRow(flyout, 'Assign to').locator('select').selectOption(definition.actions.assignTo);
  if (definition.actions.notifyChannels?.length) {
    const input = flyout.locator('[data-test-subj="wamRuleNotifyChannels"] input').first();
    for (const channel of definition.actions.notifyChannels) await pickComboOption(input, channel);
  }
  if (definition.actions.createCase) {
    await flyout.getByLabel('Create or update a deduplicated case').check();
    if (definition.actions.caseSeverity) await formRow(flyout, 'Case severity').locator('select').selectOption(definition.actions.caseSeverity);
    if (definition.actions.taskList) await flyout.locator('[data-test-subj="wamRuleTaskList"]').selectOption({ label: definition.actions.taskList });
  }
  for (const status of definition.preconditions?.statuses || []) await flyout.locator(`label[for="precondition-${status}"]`).click();
  if (definition.preconditions?.assignment) await formRow(flyout, 'Assignment precondition').locator('select').selectOption(definition.preconditions.assignment);
  if (definition.processingMode) await formRow(flyout, 'After this rule').locator('select').selectOption(definition.processingMode);

  await shot(`${shotName}-editor`);

  // 6. Preview holds the Save button of a new draft.
  await flyout.getByRole('tab', { name: '6. Preview' }).click();
  await flyout.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByText('Draft rule saved', { exact: true })).toBeVisible({ timeout: 60_000 });
  await dismissToasts();
  await expect(ruleRow(definition.name)).toBeVisible({ timeout: 60_000 });
}

/** Reopen the saved draft, run the preview, read its count from the panel, enable through "Enable after save". */
async function previewAndEnable(name: string, shotName: string, options: { enable?: boolean } = {}): Promise<{ matching: number; text: string; notifications: number }> {
  await page.reload();
  await openSettingsSection(page, 'automation');
  const editButton = page.getByRole('button', { name: `Edit ${name}`, exact: true });
  await expect(editButton).toBeEnabled({ timeout: 60_000 });
  await editButton.click();
  const flyout = page.locator('.wamRuleFlyout');
  await flyout.getByRole('tab', { name: '6. Preview' }).click();
  await flyout.getByRole('button', { name: 'Preview last 24 hours' }).click();
  const callout = flyout.getByText(/Preview passed:/);
  await expect(callout).toBeVisible({ timeout: 180_000 });
  const text = (await flyout.locator('.euiCallOut', { hasText: 'Preview passed:' }).innerText()).replace(/\s+/g, ' ').trim();
  const matching = Number((text.match(/Preview passed: ([\d,]+) matching/) || [])[1]?.replace(/,/g, '') ?? NaN);
  const notifications = Number((await flyout.locator('[data-test-subj="wamRulePreviewNotifications"] .euiStat__title').innerText().catch(() => 'NaN')).replace(/,/g, ''));
  await shot(`${shotName}-preview`);
  if (options.enable === false) {
    await flyout.getByRole('button', { name: 'Cancel' }).click();
    return { matching, text, notifications };
  }
  await flyout.getByLabel('Enable after save').check();
  await flyout.getByRole('button', { name: 'Save and enable' }).click();
  await expect(page.getByText('Rule saved and enabled', { exact: true })).toBeVisible({ timeout: 60_000 });
  await dismissToasts();
  await expect(ruleRow(name).getByRole('switch')).toHaveAttribute('aria-checked', 'true', { timeout: 60_000 });
  return { matching, text, notifications };
}

/** Options of the editor's Assign-to select (reads the live analyst list). */
async function assigneeOptions(): Promise<string[]> {
  await page.getByRole('button', { name: 'New rule' }).first().click();
  const flyout = page.locator('.wamRuleFlyout');
  await flyout.getByRole('tab', { name: '4. Actions' }).click();
  const values = await formRow(flyout, 'Assign to').locator('select option').evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value).filter(Boolean));
  await flyout.getByRole('button', { name: 'Cancel' }).click();
  return values;
}

const pickAssignee = (offered: string[], preference: string[], avoid?: string) =>
  preference.find((name) => offered.includes(name) && name !== avoid) || preference.find((name) => offered.includes(name)) || offered[0] || '';

interface QueueFilter {
  agent?: string;
  query?: string;
  statuses?: AlertStatus[];
  assignee?: string;
  ruleIds?: string[];
  levelMin?: number;
  range?: string;
}

/** Open the Alerts queue with `filter` applied and read its total from the result summary. */
async function queueTotal(filter: QueueFilter): Promise<number> {
  await page.goto('/app/wazuh-alert-manager?tab=alerts');
  await expect(page.locator('.wamFilterBar')).toBeVisible({ timeout: 60_000 });
  if (filter.statuses) {
    for (const status of ['open', 'in_progress', 'closed'] as AlertStatus[]) {
      const chip = page.locator(`[data-test-subj="wamStatusFilter-${status}"]`);
      const active = (await chip.getAttribute('class'))?.includes('wamStatusFilter--active');
      if (active !== filter.statuses.includes(status)) await chip.click();
    }
  }
  if (filter.query !== undefined) await setQueueQuery(page, filter.query);
  if (filter.agent) await addComboValues(formRow(page, 'Agent'), [filter.agent]);
  if (filter.ruleIds?.length) await addComboValues(formRow(page, 'Rule ID'), filter.ruleIds);
  if (filter.assignee) await addComboValues(formRow(page, 'Assigned to'), [filter.assignee]);
  if (filter.levelMin !== undefined) await formRow(page, 'Level min').locator('input').fill(String(filter.levelMin));
  if (filter.range) await pickQuickTimeRange(page, filter.range);
  await Promise.all([
    page.waitForResponse((response) => response.url().includes(`${API}/alerts?`) && response.request().method() === 'GET', { timeout: 60_000 }),
    applyQueueFilters(page),
  ]);
  const summary = page.locator('[data-test-subj="wamAlertResultSummary"]');
  const empty = page.locator('[data-test-subj="wamAlertQueueEmpty"]');
  await expect(summary.or(empty)).toBeVisible({ timeout: 60_000 });
  if (await empty.isVisible().catch(() => false)) return 0;
  const text = await summary.innerText();
  return Number((text.match(/of ([\d,]+) alerts/) || [])[1]?.replace(/,/g, '') ?? NaN);
}

/** Alert ids of the rows on the current queue page (after `queueTotal`). */
async function queueRowIds(): Promise<string[]> {
  // One anchor cell per queue row (the grid renders no row element, 13.1).
  return page.locator('.wamAlertRow').evaluateAll((cells) => cells.map((cell) => cell.getAttribute('data-alert-id') || '').filter(Boolean));
}

/** The History rows of one alert's flyout (newest first), as text. */
async function alertHistory(alertId: string): Promise<string[]> {
  const flyout = await openAlertFlyout(page, alertId);
  await flyout.locator('[data-test-subj="wamAlertNav-history"]').click();
  const section = flyout.locator('[data-test-subj="wamAlertSection-history"]');
  await expect(section).toBeVisible({ timeout: 30_000 });
  await expect(section.locator('[data-test-subj="wamHistory"], [data-test-subj="wamHistoryEmpty"]').first()).toBeVisible({ timeout: 30_000 });
  return section.locator('[data-test-subj="wamHistoryRow"]').allInnerTexts();
}

const ruleIdFromHistory = (rows: string[], to: string): string | null => {
  for (const row of rows) {
    const text = row.replace(/\s+/g, ' ');
    if (!text.includes('correlation-rule')) continue;
    if (!text.includes(to)) continue;
    const match = text.match(/rule:([A-Za-z0-9_-]+)/);
    if (match) return match[1];
  }
  return null;
};

/**
 * Cases queue search; returns how many rows carry exactly `title`. The box gets the quoted colon-free
 * fragment of the title by default (the 12.1 run's search was a Lucene `query_string`, in which the colons
 * of `Automation test: <x>: automated incident` were field separators; 12.3 made it a phrase-prefix
 * match) and the exact title is matched on the rows; `fullTitle` types the whole title instead.
 */
async function casesTitled(title: string, options: { fullTitle?: boolean } = {}): Promise<number> {
  await page.goto('/app/wazuh-alert-manager?tab=cases');
  const search = page.getByPlaceholder('Search by title/description');
  await expect(search).toBeVisible({ timeout: 60_000 });
  const fragment = title.replace(`${PREFIX} `, '').replace(/: automated incident$/, '').replace(/[":]/g, ' ').trim();
  await search.fill(options.fullTitle ? title : `"${fragment}"`);
  await Promise.all([
    page.waitForResponse((response) => response.url().includes(`${API}/cases?`) && response.request().method() === 'GET', { timeout: 60_000 }),
    page.locator('[data-test-subj="wamCasesRefresh"]').click(),
  ]);
  await page.waitForTimeout(500);
  return page.getByRole('button', { name: title, exact: true }).count();
}

async function openCaseTitled(title: string): Promise<{ flyout: Locator; caseId: string | null }> {
  await page.getByRole('button', { name: title, exact: true }).first().click();
  const flyout = page.locator('.wamCaseFlyout');
  await expect(flyout).toBeVisible({ timeout: 60_000 });
  await expect(flyout.locator('[data-test-subj="wamCaseFlyoutTitle"]')).toHaveText(title, { timeout: 30_000 });
  await page.waitForTimeout(500);
  return { flyout, caseId: new URL(page.url()).searchParams.get('case') };
}

/** Run the lab generator on the VM through `vagrant ssh -c` in `WAM_LAB_DIR`. */
function runGenerator(run: number) {
  const labDir = path.resolve(repoRoot, process.env.WAM_LAB_DIR || (state.profile?.line === '5' ? 'lab/agent5' : 'lab/agent'));
  const command = process.env.WAM_LAB_GENERATE || (state.profile?.line === '5' ? 'sudo WAM_LAB_SECOND_IP=10.0.2.78 bash /lab4/generate.sh' : 'sudo bash /vagrant/generate.sh');
  const startedAt = new Date().toISOString();
  let stdout = '';
  try {
    stdout = execFileSync('vagrant', ['ssh', '-c', command], { cwd: labDir, stdio: 'pipe', timeout: 600_000 }).toString();
  } catch (e: any) {
    // 12.2 review: an empty stderr Buffer is truthy and stringifies to '', which hid the 4.14 run's failure.
    // The reason carries every field the child process error offers, and the partial output is kept on disk.
    const text = (value: any) => (value == null ? '' : String(value).trim());
    const parts = [text(e?.message), e?.status != null ? `status ${e.status}` : '', text(e?.signal), text(e?.stderr), text(e?.stdout)].filter(Boolean);
    if (state.outDir) {
      fs.writeFileSync(outPath(`generator-run-${run}.log`), [
        `# generator run ${run} FAILED in ${labDir}: vagrant ssh -c ${JSON.stringify(command)}`,
        `# started ${startedAt}, failed ${new Date().toISOString()}`,
        ...parts.map((part) => `# ${part.split(/\r?\n/)[0]}`),
        '--- stdout ---', text(e?.stdout), '--- stderr ---', text(e?.stderr), '',
      ].join('\n'));
    }
    throw new Error(`generator run ${run} failed in ${labDir}: ${parts.join(' | ') || String(e)}`);
  }
  const finishedAt = new Date().toISOString();
  const summary = stdout.split(/\r?\n/).filter((line) => /^(utc_time|ssh_src_ip|ssh_user|sudo_srcuser|su_srcuser|marker_sha256)\s*:/.test(line)).join('; ');
  state.generatorRuns.push({ run, startedAt, finishedAt, summary });
  fs.writeFileSync(outPath(`generator-run-${run}.log`), stdout);
  return { startedAt, finishedAt, summary };
}

/** Wait until the lab agent's queue (last hour, every status) grew past `baseline` and stayed stable, then give the automation lanes a moment. */
async function waitForNewAlerts(baseline: number): Promise<number> {
  const profile = state.profile!;
  let last = -1;
  let stableSince = 0;
  const deadline = Date.now() + SYNC_BUDGET_MS;
  while (Date.now() < deadline) {
    const total = await queueTotal({ agent: profile.agent, statuses: ['open', 'in_progress', 'closed'], range: 'Last 1 hour' });
    if (total > baseline) {
      if (total === last) {
        if (Date.now() - stableSince >= 75_000) {
          await page.waitForTimeout(30_000); // automation worker lanes + case routing
          return total;
        }
      } else {
        last = total;
        stableSince = Date.now();
      }
    }
    await page.waitForTimeout(15_000);
  }
  if (last > baseline) return last;
  throw new Error(`no new ${profile.agent} alerts reached the queue within ${SYNC_BUDGET_MS} ms (baseline ${baseline})`);
}

/** ALLOWED API CALL 3: stdlib HTTPS receiver (self-signed certificate) for scenario G; falls back to HTTP without openssl. */
async function startReceiver(preferred?: 'http' | 'https' | null): Promise<Receiver> {
  const requests: ReceivedRequest[] = [];
  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      let json: any = null;
      try { json = body ? JSON.parse(body) : null; } catch (e) { json = null; }
      const record: ReceivedRequest = { method: req.method || 'GET', path: new URL(req.url || '/', 'http://receiver').pathname, headers: req.headers, body, json, at: new Date().toISOString() };
      requests.push(record);
      if (state.outDir) fs.appendFileSync(outPath(RECEIVER_LOG), `${JSON.stringify(record)}\n`);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  };
  let transport: 'https' | 'http' = 'https';
  let server: http.Server | https.Server;
  try {
    // 12.2: a rerun must answer on the transport the saved channel URL carries (the first 4.14 attempt bound
    // `http://` because that shell had no openssl; an https receiver then failed every outbox row).
    if ((RECEIVER_TRANSPORT ?? preferred) === 'http') throw new Error('plain HTTP requested (the saved channel URL is http://)');
    const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wam-automation-cert-'));
    const key = path.join(certDir, 'key.pem');
    const cert = path.join(certDir, 'cert.pem');
    // Node resolves the Windows OpenSSL build, which ships without a default openssl.cfg: pass a minimal one.
    const config = path.join(certDir, 'openssl.cnf');
    fs.writeFileSync(config, `[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = ${RECEIVER_HOST}
[ext]
subjectAltName = DNS:${RECEIVER_HOST}
`);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '2', '-config', config], { stdio: 'pipe', timeout: 60_000 });
    server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, handler);
  } catch (e) {
    console.warn(`openssl unavailable, receiver falls back to plain HTTP: ${String(e)}`);
    transport = 'http';
    server = http.createServer(handler);
  }
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(RECEIVER_PORT, '0.0.0.0', () => resolve());
  });
  return {
    transport,
    port: RECEIVER_PORT,
    url: `${transport}://${RECEIVER_HOST}:${RECEIVER_PORT}${RECEIVER_PATH}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** ALLOWED API CALL 1: the alert snapshot (status / assignee / case per record) before any rule is enabled. */
async function takeSnapshot(): Promise<SnapshotAlert[]> {
  const all: SnapshotAlert[] = [];
  const size = 500;
  for (let offset = 0; offset < 10_000; offset += size) {
    const query = new URLSearchParams({ from_offset: String(offset), size: String(size), sortField: '@timestamp', sortDirection: 'desc' });
    const response = await api(page, 'GET', `${API}/alerts?${query.toString()}`);
    const hits: any[] = response?.hits?.hits || [];
    for (const hit of hits) {
      const source = hit._source || {};
      all.push({
        id: hit._id,
        status: source.status,
        assigned_to: source.assigned_to ?? null,
        case_id: source.case_id ?? null,
        timestamp: source['@timestamp'],
        agent: source.agent?.name ?? null,
        rule_id: source.rule?.id != null ? String(source.rule.id) : null,
        groups: Array.isArray(source.rule?.groups) ? source.rule.groups.map(String) : [],
        level: typeof source.rule?.level === 'number' ? source.rule.level : null,
        severity_label: source.severity_label ?? null,
        srcip: source.data?.srcip ?? null,
        srcuser: source.data?.srcuser ?? null,
        process: source.data?.process?.name ?? null,
        asset_criticality: source.asset?.criticality ?? null,
      });
    }
    const total = Number(response?.hits?.total?.value ?? response?.hits?.total ?? 0);
    if (hits.length < size || all.length >= total) break;
  }
  return all;
}

/** Line identifiers: fixed on 4.x, read live from the projected records on 5.0 (UUID rule ids are never hard-coded). */
function buildProfile(line: '4' | '5', snapshot: SnapshotAlert[]): LineProfile {
  if (line === '4') {
    return {
      line,
      agent: process.env.WAM_AUTOMATION_AGENT || 'wam-lab-agent',
      failedAuthGroup: 'authentication_failed',
      sudoGroup: 'sudo',
      sudoRuleId: process.env.WAM_AUTOMATION_SUDO_RULE_ID || '5402',
      suRuleId: process.env.WAM_AUTOMATION_SU_RULE_ID || '5301',
      benignGroup: process.env.WAM_AUTOMATION_BENIGN_GROUP || 'audit_command',
      benignRuleIds: [],
      fimGroup: 'syscheck',
      srcip: '10.0.2.77',
      srcuser: 'vagrant',
      highBand: { levelMin: MIN_LEVEL },
    };
  }
  const agent = process.env.WAM_AUTOMATION_AGENT || 'wam-lab-agent-5';
  const mine = snapshot.filter((alert) => alert.agent === agent);
  const sudo = mine.find((alert) => alert.groups.includes('attack.t1548') && alert.process === 'sudo');
  const su = mine.find((alert) => alert.process === 'su' && alert.srcuser === 'vagrant');
  const benignRuleIds = Array.from(new Set(mine.filter((alert) => alert.groups.includes('wazuh-generic-1') && alert.severity_label === 'informational').map((alert) => alert.rule_id!).filter(Boolean)));
  const sudoRuleId = process.env.WAM_AUTOMATION_SUDO_RULE_ID || sudo?.rule_id || '';
  const suRuleId = process.env.WAM_AUTOMATION_SU_RULE_ID || su?.rule_id || '';
  if (!sudoRuleId || !suRuleId) throw new Error(`could not read the 5.0 sudo/su rule ids from ${agent}'s projected records (sudo=${sudoRuleId || '-'}, su=${suRuleId || '-'}); run the generator once and retry or set WAM_AUTOMATION_SUDO_RULE_ID / WAM_AUTOMATION_SU_RULE_ID`);
  return {
    line,
    agent,
    failedAuthGroup: 'attack.t1110',
    sudoGroup: 'attack.t1548',
    sudoRuleId,
    suRuleId,
    benignGroup: 'wazuh-generic-1',
    benignRuleIds,
    fimGroup: 'wazuh-fim',
    srcip: '10.0.2.78',
    srcuser: 'vagrant',
    highBand: { labels: ['high', 'critical'] },
  };
}

function writeArtefacts() {
  if (!state.outDir) return;
  saveState();
  const payload = {
    line: state.profile?.line ?? null,
    buildLine: state.buildLine,
    baseUrl: process.env.WAM_E2E_URL || null,
    profile: state.profile,
    assignee: state.assignee,
    assigneeE: state.assigneeE,
    snapshotAt: state.snapshotAt,
    snapshotSize: state.snapshot.length,
    assetSavedAt: state.assetSavedAt,
    receiver: state.receiver ? { transport: state.receiver.transport, url: state.receiver.url, requests: receiverRequests().length } : null,
    generatorRuns: state.generatorRuns,
    ruleIds: state.ruleIds,
    caseIds: state.caseIds,
    reverted: revert,
    scenarios: state.results,
    defects: state.defects,
    writtenAt: new Date().toISOString(),
  };
  fs.writeFileSync(outPath('results.json'), JSON.stringify(payload, null, 2));
  const rows = state.results.map((item) => {
    const counts = Object.entries(item.counts).map(([key, value]) => `${key}=${value}`).join(', ');
    return `| ${item.id} | ${item.pass === null ? 'not run' : item.pass ? 'PASS' : 'FAIL'} | ${counts || '-'} | ${(item.reason || item.notes.join(' ')).replace(/\|/g, '\\|').replace(/\s+/g, ' ').slice(0, 600)} | ${Math.round(item.wallMs / 1000)} s |`;
  });
  const report = [
    `# Automation rules on live device data — Wazuh ${state.profile?.line === '5' ? '5.0' : '4.x'} run`,
    '',
    `Run: ${new Date().toISOString()} against ${process.env.WAM_E2E_URL || '(default base URL)'}. Build line (Settings > About): ${state.buildLine || 'n/a'}.`,
    `Lab agent: ${state.profile?.agent || 'n/a'}; assignee: ${state.assignee || 'n/a'} (E: ${state.assigneeE || 'n/a'}); snapshot: ${state.snapshot.length} records at ${state.snapshotAt || 'n/a'} (\`snapshot.json\`).`,
    `Generator runs: ${state.generatorRuns.map((run) => `#${run.run} ${run.startedAt} -> ${run.finishedAt}`).join('; ') || 'none'}.`,
    `Reverted: ${revert ? 'yes (WAM_AUTOMATION_REVERT=1)' : 'no — rules enabled, cases, task list, channel and asset entry left in place (owner decision)'}.`,
    '',
    '| Scenario | Result | Counts read from the UI | Notes | Wall |',
    '|---|---|---|---|---|',
    ...rows,
    '',
    '## Identifiers',
    '',
    '```json',
    JSON.stringify({ profile: state.profile, ruleIds: state.ruleIds, caseIds: state.caseIds }, null, 2),
    '```',
    '',
    '## Defects / observations',
    '',
    ...(state.defects.length ? Array.from(new Set(state.defects)).map((item) => `- ${item}`) : ['- none recorded']),
    '',
  ].join('\n');
  fs.writeFileSync(outPath('REPORT.md'), report);
}

function scenario(id: string, title: string, fn: (entry: ScenarioResult) => Promise<void>, options: { timeoutMs?: number; skipUnless?: () => boolean; skipReason?: string } = {}) {
  test(`${id}: ${title}`, async () => {
    test.setTimeout(options.timeoutMs ?? 10 * 60_000);
    test.skip(!state.ready, 'the setup scenario did not complete');
    test.skip(!scenarioSelected(id), `not in WAM_AUTOMATION_SCENARIOS (${selectedScenarios.join(',')})`);
    if (options.skipUnless) test.skip(!options.skipUnless(), options.skipReason || 'skipped');
    const entry = result(id, title);
    const started = Date.now();
    try {
      await fn(entry);
      entry.pass = true;
      // The row carries the final attempt's message only: an earlier attempt's error is not a note of a pass.
      entry.reason = '';
    } catch (e: any) {
      entry.pass = false;
      entry.reason = String(e?.message || e).replace(/\s+/g, ' ').slice(0, 1500);
      await shot(`${id}-failure`);
      throw e;
    } finally {
      entry.wallMs += Date.now() - started;
      writeArtefacts();
    }
  });
}

test.describe('automation rules on live device data', () => {
  test.skip(!live, 'Set WAM_AUTOMATION_LIVE=1 and WAM_E2E_MUTATING=1 for the live automation bench.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD (.env.e2e.local or scripts/dev/env-5.0.sh)');

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(180_000);
    await restoreState();
    page = await browser.newPage();
    await signIn(page, username!, password!);
  });

  test.afterAll(async () => {
    writeArtefacts();
    if (state.receiver) await state.receiver.close().catch(() => undefined);
    await page?.close().catch(() => undefined);
  });

  test('setup: line detection (Settings > About), snapshot, identifiers', async () => {
    test.setTimeout(10 * 60_000);
    const entry = result('setup', 'line detection, snapshot, identifiers');
    const started = Date.now();
    try {
      const about = await openSettings('about');
      await expect(about.locator('[data-test-subj="wamAbout"]')).toContainText('Target Wazuh', { timeout: 60_000 });
      const aboutText = (await about.locator('[data-test-subj="wamAbout"]').innerText()).replace(/\s+/g, ' ');
      const target = aboutText.match(/Target Wazuh\s*([^ ]+ \(reads [^)]+\))/);
      state.buildLine = target ? target[1] : aboutText.slice(0, 200);
      const line: '4' | '5' = /reads wazuh-findings-v5/.test(aboutText) ? '5' : '4';
      const outDir = path.resolve(repoRoot, process.env.WAM_DOC_EVIDENCE_DIR || path.join('runtime-evidence', 'automation-live', line));
      // 12.2 review: both refusals run before any file or UI write (state.outDir stays unset, so a refused
      // setup leaves the evidence directory and the pointer untouched).
      const other = otherRunner();
      if (other) throw new Error(`another automation bench (pid ${other.runnerPid}) is running against this stack and owns ${other.outDir || outDir}; wait for it to end before a new run`);
      await openAutomation();
      const offered = await assigneeOptions();
      const assignee = pickAssignee(offered, ASSIGNEE_PREFERENCE);
      const assigneeE = pickAssignee(offered, ASSIGNEE_E_PREFERENCE, assignee);
      if (!assignee) throw new Error('the Assign-to select offers no analyst (the users route needs the security internal users API)');
      const existing = await page.locator('.wamRuleIdentity strong').allInnerTexts();
      const leftovers = existing.filter((name) => name.startsWith(PREFIX));
      if (leftovers.length && !keepExisting) throw new Error(`rules from an earlier run are still present (${leftovers.join(', ')}); delete them through Settings > Automation rules (or run with WAM_AUTOMATION_REVERT=1) before a new run`);

      state.outDir = outDir;
      fs.mkdirSync(state.outDir, { recursive: true });
      await shot('00-rules-before');
      state.assignee = assignee;
      state.assigneeE = assigneeE;
      state.results = [entry];
      state.defects = [];
      state.generatorRuns = [];
      state.ruleIds = {};
      state.caseIds = {};
      state.receiver = null;
      if (keepExisting) {
        let previous: any = null;
        try { previous = JSON.parse(fs.readFileSync(outPath('results.json'), 'utf8')); } catch (e) { /* none yet */ }
        // The channel scenario is not re-run: bring the receiver back on its port for G, on the transport the
        // saved channel URL uses.
        state.receiver = await startReceiver(previous?.receiver?.transport ?? null);
        try {
          if (!previous) throw new Error('no earlier results.json');
          state.results = [entry, ...(previous.scenarios || []).filter((item: ScenarioResult) => item.id !== 'setup')];
          // A merged PASS row keeps its notes, never an earlier attempt's error text (12.3).
          for (const item of state.results) if (item.pass) item.reason = '';
          state.defects = Array.from(new Set<string>(previous.defects || []));
          state.generatorRuns = previous.generatorRuns || [];
          state.ruleIds = previous.ruleIds || {};
          state.caseIds = previous.caseIds || {};
          entry.notes.push(`WAM_AUTOMATION_KEEP_EXISTING: merged ${state.results.length - 1} earlier scenario results`);
        } catch (e) {
          entry.notes.push('WAM_AUTOMATION_KEEP_EXISTING set but no earlier results.json to merge');
        }
      } else {
        try { fs.unlinkSync(outPath(RECEIVER_LOG)); } catch (e) { /* first run */ }
      }
      let reused = false;
      if (keepExisting) {
        try {
          const previous = JSON.parse(fs.readFileSync(outPath('snapshot.json'), 'utf8'));
          state.snapshotAt = previous.takenAt;
          state.snapshot = previous.alerts;
          reused = true;
          entry.notes.push(`snapshot reused from ${previous.takenAt}`);
        } catch (e) { /* none yet */ }
      }
      if (!reused) {
        state.snapshotAt = new Date().toISOString();
        state.snapshot = await takeSnapshot();
        fs.writeFileSync(outPath('snapshot.json'), JSON.stringify({ takenAt: state.snapshotAt, alerts: state.snapshot }, null, 2));
      }
      state.profile = buildProfile(line, state.snapshot);
      entry.counts.snapshot = state.snapshot.length;
      entry.counts.snapshotLabAgent = state.snapshot.filter((alert) => alert.agent === state.profile!.agent).length;
      entry.counts.snapshotSynthetic = state.snapshot.filter((alert) => alert.agent === 'wam-e2e-agent').length;
      entry.notes.push(`line ${line}; build ${state.buildLine}`);
      if (entry.counts.snapshotSynthetic) state.defects.push(`${entry.counts.snapshotSynthetic} synthetic wam-e2e-agent record(s) still projected on this stack (12.2 expects none; they are left alone)`);
      entry.notes.push(`assignees offered: ${offered.join(', ')}; A uses ${state.assignee}, E uses ${state.assigneeE}`);
      if (!offered.includes('automation-test')) state.defects.push(`the Assign-to select lists only the security internal users (${offered.join(', ')}); 'automation-test' is not one, so A assigns to '${state.assignee}' and E to '${state.assigneeE}'`);
      if (leftovers.length) entry.notes.push(`existing rules kept: ${leftovers.join(', ')}`);
      await openSettings('about');
      await shot('00-about');
      state.ready = true;
      entry.pass = true;
      entry.reason = '';
    } catch (e: any) {
      entry.pass = false;
      entry.reason = String(e?.message || e).slice(0, 1500);
      throw e;
    } finally {
      entry.wallMs = Date.now() - started;
      writeArtefacts();
    }
  });

  scenario('tasklist', 'task list created in Settings > Task lists', async (entry) => {
    await openSettings('task-lists');
    const existingList = page.locator('[data-test-subj="wamTaskListsTable"] tr', { hasText: TASK_LIST_NAME });
    if (await existingList.count()) {
      entry.notes.push('task list already present from an interrupted run; kept');
      entry.counts.tasks = TASK_TITLES.length;
      entry.counts.rows = await existingList.count();
      await shot('01-task-lists');
      return;
    }
    await page.locator('[data-test-subj="wamTaskListNew"]').click();
    const editor = page.locator('[data-test-subj="wamTaskListEditor"]');
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await editor.locator('[data-test-subj="wamTaskListName"]').fill(TASK_LIST_NAME);
    await editor.locator('[data-test-subj="wamTaskListDescription"]').fill('Three triage tasks applied by the Automation test: B rule.');
    for (let index = 0; index < TASK_TITLES.length; index += 1) {
      if (index > 0) await editor.locator('[data-test-subj="wamTaskListTaskAdd"]').click();
      await editor.locator(`[data-test-subj="wamTaskListTaskTitle-${index}"]`).fill(TASK_TITLES[index]);
      await editor.locator(`[data-test-subj="wamTaskListTaskDue-${index}"]`).fill(String(60 * (index + 1)));
    }
    await shot('01-task-list-editor');
    await editor.locator('[data-test-subj="wamTaskListSave"]').click();
    await expect(editor).toBeHidden({ timeout: 30_000 });
    const row = page.locator('[data-test-subj="wamTaskListsTable"] tr', { hasText: TASK_LIST_NAME });
    await expect(row).toBeVisible({ timeout: 30_000 });
    entry.counts.tasks = TASK_TITLES.length;
    entry.counts.rows = await row.count();
    await shot('01-task-lists');
  });

  scenario('channel', 'webhook channel bound in Settings > Notifications', async (entry) => {
    state.receiver = await startReceiver();
    entry.notes.push(`receiver ${state.receiver.url}`);
    await openSettings('notifications');
    const settings = page.locator('[data-test-subj="wamNotifSettings"]');
    const enabled = settings.locator('[data-test-subj="wamNotifEnabled"]');
    if (!(await enabled.isChecked())) await enabled.click();
    const existingChannel = settings.locator(`[data-test-subj="wamNotifChannel-${CHANNEL_ID}"]`);
    if (await existingChannel.count()) {
      entry.notes.push('channel already present from an interrupted run; its receiver URL is updated');
      await settings.getByRole('button', { name: `Edit ${CHANNEL_NAME}`, exact: true }).click();
      const editFlyout = page.locator('[data-test-subj="wamNotifFlyout"]');
      await expect(editFlyout).toBeVisible({ timeout: 30_000 });
      await editFlyout.locator('[data-test-subj="wamNotifUrl"]').fill(state.receiver.url);
      await editFlyout.locator('[data-test-subj="wamNotifApply"]').click();
      await expect(editFlyout).toBeHidden({ timeout: 30_000 });
    } else {
    await settings.getByLabel('Channel kind to add').selectOption('webhook');
    await settings.locator('[data-test-subj="wamNotifAdd"]').click();
    const flyout = page.locator('[data-test-subj="wamNotifFlyout"]');
    await expect(flyout).toBeVisible({ timeout: 30_000 });
    await flyout.locator('[data-test-subj="wamNotifName"]').fill(CHANNEL_NAME);
    await flyout.locator('[data-test-subj="wamNotifId"]').fill(CHANNEL_ID);
    await flyout.locator('[data-test-subj="wamNotifUrl"]').fill(state.receiver.url);
    await flyout.locator('[data-test-subj="wamNotifSecret"]').fill(CHANNEL_SECRET);
    await flyout.locator('[data-test-subj="wamNotifAllowInsecure"]').check();
    const enabledSwitch = formRow(flyout, 'Enabled').getByRole('switch');
    if ((await enabledSwitch.getAttribute('aria-checked')) !== 'true') await enabledSwitch.click();
    const events = flyout.locator('[data-test-subj="wamNotifEvents"]');
    for (const event of ['rule.action']) {
      const box = events.locator(`input#${event.replace('.', '\\.')}`);
      if (!(await box.isChecked())) await events.locator(`label[for="${event}"]`).click();
    }
    await shot('02-channel-editor');
    await flyout.locator('[data-test-subj="wamNotifApply"]').click();
    await expect(flyout).toBeHidden({ timeout: 30_000 });
    }
    if (await settings.locator('[data-test-subj="wamNotifDirty"]').count()) {
      await settings.locator('[data-test-subj="wamNotifSave"]').click();
      await expect(settings.locator('[data-test-subj="wamNotifDirty"]')).toBeHidden({ timeout: 60_000 });
    }
    await dismissToasts();
    const row = settings.locator(`[data-test-subj="wamNotifChannel-${CHANNEL_ID}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    // The channel's own test send proves the receiver is reachable from the dashboard container.
    const before = receiverRequests().length;
    await row.locator(`[data-test-subj="wamNotifTest-${CHANNEL_ID}"]`).click();
    const badge = row.locator(`[data-test-subj="wamNotifTestResult-${CHANNEL_ID}"]`);
    await expect(badge).toBeVisible({ timeout: 60_000 });
    entry.counts.testBadge = await badge.innerText();
    await shot('02-channel-saved');
    expect(entry.counts.testBadge, 'the channel test send must be delivered (egress allow list / self-signed policy)').toBe('Delivered');
    await pollUntil(page, async () => receiverRequests().length > before, { timeoutMs: 30_000, label: 'test send on the receiver' });
    entry.counts.receiverTestPosts = receiverRequests().length - before;
  });

  scenario('asset', 'asset criticality written in Settings > Assets', async (entry) => {
    const profile = state.profile!;
    await openSettings('assets');
    const settings = page.locator('[data-test-subj="wamAssetSettings"]');
    if (await settings.locator(`[data-test-subj="wamAsset-${ASSET_ID}"]`).count()) {
      entry.notes.push('asset entry already present from an interrupted run; kept (saved before this run)');
      state.assetSavedAt = `before ${new Date().toISOString()}`;
      await shot('03-assets');
      return;
    }
    await settings.locator('[data-test-subj="wamAssetAdd"]').click();
    const editor = settings.locator('[data-test-subj="wamAssetEditor"]');
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await editor.locator('[data-test-subj="wamAssetEditorKind"]').selectOption('name');
    await editor.locator('[data-test-subj="wamAssetEditorValue"]').fill(profile.agent);
    await editor.locator('[data-test-subj="wamAssetEditorId"]').fill(ASSET_ID);
    await editor.locator('[data-test-subj="wamAssetEditorCriticality"]').selectOption('high');
    await editor.locator('[data-test-subj="wamAssetEditorTags"]').fill(ASSET_TAG);
    await shot('03-asset-editor');
    await editor.locator('[data-test-subj="wamAssetEditorApply"]').click();
    await expect(settings.locator(`[data-test-subj="wamAsset-${ASSET_ID}"]`)).toBeVisible({ timeout: 30_000 });
    await settings.locator('[data-test-subj="wamAssetSave"]').click();
    await expect(settings.locator('[data-test-subj="wamAssetDirty"]')).toBeHidden({ timeout: 60_000 });
    state.assetSavedAt = new Date().toISOString();
    await dismissToasts();
    entry.notes.push(`saved at ${state.assetSavedAt}`);
    await shot('03-assets');
  });

  scenario('dedupe', 'WAM_AUTOMATION_DEDUPE=1 only: delete duplicate disabled drafts of the test rules', async (entry) => {
    await openAutomation();
    const names = await page.locator('.wamRuleIdentity strong').allInnerTexts();
    const duplicated = Array.from(new Set(names.filter((name) => name.startsWith(PREFIX) && names.filter((other) => other === name).length > 1)));
    let deleted = 0;
    for (const name of duplicated) {
      // Keep the enabled rule; delete the disabled duplicates through the list.
      for (;;) {
        const rows = page.locator('.wamAutomationRulesPanel tr.euiTableRow', { has: page.locator('.wamRuleIdentity strong', { hasText: new RegExp(`^${escapeRegExp(name)}$`) }) });
        if ((await rows.count()) <= 1) break;
        const disabled = rows.filter({ has: page.locator('[role="switch"][aria-checked="false"]') }).first();
        if (!(await disabled.count())) break;
        await disabled.getByRole('button', { name: `Delete ${name}`, exact: true }).click();
        await page.getByRole('button', { name: 'Delete', exact: true }).click();
        await expect(page.getByText('Rule deleted', { exact: true })).toBeVisible({ timeout: 60_000 });
        await dismissToasts();
        deleted += 1;
      }
    }
    entry.counts.duplicatesDeleted = deleted;
    entry.notes.push(`duplicated names: ${duplicated.join(', ') || 'none'}`);
  }, { skipUnless: () => process.env.WAM_AUTOMATION_DEDUPE === '1', skipReason: 'set WAM_AUTOMATION_DEDUPE=1 after an interrupted rerun left duplicate drafts' });

  scenario('rule-A', 'A_per_alert_triage created, previewed, enabled', async (entry) => {
    if (await keptExistingRule(RULE_NAMES.A, entry)) return;
    const profile = state.profile!;
    await openAutomation();
    await createDraft({
      name: RULE_NAMES.A,
      match: { ruleGroups: [profile.failedAuthGroup], agentNames: [profile.agent] },
      trigger: { type: 'per_alert' },
      actions: { setStatus: 'in_progress', assignTo: state.assignee },
      preconditions: { statuses: ['open'], assignment: 'unassigned' },
    }, 'A');
    const preview = await previewAndEnable(RULE_NAMES.A, 'A');
    entry.counts.previewMatching = preview.matching;
    entry.notes.push(preview.text);
  });

  scenario('rule-B', 'B_burst_case created, previewed, enabled', async (entry) => {
    if (await keptExistingRule(RULE_NAMES.B, entry)) return;
    const profile = state.profile!;
    await openAutomation();
    await createDraft({
      name: RULE_NAMES.B,
      match: { ruleGroups: [profile.failedAuthGroup], agentNames: [profile.agent] },
      trigger: { type: 'burst', predicates: [{ entity: 'srcip', operator: 'exists' }], threshold: 5, windowMinutes: 10, routing: 'separate_by_group', cooldownMinutes: 30, quietMinutes: 5 },
      actions: { createCase: true, caseSeverity: 'high', taskList: TASK_LIST_NAME },
    }, 'B');
    const preview = await previewAndEnable(RULE_NAMES.B, 'B');
    entry.counts.previewMatching = preview.matching;
    entry.notes.push(preview.text);
  });

  scenario('rule-C', 'C_cooccurrence_all created, previewed, enabled', async (entry) => {
    if (await keptExistingRule(RULE_NAMES.C, entry)) return;
    const profile = state.profile!;
    await openAutomation();
    await createDraft({
      name: RULE_NAMES.C,
      match: { ruleIds: [profile.sudoRuleId, profile.suRuleId], ruleIdsMode: 'all', agentNames: [profile.agent] },
      trigger: { type: 'burst', predicates: [{ entity: 'user', operator: 'equals', value: profile.srcuser }], threshold: 2, windowMinutes: 15, routing: 'one_per_rule', cooldownMinutes: 15, quietMinutes: 5 },
      actions: { createCase: true, caseSeverity: 'medium' },
    }, 'C');
    const preview = await previewAndEnable(RULE_NAMES.C, 'C');
    entry.counts.previewMatching = preview.matching;
    entry.notes.push(preview.text);
  });

  scenario('rule-D', 'D_min_level_band created, previewed (count cross-checked), enabled', async (entry) => {
    if (await keptExistingRule(RULE_NAMES.D, entry)) return;
    const profile = state.profile!;
    await openAutomation();
    await createDraft({
      name: RULE_NAMES.D,
      match: { minLevel: MIN_LEVEL },
      trigger: { type: 'per_alert' },
      actions: { setStatus: 'in_progress' },
    }, 'D');
    const preview = await previewAndEnable(RULE_NAMES.D, 'D');
    entry.counts.previewMatching = preview.matching;
    entry.notes.push(preview.text);
    // ALLOWED API CALL 2: read-only `_count` of the projected store over the same 24-hour window and band.
    const band = profile.highBand.labels ? { terms: { severity_label: profile.highBand.labels } } : { range: { 'rule.level': { gte: profile.highBand.levelMin } } };
    const count = await indexerRequest('POST', '/wazuh-alert-status-v2-read/_count', { query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h', lte: 'now' } } }, band] } } });
    expect(count.ok, `_count failed: ${JSON.stringify(count.body)}`).toBe(true);
    entry.counts.indexerCount = Number(count.body?.count ?? NaN);
    entry.notes.push(`band ${JSON.stringify(band)}`);
    expect(entry.counts.previewMatching, 'preview count must equal the _count cross-check').toBe(entry.counts.indexerCount);
  });

  scenario('rule-E', 'E_asset_criticality rules (high assigns, critical never fires) created, previewed, enabled', async (entry) => {
    if ((await keptExistingRule(RULE_NAMES.E, entry)) && (await keptExistingRule(RULE_NAMES.E2, entry))) return;
    const profile = state.profile!;
    await openAutomation();
    await createDraft({
      name: RULE_NAMES.E,
      match: { ruleGroups: [profile.sudoGroup], agentNames: [profile.agent], minAssetCriticality: 'high' },
      trigger: { type: 'per_alert' },
      actions: { assignTo: state.assigneeE },
    }, 'E');
    const previewE = await previewAndEnable(RULE_NAMES.E, 'E');
    entry.counts.previewMatchingHigh = previewE.matching;
    await createDraft({
      name: RULE_NAMES.E2,
      match: { ruleGroups: [profile.sudoGroup], agentNames: [profile.agent], minAssetCriticality: 'critical' },
      trigger: { type: 'per_alert' },
      actions: { setStatus: 'in_progress' },
      preconditions: { assignment: 'any' },
    }, 'E2');
    const previewE2 = await previewAndEnable(RULE_NAMES.E2, 'E2');
    entry.counts.previewMatchingCritical = previewE2.matching;
    entry.notes.push(`high: ${previewE.text}`, `critical: ${previewE2.text}`);
    expect(entry.counts.previewMatchingCritical, 'no alert carries a critical asset, so the critical floor matches nothing').toBe(0);
  });

  scenario('rule-F', 'F_auto_close_noise created, previewed, enabled', async (entry) => {
    if (await keptExistingRule(RULE_NAMES.F, entry)) return;
    const profile = state.profile!;
    await openAutomation();
    await createDraft({
      name: RULE_NAMES.F,
      priority: 200,
      match: { ruleGroups: [profile.benignGroup], ...(profile.benignRuleIds.length ? { ruleIds: profile.benignRuleIds } : {}), agentNames: [profile.agent] },
      trigger: { type: 'per_alert' },
      actions: { setStatus: 'closed', disposition: 'false_positive' },
      preconditions: { assignment: 'any' },
      processingMode: 'stop',
    }, 'F');
    const preview = await previewAndEnable(RULE_NAMES.F, 'F');
    entry.counts.previewMatching = preview.matching;
    entry.notes.push(preview.text, `benign rule ids: ${profile.benignRuleIds.join(', ') || '(group only)'}`);
  });

  scenario('rule-G', 'G_notify_only created, previewed, enabled', async (entry) => {
    const profile = state.profile!;
    await openAutomation();
    // 12.3 rerun: the rule from the earlier run stays as created (its match may still be the FIM group).
    if (await keptExistingRule(RULE_NAMES.G, entry)) return;
    // 12.3: a small bounded group (the line's sudo rule id on the lab agent, a handful per generator
    // run) instead of the FIM group, whose unattended package runs produced hundreds of alerts at once.
    await createDraft({
      name: RULE_NAMES.G,
      match: { ruleIds: [profile.sudoRuleId], agentNames: [profile.agent] },
      trigger: { type: 'per_alert' },
      actions: { notifyChannels: [CHANNEL_NAME] },
      preconditions: { assignment: 'any' },
    }, 'G');
    const preview = await previewAndEnable(RULE_NAMES.G, 'G');
    entry.counts.previewMatching = preview.matching;
    entry.counts.previewNotifications = preview.notifications;
    entry.notes.push(preview.text);
    await openAutomation();
    await shot('04-rules-enabled');
  });

  scenario('H_lifecycle', 'draft, no counters, preview, enable, edit, revisions, rollback, delete', async (entry) => {
    const profile = state.profile!;
    await openAutomation();
    if (await ruleRow(RULE_NAMES.H).count()) {
      // Left by an interrupted lifecycle: remove it through the list so the scenario starts from a clean draft.
      await page.getByRole('button', { name: `Delete ${RULE_NAMES.H}`, exact: true }).click();
      await page.getByRole('button', { name: 'Delete', exact: true }).click();
      await expect(page.getByText('Rule deleted', { exact: true })).toBeVisible({ timeout: 60_000 });
      await dismissToasts();
      entry.notes.push('a leftover H rule from an interrupted run was deleted first');
    }
    await createDraft({
      name: RULE_NAMES.H,
      match: { ruleGroups: [profile.fimGroup], agentNames: [profile.agent] },
      trigger: { type: 'per_alert' },
      actions: { setStatus: 'in_progress' },
    }, 'H');
    const row = ruleRow(RULE_NAMES.H);
    await expect(row.getByRole('switch')).toHaveAttribute('aria-checked', 'false');
    const lastFiredDraft = (await row.locator('td').nth(4).innerText()).trim();
    entry.counts.lastFiredWhileDisabled = lastFiredDraft;
    expect(lastFiredDraft, 'a disabled draft has no counters').toBe('Never');
    await expect(row).toContainText('Revision 1');
    // The activation control on the list opens the preview of a disabled rule.
    await row.getByRole('switch').click();
    const flyout = page.locator('.wamRuleFlyout');
    await expect(flyout).toBeVisible({ timeout: 30_000 });
    await expect(flyout.getByRole('heading', { name: 'Preview and activation' })).toBeVisible({ timeout: 30_000 });
    await dismissToasts();
    await flyout.getByRole('button', { name: 'Cancel' }).click();
    const preview = await previewAndEnable(RULE_NAMES.H, 'H');
    entry.counts.previewMatching = preview.matching;
    await expect(ruleRow(RULE_NAMES.H)).toContainText('Revision 2');

    // Edit the match. The editor refuses to save an enabled rule whose definition changed (the preview
    // gate can only run on a saved revision), so the edit switches the rule off in the same save.
    await page.getByRole('button', { name: `Edit ${RULE_NAMES.H}`, exact: true }).click();
    await expect(flyout).toBeVisible({ timeout: 30_000 });
    await flyout.getByLabel('Enabled', { exact: true }).uncheck();
    await flyout.getByRole('tab', { name: '2. Match' }).click();
    await addComboValues(formRow(flyout, 'Rule groups'), [profile.failedAuthGroup]);
    await shot('H-edit');
    await flyout.getByRole('tab', { name: '6. Preview' }).click();
    await flyout.getByRole('button', { name: 'Save draft' }).click();
    await expect(page.getByText('Draft rule saved', { exact: true })).toBeVisible({ timeout: 60_000 });
    await dismissToasts();
    await expect(ruleRow(RULE_NAMES.H)).toContainText('Revision 3');

    // Revisions view: three entries, rollback to 1.
    await page.getByRole('button', { name: `Edit ${RULE_NAMES.H}`, exact: true }).click();
    await flyout.getByRole('tab', { name: 'History' }).click();
    const revisionRows = flyout.locator('.euiBasicTable tr.euiTableRow');
    await expect(revisionRows).toHaveCount(3, { timeout: 30_000 });
    entry.counts.revisionsBeforeRollback = await revisionRows.count();
    await shot('H-revisions');
    const first = flyout.locator('.euiBasicTable tr.euiTableRow', { has: page.locator('.euiTableCellContent__text', { hasText: /^1$/ }) }).first();
    await first.getByRole('button', { name: 'Rollback' }).click();
    await page.getByRole('button', { name: 'Roll back', exact: true }).click();
    await expect(page.getByText('Rolled back to revision 1', { exact: true })).toBeVisible({ timeout: 60_000 });
    await dismissToasts();
    await expect(revisionRows).toHaveCount(4, { timeout: 30_000 });
    entry.counts.revisionsAfterRollback = await revisionRows.count();
    await flyout.getByRole('tab', { name: '2. Match' }).click();
    const pills = await formRow(flyout, 'Rule groups').locator('.euiComboBoxPill').allInnerTexts();
    entry.notes.push(`match after rollback: ${pills.join(', ')}`);
    expect(pills.map((pill) => pill.trim()), 'the live definition is the revision-1 match again').toEqual([profile.fimGroup]);
    await expect(flyout.locator('.euiFlyoutHeader .euiBadge')).toHaveText('Draft');
    await shot('H-rolled-back');
    await flyout.getByRole('button', { name: 'Cancel' }).click();
    await expect(ruleRow(RULE_NAMES.H)).toContainText('Revision 4');

    await page.getByRole('button', { name: `Delete ${RULE_NAMES.H}`, exact: true }).click();
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Rule deleted', { exact: true })).toBeVisible({ timeout: 60_000 });
    await dismissToasts();
    await expect(ruleRow(RULE_NAMES.H)).toHaveCount(0, { timeout: 30_000 });
    await shot('H-deleted');
    // 12.3 made an enabled rule's edit save as a new revision without a preview (rules_view.test.tsx covers it);
    // H keeps the 5.0 run's switch-off-in-the-same-save flow so both lines are compared like for like.
    entry.notes.push('edit saved with the rule switched off in the same save (the 5.0-run flow, kept for the comparison)');
  });

  scenario('generator-1', 'first generator run; new lab-agent alerts reach the queue', async (entry) => {
    const profile = state.profile!;
    const baseline = await queueTotal({ agent: profile.agent, statuses: ['open', 'in_progress', 'closed'], range: 'Last 1 hour' });
    state.baselineTotals.push(baseline);
    entry.counts.queueBefore = baseline;
    const run = runGenerator(1);
    entry.notes.push(`generator ${run.startedAt} -> ${run.finishedAt}: ${run.summary}`);
    const after = await waitForNewAlerts(baseline);
    entry.counts.queueAfter = after;
    entry.counts.newAlerts = after - baseline;
    await shot('05-queue-after-run-1');
  }, { timeoutMs: 20 * 60_000 });

  scenario('A_per_alert_triage', 'new failed-auth alerts in progress and assigned; pre-enable alerts untouched', async (entry) => {
    const profile = state.profile!;
    const inProgress = await queueTotal({ agent: profile.agent, assignee: state.assignee, statuses: ['in_progress'], range: 'Last 1 hour' });
    entry.counts.inProgressAssigned = inProgress;
    expect(inProgress, 'A must move new failed-auth alerts to In progress and assign them').toBeGreaterThan(0);
    await shot('A-queue');
    const ids = await queueRowIds();
    const rows = await alertHistory(ids[0]);
    entry.notes.push(`history of ${ids[0]}: ${rows.map((row) => row.replace(/\s+/g, ' ')).join(' || ')}`);
    const ruleId = ruleIdFromHistory(rows, 'in_progress');
    state.ruleIds.A = ruleId;
    entry.ids.rule = ruleId;
    entry.ids.alert = ids[0];
    expect(ruleId, "the alert's History carries the rule's audit entry (correlation-rule rule:<id>)").toBeTruthy();
    await shot('A-flyout-history');
    // Forward-only: a failed-auth alert from before the rule was enabled keeps the status / assignee the snapshot
    // recorded. 12.2 (4.x drift fix): an open unassigned one is preferred, not required; on 4.14 every pre-enable
    // failed-auth alert of the agent had already been closed and assigned by the earlier lab benches.
    const candidates = state.snapshot.filter((alert) => alert.agent === profile.agent && alert.groups.includes(profile.failedAuthGroup));
    const before = candidates.find((alert) => alert.status === 'open' && !alert.assigned_to) || candidates[0];
    expect(before, 'the snapshot holds a failed-auth alert from before the rule was enabled').toBeTruthy();
    const flyout = await openAlertFlyout(page, before!.id);
    const pressed = await flyout.locator('[data-test-subj="wamAlertFormGrid"] .euiButtonGroupButton-isSelected, [data-test-subj="wamAlertFormGrid"] [aria-pressed="true"]').first().innerText();
    const assignee = (await flyout.locator('[data-test-subj="wamAlertOverviewAssignee"] .euiComboBoxPill').allInnerTexts()).join(',');
    entry.ids.untouchedAlert = before!.id;
    entry.counts.untouchedStatus = pressed.trim();
    entry.counts.untouchedAssignee = assignee || '(unassigned)';
    entry.counts.untouchedInSnapshot = `${before!.status}/${before!.assigned_to || '(unassigned)'}`;
    expect(pressed.trim(), 'status unchanged since the snapshot').toBe({ open: 'Open', in_progress: 'In progress', closed: 'Closed' }[before!.status]);
    expect(assignee, 'assignee unchanged since the snapshot').toBe(before!.assigned_to || '');
    await shot('A-forward-only');
  });

  scenario('B_burst_case', 'exactly one high case with >= 5 linked alerts and the 3 tasks', async (entry) => {
    const title = `${RULE_NAMES.B}: automated incident`;
    const count = await casesTitled(title);
    entry.counts.cases = count;
    await shot('B-cases');
    // 12.3 replaced the unescaped query_string with a phrase-prefix match (cases.ts): the full title, colons
    // included, must find the case as well (12.2 cross-check, recorded as a count).
    entry.counts.casesByFullTitle = await casesTitled(title, { fullTitle: true });
    expect(entry.counts.casesByFullTitle, 'the full title (colons included) must find the case').toBe(count);
    expect(count, 'exactly one case for the srcip burst').toBe(1);
    const { flyout, caseId } = await openCaseTitled(title);
    state.caseIds.B = caseId;
    entry.ids.case = caseId;
    const linked = Number(await flyout.locator('[data-test-subj="wamCaseNavCount-alerts"]').innerText({ timeout: 30_000 }));
    entry.counts.linkedAlerts = linked;
    expect(linked).toBeGreaterThanOrEqual(5);
    await expect(flyout.locator('[data-test-subj="wamCaseFlyoutMeta"]')).toContainText('High');
    await expect(flyout.locator('[data-test-subj="wamCaseFlyoutMeta"]')).toContainText('Open');
    await flyout.locator('[data-test-subj="wamCaseNav-tasks"]').click();
    const tasks = flyout.locator('[data-test-subj^="wamCaseTaskRow-"]');
    await expect(tasks).toHaveCount(3, { timeout: 30_000 });
    entry.counts.tasks = await tasks.count();
    const titles = await flyout.locator('[data-test-subj^="wamCaseTaskTitle-"]').allInnerTexts();
    entry.notes.push(`tasks: ${titles.join(' | ')}`);
    expect(titles.map((item) => item.trim())).toEqual(TASK_TITLES);
    await shot('B-case-tasks');
    await flyout.locator('[data-test-subj="wamCaseNav-overview"]').click();
    await expect(flyout.locator('[data-test-subj="wamCaseOverviewTasks"]')).toContainText('0 of 3 done');
    await shot('B-case-overview');
  });

  scenario('C_cooccurrence_all', 'one medium case once both rule ids were seen for the same user', async (entry) => {
    const title = `${RULE_NAMES.C}: automated incident`;
    const count = await casesTitled(title);
    entry.counts.cases = count;
    await shot('C-cases');
    expect(count).toBe(1);
    const { flyout, caseId } = await openCaseTitled(title);
    state.caseIds.C = caseId;
    entry.ids.case = caseId;
    entry.counts.linkedAlerts = Number(await flyout.locator('[data-test-subj="wamCaseNavCount-alerts"]').innerText({ timeout: 30_000 }));
    await expect(flyout.locator('[data-test-subj="wamCaseFlyoutMeta"]')).toContainText('Medium');
    expect(entry.counts.linkedAlerts).toBeGreaterThanOrEqual(2);
    await shot('C-case');
  });

  scenario('D_min_level_band', 'only the >= 7 band is touched (low alerts carry no in-progress rule entry from D)', async (entry) => {
    const profile = state.profile!;
    // Band alerts of the last hour on this agent (the queue's level filter on 4.x; the band labels have no queue filter on 5.0, the Lucene query carries them).
    // 12.2 (4.x drift fix): the 4.x lab agent produces band alerts naturally (sshd / PAM brute-force rules at
    // level 10) and D is forward-only, so the band is counted from the first generator run (after D was enabled) on.
    const since = state.generatorRuns[0]?.startedAt;
    const bandQuery = [profile.highBand.labels ? `severity_label:(${profile.highBand.labels.join(' OR ')})` : '', since ? `@timestamp:[${since} TO *]` : ''].filter(Boolean).join(' AND ');
    const bandFilter: QueueFilter = {
      agent: profile.agent,
      ...(bandQuery ? { query: bandQuery } : {}),
      ...(profile.highBand.labels ? {} : { levelMin: profile.highBand.levelMin }),
      statuses: ['open', 'in_progress', 'closed'],
      range: 'Last 1 hour',
    };
    if (since) entry.notes.push(`band counted since generator run 1 (${since})`);
    const bandTotal = await queueTotal(bandFilter);
    entry.counts.bandAlertsLastHour = bandTotal;
    const bandInProgress = await queueTotal({ ...bandFilter, statuses: ['in_progress'] });
    entry.counts.bandInProgress = bandInProgress;
    await shot('D-queue-band');
    // A low alert outside the failed-auth group (so A cannot have touched it) must not carry an in-progress entry.
    const sudoTotal = await queueTotal({ agent: profile.agent, ruleIds: [profile.sudoRuleId], statuses: ['open', 'in_progress', 'closed'], range: 'Last 1 hour' });
    entry.counts.sudoAlertsLastHour = sudoTotal;
    expect(sudoTotal).toBeGreaterThan(0);
    const ids = await queueRowIds();
    const rows = await alertHistory(ids[0]);
    entry.ids.lowAlert = ids[0];
    const touched = ruleIdFromHistory(rows, 'in_progress');
    entry.notes.push(`low alert ${ids[0]} history: ${rows.map((row) => row.replace(/\s+/g, ' ')).join(' || ') || '(empty)'}`);
    expect(touched, 'a low alert must not have been set In progress by D').toBeNull();
    if (bandTotal > 0) {
      expect(bandInProgress, 'every band alert of the run is In progress').toBe(bandTotal);
    } else {
      entry.notes.push('no alert of the >= 7 band was produced by the lab agent in this run (5.0 labels the generator events low/medium/informational); the rule is proven by preview == _count');
    }
  });

  scenario('E_asset_criticality', 'alerts projected after the asset save are stamped High and assigned; the critical floor never fires', async (entry) => {
    const profile = state.profile!;
    const assigned = await queueTotal({ agent: profile.agent, assignee: state.assigneeE, ruleIds: [profile.sudoRuleId], statuses: ['open', 'in_progress', 'closed'], range: 'Last 1 hour' });
    entry.counts.sudoAssignedByE = assigned;
    await shot('E-queue');
    expect(assigned, 'E assigns the sudo alerts stamped high').toBeGreaterThan(0);
    const badges = await page.locator('.wamAlertCell [data-test-subj="wamAssetQueueBadge"], .wamAlertRow [data-test-subj="wamAssetQueueBadge"]').allInnerTexts();
    entry.counts.rowsWithAssetBadge = badges.length;
    entry.notes.push(`asset badges on the page: ${Array.from(new Set(badges.map((b) => b.trim()))).join(', ') || 'none'}`);
    expect(badges.length).toBeGreaterThan(0);
    const ids = await queueRowIds();
    const flyout = await openAlertFlyout(page, ids[ids.length - 1]);
    const stampedAt = (await flyout.locator('[data-test-subj="wamAlertMetaDetection"]').innerText()).replace(/\s+/g, ' ');
    const timestamp = stampedAt.match(/Timestamp\s*(.+?)\s*Manager/)?.[1] ?? '';
    entry.notes.push(`oldest assigned alert on the page: ${ids[ids.length - 1]} at ${timestamp}; asset saved at ${state.assetSavedAt}`);
    await shot('E-flyout');
    // Alerts from the snapshot (projected before the save) carry no criticality.
    const unstamped = state.snapshot.filter((alert) => alert.agent === profile.agent && alert.asset_criticality === null).length;
    entry.counts.snapshotAlertsWithoutCriticality = unstamped;
    entry.counts.snapshotAlerts = state.snapshot.filter((alert) => alert.agent === profile.agent).length;
    // The critical floor: no sudo alert went In progress (E2 is the only rule that would).
    const critical = await queueTotal({ agent: profile.agent, ruleIds: [profile.sudoRuleId], statuses: ['in_progress'], range: 'Last 1 hour' });
    entry.counts.sudoInProgressByCritical = critical;
    expect(critical, 'the critical floor matches no alert').toBe(0);
    state.defects.push(`E lag: the asset entry was saved at ${state.assetSavedAt}; only alerts the sync projected afterwards carry asset.criticality (${unstamped} of ${entry.counts.snapshotAlerts} snapshot records of the agent had none), so a rule with an asset floor sees nothing until the next sync tick after the save (~60 s) and nothing already projected.`);
  });

  scenario('F_auto_close_noise', 'new benign alerts closed with the false-positive disposition', async (entry) => {
    const profile = state.profile!;
    const closed = await queueTotal({ agent: profile.agent, query: `rule.groups:"${profile.benignGroup}"`, ...(profile.benignRuleIds.length ? { ruleIds: profile.benignRuleIds } : {}), statuses: ['closed'], range: 'Last 1 hour' });
    entry.counts.closedBenign = closed;
    await shot('F-queue');
    expect(closed, 'F closes the new benign alerts').toBeGreaterThan(0);
    // 12.2 drift fix: the 4.14 stack still serves the pre-13.1 table (`tr.wamAlertRow`), the 5.0 stack the 13.1 grid (`.wamAlertCell`).
    const dispositions = await page.locator('.wamAlertCell [data-test-subj="wamAlertDisposition"], .wamAlertRow [data-test-subj="wamAlertDisposition"]').allInnerTexts();
    entry.counts.rowsWithDisposition = dispositions.length;
    expect(dispositions.length).toBeGreaterThan(0);
    const ids = await queueRowIds();
    const flyout = await openAlertFlyout(page, ids[0]);
    await expect(flyout.locator('[data-test-subj="wamAlertClosureRow"]')).toContainText(/false positive/i, { timeout: 30_000 });
    const rows = await alertHistory(ids[0]);
    const ruleId = ruleIdFromHistory(rows, 'closed');
    state.ruleIds.F = ruleId;
    entry.ids.rule = ruleId;
    entry.ids.alert = ids[0];
    entry.notes.push(`history: ${rows.map((row) => row.replace(/\s+/g, ' ')).join(' || ')}`);
    expect(ruleId).toBeTruthy();
    expect(rows.join(' ')).toMatch(/False positive/);
    await shot('F-flyout');
  });

  scenario('G_notify_only', 'outbox entries and receiver POSTs for the notified alerts (bounded)', async (entry) => {
    const profile = state.profile!;
    expect(state.receiver, 'the receiver is running').toBeTruthy();
    // 12.3: the expectation is bounded. The rule matches the sudo rule id on the lab agent (a rerun may
    // still hold the earlier FIM-group rule); the queue count since the first generator run is recorded
    // for the report, and the assertion is `outbox sent >= 1 and receiver POSTs >= 1` within the drain.
    const since = state.generatorRuns[0]?.startedAt || new Date(Date.now() - 3600_000).toISOString();
    const matching = await queueTotal({ agent: profile.agent, ruleIds: [profile.sudoRuleId], query: `@timestamp:[${since} TO *]`, statuses: ['open', 'in_progress', 'closed'], range: 'Last 24 hours' });
    entry.counts.sudoAlertsSinceRun1 = matching;
    entry.notes.push(`sudo alerts (rule ${profile.sudoRuleId}) counted since ${since}`);
    // Deliveries: one POST per notified alert. The receiver is only up while the bench runs, so entries
    // that failed in between retry on the outbox backoff (30 s, 2 m, 10 m, 30 m, 1 h; dead after 5) and
    // the ones that went dead are retried through the outbox's Retry button, like an administrator would.
    const delivered = () => new Set(receiverRequests().filter((request) => request.path === RECEIVER_PATH && String(request.headers['x-wam-event'] || request.json?.event || '') === 'rule.action').map((request) => String(request.json?.alert?.id || request.headers['x-wam-delivery'] || request.at)));
    const drainMs = Number(process.env.WAM_AUTOMATION_NOTIFY_DRAIN_MS || 120_000);
    const deadline = Date.now() + drainMs;
    let retried = 0;
    await openSettings('notifications');
    const outbox = page.locator('[data-test-subj="wamNotifOutbox"]');
    await expect(outbox).toBeVisible({ timeout: 30_000 });
    const sentCount = async () => Number((await outbox.locator('[data-test-subj="wamNotifOutboxCount-sent"] .euiStat__title').innerText().catch(() => '0')).replace(/,/g, '')) || 0;
    while ((delivered().size < 1 || (await sentCount()) < 1) && Date.now() < deadline) {
      await outbox.locator('[data-test-subj="wamNotifOutboxRefresh"]').click().catch(() => undefined);
      await page.waitForTimeout(1_000);
      // Rows that failed while the receiver was down (and the ones that went dead) get the outbox's Retry.
      for (const status of ['dead', 'failed']) {
        const count = Number((await outbox.locator(`[data-test-subj="wamNotifOutboxCount-${status}"] .euiStat__title`).innerText().catch(() => '0')).replace(/,/g, '')) || 0;
        if (count === 0) continue;
        await outbox.locator('[data-test-subj="wamNotifOutboxFilter"]').selectOption(status).catch(() => undefined);
        await page.waitForTimeout(1_000);
        for (let more = 0; more < 10; more += 1) {
          const loadMore = outbox.locator('[data-test-subj="wamNotifOutboxLoadMore"]');
          if (!(await loadMore.isVisible().catch(() => false)) || !(await loadMore.isEnabled().catch(() => false))) break;
          await loadMore.click().catch(() => undefined);
          await page.waitForTimeout(800);
        }
        for (const button of await outbox.locator('[data-test-subj^="wamNotifOutboxRetry-"]').all()) {
          await button.click().catch(() => undefined);
          retried += 1;
          await page.waitForTimeout(150);
        }
        await outbox.locator('[data-test-subj="wamNotifOutboxFilter"]').selectOption('').catch(() => undefined);
      }
      await page.waitForTimeout(10_000);
    }
    entry.counts.receiverDistinctAlerts = delivered().size;
    entry.counts.outboxRetriedByUi = retried;
    entry.ids.rule = receiverRequests().find((request) => request.json?.rule?.id)?.json?.rule?.id ?? null;
    state.ruleIds.G = entry.ids.rule;
    await outbox.locator('[data-test-subj="wamNotifOutboxRefresh"]').click().catch(() => undefined);
    await page.waitForTimeout(1_500);
    for (const status of ['pending', 'sending', 'sent', 'failed', 'dead']) {
      entry.counts[`outbox ${status}`] = (await outbox.locator(`[data-test-subj="wamNotifOutboxCount-${status}"] .euiStat__title`).innerText().catch(() => '-')).trim();
    }
    const rows = outbox.locator('[data-test-subj^="wamNotifOutboxRow-"]', { has: page.locator('[data-test-subj="wamNotifOutboxChannel"]', { hasText: CHANNEL_ID }) });
    await expect(rows.first()).toBeVisible({ timeout: 60_000 });
    const events = await rows.locator('[data-test-subj="wamNotifOutboxEvent"]').allInnerTexts();
    const statuses = await rows.locator('[data-test-subj="wamNotifOutboxStatusBadge"]').allInnerTexts();
    entry.counts.outboxRowsOnPage = events.length;
    entry.notes.push(`first outbox page: events ${Array.from(new Set(events.map((event) => event.trim()))).join(', ')}; statuses ${Array.from(new Set(statuses.map((status) => status.trim()))).join(', ')}`);
    await shot('G-outbox');
    expect(events.every((event) => event.trim() === 'rule.action'), 'every outbox row of the channel is a rule.action').toBe(true);
    entry.notes.push(`${entry.counts.receiverDistinctAlerts} distinct alert(s) delivered to the receiver within ${Math.round(drainMs / 1000)} s against ${matching} matching alert(s) in the queue`);
    expect(Number(String(entry.counts['outbox sent']).replace(/,/g, '')), 'at least one sent outbox entry (read from the Notifications outbox view)').toBeGreaterThanOrEqual(1);
    expect(entry.counts.receiverDistinctAlerts, 'at least one rule.action POST on the receiver').toBeGreaterThanOrEqual(1);
  }, { timeoutMs: 25 * 60_000 });

  scenario('runtime', 'Automation runtime card and the enabled rules list', async (entry) => {
    await openAutomation();
    const stats = page.locator('.wamAutomationStats .euiStat');
    await expect(stats.first()).toBeVisible({ timeout: 30_000 });
    for (const stat of await stats.all()) {
      const title = (await stat.locator('.euiStat__title').innerText()).trim();
      const description = (await stat.locator('.euiStat__description').innerText()).trim();
      entry.counts[description] = title;
    }
    await expect(page.locator('.wamAutomationHealth .euiBadge').first()).toContainText('Queue running');
    const names = Object.values(RULE_NAMES).filter((name) => name !== RULE_NAMES.H);
    for (const name of names) {
      const row = ruleRow(name);
      await expect(row.getByRole('switch')).toHaveAttribute('aria-checked', 'true');
      entry.counts[`lastFired ${name.slice(PREFIX.length + 1)}`] = (await row.locator('td').nth(4).innerText()).trim();
    }
    entry.counts.enabledTestRules = names.length;
    await shot('06-runtime-card');
    expect(Number(entry.counts['Dead letters']), 'no dead letters').toBe(0);
    // 12.3: "Last fired" reads the per-rule execution state the worker writes ("<relative> · N matched");
    // a rule that never matched (D's band, E's critical floor) legitimately reads "Never".
    const never = Object.entries(entry.counts).filter(([key, value]) => key.startsWith('lastFired') && value === 'Never').map(([key]) => key.slice('lastFired '.length));
    entry.notes.push(never.length ? `Last fired reads Never for: ${never.join(', ')}` : 'every enabled test rule shows a Last fired time and match count');
    const counters = (await page.locator('[data-test-subj="wamAutomationRuleCounters"]').innerText().catch(() => '')).trim();
    entry.notes.push(counters.slice(0, 400));
    if (never.length === names.length) {
      state.defects.push('rules_view.tsx "Last fired" reads Never for every enabled rule although rules fired: the rule-execution companions are not being written or joined (step 12.3 wiring).');
    }
  });

  scenario('generator-2', 'second generator run inside the cooldown: B opens no second case', async (entry) => {
    const profile = state.profile!;
    const baseline = await queueTotal({ agent: profile.agent, statuses: ['open', 'in_progress', 'closed'], range: 'Last 1 hour' });
    state.baselineTotals.push(baseline);
    entry.counts.queueBefore = baseline;
    const run = runGenerator(2);
    entry.notes.push(`generator ${run.startedAt} -> ${run.finishedAt}: ${run.summary}`);
    const after = await waitForNewAlerts(baseline);
    entry.counts.queueAfter = after;
    const title = `${RULE_NAMES.B}: automated incident`;
    const count = await casesTitled(title);
    entry.counts.casesB = count;
    await shot('07-cases-after-run-2');
    expect(count, 'the cooldown suppresses a second case').toBe(1);
    const { flyout } = await openCaseTitled(title);
    entry.counts.linkedAlertsAfterRun2 = Number(await flyout.locator('[data-test-subj="wamCaseNavCount-alerts"]').innerText({ timeout: 30_000 }));
    await shot('07-case-B-after-run-2');
  }, { timeoutMs: 20 * 60_000 });

  scenario('revert', 'WAM_AUTOMATION_REVERT=1 only: delete what the run created and restore the snapshot', async (entry) => {
    const profile = state.profile!;
    await openAutomation();
    for (const name of Object.values(RULE_NAMES)) {
      if ((await ruleRow(name).count()) === 0) continue;
      await page.getByRole('button', { name: `Delete ${name}`, exact: true }).click();
      await page.getByRole('button', { name: 'Delete', exact: true }).click();
      await expect(page.getByText('Rule deleted', { exact: true })).toBeVisible({ timeout: 60_000 });
      await dismissToasts();
    }
    for (const key of ['B', 'C'] as const) {
      const title = `${RULE_NAMES[key]}: automated incident`;
      if ((await casesTitled(title)) === 0) continue;
      const { flyout } = await openCaseTitled(title);
      await flyout.getByRole('button', { name: /^Close case/ }).first().click().catch(() => undefined);
      await page.getByRole('button', { name: /^Close/ }).last().click().catch(() => undefined);
      entry.notes.push(`case ${title} closed`);
    }
    await openSettings('notifications');
    const settings = page.locator('[data-test-subj="wamNotifSettings"]');
    if (await settings.locator(`[data-test-subj="wamNotifChannel-${CHANNEL_ID}"]`).count()) {
      await settings.getByRole('button', { name: `Remove ${CHANNEL_NAME}` }).click();
      await settings.locator('[data-test-subj="wamNotifSave"]').click();
      await expect(settings.locator('[data-test-subj="wamNotifDirty"]')).toBeHidden({ timeout: 60_000 });
    }
    await openSettings('assets');
    const assets = page.locator('[data-test-subj="wamAssetSettings"]');
    if (await assets.locator(`[data-test-subj="wamAssetRemove-${ASSET_ID}"]`).count()) {
      await assets.locator(`[data-test-subj="wamAssetRemove-${ASSET_ID}"]`).click();
      await assets.locator('[data-test-subj="wamAssetSave"]').click();
      await expect(assets.locator('[data-test-subj="wamAssetDirty"]')).toBeHidden({ timeout: 60_000 });
    }
    await openSettings('task-lists');
    const row = page.locator('[data-test-subj="wamTaskListsTable"] tr', { hasText: TASK_LIST_NAME });
    if (await row.count()) {
      await row.locator('[data-test-subj^="wamTaskListDelete-"]').click();
      await page.locator('[data-test-subj="wamTaskListDeleteConfirm"]').click();
    }
    // ALLOWED API CALL 1 (restore): the snapshot's status / assignee / case per record, in bulks.
    const touched = state.snapshot.filter((alert) => alert.agent === profile.agent);
    const groups = new Map<string, string[]>();
    for (const alert of touched) {
      const key = JSON.stringify([alert.status, alert.assigned_to, alert.case_id]);
      groups.set(key, [...(groups.get(key) || []), alert.id]);
    }
    let restored = 0;
    for (const [key, ids] of groups) {
      const [status, assignedTo, caseId] = JSON.parse(key);
      for (let offset = 0; offset < ids.length; offset += 500) {
        await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: ids.slice(offset, offset + 500), status, assignedTo, caseId });
        restored += Math.min(500, ids.length - offset);
      }
    }
    entry.counts.restored = restored;
  }, { skipUnless: () => revert, skipReason: 'nothing is reverted unless WAM_AUTOMATION_REVERT=1 (owner decision)' });
});
