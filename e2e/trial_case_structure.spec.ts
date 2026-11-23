import { expect, Page, test } from '@playwright/test';
import { API, api, apiRaw, applyQueueFilters, caseQueueRow, caseQueueRowCell, fromSeedRun, openAlertFlyout, openCaseFlyout, openSettingsSection, pollUntil, queueRow, queueRowCell, queueRowCheckbox, seedAlerts, signIn } from './helpers';

/**
 * Phase 2 bench (PLAN.md 2.5): response structure inside a case on a live
 * 4.x stack. One task list (three tasks, one with a 60-minute due offset) is
 * created through the API and shown in Settings > TaskLists; two seeded alerts
 * become a case through the queue's "Create case from selected" modal with the
 * task list picked; a task is ticked in the Tasks tab and one is added inline;
 * the Timeline tab and `GET /cases/{id}/timeline` list the alerts and the
 * task list / task events in order (cursor paging, tampered cursor = 400); the
 * case is closed from the flyout as a false positive, which stamps the
 * disposition on the case and on both alerts (list API, queue badge, filter);
 * `GET /reports/metrics` and the Reporting app show the dispositions; and on
 * this 4.x build the version route reports major 4 and the alert flyout has
 * no "Native case" block (step 2.6 projects it from 5.0 findings only).
 *
 * Mutating: seeds alerts, creates a task list (deleted in afterAll) and a case
 * (closed by test 5; cases are not deleted by the plugin API).
 */

const AGENT_NAME = 'wam-e2e-agent';
/** `e2e/seed_alerts.py` writes `rule.id = 930001`, `rule.level = 10`. */
const SEEDED_RULE_ID = '930001';
const QUEUE_QUERY = `${API}/alerts?from_offset=0&size=50&sortField=@timestamp&sortDirection=desc&agentNames=${AGENT_NAME}`;
const RUN = Date.now().toString(36);
const TASK_LIST_NAME = `WAM e2e task list ${RUN}`;
const CASE_TITLE = `WAM e2e structure ${RUN}`;
const TASK_TITLES = ['Triage the alert', 'Contain the host', 'Write up the findings'];
const INLINE_TASK_TITLE = `Follow-up ${RUN}`;
const CLOSURE_REASON = `Benchmark traffic from the e2e seeder (${RUN})`;
const MINUTE_MS = 60_000;

const mutating = process.env.WAM_E2E_MUTATING === '1';
const username = process.env.WAM_E2E_USERNAME;
const password = process.env.WAM_E2E_PASSWORD;

test.describe.configure({ mode: 'serial' });

/** base64url, as `encodeTimelineCursor` writes it (used to forge a cursor of another case). */
function base64Url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value: string): string {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded + '='.repeat((4 - (padded.length % 4)) % 4), 'base64').toString('utf8');
}

test.describe('trial: task list, tasks, timeline, disposition and reporting', () => {
  test.skip(!mutating, 'Set WAM_E2E_MUTATING=1 to run the mutating case-structure bench.');
  test.skip(!username || !password, 'Set WAM_E2E_USERNAME and WAM_E2E_PASSWORD in .env.e2e.local');

  let page: Page;
  let taskListId = '';
  let seededIds: string[] = [];
  let caseId = '';
  let caseTasks: any[] = [];
  let completedTaskId = '';

  const readCase = async () => (await api(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}`)).case;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await signIn(page, username!, password!);
  });

  test.afterAll(async () => {
    try {
      if (taskListId) await api(page, 'DELETE', `${API}/task-lists/${encodeURIComponent(taskListId)}`);
    } catch (e) {
      console.warn(`could not delete the task list: ${String(e)}`);
    }
    try {
      // Test 5 closes them with the case; this only matters when an earlier test failed.
      if (seededIds.length) await api(page, 'POST', `${API}/alerts/bulk-update`, { ids: seededIds, status: 'closed' });
    } catch (e) {
      console.warn(`could not close the seeded alerts: ${String(e)}`);
    }
    await page?.close();
  });

  test('an administrator creates a three-task task list and Settings > Task lists lists it', async () => {
    test.setTimeout(120_000);
    const created = await api(page, 'POST', `${API}/task-lists`, {
      name: TASK_LIST_NAME,
      description: 'Created by trial_case_structure.spec.ts',
      tasks: [
        { title: TASK_TITLES[0] },
        { title: TASK_TITLES[1], owner: 'wam-e2e-analyst', dueOffsetMinutes: 60 },
        { title: TASK_TITLES[2] },
      ],
      enabled: true,
    });
    const taskList = created.taskList;
    expect(taskList.id).toMatch(/^pb-[0-9a-f]{16}$/);
    taskListId = taskList.id;
    expect(taskList.name).toBe(TASK_LIST_NAME);
    expect(taskList.enabled).toBe(true);
    expect(taskList.tasks.map((task: any) => task.title)).toEqual(TASK_TITLES);
    expect(taskList.tasks[1]).toMatchObject({ owner: 'wam-e2e-analyst', dueOffsetMinutes: 60 });
    expect(taskList.created_by).toBe(username);

    const listed = await api(page, 'GET', `${API}/task-lists`);
    expect(listed.taskLists.find((item: any) => item.id === taskListId)).toMatchObject({ name: TASK_LIST_NAME, enabled: true });

    await page.goto('/app/wazuh-alert-manager?tab=settings');
    await openSettingsSection(page, 'task-lists');
    await expect(page.locator('[data-test-subj="wamTaskLists"]')).toBeVisible({ timeout: 30_000 });
    const name = page.locator(`[data-test-subj="wamTaskListName-${taskListId}"]`);
    await expect(name).toBeVisible({ timeout: 30_000 });
    await expect(name).toHaveText(TASK_LIST_NAME);
    await expect(page.locator(`[data-test-subj="wamTaskListTasks-${taskListId}"]`)).toContainText('3');
  });

  test('two seeded alerts become a case through "Create case from selected" with the task list; applying it again is a no-op', async () => {
    test.setTimeout(360_000);
    expect(taskListId, 'previous step creates the task list').not.toBe('');
    const seed = seedAlerts({ count: 2 });
    const fromRun = fromSeedRun(seed.run);
    const hits: any[] = await pollUntil(
      page,
      async () => {
        const rows = ((await api(page, 'GET', QUEUE_QUERY))?.hits?.hits || []).filter(fromRun);
        return rows.length === 2 ? rows : null;
      },
      { label: 'both seeded alerts projected', timeoutMs: 180_000, pollMs: 5_000 }
    );
    seededIds = hits.map((hit) => hit._id as string);
    for (const hit of hits) expect(hit._source.rule?.id).toBe(SEEDED_RULE_ID);

    // The queue: select both rows, open the modal, pick the task list (a native
    // <select>, so Playwright's selectOption drives it), create.
    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    for (const id of seededIds) {
      const row = queueRow(page, id);
      await expect(row).toBeVisible({ timeout: 60_000 });
      await queueRowCheckbox(page, id).check();
    }
    await page.getByRole('button', { name: 'Create case from selected' }).click();
    const modal = page.locator('.wamCreateCaseModal');
    await expect(modal).toBeVisible({ timeout: 30_000 });
    await modal.locator('[data-test-subj="wamCreateCaseTitle"]').fill(CASE_TITLE);
    const picker = modal.locator('[data-test-subj="wamCreateCaseTaskList"]');
    await expect(picker).toBeEnabled({ timeout: 30_000 });
    await picker.selectOption(taskListId);
    await expect(picker).toHaveValue(taskListId);
    await modal.locator('[data-test-subj="wamCreateCaseSubmit"]').click();

    // The workbench opens the new case (`?tab=cases&case=<id>`).
    await expect(page).toHaveURL(/[?&]case=case-[0-9a-f]+/, { timeout: 60_000 });
    caseId = new URL(page.url()).searchParams.get('case') || '';
    expect(caseId).toMatch(/^case-[0-9a-f]+$/);
    await expect(page.locator('.wamCaseFlyout')).toBeVisible({ timeout: 60_000 });

    const caseDoc = await readCase();
    expect(caseDoc.title).toBe(CASE_TITLE);
    expect(caseDoc.status).toBe('open');
    expect(caseDoc.alert_ids).toEqual(expect.arrayContaining(seededIds));
    expect(caseDoc.applied_task_lists.map((entry: any) => entry.task_list_id)).toContain(taskListId);
    caseTasks = caseDoc.tasks;
    expect(caseTasks).toHaveLength(3);
    expect(caseTasks.map((task: any) => task.title)).toEqual(TASK_TITLES);
    expect(caseDoc.task_counts).toEqual({ open: 3, done: 0 });
    const appliedAt = Date.parse(caseDoc.applied_task_lists.find((entry: any) => entry.task_list_id === taskListId).applied_at);
    const withDue = caseTasks[1];
    expect(withDue.owner).toBe('wam-e2e-analyst');
    expect(Date.parse(withDue.due_at) - appliedAt).toBe(60 * MINUTE_MS);
    expect(caseTasks[0].due_at ?? null).toBeNull();
    expect((caseDoc.history || []).some((entry: any) => entry.action === 'task_list_applied')).toBe(true);

    const again = await api(page, 'POST', `${API}/cases/${encodeURIComponent(caseId)}/task-lists/${encodeURIComponent(taskListId)}/apply`, {});
    expect(again).toMatchObject({ applied: false, reason: 'already_applied', task_list_id: taskListId, tasks_added: 0, counts: { open: 3, done: 0 } });
    expect((await readCase()).tasks).toHaveLength(3);
  });

  test('ticking a task in the Tasks tab updates the queue chip and the history; the inline form adds a task', async () => {
    test.setTimeout(180_000);
    expect(caseId, 'previous step creates the case').not.toBe('');
    const target = caseTasks[0];
    const flyout = await openCaseFlyout(page, caseId);
    await flyout.locator('[data-test-subj="wamCaseNav-tasks"]').click();
    const tasksTab = flyout.locator('[data-test-subj="wamCaseTasks"]');
    await expect(tasksTab).toBeVisible({ timeout: 30_000 });
    await expect(tasksTab.locator('[data-test-subj="wamCaseTasksCounts"]')).toHaveText('0/3 done');
    for (const task of caseTasks) {
      await expect(tasksTab.locator(`[data-test-subj="wamCaseTaskTitle-${task.id}"]`)).toHaveText(task.title);
    }
    const checkbox = tasksTab.locator(`[data-test-subj="wamCaseTaskDone-${target.id}"]`);
    await expect(checkbox).not.toBeChecked();
    // Controlled EuiCheckbox: it flips only after the PUT round-trips, so click and wait on the state.
    await checkbox.click();
    await expect(checkbox).toBeChecked({ timeout: 30_000 });
    await expect(tasksTab.locator('[data-test-subj="wamCaseTasksCounts"]')).toHaveText('1/3 done', { timeout: 30_000 });
    await expect(tasksTab.locator(`[data-test-subj="wamCaseTaskDoneBy-${target.id}"]`)).toContainText(username!);
    completedTaskId = target.id;

    const updated = await pollUntil(page, async () => {
      const doc = await readCase();
      return doc.task_counts?.done === 1 ? doc : null;
    }, { label: 'task completion stored', timeoutMs: 30_000 });
    expect(updated.task_counts).toEqual({ open: 2, done: 1 });
    const done = updated.tasks.find((task: any) => task.id === target.id);
    expect(done).toMatchObject({ done: true, done_by: username });
    expect(Number.isFinite(Date.parse(done.done_at))).toBe(true);
    const completion = (updated.history || []).filter((entry: any) => entry.action === 'task_completed');
    expect(completion).toHaveLength(1);
    expect(completion[0].to).toBe(target.title);

    // Cases table chip and the History tab wording.
    await page.goto('/app/wazuh-alert-manager?tab=cases');
    // The case queue is an EuiDataGrid (13.2): it renders no row element, so
    // the row is its anchor cell and the chip is reached by the row's id.
    await expect(caseQueueRow(page, caseId)).toBeVisible({ timeout: 60_000 });
    await expect(caseQueueRow(page, caseId)).toContainText(CASE_TITLE);
    await expect(caseQueueRowCell(page, caseId, '[data-test-subj="wamCaseTasksChip"]')).toHaveText('1/3 tasks');

    const reopened = await openCaseFlyout(page, caseId);
    await reopened.locator('[data-test-subj="wamCaseNav-history"]').click();
    await expect(reopened).toContainText('completed a task', { timeout: 30_000 });
    await expect(reopened).toContainText('applied a task list');

    // Inline add form.
    await reopened.locator('[data-test-subj="wamCaseNav-tasks"]').click();
    const tab = reopened.locator('[data-test-subj="wamCaseTasks"]');
    await tab.locator('[data-test-subj="wamCaseTaskAdd"]').click();
    const form = tab.locator('[data-test-subj="wamCaseTaskForm"]');
    await expect(form).toBeVisible();
    await form.locator('[data-test-subj="wamCaseTaskNewTitle"]').fill(INLINE_TASK_TITLE);
    // Owner is an AssigneePicker (EuiComboBox): type into its search input and confirm with Enter.
    const ownerInput = form.locator('[data-test-subj="wamCaseTaskNewOwner"] input');
    await ownerInput.fill(username!);
    await ownerInput.press('Enter');
    await expect(form.locator('[data-test-subj="wamCaseTaskNewOwner"]')).toContainText(username!);
    await form.locator('[data-test-subj="wamCaseTaskSave"]').click();
    await expect(tab).toContainText(INLINE_TASK_TITLE, { timeout: 30_000 });
    await expect(tab.locator('[data-test-subj="wamCaseTasksCounts"]')).toHaveText('1/4 done', { timeout: 30_000 });
    const withAdded = await readCase();
    expect(withAdded.tasks).toHaveLength(4);
    const added = withAdded.tasks.find((task: any) => task.title === INLINE_TASK_TITLE);
    expect(added).toMatchObject({ owner: username, done: false, created_by: username, order: 3 });
    expect(withAdded.task_counts).toEqual({ open: 3, done: 1 });
    expect((withAdded.history || []).filter((entry: any) => entry.action === 'task_added').map((entry: any) => entry.to)).toContain(INLINE_TASK_TITLE);
  });

  test('the Timeline tab lists the alerts, the task list and the task events in order; the API pages with a scoped cursor', async () => {
    test.setTimeout(180_000);
    expect(completedTaskId, 'previous step completes a task').not.toBe('');
    // The activity index is not refreshed on write: wait until the inline add of the previous test is searchable.
    const timeline = await pollUntil(
      page,
      async () => {
        const result = await api(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/timeline?limit=500`);
        return (result?.entries || []).some((entry: any) => entry.action === 'task_added') ? result : null;
      },
      { label: 'task_added visible in the timeline', timeoutMs: 30_000 }
    );
    expect(timeline.next_cursor).toBeNull();
    expect(timeline.truncated_alerts).toBe(false);
    const entries: any[] = timeline.entries;
    for (let i = 1; i < entries.length; i += 1) {
      expect(entries[i].at >= entries[i - 1].at, `entries ordered by at (${entries[i - 1].at} <= ${entries[i].at})`).toBe(true);
    }
    for (const id of seededIds) {
      const alertEntry = entries.find((entry) => entry.id === `alert:${id}`);
      expect(alertEntry).toMatchObject({ kind: 'alert', ref: { alert_id: id }, severity_band: 'high' });
      expect(alertEntry.details).toContain(`rule ${SEEDED_RULE_ID}`);
    }
    const indexOf = (action: string) => entries.findIndex((entry) => entry.kind === 'audit' && entry.action === action);
    const applied = indexOf('task_list_applied');
    const completed = indexOf('task_completed');
    const added = indexOf('task_added');
    expect(applied).toBeGreaterThanOrEqual(0);
    expect(completed).toBeGreaterThan(applied);
    expect(added).toBeGreaterThan(completed);
    expect(entries[applied].title).toBe(`task list applied: ${TASK_LIST_NAME}`);
    expect(entries[applied].details).toBe('3 tasks added');
    expect(entries[applied].actor).toBe(username);
    expect(entries[completed].title).toBe(`task completed: ${TASK_TITLES[0]}`);
    expect(entries.find((entry) => entry.kind === 'audit' && entry.action === 'case_created')).toBeTruthy();
    // The open task with a due date is listed as a task_due entry; the completed one is not.
    const dues = entries.filter((entry) => entry.kind === 'task_due');
    expect(dues.map((entry) => entry.ref.task_id)).toEqual([caseTasks[1].id]);
    expect(dues[0].at).toBe(caseTasks[1].due_at);

    // Cursor paging: two pages of two entries, no overlap, continuing the order.
    const first = await api(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/timeline?limit=2`);
    expect(first.entries).toHaveLength(2);
    expect(first.entries.map((entry: any) => entry.id)).toEqual(entries.slice(0, 2).map((entry) => entry.id));
    expect(typeof first.next_cursor).toBe('string');
    const second = await api(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/timeline?limit=2&cursor=${encodeURIComponent(first.next_cursor)}`);
    expect(second.entries).toHaveLength(2);
    expect(second.entries.map((entry: any) => entry.id)).toEqual(entries.slice(2, 4).map((entry) => entry.id));

    const garbage = await apiRaw(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/timeline?limit=2&cursor=not-a-cursor`);
    expect(garbage.status).toBe(400);
    expect(JSON.parse(garbage.text).message).toBeTruthy();
    // A well-formed cursor of another case: decode the genuine one and change only its case so the scope check is what rejects it.
    const genuine = JSON.parse(base64UrlDecode(first.next_cursor));
    expect(genuine).toMatchObject({ v: 1, case: caseId });
    const foreign = base64Url(JSON.stringify({ ...genuine, case: 'case-0000' }));
    const scoped = await apiRaw(page, 'GET', `${API}/cases/${encodeURIComponent(caseId)}/timeline?limit=2&cursor=${encodeURIComponent(foreign)}`);
    expect(scoped.status).toBe(400);
    const unknown = await apiRaw(page, 'GET', `${API}/cases/case-doesnotexist/timeline`);
    expect(unknown.status).toBe(404);

    // The tab renders the same rows in the same order.
    const flyout = await openCaseFlyout(page, caseId);
    await flyout.locator('[data-test-subj="wamCaseNav-timeline"]').click();
    const tab = flyout.locator('[data-test-subj="wamCaseTimeline"]');
    await expect(tab).toBeVisible({ timeout: 30_000 });
    for (const id of seededIds) {
      await expect(tab.locator(`[data-test-subj="wamCaseTimelineRow-alert:${id}"]`)).toBeVisible({ timeout: 30_000 });
      await expect(tab.locator(`[data-test-subj="wamCaseTimelineOpenAlert-alert:${id}"]`)).toBeVisible();
    }
    const appliedRow = tab.locator(`[data-test-subj="wamCaseTimelineRow-${entries[applied].id}"]`);
    await expect(appliedRow.locator(`[data-test-subj="wamCaseTimelineBadge-${entries[applied].id}"]`)).toHaveText('Task list');
    await expect(appliedRow).toContainText(TASK_LIST_NAME);
    await expect(appliedRow).toContainText('3 tasks added');
    const completedRow = tab.locator(`[data-test-subj="wamCaseTimelineRow-${entries[completed].id}"]`);
    await expect(completedRow.locator(`[data-test-subj="wamCaseTimelineBadge-${entries[completed].id}"]`)).toHaveText('Task done');
    await expect(completedRow).toContainText(TASK_TITLES[0]);
    const rendered = await tab.locator('[data-test-subj^="wamCaseTimelineRow-"]').evaluateAll((nodes) =>
      nodes.map((node) => (node.getAttribute('data-test-subj') || '').replace(/^wamCaseTimelineRow-/, ''))
    );
    const renderedIds = rendered.filter((id) => entries.some((entry) => entry.id === id));
    expect(renderedIds.indexOf(entries[applied].id)).toBeGreaterThanOrEqual(0);
    expect(renderedIds.indexOf(entries[completed].id)).toBeGreaterThan(renderedIds.indexOf(entries[applied].id));
    for (const id of seededIds) expect(renderedIds.indexOf(`alert:${id}`)).toBeLessThan(renderedIds.indexOf(entries[applied].id));
  });

  test('closing the case as a false positive stamps the disposition on the case and both alerts, with a queue badge and filter', async () => {
    test.setTimeout(240_000);
    expect(caseId, 'previous steps create the case').not.toBe('');
    const flyout = await openCaseFlyout(page, caseId);
    const statusGroup = flyout.locator('fieldset', { has: page.locator('legend', { hasText: 'Status' }) }).first();
    await expect(statusGroup).toBeVisible({ timeout: 30_000 });
    await statusGroup.getByText('Closed', { exact: true }).first().click();

    const dialog = page.locator('[data-test-subj="wamCaseCloseDialog"]');
    await expect(dialog).toBeVisible({ timeout: 30_000 });
    await expect(dialog).toContainText('2 currently loaded linked alerts still open');
    await dialog.locator('[data-test-subj="wamCaseCloseDialogDisposition"]').click();
    await page.locator('[data-test-subj="wamDispositionOption-false_positive"]').click();
    await expect(dialog.locator('[data-test-subj="wamCaseCloseDialogDisposition"]')).toContainText('False positive');
    await dialog.locator('[data-test-subj="wamCaseCloseDialogReason"]').fill(CLOSURE_REASON);
    await expect(dialog.locator('[data-test-subj="wamCaseCloseDialogConfirm"]')).toHaveText('Close case and 2 alert(s)');
    await dialog.locator('[data-test-subj="wamCaseCloseDialogConfirm"]').click();
    await expect(dialog).toBeHidden({ timeout: 60_000 });

    const closed = await pollUntil(page, async () => {
      const doc = await readCase();
      return doc.status === 'closed' ? doc : null;
    }, { label: 'case closed', timeoutMs: 60_000 });
    expect(closed.disposition).toBe('false_positive');
    expect(closed.closure_reason).toBe(CLOSURE_REASON);
    expect(Number.isFinite(Date.parse(closed.closed_at))).toBe(true);
    const closeRow = (closed.history || []).find((entry: any) => entry.action === 'status_change' && entry.to === 'closed');
    expect(closeRow?.disposition).toBe('false_positive');

    // Flyout overview shows the outcome and the reason.
    const overview = await openCaseFlyout(page, caseId);
    await expect(overview.locator('[data-test-subj="wamCaseOverviewDisposition"]')).toHaveText('False positive', { timeout: 30_000 });
    await expect(overview.locator('[data-test-subj="wamCaseClosureReason"]')).toHaveText(CLOSURE_REASON);

    // Both alerts: closed with the same outcome, listed by the disposition filter.
    const listed = await pollUntil(page, async () => {
      const result = await api(page, 'GET', `${QUEUE_QUERY}&statuses=closed&disposition=false_positive`);
      const rows = (result?.hits?.hits || []).filter((hit: any) => seededIds.includes(hit._id));
      return rows.length === 2 ? rows : null;
    }, { label: 'both alerts listed as false positives', timeoutMs: 60_000 });
    for (const hit of listed) {
      expect(hit._source.status).toBe('closed');
      expect(hit._source.disposition).toBe('false_positive');
      expect(hit._source.closure_reason).toBe(CLOSURE_REASON);
      expect(hit._source.case_id).toBe(caseId);
      const row = (hit._source.history || []).find((entry: any) => entry.action === 'status_change' && entry.to === 'closed');
      expect(row?.disposition).toBe('false_positive');
    }
    const excluded = await api(page, 'GET', `${QUEUE_QUERY}&statuses=closed&disposition=true_positive,benign`);
    expect((excluded?.hits?.hits || []).filter((hit: any) => seededIds.includes(hit._id))).toHaveLength(0);

    // Queue: include closed alerts, filter on the disposition, badge on the row.
    await page.goto('/app/wazuh-alert-manager?tab=alerts');
    await page.locator('[data-test-subj="wamStatusFilter-closed"]').click();
    const combo = page.locator('[data-test-subj="wamDispositionFilter"]');
    await combo.locator('input').click();
    await combo.locator('input').fill('False positive');
    await page.getByRole('option', { name: 'False positive' }).click();
    await applyQueueFilters(page);
    for (const id of seededIds) {
      const row = queueRow(page, id);
      await expect(row).toBeVisible({ timeout: 60_000 });
      await expect(queueRowCell(page, id, '[data-test-subj="wamAlertDisposition"]')).toHaveText('False positive');
    }
    const alertFlyout = await openAlertFlyout(page, seededIds[0]);
    await expect(alertFlyout.locator('[data-test-subj="wamAlertFlyoutDisposition"]')).toHaveText('False positive', { timeout: 30_000 });
    await expect(alertFlyout.locator('[data-test-subj="wamAlertClosureReason"]')).toHaveText(CLOSURE_REASON);
  });

  test('report metrics and the Reporting app show the false positives by rule', async () => {
    test.setTimeout(120_000);
    expect(seededIds.length, 'previous steps close the seeded alerts').toBe(2);
    const to = new Date(Date.now() + 5 * MINUTE_MS);
    const from = new Date(Date.now() - 60 * MINUTE_MS);
    const metrics = await pollUntil(page, async () => {
      const result = await api(page, 'GET', `${API}/reports/metrics?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`);
      return (result?.dispositions?.false_positive ?? 0) >= 2 ? result : null;
    }, { label: 'false positives counted by the report', timeoutMs: 60_000, pollMs: 5_000 });
    expect(metrics.dispositions.false_positive).toBeGreaterThanOrEqual(2);
    const ruleRow = (metrics.falsePositiveByRule || []).find((row: any) => row.rule_id === SEEDED_RULE_ID);
    expect(ruleRow).toBeTruthy();
    expect(ruleRow.closed).toBeGreaterThanOrEqual(2);
    expect(ruleRow.false_positive).toBeGreaterThanOrEqual(2);
    expect(ruleRow.rate).toBeGreaterThan(0);
    expect(ruleRow.rate).toBeLessThanOrEqual(1);

    await page.goto('/app/wazuhAlertManagerReporting');
    const section = page.locator('[data-test-subj="wamReportDispositions"]');
    await expect(section).toBeVisible({ timeout: 60_000 });
    await expect(section).toContainText('Dispositions');
    await expect(section.locator('[data-test-subj="wamReportDispositionsDonut"]')).toBeVisible();
    const table = section.locator('[data-test-subj="wamReportFalsePositiveTable"]');
    await expect(table).toBeVisible({ timeout: 30_000 });
    await expect(table.locator('tr', { hasText: SEEDED_RULE_ID }).first()).toBeVisible();
  });

  test('this 4.x build reports Wazuh major 4 and the alert flyout has no "Native case" block', async () => {
    test.setTimeout(120_000);
    const version = await api(page, 'GET', `${API}/system/version`);
    expect(version.targetWazuhMajor).toBe(4);
    expect(String(version.targetWazuhVersion)).toMatch(/^4\./);
    const hit = (await api(page, 'GET', `${QUEUE_QUERY}&statuses=closed`)).hits.hits.find((row: any) => row._id === seededIds[0]);
    expect(hit._source.native_case ?? null).toBeNull();

    const flyout = await openAlertFlyout(page, seededIds[0]);
    await expect(flyout.locator('.wamAlertId')).toBeVisible({ timeout: 30_000 });
    await expect(flyout.locator('[data-test-subj="wamAlertNativeCase"]')).toHaveCount(0);
    await expect(flyout.locator('[data-native-status]')).toHaveCount(0);
    await expect(flyout).not.toContainText('Native case');
  });
});
