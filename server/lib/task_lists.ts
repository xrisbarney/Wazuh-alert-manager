import { randomBytes } from 'crypto';
import {
  CASE_TASKS_MAX,
  CASE_TASK_OWNER_MAX_LENGTH,
  CASE_TASK_TITLE_MAX_LENGTH,
  TASK_LISTS_INDEX,
  TASK_LISTS_MAX,
  TASK_LIST_APPLIED_ACTION,
  TASK_LIST_DESCRIPTION_MAX_LENGTH,
  TASK_LIST_DUE_OFFSET_MAX_MINUTES,
  TASK_LIST_DUE_OFFSET_MIN_MINUTES,
  TASK_LIST_NAME_MAX_LENGTH,
  TASK_LIST_TASKS_MAX,
  AppliedTaskList,
  CaseTask,
  CaseTaskCounts,
  TaskList,
  TaskListApplyResponse,
  TaskListTask,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { appendActivity, appendActivityOnce } from './activity';
import { addTask, mutateCaseTasks, reorderTasks, taskCounts, TaskListMutation } from './case_tasks';

/**
 * TaskLists (step 2.2): reusable task templates stored one document per
 * task list in the fixed index TASK_LISTS_INDEX, and the one apply function
 * every entry point uses (the apply route behind the case Tasks tab,
 * `POST /cases` with `taskListId` from the Create case modal, and automation
 * case creation).
 *
 * Storage is snake_case (`due_offset_minutes`), the API camelCase
 * (`dueOffsetMinutes`); `fromStoredTaskList` / `toStoredTaskList` convert.
 * Name uniqueness (case-insensitive) and the TASK_LISTS_MAX cap are enforced
 * in code over the bounded list rather than by the mapping, since the index
 * is small by construction. Errors carry `statusCode` (400 validation, 404
 * unknown, 409 duplicate name / cap / disabled) like server/lib/case_tasks.ts.
 */

export function taskListError(statusCode: number, message: string): Error {
  const error: any = new Error(message);
  error.statusCode = statusCode;
  return error;
}

export const TASK_LIST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** `pb-` + 16 hex characters (64 random bits). */
export function newTaskListId(): string {
  return `pb-${randomBytes(8).toString('hex')}`;
}

export function isTaskListId(value: unknown): value is string {
  return typeof value === 'string' && TASK_LIST_ID_PATTERN.test(value);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface NormalisedTaskList {
  name: string;
  description: string;
  tasks: TaskListTask[];
  enabled: boolean;
}

function singleLine(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
}

function normaliseName(value: unknown): string {
  if (typeof value !== 'string') throw taskListError(400, 'A task list needs a name.');
  const name = singleLine(value);
  if (!name) throw taskListError(400, 'A task list needs a name.');
  if (name.length > TASK_LIST_NAME_MAX_LENGTH) {
    throw taskListError(400, `The name must be at most ${TASK_LIST_NAME_MAX_LENGTH} characters.`);
  }
  return name;
}

function normaliseDescription(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'string') throw taskListError(400, 'The description must be text.');
  const description = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim();
  if (description.length > TASK_LIST_DESCRIPTION_MAX_LENGTH) {
    throw taskListError(400, `The description must be at most ${TASK_LIST_DESCRIPTION_MAX_LENGTH} characters.`);
  }
  return description;
}

function normaliseTaskTitle(value: unknown, position: number): string {
  if (typeof value !== 'string') throw taskListError(400, `Task ${position} needs a title.`);
  const title = singleLine(value);
  if (!title) throw taskListError(400, `Task ${position} needs a title.`);
  if (title.length > CASE_TASK_TITLE_MAX_LENGTH) {
    throw taskListError(400, `Task ${position}: the title must be at most ${CASE_TASK_TITLE_MAX_LENGTH} characters.`);
  }
  return title;
}

function normaliseTaskOwner(value: unknown, position: number): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw taskListError(400, `Task ${position}: the owner must be a user name.`);
  const owner = value.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!owner) return null;
  if (owner.length > CASE_TASK_OWNER_MAX_LENGTH) {
    throw taskListError(400, `Task ${position}: the owner must be at most ${CASE_TASK_OWNER_MAX_LENGTH} characters.`);
  }
  return owner;
}

function normaliseDueOffset(value: unknown, position: number): number | null {
  if (value === null || value === undefined || value === '') return null;
  const minutes = typeof value === 'number' ? value : Number(value);
  if (
    typeof value === 'boolean' ||
    !Number.isInteger(minutes) ||
    minutes < TASK_LIST_DUE_OFFSET_MIN_MINUTES ||
    minutes > TASK_LIST_DUE_OFFSET_MAX_MINUTES
  ) {
    throw taskListError(
      400,
      `Task ${position}: the due offset must be a whole number of minutes between ${TASK_LIST_DUE_OFFSET_MIN_MINUTES} and ${TASK_LIST_DUE_OFFSET_MAX_MINUTES}.`
    );
  }
  return minutes;
}

/** Validate a create/update payload (whole-document semantics: every field is replaced). */
export function validateTaskListInput(input: unknown): NormalisedTaskList {
  const source: any = input && typeof input === 'object' ? input : {};
  const name = normaliseName(source.name);
  const description = normaliseDescription(source.description);
  if (!Array.isArray(source.tasks) || !source.tasks.length) {
    throw taskListError(400, 'A task list needs at least one task.');
  }
  if (source.tasks.length > TASK_LIST_TASKS_MAX) {
    throw taskListError(400, `A task list can hold at most ${TASK_LIST_TASKS_MAX} tasks.`);
  }
  const tasks: TaskListTask[] = source.tasks.map((task: any, index: number) => {
    const item = task && typeof task === 'object' ? task : {};
    const position = index + 1;
    return {
      title: normaliseTaskTitle(item.title, position),
      owner: normaliseTaskOwner(item.owner, position),
      dueOffsetMinutes: normaliseDueOffset(item.dueOffsetMinutes, position),
      order: index,
    };
  });
  if (source.enabled !== undefined && typeof source.enabled !== 'boolean') {
    throw taskListError(400, 'enabled must be a boolean.');
  }
  return { name, description, tasks, enabled: source.enabled !== false };
}

// ---------------------------------------------------------------------------
// Storage shape
// ---------------------------------------------------------------------------

export function toStoredTaskList(
  id: string,
  fields: NormalisedTaskList,
  actor: string,
  now: string,
  existing?: TaskList | null
) {
  return {
    id,
    name: fields.name,
    description: fields.description,
    tasks: fields.tasks.map((task, index) => ({
      title: task.title,
      owner: task.owner ?? null,
      due_offset_minutes: task.dueOffsetMinutes ?? null,
      order: index,
    })),
    enabled: fields.enabled,
    created_by: existing?.created_by || actor,
    created_at: existing?.created_at || now,
    updated_by: actor,
    updated_at: now,
  };
}

/** Defensive read of a stored document: returns null when it is unusable, never throws. */
export function fromStoredTaskList(id: string, source: any): TaskList | null {
  if (!source || typeof source !== 'object') return null;
  const name = typeof source.name === 'string' ? source.name : '';
  if (!id || !name) return null;
  const rawTasks = Array.isArray(source.tasks) ? source.tasks : [];
  const tasks: TaskListTask[] = [];
  for (const item of rawTasks) {
    if (!item || typeof item !== 'object' || typeof item.title !== 'string' || !item.title) continue;
    const offset = Number(item.due_offset_minutes);
    tasks.push({
      title: item.title,
      owner: typeof item.owner === 'string' && item.owner ? item.owner : null,
      dueOffsetMinutes: Number.isInteger(offset) && offset > 0 ? offset : null,
      order: Number.isFinite(Number(item.order)) ? Number(item.order) : Number.MAX_SAFE_INTEGER,
    });
  }
  tasks.sort((a, b) => a.order - b.order);
  return {
    id,
    name,
    description: typeof source.description === 'string' ? source.description : '',
    tasks: tasks.map((task, index) => ({ ...task, order: index })),
    enabled: source.enabled !== false,
    created_by: typeof source.created_by === 'string' ? source.created_by : '',
    created_at: typeof source.created_at === 'string' ? source.created_at : '',
    updated_by: typeof source.updated_by === 'string' ? source.updated_by : '',
    updated_at: typeof source.updated_at === 'string' ? source.updated_at : '',
  };
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

function isMissingIndex(error: any): boolean {
  const status = error?.meta?.statusCode || error?.statusCode;
  const type = error?.meta?.body?.error?.type || error?.body?.error?.type;
  return status === 404 || type === 'index_not_found_exception';
}

/** Every task list, sorted by name (case-insensitive); `[]` when the index does not exist yet. */
export async function listTaskLists(client: any, options: { enabledOnly?: boolean } = {}): Promise<TaskList[]> {
  let response: any;
  try {
    response = await client.search({
      index: TASK_LISTS_INDEX,
      body: {
        size: TASK_LISTS_MAX + 1,
        track_total_hits: true,
        query: options.enabledOnly ? { term: { enabled: true } } : { match_all: {} },
      },
    });
  } catch (error: any) {
    if (isMissingIndex(error)) return [];
    throw error;
  }
  const hits: any[] = response?.body?.hits?.hits || [];
  const taskLists: TaskList[] = [];
  for (const hit of hits) {
    const taskList = fromStoredTaskList(String(hit._id || ''), hit._source);
    if (taskList) taskLists.push(taskList);
  }
  return taskLists.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) || a.id.localeCompare(b.id));
}

/** One task list by id; 404 when unknown (or the index is missing). */
export async function getTaskList(client: any, id: string): Promise<TaskList> {
  if (!isTaskListId(id)) throw taskListError(404, 'Task list not found.');
  let response: any;
  try {
    response = await client.get({ index: TASK_LISTS_INDEX, id });
  } catch (error: any) {
    if (isMissingIndex(error)) throw taskListError(404, 'Task list not found.');
    throw error;
  }
  const taskList = response?.body?.found === false ? null : fromStoredTaskList(id, response?.body?._source);
  if (!taskList) throw taskListError(404, 'Task list not found.');
  return taskList;
}

/** 409 when another task list already uses `name` ignoring case. */
export function assertUniqueTaskListName(existing: readonly TaskList[], name: string, excludeId?: string): void {
  const wanted = name.trim().toLowerCase();
  const clash = existing.find((item) => item.id !== excludeId && item.name.trim().toLowerCase() === wanted);
  if (clash) throw taskListError(409, `A task list named "${clash.name}" already exists.`);
}

export async function createTaskList(
  client: any,
  input: unknown,
  actor: string,
  now: string = new Date().toISOString(),
  id: string = newTaskListId()
): Promise<TaskList> {
  const fields = validateTaskListInput(input);
  const existing = await listTaskLists(client);
  if (existing.length >= TASK_LISTS_MAX) {
    throw taskListError(409, `There are already ${TASK_LISTS_MAX} task lists; delete one first.`);
  }
  assertUniqueTaskListName(existing, fields.name);
  const doc = toStoredTaskList(id, fields, actor, now);
  await client.create({ index: assertManagedWriteTarget(TASK_LISTS_INDEX), id, body: doc, refresh: 'wait_for' });
  return fromStoredTaskList(id, doc) as TaskList;
}

export async function updateTaskList(
  client: any,
  id: string,
  input: unknown,
  actor: string,
  now: string = new Date().toISOString()
): Promise<{ taskList: TaskList; previous: TaskList }> {
  const fields = validateTaskListInput(input);
  const previous = await getTaskList(client, id);
  const existing = await listTaskLists(client);
  assertUniqueTaskListName(existing, fields.name, id);
  const doc = toStoredTaskList(id, fields, actor, now, previous);
  await client.index({ index: assertManagedWriteTarget(TASK_LISTS_INDEX), id, body: doc, refresh: 'wait_for' });
  return { taskList: fromStoredTaskList(id, doc) as TaskList, previous };
}

export async function deleteTaskList(client: any, id: string): Promise<TaskList> {
  const previous = await getTaskList(client, id);
  await client.delete({ index: assertManagedWriteTarget(TASK_LISTS_INDEX), id, refresh: 'wait_for' });
  return previous;
}

// ---------------------------------------------------------------------------
// Apply to a case
// ---------------------------------------------------------------------------

/** Defensive read of the case's `applied_task_lists` marker list. */
export function normaliseAppliedTaskLists(raw: unknown): AppliedTaskList[] {
  if (!Array.isArray(raw)) return [];
  const out: AppliedTaskList[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object' || typeof item.task_list_id !== 'string' || !item.task_list_id) continue;
    out.push({
      task_list_id: item.task_list_id,
      applied_at: typeof item.applied_at === 'string' ? item.applied_at : '',
      applied_by: typeof item.applied_by === 'string' ? item.applied_by : '',
    });
  }
  return out;
}

export interface TaskListApplyResult extends TaskListMutation {
  transition: 'applied' | 'unchanged';
  /** Tasks appended by this apply (empty when already applied). */
  added: CaseTask[];
  appliedTaskLists: AppliedTaskList[];
}

/**
 * Pure apply: append the task list's tasks to `tasks` (due_at = now + offset,
 * owner carried over, created_by = actor) unless `source.applied_task_lists`
 * already names the task list (then `transition: 'unchanged'` and nothing is
 * added). 409 when the result would exceed CASE_TASKS_MAX, with the count
 * that would overflow; nothing is applied in that case.
 */
export function applyTaskListTasks(
  tasks: CaseTask[],
  source: any,
  taskList: TaskList,
  actor: string,
  now: string = new Date().toISOString(),
  /** Test hook: deterministic task ids (default: `newTaskId` through `addTask`). */
  ids?: () => string
): TaskListApplyResult {
  const current = reorderTasks(tasks);
  const applied = normaliseAppliedTaskLists(source?.applied_task_lists);
  if (applied.some((item) => item.task_list_id === taskList.id)) {
    return { tasks: current, counts: taskCounts(current), transition: 'unchanged', added: [], appliedTaskLists: applied };
  }
  const total = current.length + taskList.tasks.length;
  if (total > CASE_TASKS_MAX) {
    throw taskListError(
      409,
      `Applying "${taskList.name}" would give this case ${total} tasks; the limit is ${CASE_TASKS_MAX}. Nothing was added.`
    );
  }
  const base = Date.parse(now);
  let next = current;
  const added: CaseTask[] = [];
  for (const template of [...taskList.tasks].sort((a, b) => a.order - b.order)) {
    const dueAt =
      template.dueOffsetMinutes && Number.isFinite(base)
        ? new Date(base + template.dueOffsetMinutes * 60000).toISOString()
        : null;
    const result = addTask(
      next,
      { title: template.title, owner: template.owner ?? null, dueAt },
      actor,
      now,
      ids ? ids() : undefined
    );
    next = result.tasks;
    added.push(result.task);
  }
  const appliedTaskLists = [...applied, { task_list_id: taskList.id, applied_at: now, applied_by: actor }];
  return { tasks: next, counts: taskCounts(next), transition: 'applied', added, appliedTaskLists };
}

export interface ApplyTaskListOptions {
  /** Activity `source` (`user` by default; automation passes `automation` + operation id). */
  source?: string;
  operationId?: string;
  ruleRevision?: number;
  /** Deterministic activity id (automation retries) instead of a plain append. */
  activityId?: string;
}

/**
 * Apply `task list` to the case `caseId`: one fenced read-modify-write through
 * `mutateCaseTasks` (so a closed case answers 409 and a concurrent edit is
 * retried once), writing `applied_task_lists` next to the task list, then one
 * `task_list_applied` activity event with `{ task_list_id, name, tasks_added }`.
 * 409 when the task list is disabled; a second apply of the same task list
 * answers `{ applied: false, reason: 'already_applied' }` without writing.
 */
export async function applyTaskListToCase(
  client: any,
  caseId: string,
  taskList: TaskList,
  actor: string,
  now: string = new Date().toISOString(),
  options: ApplyTaskListOptions = {}
): Promise<TaskListApplyResponse> {
  if (!taskList.enabled) throw taskListError(409, `Task list "${taskList.name}" is disabled.`);
  const { result } = await mutateCaseTasks(
    client,
    caseId,
    actor,
    (tasks, source) => applyTaskListTasks(tasks, source, taskList, actor, now),
    () => ({ action: TASK_LIST_APPLIED_ACTION, to: taskList.name }),
    now,
    (r) => ({ applied_task_lists: r.appliedTaskLists })
  );
  const counts: CaseTaskCounts = result.counts;
  if (result.transition === 'unchanged') {
    return { applied: false, reason: 'already_applied', task_list_id: taskList.id, tasks_added: 0, counts };
  }
  const event = {
    targetType: 'case' as const,
    targetId: caseId,
    user: actor,
    action: TASK_LIST_APPLIED_ACTION,
    to: taskList.name,
    timestamp: now,
    source: options.source,
    operationId: options.operationId,
    ruleRevision: options.ruleRevision,
    details: { task_list_id: taskList.id, name: taskList.name, tasks_added: result.added.length },
  };
  if (options.activityId) await appendActivityOnce(client, options.activityId, event);
  else await appendActivity(client, event);
  return { applied: true, task_list_id: taskList.id, tasks_added: result.added.length, counts };
}
