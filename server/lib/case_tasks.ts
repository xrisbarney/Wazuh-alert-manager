import { randomBytes } from 'crypto';
import {
  CASE_TASKS_MAX,
  CASE_TASK_OWNER_MAX_LENGTH,
  CASE_TASK_TITLE_MAX_LENGTH,
  CaseTask,
  CaseTaskCounts,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { APPEND_HISTORY_SCRIPT_SOURCE, buildHistoryEntry } from './history';
import { resolveCase, ResolvedCaseDocument } from './case_index_resolution';

/**
 * Case checklist (step 2.1): pure operations over the `tasks[]` array stored
 * on a case document. Every function returns a new array and never mutates
 * its input; `order` is renumbered 0..n-1 on every write so the stored list
 * is always dense and sorted, and `taskCounts` is the one place the
 * denormalised `task_counts {open, done}` pair is derived from.
 *
 * Errors carry `statusCode` (400 validation, 404 unknown task, 409 cap) so
 * the routes can map them without inspecting messages.
 */

export function taskError(statusCode: number, message: string): Error {
  const error: any = new Error(message);
  error.statusCode = statusCode;
  return error;
}

/** Validated, normalised field set a create or update may apply. */
export interface NormalisedTaskInput {
  title?: string;
  owner?: string | null;
  due_at?: string | null;
}

export interface TaskInputLike {
  title?: unknown;
  owner?: unknown;
  dueAt?: unknown;
}

/** 12 lower-case base36 characters from 64 random bits (36^12 > 2^62). */
export function newTaskId(): string {
  const value = BigInt('0x' + randomBytes(8).toString('hex'));
  return value.toString(36).padStart(12, '0').slice(-12);
}

function normaliseTitle(value: unknown): string {
  if (typeof value !== 'string') throw taskError(400, 'A task needs a title.');
  // Single line: control characters (newlines included) are stripped, not refused.
  const title = value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!title) throw taskError(400, 'A task needs a title.');
  if (title.length > CASE_TASK_TITLE_MAX_LENGTH) {
    throw taskError(400, `The title must be at most ${CASE_TASK_TITLE_MAX_LENGTH} characters.`);
  }
  return title;
}

function normaliseOwner(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw taskError(400, 'The owner must be a user name.');
  const owner = value.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!owner) return null;
  if (owner.length > CASE_TASK_OWNER_MAX_LENGTH) {
    throw taskError(400, `The owner must be at most ${CASE_TASK_OWNER_MAX_LENGTH} characters.`);
  }
  return owner;
}

function normaliseDueAt(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || !value.trim()) return null;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw taskError(400, 'The due date must be an ISO 8601 timestamp.');
  return new Date(time).toISOString();
}

/**
 * Validate a task payload. `partial: false` (create) requires a title;
 * `partial: true` (update) only normalises the keys that are present, so an
 * omitted key means "leave as is" while an explicit null clears it.
 */
export function validateTaskInput(input: TaskInputLike, options: { partial?: boolean } = {}): NormalisedTaskInput {
  const out: NormalisedTaskInput = {};
  const source = input || {};
  if (!options.partial || source.title !== undefined) out.title = normaliseTitle(source.title);
  if (!options.partial || source.owner !== undefined) out.owner = normaliseOwner(source.owner);
  if (!options.partial || source.dueAt !== undefined) out.due_at = normaliseDueAt(source.dueAt);
  return out;
}

/** Defensive read of a stored list: drops malformed rows, never throws. */
export function normaliseStoredTasks(raw: unknown): CaseTask[] {
  if (!Array.isArray(raw)) return [];
  const tasks: CaseTask[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const id = typeof item.id === 'string' ? item.id : '';
    const title = typeof item.title === 'string' ? item.title : '';
    if (!id || !title) continue;
    tasks.push({
      id,
      title,
      owner: typeof item.owner === 'string' ? item.owner : null,
      due_at: typeof item.due_at === 'string' ? item.due_at : null,
      done: item.done === true,
      done_by: typeof item.done_by === 'string' ? item.done_by : null,
      done_at: typeof item.done_at === 'string' ? item.done_at : null,
      created_by: typeof item.created_by === 'string' ? item.created_by : '',
      created_at: typeof item.created_at === 'string' ? item.created_at : '',
      order: Number.isFinite(Number(item.order)) ? Number(item.order) : Number.MAX_SAFE_INTEGER,
    });
  }
  return reorderTasks(tasks);
}

/**
 * Sort by `order` (ties by created_at, then id) and renumber 0..n-1.
 * Returns a new array of new objects.
 */
export function reorderTasks(tasks: CaseTask[]): CaseTask[] {
  return [...tasks]
    .sort((a, b) => {
      if (a.order !== b.order) return a.order - b.order;
      if (a.created_at !== b.created_at) return a.created_at < b.created_at ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    })
    .map((task, index) => ({ ...task, order: index }));
}

export function taskCounts(tasks: CaseTask[]): CaseTaskCounts {
  let done = 0;
  for (const task of tasks) if (task.done) done += 1;
  return { open: tasks.length - done, done };
}

export interface TaskListResult {
  tasks: CaseTask[];
  task: CaseTask;
  counts: CaseTaskCounts;
}

/** Append a task at the end of the list; 409 when the cap is reached. */
export function addTask(
  tasks: CaseTask[],
  input: TaskInputLike,
  actor: string,
  now: string = new Date().toISOString(),
  id: string = newTaskId()
): TaskListResult {
  const current = reorderTasks(tasks);
  if (current.length >= CASE_TASKS_MAX) {
    throw taskError(409, `This case already has ${CASE_TASKS_MAX} tasks; remove one first.`);
  }
  const fields = validateTaskInput(input);
  if (current.some((task) => task.id === id)) throw taskError(409, 'Task id collision; retry.');
  const task: CaseTask = {
    id,
    title: fields.title as string,
    owner: fields.owner ?? null,
    due_at: fields.due_at ?? null,
    done: false,
    done_by: null,
    done_at: null,
    created_by: actor,
    created_at: now,
    order: current.length,
  };
  const next = [...current, task];
  return { tasks: next, task, counts: taskCounts(next) };
}

export type TaskTransition = 'completed' | 'reopened' | 'updated' | 'unchanged';

export interface TaskUpdateResult extends TaskListResult {
  previous: CaseTask;
  /** What the patch did to the done flag, for the audit action. */
  transition: TaskTransition;
}

export interface TaskPatch extends TaskInputLike {
  done?: unknown;
  order?: unknown;
}

/**
 * Apply a partial update. A `done: true` transition stamps `done_by`/`done_at`
 * with the actor and `now`; `done: false` clears them. `order` moves the
 * task to that position (clamped), everything else is renumbered around it.
 */
export function updateTask(
  tasks: CaseTask[],
  taskId: string,
  patch: TaskPatch,
  actor: string,
  now: string = new Date().toISOString()
): TaskUpdateResult {
  const current = reorderTasks(tasks);
  const index = current.findIndex((task) => task.id === taskId);
  if (index < 0) throw taskError(404, 'Task not found.');
  const previous = current[index];
  const fields = validateTaskInput(patch || {}, { partial: true });
  if (patch?.done !== undefined && typeof patch.done !== 'boolean') {
    throw taskError(400, 'done must be a boolean.');
  }
  if (patch?.order !== undefined && (!Number.isInteger(patch.order) || (patch.order as number) < 0)) {
    throw taskError(400, 'order must be a non-negative integer.');
  }

  let updated: CaseTask = { ...previous, ...fields };
  let transition: TaskTransition = 'unchanged';
  if (
    fields.title !== undefined && fields.title !== previous.title ||
    fields.owner !== undefined && fields.owner !== (previous.owner ?? null) ||
    fields.due_at !== undefined && fields.due_at !== (previous.due_at ?? null)
  ) {
    transition = 'updated';
  }
  if (typeof patch?.done === 'boolean' && patch.done !== previous.done) {
    if (patch.done) {
      updated = { ...updated, done: true, done_by: actor, done_at: now };
      transition = 'completed';
    } else {
      updated = { ...updated, done: false, done_by: null, done_at: null };
      transition = 'reopened';
    }
  }

  let next = current.map((task, i) => (i === index ? updated : task));
  if (patch?.order !== undefined) {
    const target = Math.min(patch.order as number, next.length - 1);
    if (target !== index) {
      const without = next.filter((_, i) => i !== index);
      without.splice(target, 0, updated);
      next = without.map((task, i) => ({ ...task, order: i }));
      if (transition === 'unchanged') transition = 'updated';
    }
  }
  next = reorderTasks(next);
  const task = next.find((item) => item.id === taskId) as CaseTask;
  return { tasks: next, task, previous, counts: taskCounts(next), transition };
}

/** Remove a task; 404 when unknown. The rest is renumbered. */
export function removeTask(tasks: CaseTask[], taskId: string): TaskListResult {
  const current = reorderTasks(tasks);
  const task = current.find((item) => item.id === taskId);
  if (!task) throw taskError(404, 'Task not found.');
  const next = reorderTasks(current.filter((item) => item.id !== taskId));
  return { tasks: next, task, counts: taskCounts(next) };
}

// ---------------------------------------------------------------------------
// Persistence: one read-modify-write of the case document (moved here from
// routes/case_tasks.ts in step 2.2 so task lists can reuse it).
// ---------------------------------------------------------------------------

/** The minimum a mutation must return for `mutateCaseTasks` to persist it. */
export interface TaskListMutation {
  tasks: CaseTask[];
  counts: CaseTaskCounts;
  /** `'unchanged'` means "nothing to write": no history row, no `updated_*` bump. */
  transition?: string;
}

function isConflict(error: any): boolean {
  return (error?.meta?.statusCode || error?.statusCode) === 409;
}

function assertCaseOpen(current: ResolvedCaseDocument): void {
  if (current.source?.status === 'closed') throw taskError(409, 'Case is closed');
}

export interface TaskMutationOutcome<T extends TaskListMutation = TaskListResult> {
  result: T;
  /** The case document the mutation was applied to (post-write values not reloaded). */
  current: ResolvedCaseDocument;
}

/**
 * Apply `mutate` to the stored task list and persist the new list, counts,
 * `updated_*`, any `extraFields` and a history entry on the case with
 * optimistic concurrency (`if_seq_no` / `if_primary_term`; one retry after
 * a realtime GET, then 409). `mutate` must be pure (it is re-run against the
 * fresh document and its source on retry, so authorization that depends on
 * the document belongs inside it). The first read goes through the alias
 * search (`resolveCase`, the only way to learn the physical generation); the
 * retry re-reads with a realtime GET on that index, because a search-derived
 * token is only refresh-visible and would stay stale right after a
 * `refresh: false` writer (SLA scanner, automation routing) touched the case.
 * A closed case is read-only.
 */
export async function mutateCaseTasks<T extends TaskListMutation>(
  client: any,
  caseId: string,
  actor: string,
  mutate: (tasks: CaseTask[], source: any) => T,
  history: (result: T) => { action: string; from?: string | null; to?: string | null },
  now: string = new Date().toISOString(),
  extraFields?: (result: T, source: any) => Record<string, any>
): Promise<TaskMutationOutcome<T>> {
  let current = await resolveCase(client, caseId);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assertCaseOpen(current);
    const source = current.source || {};
    const result = mutate(normaliseStoredTasks(source.tasks), source);
    // A no-op patch (e.g. `done: false` on an open task) changes nothing:
    // no history row, no `updated_*` bump, no write at all.
    if (result.transition === 'unchanged') {
      return { result, current };
    }
    const entry = buildHistoryEntry({ user: actor, ...history(result) });
    const fields = {
      ...(extraFields ? extraFields(result, source) : {}),
      tasks: result.tasks,
      task_counts: result.counts,
      updated_at: now,
      updated_by: actor,
    };
    try {
      await client.update({
        index: assertManagedWriteTarget(current.index),
        id: caseId,
        refresh: 'wait_for',
        ...(current.seqNo === undefined || current.primaryTerm === undefined
          ? {}
          : { if_seq_no: current.seqNo, if_primary_term: current.primaryTerm }),
        body: { script: { lang: 'painless', source: APPEND_HISTORY_SCRIPT_SOURCE, params: { entry, fields } } },
      });
      return { result, current };
    } catch (error: any) {
      if (!isConflict(error)) throw error;
      if (attempt === 1) break;
      // Realtime read of the same physical document: the fresh
      // _seq_no/_primary_term, not the refresh-visible pair the alias search saw.
      const fresh: any = await client.get({ index: current.index, id: caseId });
      current = {
        ...current,
        source: fresh?.body?._source || {},
        seqNo: fresh?.body?._seq_no,
        primaryTerm: fresh?.body?._primary_term,
      };
    }
  }
  throw taskError(409, 'The case was changed by someone else while saving the task; reload and try again.');
}
