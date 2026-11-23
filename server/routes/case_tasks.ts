import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  CASE_TASKS_MAX,
  CASE_TASK_OWNER_MAX_LENGTH,
  CASE_TASK_TITLE_MAX_LENGTH,
  CaseTask,
  CaseTaskCounts,
  CaseTaskListResponse,
  CaseTaskMutationResponse,
} from '../../common';
import {
  TASK_ADDED_ACTION,
  TASK_COMPLETED_ACTION,
  TASK_REMOVED_ACTION,
  TASK_REOPENED_ACTION,
  TASK_UPDATED_ACTION,
  appendActivity,
} from '../lib/activity';
import { trustedIdentity, TrustedIdentity } from '../lib/identity';
import { getCurrentUsername } from '../lib/opensearch';
import { isPluginAdmin } from '../lib/authorization';
import { resolveCase } from '../lib/case_index_resolution';
import {
  addTask,
  normaliseStoredTasks,
  removeTask,
  taskCounts,
  taskError,
  updateTask,
  mutateCaseTasks,
  TaskMutationOutcome,
} from '../lib/case_tasks';

/**
 * Case tasks (step 2.1): the checklist lives on the case document itself
 * (`tasks[]` + `task_counts`), so every mutation is a read-modify-write of
 * the case through the same history-appending script PUT /cases/{id} uses,
 * fenced with `if_seq_no` / `if_primary_term` so two analysts editing the
 * list at once cannot clobber each other (one retry on 409, then 409 to
 * the caller). The first read goes through the alias search (`resolveCase`,
 * the only way to learn the physical generation); the retry re-reads the
 * document with a realtime GET on that index, because a search-derived
 * token is only refresh-visible and would stay stale right after a
 * `refresh: false` writer (SLA scanner, automation routing) touched the
 * case. A closed case is read-only. Attribution follows the other case
 * writers (`getCurrentUsername`); only DELETE needs a trusted identity
 * because that is where an authorization decision is made.
 */

// `mutateCaseTasks` (the fenced read-modify-write) lives in the lib since
// step 2.2 so task lists can append tasks through the same path; it is
// re-exported here for the existing callers and tests.
export { mutateCaseTasks };
export type { TaskMutationOutcome };

export function listCaseTasks(source: any): CaseTaskListResponse {
  const tasks = normaliseStoredTasks(source?.tasks);
  return { tasks, counts: taskCounts(tasks), limit: CASE_TASKS_MAX };
}

/** Who may remove a task: its author, the case assignee, or a plugin admin. */
export function canRemoveTask(identity: TrustedIdentity, task: CaseTask, caseSource: any): boolean {
  if (identity.source === 'anonymous') return false;
  if (isPluginAdmin(identity)) return true;
  if (task.created_by && task.created_by === identity.name) return true;
  return Boolean(caseSource?.assigned_to) && caseSource.assigned_to === identity.name;
}

const caseParams = schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) });
const taskParams = schema.object({
  id: schema.string({ minLength: 1, maxLength: 256 }),
  taskId: schema.string({ minLength: 1, maxLength: 64 }),
});

export const createTaskBodySchema = schema.object({
  title: schema.string({ minLength: 1, maxLength: CASE_TASK_TITLE_MAX_LENGTH }),
  owner: schema.maybe(schema.nullable(schema.string({ maxLength: CASE_TASK_OWNER_MAX_LENGTH }))),
  dueAt: schema.maybe(schema.nullable(schema.string({ maxLength: 64 }))),
});

export const updateTaskBodySchema = schema.object({
  title: schema.maybe(schema.string({ minLength: 1, maxLength: CASE_TASK_TITLE_MAX_LENGTH })),
  owner: schema.maybe(schema.nullable(schema.string({ maxLength: CASE_TASK_OWNER_MAX_LENGTH }))),
  dueAt: schema.maybe(schema.nullable(schema.string({ maxLength: 64 }))),
  done: schema.maybe(schema.boolean()),
  order: schema.maybe(schema.number({ min: 0, max: CASE_TASKS_MAX })),
});

function failure(response: any, error: any) {
  const statusCode = error?.statusCode || error?.meta?.statusCode || 500;
  const body = { message: error?.message || 'Operation failed' };
  if (statusCode === 404) return response.notFound({ body });
  if (statusCode === 403) return response.forbidden({ body });
  if (statusCode === 400) return response.badRequest({ body });
  return response.customError({ statusCode, body });
}

function taskDetails(task: CaseTask) {
  return { task_id: task.id, title: task.title };
}

export function defineCaseTaskRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/cases/{id}/tasks`,
      validate: { params: caseParams },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const current = await resolveCase(client, id);
        return response.ok({ body: listCaseTasks(current.source) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/cases/{id}/tasks`,
      validate: { params: caseParams, body: createTaskBodySchema },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const body = request.body as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const actor = await getCurrentUsername(context, request);
        const now = new Date().toISOString();
        const { result } = await mutateCaseTasks(
          client,
          id,
          actor,
          (tasks) => addTask(tasks, body, actor, now),
          (r) => ({ action: TASK_ADDED_ACTION, to: r.task.title }),
          now
        );
        await appendActivity(client, {
          targetType: 'case',
          targetId: id,
          user: actor,
          action: TASK_ADDED_ACTION,
          to: result.task.title,
          timestamp: now,
          details: taskDetails(result.task),
        });
        const payload: CaseTaskMutationResponse = { task: result.task, counts: result.counts };
        return response.ok({ body: payload });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.put(
    {
      path: `${API_ROOT}/cases/{id}/tasks/{taskId}`,
      validate: { params: taskParams, body: updateTaskBodySchema },
    },
    async (context, request, response) => {
      const { id, taskId } = request.params as any;
      const body = request.body as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const actor = await getCurrentUsername(context, request);
        const now = new Date().toISOString();
        const actionFor = (transition: string) =>
          transition === 'completed' ? TASK_COMPLETED_ACTION : transition === 'reopened' ? TASK_REOPENED_ACTION : TASK_UPDATED_ACTION;
        const { result } = await mutateCaseTasks(
          client,
          id,
          actor,
          (tasks) => updateTask(tasks, taskId, body, actor, now),
          (r) => ({
            action: actionFor(r.transition),
            from: r.previous.title !== r.task.title ? r.previous.title : null,
            to: r.task.title,
          }),
          now
        );
        if (result.transition !== 'unchanged') {
          await appendActivity(client, {
            targetType: 'case',
            targetId: id,
            user: actor,
            action: actionFor(result.transition),
            from: result.previous.title !== result.task.title ? result.previous.title : null,
            to: result.task.title,
            timestamp: now,
            details: taskDetails(result.task),
          });
        }
        const payload: CaseTaskMutationResponse = { task: result.task, counts: result.counts };
        return response.ok({ body: payload });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.delete(
    {
      path: `${API_ROOT}/cases/{id}/tasks/{taskId}`,
      validate: { params: taskParams },
    },
    async (context, request, response) => {
      const { id, taskId } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const identity = await trustedIdentity(context, request);
        const actor = identity.name;
        const now = new Date().toISOString();
        const { result } = await mutateCaseTasks(
          client,
          id,
          actor,
          (tasks, source) => {
            const existing = tasks.find((task) => task.id === taskId);
            if (!existing) throw taskError(404, 'Task not found.');
            if (!canRemoveTask(identity, existing, source)) {
              throw taskError(403, 'Only the task author, the case assignee or a plugin administrator can remove a task.');
            }
            return removeTask(tasks, taskId);
          },
          (r) => ({ action: TASK_REMOVED_ACTION, from: r.task.title }),
          now
        );
        await appendActivity(client, {
          targetType: 'case',
          targetId: id,
          user: actor,
          action: TASK_REMOVED_ACTION,
          from: result.task.title,
          timestamp: now,
          details: taskDetails(result.task),
        });
        const counts: CaseTaskCounts = result.counts;
        return response.ok({ body: { deleted: true, counts } });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}
