import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  CASE_TASK_OWNER_MAX_LENGTH,
  CASE_TASK_TITLE_MAX_LENGTH,
  TASK_LISTS_MAX,
  TASK_LIST_DESCRIPTION_MAX_LENGTH,
  TASK_LIST_DUE_OFFSET_MAX_MINUTES,
  TASK_LIST_DUE_OFFSET_MIN_MINUTES,
  TASK_LIST_NAME_MAX_LENGTH,
  TASK_LIST_TASKS_MAX,
  TaskListApplyResponse,
  TaskListListResponse,
  TaskListMutationResponse,
} from '../../common';
import {
  TASK_LIST_CREATED_ACTION,
  TASK_LIST_DELETED_ACTION,
  TASK_LIST_UPDATED_ACTION,
  appendActivity,
} from '../lib/activity';
import { requirePluginAdmin } from '../lib/authorization';
import { getCurrentUsername } from '../lib/opensearch';
import {
  applyTaskListToCase,
  createTaskList,
  deleteTaskList,
  getTaskList,
  listTaskLists,
  updateTaskList,
} from '../lib/task_lists';

/**
 * TaskLists (step 2.2).
 *
 *   GET    /task-lists[?enabled=true]                 any signed-in user -> { task lists, limit }
 *   GET    /task-lists/{id}                           any signed-in user -> { task list }
 *   POST   /task-lists                                administrator; 200 { task list }; 409 duplicate name / cap
 *   PUT    /task-lists/{id}                           administrator; whole-document replace; 404 / 409
 *   DELETE /task-lists/{id}                           administrator; 200 { deleted: true }; 404
 *   POST   /cases/{id}/task-lists/{taskListId}/apply  any signed-in user (attribution like the task routes);
 *                                                    404 unknown case or task list, 409 disabled task list,
 *                                                    closed case or task cap; 200 TaskListApplyResponse
 *                                                    (`applied: false, reason: 'already_applied'` on a repeat)
 *
 * Writes audit `task_list_created|updated|deleted` on `system/task_list:<id>`
 * (`to` = name, `from` = previous name on update/delete); the apply writes
 * `task_list_applied` on the case through `applyTaskListToCase`.
 */

const idParams = schema.object({ id: schema.string({ minLength: 1, maxLength: 64 }) });
const applyParams = schema.object({
  id: schema.string({ minLength: 1, maxLength: 256 }),
  taskListId: schema.string({ minLength: 1, maxLength: 64 }),
});

export const taskListTaskSchema = schema.object(
  {
    title: schema.string({ minLength: 1, maxLength: CASE_TASK_TITLE_MAX_LENGTH }),
    owner: schema.maybe(schema.nullable(schema.string({ maxLength: CASE_TASK_OWNER_MAX_LENGTH }))),
    dueOffsetMinutes: schema.maybe(
      schema.nullable(schema.number({ min: TASK_LIST_DUE_OFFSET_MIN_MINUTES, max: TASK_LIST_DUE_OFFSET_MAX_MINUTES }))
    ),
  },
  { unknowns: 'forbid' }
);

export const taskListBodySchema = schema.object(
  {
    name: schema.string({ minLength: 1, maxLength: TASK_LIST_NAME_MAX_LENGTH }),
    description: schema.maybe(schema.nullable(schema.string({ maxLength: TASK_LIST_DESCRIPTION_MAX_LENGTH }))),
    tasks: schema.arrayOf(taskListTaskSchema, { minSize: 1, maxSize: TASK_LIST_TASKS_MAX }),
    enabled: schema.boolean({ defaultValue: true }),
  },
  { unknowns: 'forbid' }
);

function failure(response: any, error: any) {
  const statusCode = error?.statusCode || error?.meta?.statusCode || 500;
  const body = { message: error?.message || 'Operation failed' };
  if (statusCode === 404) return response.notFound({ body });
  if (statusCode === 403) return response.forbidden({ body });
  if (statusCode === 400) return response.badRequest({ body });
  return response.customError({ statusCode, body });
}

export function defineTaskListRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/task-lists`,
      validate: { query: schema.object({ enabled: schema.maybe(schema.boolean()) }) },
    },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const { enabled } = request.query as any;
        const taskLists = await listTaskLists(client, { enabledOnly: enabled === true });
        const body: TaskListListResponse = { taskLists, limit: TASK_LISTS_MAX };
        return response.ok({ body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get(
    { path: `${API_ROOT}/task-lists/{id}`, validate: { params: idParams } },
    async (context, request, response) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const taskList = await getTaskList(client, (request.params as any).id);
        const body: TaskListMutationResponse = { taskList };
        return response.ok({ body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    { path: `${API_ROOT}/task-lists`, validate: { body: taskListBodySchema } },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const now = new Date().toISOString();
        const taskList = await createTaskList(client, request.body, identity.name, now);
        await appendActivity(client, {
          targetType: 'system',
          targetId: `task_list:${taskList.id}`,
          user: identity.name,
          action: TASK_LIST_CREATED_ACTION,
          to: taskList.name,
          timestamp: now,
          details: { task_list_id: taskList.id, tasks: taskList.tasks.length, enabled: taskList.enabled },
        });
        const body: TaskListMutationResponse = { taskList };
        return response.ok({ body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.put(
    { path: `${API_ROOT}/task-lists/{id}`, validate: { params: idParams, body: taskListBodySchema } },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const now = new Date().toISOString();
        const { taskList, previous } = await updateTaskList(client, (request.params as any).id, request.body, identity.name, now);
        await appendActivity(client, {
          targetType: 'system',
          targetId: `task_list:${taskList.id}`,
          user: identity.name,
          action: TASK_LIST_UPDATED_ACTION,
          from: previous.name,
          to: taskList.name,
          timestamp: now,
          details: { task_list_id: taskList.id, tasks: taskList.tasks.length, enabled: taskList.enabled },
        });
        const body: TaskListMutationResponse = { taskList };
        return response.ok({ body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.delete(
    { path: `${API_ROOT}/task-lists/{id}`, validate: { params: idParams } },
    async (context, request, response) => {
      try {
        const identity = await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const now = new Date().toISOString();
        const previous = await deleteTaskList(client, (request.params as any).id);
        await appendActivity(client, {
          targetType: 'system',
          targetId: `task_list:${previous.id}`,
          user: identity.name,
          action: TASK_LIST_DELETED_ACTION,
          from: previous.name,
          timestamp: now,
          details: { task_list_id: previous.id },
        });
        return response.ok({ body: { deleted: true } });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    { path: `${API_ROOT}/cases/{id}/task-lists/{taskListId}/apply`, validate: { params: applyParams } },
    async (context, request, response) => {
      const { id, taskListId } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const actor = await getCurrentUsername(context, request);
        const now = new Date().toISOString();
        const taskList = await getTaskList(client, taskListId);
        const body: TaskListApplyResponse = await applyTaskListToCase(client, id, taskList, actor, now);
        return response.ok({ body });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}
