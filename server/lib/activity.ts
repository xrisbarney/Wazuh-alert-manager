import { randomUUID } from 'crypto';
import {
  ACTIVITY_READ_ALIAS,
  ACTIVITY_WRITE_ALIAS,
  SLA_BREACHED_ACTION,
  SLA_ESCALATED_ACTION,
  TASK_ADDED_ACTION,
  TASK_COMPLETED_ACTION,
  TASK_REMOVED_ACTION,
  TASK_REOPENED_ACTION,
  TASK_UPDATED_ACTION,
  TASK_LIST_APPLIED_ACTION,
  TASK_LIST_CREATED_ACTION,
  TASK_LIST_DELETED_ACTION,
  TASK_LIST_UPDATED_ACTION,
  NOTIFICATION_SETTINGS_UPDATED_ACTION,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';

// SLA escalation scanner actions (step 3.3): `sla_breached` once per record
// when its resolve due date passes, `sla_escalated` once per record and
// escalation (`details` carries the escalation and the actions applied,
// including the `notify` channel ids phase 1 delivers from this event).
export { SLA_BREACHED_ACTION, SLA_ESCALATED_ACTION };

// Case attachment audit actions (step 5.3); `to` carries `<kind>:<name>`.
export const ATTACHMENT_ADDED_ACTION = 'attachment_added';
export const ATTACHMENT_REMOVED_ACTION = 'attachment_removed';

// Case task audit actions (step 2.1); `details` carries `{task_id, title}` and
// `to` (added / completed / reopened / updated) or `from` (removed) the title.
export { TASK_ADDED_ACTION, TASK_UPDATED_ACTION, TASK_COMPLETED_ACTION, TASK_REOPENED_ACTION, TASK_REMOVED_ACTION };
export const TASK_ACTIONS = [
  TASK_ADDED_ACTION,
  TASK_UPDATED_ACTION,
  TASK_COMPLETED_ACTION,
  TASK_REOPENED_ACTION,
  TASK_REMOVED_ACTION,
] as const;

// TaskList audit actions (step 2.2): `task_list_created|updated|deleted` on
// `system/task-list:<id>` (`to` = name); `task_list_applied` on the case with
// `details { task_list_id, name, tasks_added }`.
export { TASK_LIST_CREATED_ACTION, TASK_LIST_UPDATED_ACTION, TASK_LIST_DELETED_ACTION, TASK_LIST_APPLIED_ACTION };

// Notification settings audit (step 1.1): `notification_settings_updated` on
// `system/notification_settings`; `from` / `to` carry the compact summary of
// `notificationSettingsAuditSummary` (enabled flag, channel count, ids+kinds).
export { NOTIFICATION_SETTINGS_UPDATED_ACTION };

export interface ActivityInput {
  eventType?: 'audit' | 'comment';
  targetType: 'alert' | 'case' | 'rule' | 'system';
  targetId: string;
  user: string;
  action: string;
  from?: string | null;
  to?: string | null;
  timestamp?: string;
  source?: string;
  operationId?: string;
  ruleRevision?: number;
  /** Comment body; only meaningful with `eventType: 'comment'`. */
  text?: string;
  /** Structured, unindexed detail (activity mapping is `dynamic: false`). */
  details?: Record<string, any> | null;
  /**
   * Stored id of the event (`event_uid`, keyword) and the `_id` the writers
   * below index it under: the stable tiebreak of `queryCaseActivity`. Random
   * when omitted; `appendActivityOnce` uses its deterministic id.
   */
  eventUid?: string;
}

export interface ActivityFailureObserver {
  error(message: string): void;
  increment?(metric: 'automation_audit_write_failures'): void;
}

export function buildActivityEvent(input: ActivityInput) {
  const timestamp = input.timestamp || new Date().toISOString();
  return {
    event_uid: input.eventUid || randomUUID(),
    event_type: input.eventType || 'audit',
    target_type: input.targetType,
    target_id: input.targetId,
    alert_id: input.targetType === 'alert' ? input.targetId : null,
    case_id: input.targetType === 'case' ? input.targetId : null,
    timestamp,
    created_at: timestamp,
    user: input.user,
    author: input.user,
    action: input.action,
    from: input.from ?? null,
    to: input.to ?? null,
    source: input.source || 'user',
    operation_id: input.operationId || null,
    rule_revision: input.ruleRevision ?? null,
    ...(input.text !== undefined ? { text: input.text } : {}),
    ...(input.details ? { details: input.details } : {}),
  };
}

/** The stored shape of one activity document, as `buildActivityEvent` writes it. */
export type ActivityEventDoc = ReturnType<typeof buildActivityEvent>;

/**
 * Post-write hook for case events (step 1.3). The notification emitter
 * registers itself at plugin start; it is called after a SUCCESSFUL
 * `appendActivity` / `appendActivityOnce` of a `targetType: 'case'` event
 * (never after a 409 "already written", so a retried deterministic write
 * does not notify twice). Opt-in: with no emitter registered nothing happens,
 * so unit tests of the writers stay unaffected. A throwing emitter is
 * swallowed here as well: notifications never break the primary write.
 */
export type ActivityEmitter = (event: ActivityEventDoc) => Promise<void> | void;

let activityEmitter: ActivityEmitter | null = null;

export function registerActivityEmitter(emitter: ActivityEmitter | null): void {
  activityEmitter = emitter;
}

export function getActivityEmitter(): ActivityEmitter | null {
  return activityEmitter;
}

export async function notifyActivityEmitter(event: ActivityEventDoc): Promise<void> {
  if (!activityEmitter || event?.target_type !== 'case') return;
  try {
    await activityEmitter(event);
  } catch {
    // The emitter logs its own failures; the activity write already succeeded.
  }
}

export async function appendActivity(client: any, input: ActivityInput) {
  const doc = buildActivityEvent(input);
  await client.index({ index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS), id: doc.event_uid, body: doc });
  await notifyActivityEmitter(doc);
  return doc;
}

/** A deterministic activity write is safe to retry after an ambiguous failure. */
export async function appendActivityOnce(client: any, id: string, input: ActivityInput) {
  const doc = buildActivityEvent({ ...input, eventUid: id });
  try {
    await client.index({
      index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS),
      id,
      op_type: 'create',
      body: doc,
    });
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) !== 409) throw error;
    return doc;
  }
  await notifyActivityEmitter(doc);
  return doc;
}

export function reportActivityFailure(observer: ActivityFailureObserver, operationId: string, error: any) {
  observer.increment?.('automation_audit_write_failures');
  observer.error(
    `wazuh-alert-manager rules audit ${operationId} remains in the durable outbox: ${error?.message || String(error)}`
  );
}

export function pushActivityBulk(body: any[], input: ActivityInput) {
  const doc = buildActivityEvent(input);
  body.push({ index: { _index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS), _id: doc.event_uid } });
  body.push(doc);
}

export interface CaseActivityPage {
  /** Raw hits, oldest first; each carries `sort` = `[created_at millis, event_uid | null]`. */
  hits: any[];
  /** Sort values of the last hit (the `after` of the next page), null when the page is empty. */
  lastSort: ActivitySortValue[] | null;
  /** True when more events exist beyond this page. */
  hasMore: boolean;
}

/** A `search_after` value of the activity sort: millis, the keyword, or null for a legacy event without `event_uid`. */
export type ActivitySortValue = string | number | null;

/**
 * Every activity event of one case (comments and audit events of every
 * action: status / assignment changes, `task_*`, `task_list_applied`,
 * `sla_*`, `attachment_*`, ...), oldest first, keyed `[created_at, event_uid]`
 * so `search_after` paging is stable across the activity generations.
 * `created_at` is the one time field every activity document carries
 * (`POST /comments` historically wrote no `timestamp`); `event_uid` is the
 * stored keyword copy of the `_id` every writer in this module stamps, so no
 * `_id` fielddata is loaded (events written before the field existed sort
 * `_first` within their millisecond). Unlike `routes/comments.ts#listComments`
 * there is no `event_type` or action filter; the case timeline (step 2.3)
 * merges these with alerts and tasks.
 */
export async function queryCaseActivity(
  client: any,
  caseId: string,
  options: { after?: ActivitySortValue[] | null; limit: number }
): Promise<CaseActivityPage> {
  const limit = Math.max(1, Math.floor(options.limit));
  const result: any = await client.search({
    index: ACTIVITY_READ_ALIAS,
    body: {
      size: limit + 1,
      track_total_hits: false,
      sort: [{ created_at: { order: 'asc' } }, { event_uid: { order: 'asc', missing: '_first' } }],
      query: { bool: { filter: [{ term: { case_id: caseId } }] } },
      ...(options.after && options.after.length ? { search_after: options.after } : {}),
    },
  });
  const all: any[] = result?.body?.hits?.hits || [];
  const hits = all.slice(0, limit);
  const last = hits[hits.length - 1];
  return {
    hits,
    lastSort: Array.isArray(last?.sort) ? last.sort : null,
    hasMore: all.length > limit,
  };
}
