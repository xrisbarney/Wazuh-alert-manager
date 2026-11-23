import { NOTIFICATION_ENQUEUE_BULK_SIZE } from '../../../common/constants';
import type { NotificationEvent, NotificationSettings } from '../../../common/types';
import { resolveNotificationChannels } from './emitters';
import { enqueueMany, EnqueueInput } from './outbox';
import { NotificationPayload, NotificationRuleActions, projectAlertForNotification, projectCaseEvent, renderSubject } from './render';
import { getNotificationChannels, NotificationSettingsLogger } from './settings';

/**
 * Rule action `notify` (step 1.4): the outbox producer the automation
 * evaluator calls once per worker batch, after the alert writes and the case
 * routing, for every (rule, alert) pair whose plan carries `notify`.
 *
 * - Event `rule.action`; payload = `projectAlertForNotification(alert)` with
 *   the rule `{id, name}` and `actions {status?, assignee?, caseId?}` naming
 *   what the rule did, so the message reflects the applied outcome, never a
 *   raw document.
 * - One outbox entry per channel with the deterministic id
 *   `ruleNotifyOutboxId(ruleId, alertId, channelId)`, so a re-evaluation of
 *   the same event (queue retry, second replica, continuation) is a silent
 *   duplicate: the outbox answers a 409 and it is counted as skipped, never
 *   delivered twice.
 * - Entries are written through `enqueueMany` in bulks of
 *   `NOTIFICATION_ENQUEUE_BULK_SIZE` (a 256-alert batch times its channels
 *   times its rules is one round trip per 500 entries, not one per entry);
 *   `beforeChunk` lets the caller re-assert its lease between bulks.
 * - Channel ids that are unknown or disabled at execution time, and every id
 *   while notifications are globally disabled, are skipped and counted.
 * - The settings read is strict (`throwOnError`): a skip here is final (the
 *   trigger is consumed, nothing replays), so a failed read must reject and
 *   become the evaluator's retryable `notification_enqueue` failure instead
 *   of "disabled globally".
 * - A bulk item failure other than a duplicate is returned in `failures` (the
 *   evaluator turns it into a retryable outcome: the ids are idempotent, so a
 *   replay is safe); a transport failure of a whole bulk rejects.
 */

export const RULE_ACTION_EVENT: NotificationEvent = 'rule.action';

export interface RuleNotificationTask {
  ruleId: string;
  ruleName: string;
  alertId: string;
  /** The alert's live `_source` after the rule's writes (projected through the allowlist here). */
  source: any;
  /** The rule's `notify.channelIds`. */
  channelIds: readonly string[];
  /** What the rule applied to this alert (only the applied actions). */
  actions: NotificationRuleActions;
  now?: Date;
}

export interface RuleNotificationFailure {
  ruleId: string;
  alertId: string;
  channelId: string;
  message: string;
}

export interface RuleNotificationResult {
  /** Outbox entries written by this call. */
  enqueued: number;
  /** Entries not written: unknown / disabled channel ids, a globally disabled outbox, and duplicates of an earlier run. */
  skipped: number;
  /** Rule ids with at least one entry written by this call (sorted): the rules that acted. */
  rulesEnqueued: string[];
  failures: RuleNotificationFailure[];
}

function keyPart(value: unknown): string {
  const text = value === undefined || value === null ? '' : String(value).trim();
  return (text || 'na').slice(0, 128);
}

/** `notify:{ruleId}:{alertId}` plus the channel, because one outbox entry carries one channel. */
export function ruleNotifyOutboxId(ruleId: string, alertId: string, channelId: string): string {
  return `notify:${keyPart(ruleId)}:${keyPart(alertId)}:${channelId}`;
}

/** The allowlisted `rule.action` payload of one task (exported for tests and the preview of a message). */
export function ruleActionPayload(task: RuleNotificationTask): NotificationPayload {
  const actions: NotificationRuleActions = {};
  if (task.actions?.status) actions.status = task.actions.status;
  if (task.actions?.assignee) actions.assignee = task.actions.assignee;
  if (task.actions?.caseId) actions.caseId = task.actions.caseId;
  return projectCaseEvent(
    RULE_ACTION_EVENT,
    null,
    {
      actor: 'correlation-rule',
      rule: { id: task.ruleId, name: task.ruleName },
      alert: projectAlertForNotification(task.source, { id: task.alertId }),
      actions,
    },
    { now: task.now }
  );
}

export interface EnqueueRuleNotificationsOptions {
  /** Pre-read settings (tests); default: `getNotificationChannels(client, logger, { throwOnError: true })`. */
  settings?: NotificationSettings;
  /** Called before every bulk after the first (the evaluator re-asserts its lease); a rejection propagates. */
  beforeChunk?: () => Promise<void>;
  /** Bulk size (tests); default `NOTIFICATION_ENQUEUE_BULK_SIZE`. */
  chunkSize?: number;
}

interface PendingEntry {
  input: EnqueueInput;
  ruleId: string;
  alertId: string;
  channelId: string;
}

export async function enqueueRuleNotifications(
  client: any,
  tasks: readonly RuleNotificationTask[],
  logger: NotificationSettingsLogger,
  options: EnqueueRuleNotificationsOptions = {}
): Promise<RuleNotificationResult> {
  const result: RuleNotificationResult = { enqueued: 0, skipped: 0, rulesEnqueued: [], failures: [] };
  if (!tasks.length) return result;
  const settings = options.settings || (await getNotificationChannels(client, logger, { throwOnError: true }));
  const skippedIds = new Set<string>();
  let disabledGlobally = false;
  const pending: PendingEntry[] = [];
  for (const task of tasks) {
    const resolved = resolveNotificationChannels(settings, RULE_ACTION_EVENT, task.channelIds);
    if (!resolved.enabled) {
      disabledGlobally = true;
      result.skipped += new Set(task.channelIds).size;
      continue;
    }
    for (const id of [...resolved.unknown, ...resolved.disabled]) skippedIds.add(id);
    result.skipped += resolved.unknown.length + resolved.disabled.length;
    if (!resolved.channels.length) continue;
    const payload = ruleActionPayload(task);
    const subject = renderSubject(RULE_ACTION_EVENT, payload);
    for (const channel of resolved.channels) {
      pending.push({
        ruleId: task.ruleId,
        alertId: task.alertId,
        channelId: channel.id,
        input: {
          id: ruleNotifyOutboxId(task.ruleId, task.alertId, channel.id),
          event: RULE_ACTION_EVENT,
          channelId: channel.id,
          channelKind: channel.kind,
          targetType: 'alert',
          targetId: task.alertId,
          subject,
          payload: payload as Record<string, any>,
          now: task.now,
        },
      });
    }
  }
  const chunkSize = Math.max(1, options.chunkSize ?? NOTIFICATION_ENQUEUE_BULK_SIZE);
  const rulesEnqueued = new Set<string>();
  for (let offset = 0; offset < pending.length; offset += chunkSize) {
    if (offset > 0 && options.beforeChunk) await options.beforeChunk();
    const chunk = pending.slice(offset, offset + chunkSize);
    const byId = new Map(chunk.map((entry) => [entry.input.id as string, entry]));
    const written = await enqueueMany(client, chunk.map((entry) => entry.input));
    result.enqueued += written.enqueued.length;
    result.skipped += written.duplicates.length;
    for (const id of written.enqueued) {
      const entry = byId.get(id);
      if (entry) rulesEnqueued.add(entry.ruleId);
    }
    for (const failure of written.failures) {
      const entry = byId.get(failure.id);
      result.failures.push({
        ruleId: entry?.ruleId ?? 'na',
        alertId: entry?.alertId ?? 'na',
        channelId: entry?.channelId ?? 'na',
        message: failure.error,
      });
    }
  }
  result.rulesEnqueued = Array.from(rulesEnqueued).sort();
  if (disabledGlobally) {
    logger.warn?.('wazuh-alert-manager notifications: rule.action skipped, notifications are disabled in Settings > Notifications');
  }
  if (skippedIds.size) {
    logger.warn?.(
      `wazuh-alert-manager notifications: rule.action skipped unknown or disabled channel id(s) ${Array.from(skippedIds).sort().join(', ')}`
    );
  }
  return result;
}
