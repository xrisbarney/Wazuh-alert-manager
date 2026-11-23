import { API_ROOT, CASE_SEVERITIES, NOTIFICATION_ENQUEUE_BULK_SIZE } from '../../../common/constants';
import type {
  Case,
  NotificationChannel,
  NotificationEvent,
  NotificationSettings,
  NotificationTargetType,
  ReportRun,
  ReportSchedule,
  SlaEscalation,
  SlaEscalationTarget,
} from '../../../common/types';
import type { ActivityEmitter, ActivityEventDoc } from '../activity';
import { resolveCase } from '../case_index_resolution';
import { enqueueMany, enqueueNotification, EnqueueInput } from './outbox';
import {
  getNotificationDashboardUrl,
  NotificationEventExtra,
  NotificationPayload,
  projectAlertForNotification,
  projectCaseEvent,
  renderSubject,
} from './render';
import { channelsForEvent, findChannel, getNotificationChannels } from './settings';

/**
 * Notification emitters (step 1.3): the producers of the outbox.
 *
 * One emitter instance (created at plugin start with the internal client)
 * serves three producers:
 *
 * - the activity hook (`activityHook`, registered through
 *   `registerActivityEmitter` in `activity.ts`): every successful case
 *   activity write is mapped by `caseEventForActivity` to one of
 *   `case.created` / `case.assigned` / `case.closed`, the case document is
 *   loaded once (`resolveCase`) and the event is fanned out to its bound
 *   channels. `case.severity_raised` cannot be derived from the activity
 *   stream (the `case_updated` audit row records the status, not the
 *   severity), so the PUT route and the SLA escalation call `emitCaseEvent`
 *   directly with the old and new severity; likewise `case.assigned` when
 *   one request changes status and assignee together (its only audit row is
 *   the `status_change`: PUT and bulk) and `case.closed` for the duplicate
 *   cases an automation consolidation closes (no case activity row at all);
 * - the SLA scanner (`emitSlaEvent`, and `emitSlaEvents` for the breach pass,
 *   one scan page per call written through `enqueueMany` bulks): `sla.breached`
 *   goes to the bound channels, `sla.escalated` to the escalation's `notify`
 *   channel ids when present, else to the bound channels;
 * - the report scheduler and "Run now" (`emitReportEvent`): `report.scheduled`
 *   to the schedule's `channelIds` with the rendered Markdown as the message.
 *
 * Explicit channel ids (`notify`) bypass the event binding but the channel
 * must still exist and be enabled (and notifications globally enabled);
 * unknown or disabled ids are logged and skipped. Every outbox id is
 * deterministic (`caseOutboxId` / `slaOutboxId` / `reportOutboxId`, one per
 * channel), so a retried write, a second replica or a "Run now" of an already
 * delivered slot is a silent duplicate. Every failure is logged and
 * swallowed: a notification never breaks the primary write.
 */

export type CaseNotificationEvent = 'case.created' | 'case.assigned' | 'case.severity_raised' | 'case.closed';
export type SlaNotificationEvent = 'sla.breached' | 'sla.escalated';

export interface NotificationEmitterLogger {
  debug?(message: string): void;
  info?(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

/** What one emit did; never rejects. */
export interface EmitResult {
  event: NotificationEvent | null;
  /** Outbox ids written by this call. */
  enqueued: string[];
  /** Outbox ids that already existed (idempotent replay). */
  duplicates: string[];
  /** Channel ids skipped: explicit ids that are unknown or disabled, and `event` when nothing applied. */
  skipped: string[];
  /** Channels the event resolved to. */
  channels: number;
  /** First failure message, when any channel write (or the settings read) failed. */
  error: string | null;
}

export interface CaseEventChanges {
  from?: string | null;
  to?: string | null;
}

export interface EmitCaseEventOptions {
  /** Who did it; defaults to the case's `updated_by`. */
  actor?: string | null;
  changes?: CaseEventChanges | null;
  /** The activity event behind the emit; the idempotency key of `case.assigned`. */
  activityId?: string | null;
  /** Overrides the default idempotency key (created_at / closed_at / updated_at / activityId). */
  key?: string | null;
  /** Explicit channel ids (bypass the event binding); null / empty = the bound channels. */
  notify?: string[] | null;
  now?: Date;
}

export interface SlaEventRecord {
  id: string;
  /** The record's `_source` (alert or case), projected through the allowlist before it leaves the process. */
  source: any;
}

export interface EmitSlaEventInput {
  target: SlaEscalationTarget;
  record: SlaEventRecord;
  /** The escalation that fired (`sla.escalated`). */
  escalation?: Pick<SlaEscalation, 'id' | 'name'> | null;
  /** Explicit channel ids (the escalation's `notify`); empty / null = the bound channels. */
  notify?: string[] | null;
  /** The due date that passed (`sla.breached`); part of the idempotency key. */
  dueAt?: string | null;
  /** One-line summary of the actions applied. */
  message?: string | null;
  now?: Date;
}

export interface NotificationEmitter {
  emitCaseEvent(event: CaseNotificationEvent, caseDoc: CaseLike, options?: EmitCaseEventOptions): Promise<EmitResult>;
  emitSlaEvent(event: SlaNotificationEvent, input: EmitSlaEventInput): Promise<EmitResult>;
  /**
   * The batch form of `emitSlaEvent` (the breach pass: one scan page at a
   * time): the settings are read once and every (record, channel) entry of
   * the batch goes to the outbox in bulks of NOTIFICATION_ENQUEUE_BULK_SIZE
   * `create` ops. Same result shape, aggregated over the batch.
   */
  emitSlaEvents(event: SlaNotificationEvent, inputs: EmitSlaEventInput[]): Promise<EmitResult>;
  emitReportEvent(schedule: ReportSchedule, run: ReportRun, options?: { now?: Date }): Promise<EmitResult>;
  /** The function `activity.ts` calls after a successful case activity write. */
  activityHook: ActivityEmitter;
}

/** A case document with its id (`{ id, ...source }` as the routes return it). */
export type CaseLike = Partial<Case> & { id?: string | null } & Record<string, any>;

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested on their own)
// ---------------------------------------------------------------------------

export interface CaseEventMapping {
  event: CaseNotificationEvent;
  from: string | null;
  to: string | null;
}

/** Activity actions that mean "a case was created" (`cases.ts`, automation routing). */
export const CASE_CREATED_ACTIONS: ReadonlySet<string> = new Set(['case_created', 'case_auto_created_evidence']);

/**
 * Map one case activity event to the notification event it means, or null.
 * The real action names of `routes/cases.ts` / `automation_case_routing.ts`:
 * `case_created` and `case_auto_created_evidence` (creation),
 * `assignment_change` (PUT, bulk), `status_change` to `closed` and the
 * route-level `case_closed` (`to: 'complete'`) of the coordinated close.
 * `case_updated` carries the status in `from` / `to`, never the severity, so
 * a severity raise is emitted directly by its writer.
 */
export function caseEventForActivity(
  event: Pick<ActivityEventDoc, 'action' | 'from' | 'to'> & { target_type?: string; details?: Record<string, any> | null }
): CaseEventMapping | null {
  if (event.target_type !== undefined && event.target_type !== 'case') return null;
  const action = String(event.action || '');
  const from = event.from ?? null;
  const to = event.to ?? null;
  if (CASE_CREATED_ACTIONS.has(action)) return { event: 'case.created', from: null, to: null };
  if (action === 'assignment_change') {
    if (!to || to === from) return null;
    return { event: 'case.assigned', from, to };
  }
  if (action === 'status_change' && to === 'closed') return { event: 'case.closed', from, to };
  // A re-close of an already closed case (`details.already_closed`, POST
  // /close) re-audits the stored outcome but closed nothing: no notification.
  if (action === 'case_closed' && to === 'complete' && !event.details?.already_closed) return { event: 'case.closed', from: null, to: 'closed' };
  return null;
}

/** True when `to` is a higher case severity band than `from` (unknown values never count as a raise). */
export function severityRaised(from: unknown, to: unknown): boolean {
  const bands: readonly string[] = CASE_SEVERITIES;
  const before = bands.indexOf(String(from ?? ''));
  const after = bands.indexOf(String(to ?? ''));
  return before >= 0 && after >= 0 && after > before;
}

function keyPart(value: unknown, fallback: string = 'na'): string {
  const text = value === undefined || value === null ? '' : String(value).trim();
  return (text || fallback).slice(0, 128);
}

export function caseOutboxId(event: CaseNotificationEvent, caseId: string, key: string, channelId: string): string {
  return `case:${event}:${keyPart(caseId)}:${keyPart(key)}:${channelId}`;
}

export function slaOutboxId(event: SlaNotificationEvent, target: SlaEscalationTarget, recordId: string, slot: string, channelId: string): string {
  return `sla:${event}:${target}:${keyPart(recordId)}:${keyPart(slot)}:${channelId}`;
}

export function reportOutboxId(scheduleId: string, slot: string, channelId: string): string {
  return `report:${keyPart(scheduleId)}:${keyPart(slot)}:${channelId}`;
}

export interface ChannelResolution {
  /** False when notifications are globally disabled (nothing resolves). */
  enabled: boolean;
  channels: NotificationChannel[];
  /** Explicit ids no channel carries. */
  unknown: string[];
  /** Explicit ids of disabled channels. */
  disabled: string[];
}

/**
 * The channels one event goes to: the explicit `notify` ids when given
 * (each must exist and be enabled), else the channels bound to the event.
 */
export function resolveNotificationChannels(
  settings: NotificationSettings | null | undefined,
  event: NotificationEvent,
  notify?: readonly string[] | null
): ChannelResolution {
  const result: ChannelResolution = { enabled: settings?.enabled === true, channels: [], unknown: [], disabled: [] };
  if (!result.enabled) return result;
  const explicit = Array.from(new Set((notify || []).map((id) => String(id ?? '').trim()).filter(Boolean)));
  if (!explicit.length) {
    result.channels = channelsForEvent(settings, event);
    return result;
  }
  for (const id of explicit) {
    const channel = findChannel(settings, id);
    if (!channel) result.unknown.push(id);
    else if (!channel.enabled) result.disabled.push(id);
    else result.channels.push(channel);
  }
  return result;
}

/** Download link of a schedule's last run (absolute when a dashboard URL is configured). */
export function reportRunLink(scheduleId: string, dashboardUrl: string | null = getNotificationDashboardUrl()): string {
  return `${dashboardUrl ? dashboardUrl.replace(/\/+$/, '') : ''}${API_ROOT}/reports/schedules/${encodeURIComponent(scheduleId)}/last-run.md`;
}

/** One-line summary of an escalation's applied actions for the payload `message`. */
export function describeEscalationActions(actions: { assignTo?: string | null; raiseSeverity?: { from: string; to: string } | null; comment?: boolean } | null | undefined): string | null {
  if (!actions) return null;
  const parts: string[] = [];
  if (actions.assignTo) parts.push(`assigned to ${actions.assignTo}`);
  if (actions.raiseSeverity) parts.push(`severity raised ${actions.raiseSeverity.from} -> ${actions.raiseSeverity.to}`);
  if (actions.comment) parts.push('comment added');
  return parts.length ? parts.join('; ') : null;
}

function errorMessage(e: any): string {
  return e?.message || String(e);
}

function defaultCaseKey(event: CaseNotificationEvent, doc: CaseLike, options: EmitCaseEventOptions): string {
  switch (event) {
    case 'case.created':
      return keyPart(doc.created_at, keyPart(options.activityId));
    case 'case.closed':
      return keyPart(doc.closed_at, keyPart(options.activityId, keyPart(doc.updated_at)));
    case 'case.assigned':
      return keyPart(options.activityId, keyPart(doc.updated_at));
    case 'case.severity_raised':
    default:
      return keyPart(doc.updated_at, keyPart(options.activityId));
  }
}

// ---------------------------------------------------------------------------
// The emitter
// ---------------------------------------------------------------------------

interface EmitInput {
  targetType: NotificationTargetType;
  targetId: string;
  payload: NotificationPayload;
  notify?: readonly string[] | null;
  idFor: (channel: NotificationChannel) => string;
  now?: Date;
}

export function createNotificationEmitter(getClient: () => any, logger: NotificationEmitterLogger): NotificationEmitter {
  const emit = async (event: NotificationEvent, input: EmitInput): Promise<EmitResult> => {
    const result: EmitResult = { event, enqueued: [], duplicates: [], skipped: [], channels: 0, error: null };
    try {
      const client = getClient();
      const settings = await getNotificationChannels(client, logger);
      const resolved = resolveNotificationChannels(settings, event, input.notify);
      if (resolved.unknown.length || resolved.disabled.length) {
        result.skipped.push(...resolved.unknown, ...resolved.disabled);
        logger.warn(
          `wazuh-alert-manager notifications: ${event} for ${input.targetType} ${input.targetId}: ` +
            `${resolved.unknown.length ? `unknown channel id(s) ${resolved.unknown.join(', ')}` : ''}` +
            `${resolved.unknown.length && resolved.disabled.length ? '; ' : ''}` +
            `${resolved.disabled.length ? `disabled channel id(s) ${resolved.disabled.join(', ')}` : ''} skipped`
        );
      }
      result.channels = resolved.channels.length;
      if (!resolved.channels.length) return result;
      const subject = renderSubject(event, input.payload);
      for (const channel of resolved.channels) {
        try {
          const written = await enqueueNotification(client, {
            id: input.idFor(channel),
            event,
            channelId: channel.id,
            channelKind: channel.kind,
            targetType: input.targetType,
            targetId: input.targetId,
            subject,
            payload: input.payload as Record<string, any>,
            now: input.now,
          });
          (written.created ? result.enqueued : result.duplicates).push(written.id);
        } catch (e: any) {
          if (!result.error) result.error = errorMessage(e);
          logger.error(`wazuh-alert-manager notifications: could not enqueue ${event} for ${input.targetType} ${input.targetId} to channel ${channel.id}: ${errorMessage(e)}`);
        }
      }
    } catch (e: any) {
      result.error = errorMessage(e);
      logger.error(`wazuh-alert-manager notifications: ${event} for ${input.targetType} ${input.targetId} not enqueued: ${errorMessage(e)}`);
    }
    return result;
  };

  const emitCaseEvent: NotificationEmitter['emitCaseEvent'] = async (event, caseDoc, options = {}) => {
    const skipped: EmitResult = { event, enqueued: [], duplicates: [], skipped: [event], channels: 0, error: null };
    try {
      const doc: CaseLike = caseDoc && typeof caseDoc === 'object' ? caseDoc : {};
      const caseId = keyPart(doc.id ?? doc.case_uid, '');
      if (!caseId) {
        logger.warn(`wazuh-alert-manager notifications: ${event} without a case id skipped`);
        return skipped;
      }
      const changes = options.changes || {};
      if (event === 'case.severity_raised' && !severityRaised(changes.from, changes.to)) return skipped;
      const extra: NotificationEventExtra = { actor: options.actor ?? doc.updated_by ?? null };
      if (changes.from !== undefined) extra.from = changes.from ?? null;
      if (changes.to !== undefined) extra.to = changes.to ?? null;
      const payload = projectCaseEvent(event, { ...doc, id: caseId }, extra, { now: options.now });
      const key = options.key || defaultCaseKey(event, doc, options);
      return await emit(event, {
        targetType: 'case',
        targetId: caseId,
        payload,
        notify: options.notify,
        idFor: (channel) => caseOutboxId(event, caseId, key, channel.id),
        now: options.now,
      });
    } catch (e: any) {
      logger.error(`wazuh-alert-manager notifications: ${event} not enqueued: ${errorMessage(e)}`);
      return { ...skipped, error: errorMessage(e) };
    }
  };

  /** The emit input of one SLA event, or null (logged) when the record has no id. */
  const slaEmitInput = (event: SlaNotificationEvent, input: EmitSlaEventInput): EmitInput | null => {
    const recordId = keyPart(input.record?.id, '');
    if (!recordId) {
      logger.warn(`wazuh-alert-manager notifications: ${event} without a record id skipped`);
      return null;
    }
    const source = input.record.source && typeof input.record.source === 'object' ? input.record.source : {};
    const extra: NotificationEventExtra = { actor: 'system:sla' };
    if (input.escalation) extra.escalation = { id: input.escalation.id, name: input.escalation.name };
    if (input.message) extra.message = input.message;
    if (input.target === 'alert') extra.alert = projectAlertForNotification(source, { id: recordId });
    const caseDoc = input.target === 'case' ? { ...source, id: recordId } : null;
    const payload = projectCaseEvent(event, caseDoc, extra, { now: input.now });
    const slot = event === 'sla.escalated' ? keyPart(input.escalation?.id, 'escalation') : keyPart(input.dueAt, 'due');
    return {
      targetType: input.target,
      targetId: recordId,
      payload,
      notify: event === 'sla.escalated' ? input.notify : null,
      idFor: (channel) => slaOutboxId(event, input.target, recordId, slot, channel.id),
      now: input.now,
    };
  };

  const emitSlaEvent: NotificationEmitter['emitSlaEvent'] = async (event, input) => {
    const failed = (error: string | null): EmitResult => ({ event, enqueued: [], duplicates: [], skipped: [event], channels: 0, error });
    try {
      const prepared = slaEmitInput(event, input);
      if (!prepared) return failed(null);
      return await emit(event, prepared);
    } catch (e: any) {
      logger.error(`wazuh-alert-manager notifications: ${event} not enqueued: ${errorMessage(e)}`);
      return failed(errorMessage(e));
    }
  };

  const emitSlaEvents: NotificationEmitter['emitSlaEvents'] = async (event, inputs) => {
    const result: EmitResult = { event, enqueued: [], duplicates: [], skipped: [], channels: 0, error: null };
    if (!Array.isArray(inputs) || !inputs.length) return result;
    try {
      const client = getClient();
      const settings = await getNotificationChannels(client, logger);
      const pending: EnqueueInput[] = [];
      for (const input of inputs) {
        const prepared = slaEmitInput(event, input);
        if (!prepared) {
          result.skipped.push(event);
          continue;
        }
        const resolved = resolveNotificationChannels(settings, event, prepared.notify);
        if (resolved.unknown.length || resolved.disabled.length) {
          result.skipped.push(...resolved.unknown, ...resolved.disabled);
          logger.warn(
            `wazuh-alert-manager notifications: ${event} for ${prepared.targetType} ${prepared.targetId}: ` +
              `${[...resolved.unknown, ...resolved.disabled].join(', ')} unknown or disabled channel id(s) skipped`
          );
        }
        result.channels += resolved.channels.length;
        const subject = resolved.channels.length ? renderSubject(event, prepared.payload) : '';
        for (const channel of resolved.channels) {
          pending.push({
            id: prepared.idFor(channel),
            event,
            channelId: channel.id,
            channelKind: channel.kind,
            targetType: prepared.targetType,
            targetId: prepared.targetId,
            subject,
            payload: prepared.payload as Record<string, any>,
            now: prepared.now,
          });
        }
      }
      for (let offset = 0; offset < pending.length; offset += NOTIFICATION_ENQUEUE_BULK_SIZE) {
        const chunk = pending.slice(offset, offset + NOTIFICATION_ENQUEUE_BULK_SIZE);
        try {
          const written = await enqueueMany(client, chunk);
          result.enqueued.push(...written.enqueued);
          result.duplicates.push(...written.duplicates);
          if (written.failures.length) {
            if (!result.error) result.error = written.failures[0].error;
            logger.error(
              `wazuh-alert-manager notifications: ${written.failures.length} ${event} entr${written.failures.length === 1 ? 'y' : 'ies'} not enqueued, first: ${written.failures[0].id}: ${written.failures[0].error}`
            );
          }
        } catch (e: any) {
          if (!result.error) result.error = errorMessage(e);
          logger.error(`wazuh-alert-manager notifications: could not enqueue ${chunk.length} ${event} entr${chunk.length === 1 ? 'y' : 'ies'}: ${errorMessage(e)}`);
        }
      }
    } catch (e: any) {
      result.error = errorMessage(e);
      logger.error(`wazuh-alert-manager notifications: ${event} batch not enqueued: ${errorMessage(e)}`);
    }
    return result;
  };

  const emitReportEvent: NotificationEmitter['emitReportEvent'] = async (schedule, run, options = {}) => {
    const event: NotificationEvent = 'report.scheduled';
    const none: EmitResult = { event, enqueued: [], duplicates: [], skipped: [], channels: 0, error: null };
    try {
      const channelIds = Array.isArray(schedule?.channelIds) ? schedule.channelIds : [];
      if (!channelIds.length) return none;
      const scheduleId = keyPart(schedule.id, '');
      const slot = keyPart(run?.slot, '');
      if (!scheduleId || !slot) {
        logger.warn(`wazuh-alert-manager notifications: report.scheduled for schedule "${schedule?.id ?? ''}" without a slot skipped`);
        return { ...none, skipped: [event] };
      }
      const payload = projectCaseEvent(
        event,
        null,
        {
          actor: run.triggered_by ?? null,
          report: { id: scheduleId, name: schedule.name, link: reportRunLink(scheduleId), slot: run.slot, markdown: run.markdown ?? '' },
        },
        { now: options.now }
      );
      return await emit(event, {
        targetType: 'report',
        targetId: scheduleId,
        payload,
        notify: channelIds,
        idFor: (channel) => reportOutboxId(scheduleId, slot, channel.id),
        now: options.now,
      });
    } catch (e: any) {
      logger.error(`wazuh-alert-manager notifications: report.scheduled not enqueued: ${errorMessage(e)}`);
      return { ...none, skipped: [event], error: errorMessage(e) };
    }
  };

  const activityHook: ActivityEmitter = async (event) => {
    try {
      const mapped = caseEventForActivity(event);
      if (!mapped) return;
      const caseId = String(event.case_id || event.target_id || '');
      if (!caseId) return;
      let doc: CaseLike;
      try {
        const resolved = await resolveCase(getClient(), caseId);
        doc = { ...(resolved.source || {}), id: caseId };
      } catch (e: any) {
        logger.warn(`wazuh-alert-manager notifications: ${mapped.event} for case ${caseId} skipped, the case could not be read: ${errorMessage(e)}`);
        return;
      }
      if (mapped.event === 'case.closed' && doc.status !== 'closed') return;
      const at = typeof event.timestamp === 'string' ? new Date(event.timestamp) : new Date();
      await emitCaseEvent(mapped.event, doc, {
        actor: event.user,
        changes: { from: mapped.from, to: mapped.to },
        activityId: event.event_uid,
        now: Number.isNaN(at.getTime()) ? undefined : at,
      });
    } catch (e: any) {
      logger.error(`wazuh-alert-manager notifications: activity hook failed: ${errorMessage(e)}`);
    }
  };

  return { emitCaseEvent, emitSlaEvent, emitSlaEvents, emitReportEvent, activityHook };
}

// ---------------------------------------------------------------------------
// Process-wide registration (the routes have no handle on the plugin instance)
// ---------------------------------------------------------------------------

let registered: NotificationEmitter | null = null;

/** Register the emitter the routes use (`cases.ts` severity raise, `reports.ts` run-now); null unregisters. */
export function registerNotificationEmitter(emitter: NotificationEmitter | null): void {
  registered = emitter;
}

export function getNotificationEmitter(): NotificationEmitter | null {
  return registered;
}
