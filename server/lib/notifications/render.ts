import { NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES, PLUGIN_NAME } from '../../../common/constants';
import type { Case, NotificationEvent } from '../../../common/types';
import { severityDisplay } from '../../../common/severity';
import type { AlertManagerConfigType } from '../../config';

/**
 * Notification payloads and text rendering (step 1.1; consumed by the
 * dispatcher of 1.2 and the emitters of 1.3).
 *
 * Every payload is an explicit allowlisted projection: `projectAlertForNotification`
 * and `projectCaseEvent` copy named fields only, never a raw `_source`, so a
 * receiver (a Notifications webhook, Slack, a direct webhook) only ever sees
 * identifiers, titles, status/severity, assignee, timestamps, the rule and
 * agent identity, disposition and SLA due dates.
 */

/** Projected alert for a notification payload; every key is optional-null, never a raw document. */
export interface NotificationAlert {
  id: string | null;
  title: string | null;
  status: string | null;
  severity: { band: string | null; level: number | null; label: string | null };
  assigned_to: string | null;
  timestamp: string | null;
  updated_at: string | null;
  rule: { id: string | null; description: string | null };
  agent: { id: string | null; name: string | null };
  disposition: string | null;
  sla_due_at: string | null;
  case_id: string | null;
  link: string | null;
}

export interface NotificationCase {
  id: string | null;
  case_uid: string | null;
  title: string | null;
  severity: string | null;
  status: string | null;
  assigned_to: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  closed_at: string | null;
  disposition: string | null;
  sla_due_at: string | null;
  alert_count: number | null;
  link: string | null;
}

/** Event-specific detail the emitter adds; every field is a named scalar or a projected alert. */
export interface NotificationRuleActions {
  status?: string | null;
  assignee?: string | null;
  caseId?: string | null;
}

export interface NotificationEventExtra {
  /** Who did it (`system:sla`, a rule id, a user name). */
  actor?: string | null;
  /** Previous / new value for assignment, severity and status changes. */
  from?: string | null;
  to?: string | null;
  /** SLA escalation that fired. */
  escalation?: { id: string; name: string } | null;
  /** Automation rule that fired (`rule.action`). */
  rule?: { id: string; name: string } | null;
  /**
   * What the rule did to the alert (`rule.action`, step 1.4): the status it
   * set, the analyst it assigned and the case it created or extended. Only the
   * actions that were applied are present.
   */
  actions?: NotificationRuleActions | null;
  /**
   * Scheduled report (`report.scheduled`): `slot` is the UTC slot the run
   * covers and `markdown` the rendered body, cut on a UTF-8 boundary at
   * NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES (step 1.3).
   */
  report?: { id: string; name: string; link?: string | null; slot?: string | null; markdown?: string | null } | null;
  /** The alert the event is about (SLA / rule events). */
  alert?: NotificationAlert | null;
  /** Free-form single-line note (bounded). */
  message?: string | null;
}

export interface NotificationPayload extends NotificationEventExtra {
  event: NotificationEvent | 'test';
  occurred_at: string;
  source: string;
  case: NotificationCase | null;
}

const MAX_TEXT = 512;

function str(value: unknown, max: number = MAX_TEXT): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value);
  return text.length > max ? text.slice(0, max) : text;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

let runtime: { dashboardUrl: string | null } = { dashboardUrl: null };

/**
 * Record `wazuh_alert_manager.notifications.dashboardUrl` (the public base
 * URL of the dashboard, e.g. `https://soc.example.com`) so deep links in
 * notifications are absolute. Called from plugin start; null resets it.
 */
export function setNotificationRuntime(config: Pick<AlertManagerConfigType, 'notifications'> | null | undefined): void {
  const raw = config?.notifications?.dashboardUrl;
  runtime = { dashboardUrl: typeof raw === 'string' && raw.trim() ? raw.trim().replace(/\/+$/, '') : null };
}

export function getNotificationDashboardUrl(): string | null {
  return runtime.dashboardUrl;
}

/** App-relative path of the workbench (`/app/wazuh-alert-manager`). */
export const WORKBENCH_APP_PATH = `/app/${PLUGIN_NAME}`;

/** Deep link to a case or alert: absolute when a dashboard URL is configured, else app-relative. */
export function notificationLink(target: { caseId?: string | null; alertId?: string | null }, dashboardUrl: string | null = getNotificationDashboardUrl()): string {
  const base = dashboardUrl ? `${dashboardUrl.replace(/\/+$/, '')}${WORKBENCH_APP_PATH}` : WORKBENCH_APP_PATH;
  if (target.caseId) return `${base}?tab=cases&case=${encodeURIComponent(target.caseId)}`;
  if (target.alertId) return `${base}?tab=alerts&alert=${encodeURIComponent(target.alertId)}`;
  return base;
}

/** Allowlisted projection of an alert record (`_source` of the status index) for a payload. */
export function projectAlertForNotification(alertSource: any, options: { id?: string | null; dashboardUrl?: string | null } = {}): NotificationAlert {
  const source = alertSource && typeof alertSource === 'object' ? alertSource : {};
  const severity = severityDisplay(source);
  const id = str(options.id ?? source._id ?? source.alert_id ?? null, 512);
  return {
    id,
    title: str(source.rule?.description),
    status: str(source.status, 32),
    severity: { band: severity.band, level: severity.level, label: str(severity.label, 32) },
    assigned_to: str(source.assigned_to, 256),
    timestamp: str(source['@timestamp'], 64),
    updated_at: str(source.updated_at, 64),
    rule: { id: str(source.rule?.id, 64), description: str(source.rule?.description) },
    agent: { id: str(source.agent?.id, 64), name: str(source.agent?.name, 256) },
    disposition: str(source.disposition, 32),
    sla_due_at: str(source.reporting?.sla_due_at, 64),
    case_id: str(source.case_id, 256),
    link: id ? notificationLink({ alertId: id }, options.dashboardUrl === undefined ? getNotificationDashboardUrl() : options.dashboardUrl) : null,
  };
}

/** Allowlisted projection of a case document. */
export function projectCase(caseDoc: Partial<Case> | Record<string, any> | null | undefined, dashboardUrl: string | null = getNotificationDashboardUrl()): NotificationCase | null {
  if (!caseDoc || typeof caseDoc !== 'object') return null;
  const doc: any = caseDoc;
  const id = str(doc.id, 256);
  const evidenceCount = num(doc.evidence_count);
  return {
    id,
    case_uid: str(doc.case_uid, 256),
    title: str(doc.title),
    severity: str(doc.severity, 32),
    status: str(doc.status, 32),
    assigned_to: str(doc.assigned_to, 256),
    created_by: str(doc.created_by, 256),
    created_at: str(doc.created_at, 64),
    updated_at: str(doc.updated_at, 64),
    closed_at: str(doc.closed_at, 64),
    disposition: str(doc.disposition, 32),
    sla_due_at: str(doc.sla_due_at, 64),
    alert_count: evidenceCount ?? (Array.isArray(doc.alert_ids) ? doc.alert_ids.length : null),
    link: id ? notificationLink({ caseId: id }, dashboardUrl) : null,
  };
}

function projectExtra(extra: NotificationEventExtra | null | undefined): NotificationEventExtra {
  const input = extra && typeof extra === 'object' ? extra : {};
  const out: NotificationEventExtra = {};
  if (input.actor !== undefined) out.actor = str(input.actor, 256);
  if (input.from !== undefined) out.from = str(input.from, 256);
  if (input.to !== undefined) out.to = str(input.to, 256);
  if (input.message !== undefined) out.message = str(input.message, 2000);
  if (input.escalation) out.escalation = { id: str(input.escalation.id, 64) || '', name: str(input.escalation.name, 120) || '' };
  if (input.rule) out.rule = { id: str(input.rule.id, 128) || '', name: str(input.rule.name, 256) || '' };
  if (input.actions && typeof input.actions === 'object') {
    const actions: NotificationRuleActions = {};
    if (input.actions.status != null) actions.status = str(input.actions.status, 32);
    if (input.actions.assignee != null) actions.assignee = str(input.actions.assignee, 256);
    if (input.actions.caseId != null) actions.caseId = str(input.actions.caseId, 256);
    out.actions = actions;
  }
  if (input.report) {
    out.report = {
      id: str(input.report.id, 64) || '',
      name: str(input.report.name, 120) || '',
      link: str(input.report.link, 2048),
      ...(input.report.slot !== undefined ? { slot: str(input.report.slot, 64) } : {}),
      ...(typeof input.report.markdown === 'string'
        ? { markdown: truncateUtf8(input.report.markdown, NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES) }
        : {}),
    };
  }
  if (input.alert) out.alert = projectAlertForNotification(alertFromProjected(input.alert), { id: input.alert.id });
  return out;
}

export const NOTIFICATION_TRUNCATION_NOTE = '\n\n_Truncated for delivery._\n';

/** Cut `text` at `maxBytes` of UTF-8 on a character boundary, appending NOTIFICATION_TRUNCATION_NOTE when it was cut. */
export function truncateUtf8(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const budget = Math.max(0, maxBytes - Buffer.byteLength(NOTIFICATION_TRUNCATION_NOTE, 'utf8'));
  const cut = Buffer.from(text, 'utf8').subarray(0, budget).toString('utf8').replace(/�+$/, '');
  return `${cut}${NOTIFICATION_TRUNCATION_NOTE}`;
}

/** Re-shape an already projected alert so the allowlist runs once more (idempotent). */
function alertFromProjected(alert: NotificationAlert): any {
  return {
    rule: { id: alert.rule?.id, description: alert.title ?? alert.rule?.description, level: alert.severity?.level },
    severity_label: alert.severity?.label,
    status: alert.status,
    assigned_to: alert.assigned_to,
    '@timestamp': alert.timestamp,
    updated_at: alert.updated_at,
    agent: alert.agent,
    disposition: alert.disposition,
    reporting: { sla_due_at: alert.sla_due_at },
    case_id: alert.case_id,
  };
}

/**
 * Build the payload of a case-related event (also used for SLA / rule events
 * that carry no case: pass `null`). The result holds only allowlisted keys.
 */
export function projectCaseEvent(
  event: NotificationEvent | 'test',
  caseDoc: Partial<Case> | Record<string, any> | null | undefined,
  extra: NotificationEventExtra | null = null,
  options: { now?: Date; dashboardUrl?: string | null } = {}
): NotificationPayload {
  const dashboardUrl = options.dashboardUrl === undefined ? getNotificationDashboardUrl() : options.dashboardUrl;
  return {
    event,
    occurred_at: (options.now || new Date()).toISOString(),
    source: PLUGIN_NAME,
    case: projectCase(caseDoc, dashboardUrl),
    ...projectExtra(extra),
  };
}

const EVENT_TITLES: Record<NotificationEvent | 'test', string> = {
  'case.created': 'Case created',
  'case.assigned': 'Case assigned',
  'case.severity_raised': 'Case severity raised',
  'case.closed': 'Case closed',
  'sla.breached': 'SLA breached',
  'sla.escalated': 'SLA escalated',
  'rule.action': 'Automation rule fired',
  'report.scheduled': 'Scheduled report',
  test: 'Test notification',
};

export function eventTitle(event: NotificationEvent | 'test'): string {
  return EVENT_TITLES[event] || String(event);
}

function subjectTarget(payload: NotificationPayload): string | null {
  if (payload.case?.title) return payload.case.title;
  if (payload.alert?.title) return payload.alert.title;
  if (payload.report?.name) return payload.report.name;
  if (payload.rule?.name) return payload.rule.name;
  return null;
}

/** One-line subject (email subject / Slack first line), <= 200 characters. */
export function renderSubject(event: NotificationEvent | 'test', payload: NotificationPayload): string {
  const target = subjectTarget(payload);
  const subject = `[Wazuh Alert Manager] ${eventTitle(event)}${target ? `: ${target}` : ''}`;
  return subject.length > 200 ? `${subject.slice(0, 197)}...` : subject;
}

function line(label: string, value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  return `${label}: ${String(value)}`;
}

/** Plain-text body with a deep link; no HTML, no raw document fields. */
export function renderText(event: NotificationEvent | 'test', payload: NotificationPayload, dashboardUrl: string | null = getNotificationDashboardUrl()): string {
  const lines: Array<string | null> = [renderSubject(event, payload), ''];
  const c = payload.case;
  if (c) {
    lines.push(line('Case', c.case_uid ? `${c.case_uid} ${c.title || ''}`.trim() : c.title));
    lines.push(line('Severity', c.severity));
    lines.push(line('Status', c.status));
    lines.push(line('Assigned to', c.assigned_to));
    lines.push(line('Alerts', c.alert_count));
    lines.push(line('Disposition', c.disposition));
    lines.push(line('SLA due', c.sla_due_at));
  }
  const a = payload.alert;
  if (a) {
    lines.push(line('Alert', a.title || a.id));
    lines.push(line('Rule', a.rule?.id ? `${a.rule.id}${a.rule.description && a.rule.description !== a.title ? ` ${a.rule.description}` : ''}` : null));
    lines.push(line('Severity', a.severity?.label || (a.severity?.band ? `${a.severity.band}${a.severity.level !== null ? ` (level ${a.severity.level})` : ''}` : null)));
    lines.push(line('Agent', a.agent?.name ? `${a.agent.name}${a.agent.id ? ` (${a.agent.id})` : ''}` : a.agent?.id));
    lines.push(line('Status', a.status));
    lines.push(line('Assigned to', a.assigned_to));
    lines.push(line('SLA due', a.sla_due_at));
  }
  if (payload.from !== undefined || payload.to !== undefined) lines.push(line('Change', `${payload.from ?? '-'} -> ${payload.to ?? '-'}`));
  lines.push(line('Escalation', payload.escalation?.name));
  lines.push(line('Rule', payload.rule ? `${payload.rule.name} (${payload.rule.id})` : null));
  if (payload.actions) {
    const applied = [
      payload.actions.status ? `status set to ${payload.actions.status}` : null,
      payload.actions.assignee ? `assigned to ${payload.actions.assignee}` : null,
      payload.actions.caseId ? `case ${payload.actions.caseId} ${notificationLink({ caseId: payload.actions.caseId }, dashboardUrl)}` : null,
    ].filter(Boolean);
    lines.push(line('Actions', applied.length ? applied.join('; ') : 'notification only'));
  }
  lines.push(line('Report', payload.report ? `${payload.report.name}${payload.report.link ? ` ${payload.report.link}` : ''}` : null));
  lines.push(line('By', payload.actor));
  lines.push(line('Note', payload.message));
  lines.push(line('At', payload.occurred_at));
  const link = c?.id ? notificationLink({ caseId: c.id }, dashboardUrl) : a?.id ? notificationLink({ alertId: a.id }, dashboardUrl) : null;
  if (link) {
    lines.push('');
    lines.push(`Open: ${link}`);
  }
  // A scheduled report carries its (already bounded) Markdown body after the header lines.
  if (payload.report?.markdown) {
    lines.push('');
    lines.push(payload.report.markdown);
  }
  return lines.filter((entry): entry is string => entry !== null).join('\n');
}

/**
 * Make a string safe to embed in a Mustache template (`subject_template` /
 * `message_template` of the inline monitor): Mustache only interprets `{{`,
 * so a body without it is returned unchanged; otherwise the delimiters are
 * switched to `<% %>` for the whole template and every literal `<%` inside is
 * split with an empty comment so it renders back verbatim.
 */
export function mustacheEscape(value: string): string {
  const text = String(value ?? '');
  if (!text.includes('{{')) return text;
  return `{{=<% %>=}}${text.replace(/<%/g, '<<%! %>%')}`;
}
