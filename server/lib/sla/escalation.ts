import { Logger } from '../../../../../src/core/server';
import {
  ACTIVITY_WRITE_ALIAS,
  ALERTS_READ_ALIAS,
  CASES_READ_ALIAS,
  META_INDEX,
  SLA_BANDS,
  SLA_BREACH_MAX_PER_TICK,
  SLA_BREACH_NOTIFY_GRACE_MINUTES,
  SLA_BREACHED_ACTION,
  SLA_ESCALATED_ACTION,
  SLA_ESCALATION_ACTOR,
  SLA_ESCALATION_LEASE_ID,
  SLA_ESCALATION_MAX_ACTIONS_PER_TICK,
  SLA_ESCALATION_STATUS_DOC_ID,
  SLA_ESCALATION_STATUS_MAX_ERRORS,
  SLA_SCAN_PAGE_SIZE,
} from '../../../common/constants';
import type {
  SlaBand,
  SlaEscalation,
  SlaEscalationStatus,
  SlaEscalationStatusError,
  SlaEscalationTarget,
  SlaPolicy,
} from '../../../common/types';
import { bandLevelRange, labelsOfBand, severityBandOf } from '../../../common/severity';
import type { AlertManagerConfigType } from '../../config';
import { ActivityInput, buildActivityEvent } from '../activity';
import { buildHistoryEntry } from '../history';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from '../index_namespace';
import { acquireOrRenewLease, holderId, releaseLease } from '../lease';
import { buildReportingUpdate, computeCaseDueAt, REPORTING_MERGE_SCRIPT, slaTargetOf } from '../reporting_fields';
import { describeEscalationActions, NotificationEmitter } from '../notifications/emitters';
import { getSlaPolicy, slaBandOf } from './policy';
import { sanitizeBackfillError } from './due_backfill';

/**
 * The part of the notification emitter (step 1.3) the scanner uses: an
 * `sla.breached` per newly stamped record, an `sla.escalated` (to the
 * escalation's `notify` ids when present, else the bound channels) per
 * marked record, plus `case.assigned` / `case.severity_raised` for the case
 * actions the escalation applied itself (its activity writes bypass the
 * `activity.ts` hook). Optional: the tests run without one.
 */
export type SlaNotificationEmitter = Pick<NotificationEmitter, 'emitSlaEvent' | 'emitSlaEvents' | 'emitCaseEvent'>;

/**
 * SLA escalation scanner (step 3.3).
 *
 * One replica (the `sla_escalation` lease holder) ticks every
 * `sla.escalation.tickSeconds`. A tick loads the policy and runs
 *
 *   (a) the BREACH pass: every open/in_progress alert whose
 *       `reporting.sla_due_at` has passed, and every non-closed case whose
 *       `sla_due_at` has passed (or, for a case written before step 3.2 that
 *       has no `sla_due_at`, whose `created_at` plus the band's resolve
 *       target has passed), gets exactly one `sla_breached` activity event
 *       (`create` under the id `sla-breach:<id>`, 409 = already written) and
 *       THEN `sla.breached_at = now` (scripted, only when absent) plus a
 *       `sla_breached` history entry; and
 *   (b) the ESCALATION pass: for every enabled `escalations[]` entry, the
 *       candidates are the not-closed alerts (target `alert`) or cases
 *       (target `case`) that have used `thresholdPercent` of their band's
 *       resolve target and match `condition`, minus the records whose
 *       `sla.escalated[]` already holds the escalation id. The actions are
 *       applied in the order assignTo, raiseSeverity, comment, notify through
 *       the same history / reporting write shape the routes use, then the one
 *       `sla_escalated` activity event is written and the marker is pushed.
 *
 * Query form of the threshold (documented choice): the elapsed fraction of
 * the resolve target is evaluated per band from the CURRENT policy instead
 * of from each record's stored `sla_due_at`: a record of band B is a
 * candidate when its base timestamp (`@timestamp` for alerts, `created_at`
 * for cases) is at or before `now - resolveMinutes(B) * thresholdPercent /
 * 100`. This keeps the scan one filter query per escalation (no script
 * query), and a policy change takes effect immediately even before the
 * due-date backfill has rewritten `sla_due_at`.
 *
 * Conditions: `any` adds no filter; `unassigned` = `assigned_to` missing,
 * null or empty; `untouched` = `unassigned` AND status still `open` AND (for
 * alerts) no `reporting.first_assigned_at` AND no history entry other than
 * `case_created` or one written by `system:sla` itself (a breach stamp or
 * an earlier escalation never counts as an analyst touching the record).
 *
 * Idempotency and ordering: in both passes the activity event (the thing
 * step 3.4 counts and phase 1 delivers from) is written BEFORE the marker
 * that excludes the record from the next scan, so a crash between the two
 * leaves an event without a marker and the next tick finishes the record
 * (create 409 + marker), never a marker without an event. Every action
 * script re-checks its own effect at write time (closed, already marked,
 * the rule's `unassigned` / `untouched` condition, the assignee or severity
 * already equal) and is a noop otherwise, so a stale search hit (another
 * rule or lease holder wrote the record after the search; candidates are
 * searched without a refresh) never appends duplicate history rows; the
 * record is re-evaluated against fresh state on the next tick. Comments are
 * created under a deterministic activity id. Known limitation: for an
 * `unassigned` / `untouched` rule whose `assignTo` landed right before a
 * crash, the record no longer matches, so its marker, comment and
 * `sla_escalated` event are not written (the assignment itself, with its
 * history rows and activity, is complete).
 *
 * Errors: the tick result and the server log carry the full messages (one
 * aggregated line per pass, first message quoted); the status doc that
 * `GET /sla/escalation/status` answers to any signed-in user only gets a
 * sanitised form (error type + HTTP status, no raw OpenSearch text or index
 * names), capped at SLA_ESCALATION_STATUS_MAX_ERRORS entries per pass.
 */

export const SLA_ESCALATION_SOURCE = 'sla';
/** The lease is renewed between passes and after this many applied escalation records. */
export const SLA_ESCALATION_LEASE_RENEW_EVERY = 50;

const ACTIVE_ALERT_STATUSES = ['open', 'in_progress'];
const MANAGED_PREFIX: Record<SlaEscalationTarget, string> = {
  alert: 'wazuh-alert-status-v2-',
  case: 'wazuh-alert-manager-v2-cases-',
};
const READ_ALIAS: Record<SlaEscalationTarget, string> = { alert: ALERTS_READ_ALIAS, case: CASES_READ_ALIAS };
const BASE_FIELD: Record<SlaEscalationTarget, string> = { alert: '@timestamp', case: 'created_at' };
const DUE_FIELD: Record<SlaEscalationTarget, string> = { alert: 'reporting.sla_due_at', case: 'sla_due_at' };
const UID_FIELD: Record<SlaEscalationTarget, string> = { alert: 'alert_uid', case: 'case_uid' };
const BAND_ORDER: SlaBand[] = ['low', 'medium', 'high', 'critical'];
const MAX_ERROR_LENGTH = 500;

// ---------------------------------------------------------------------------
// Runtime (what the status route reports for this replica)
// ---------------------------------------------------------------------------

interface Runtime {
  /** null = the scanner was never started on this replica (plugin not initialised). */
  enabled: boolean | null;
  tickSeconds: number;
}

let runtime: Runtime = { enabled: null, tickSeconds: 60 };

/**
 * Record the effective config so `GET /sla/escalation/status` can report it
 * (routes have no config access). `null` marks the scanner as not started on
 * this replica (the initial state, and the state after the plugin stopped).
 */
export function setSlaEscalationRuntime(config: Pick<AlertManagerConfigType, 'sla'> | null | undefined): void {
  if (config === null) {
    runtime = { enabled: null, tickSeconds: 60 };
    return;
  }
  runtime = {
    enabled: config?.sla?.escalation?.enabled !== false,
    tickSeconds: config?.sla?.escalation?.tickSeconds ?? 60,
  };
}

export function getSlaEscalationRuntime(): Runtime {
  return { ...runtime };
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

function statusClause(target: SlaEscalationTarget): any {
  // Alerts have exactly the three statuses; cases are "open" when not closed.
  return target === 'alert'
    ? { terms: { status: ACTIVE_ALERT_STATUSES } }
    : { bool: { must_not: [{ term: { status: 'closed' } }] } };
}

/** `assigned_to` missing, null or the empty string. */
export const UNASSIGNED_CLAUSE = {
  bool: {
    should: [{ bool: { must_not: [{ exists: { field: 'assigned_to' } }] } }, { term: { assigned_to: '' } }],
    minimum_should_match: 1,
  },
};

/** Any history entry other than `case_created` or one written by the scanner itself. */
export const TOUCHED_HISTORY_CLAUSE = {
  nested: {
    path: 'history',
    query: {
      bool: {
        must_not: [{ term: { 'history.action': 'case_created' } }, { term: { 'history.user': SLA_ESCALATION_ACTOR } }],
      },
    },
  },
};

/**
 * The breach pass query: due date in the past, not closed, no breach marker
 * yet. Cases created before step 3.2 carry no `sla_due_at` (the due backfill
 * covers alerts only), so with a policy the case query also accepts a record
 * without `sla_due_at` whose `created_at` plus its band's resolve target has
 * passed: the same instant 3.2 would have stored.
 */
export function breachQuery(target: SlaEscalationTarget, now: string, policy?: SlaPolicy | null): any {
  const due: any = { range: { [DUE_FIELD[target]]: { lte: now } } };
  let dueClause = due;
  if (target === 'case' && policy) {
    const missingDue = SLA_BANDS.map((band) => ({
      bool: {
        filter: [bandClause('case', band), { range: { created_at: { lte: thresholdInstant(policy, band, 100, now) } } }],
        must_not: [{ exists: { field: 'sla_due_at' } }],
      },
    }));
    dueClause = { bool: { should: [due, ...missingDue], minimum_should_match: 1 } };
  }
  return {
    bool: {
      filter: [statusClause(target), dueClause],
      must_not: [{ exists: { field: 'sla.breached_at' } }],
    },
  };
}

/**
 * Records of one SLA band, for either family: 4.x by the band's `rule.level`
 * range, 5.0 by `severity_label` (every alias of the band, `informational`
 * folded into `low`) when the record carries no numeric level, exactly like
 * `severityBandOf` in common/severity.ts. Cases: the `severity` keyword.
 */
export function bandClause(target: SlaEscalationTarget, band: SlaBand): any {
  if (target === 'case') return { term: { severity: band } };
  const range = bandLevelRange(band)!;
  const level: any = { gte: range.min };
  if (range.max != null) level.lte = range.max;
  const labels = labelsOfBand(band).concat(band === 'low' ? labelsOfBand('informational') : []);
  return {
    bool: {
      should: [
        { range: { 'rule.level': level } },
        { bool: { filter: [{ terms: { severity_label: labels } }], must_not: [{ exists: { field: 'rule.level' } }] } },
      ],
      minimum_should_match: 1,
    },
  };
}

/** The instant a band's record must have started at (or before) to have used `thresholdPercent` of its resolve target. */
export function thresholdInstant(policy: SlaPolicy, band: SlaBand, thresholdPercent: number, now: string): string {
  const target = slaTargetOf(policy, band);
  const elapsedMs = Math.round((target.resolveMinutes * 60000 * thresholdPercent) / 100);
  return new Date(Date.parse(now) - elapsedMs).toISOString();
}

/** The candidate query of one escalation (see the module comment for the threshold and condition rules). */
export function escalationQuery(escalation: SlaEscalation, policy: SlaPolicy, now: string): any {
  const target = escalation.target;
  const base = BASE_FIELD[target];
  const bands = SLA_BANDS.map((band) => ({
    bool: {
      filter: [bandClause(target, band), { range: { [base]: { lte: thresholdInstant(policy, band, escalation.thresholdPercent, now) } } }],
    },
  }));
  const filter: any[] = [statusClause(target), { bool: { should: bands, minimum_should_match: 1 } }];
  const mustNot: any[] = [{ term: { 'sla.escalated': escalation.id } }];
  if (escalation.condition === 'unassigned' || escalation.condition === 'untouched') filter.push(UNASSIGNED_CLAUSE);
  if (escalation.condition === 'untouched') {
    filter.push({ term: { status: 'open' } });
    if (target === 'alert') mustNot.push({ exists: { field: 'reporting.first_assigned_at' } });
    mustNot.push(TOUCHED_HISTORY_CLAUSE);
  }
  return { bool: { filter, must_not: mustNot } };
}

// ---------------------------------------------------------------------------
// Painless
// ---------------------------------------------------------------------------

/** Breach stamp: only when absent; appends the `sla_breached` history entry; never touches updated_at/updated_by. */
export const BREACH_SCRIPT = `
  if (ctx._source.sla == null) { ctx._source.sla = [:]; }
  if (ctx._source.sla.breached_at != null) { ctx.op = 'noop'; return; }
  ctx._source.sla.breached_at = params.breach_now;
  if (ctx._source.history == null) { ctx._source.history = []; }
  ctx._source.history.add(params.entry);
  while (ctx._source.history.size() > 1000) { ctx._source.history.remove(0); }
`;

// Noop when the record was closed, escalated by this rule, assigned (for an
// `unassigned` / `untouched` rule), moved off `open` (`untouched`) or already
// carries the value this write would set, by another replica, another rule
// of the same tick or an earlier partial run, between the search and this
// write. The search hit is never trusted for the record's current state.
const ESCALATION_GUARD = `
  if (ctx._source.status == 'closed') { ctx.op = 'noop'; return; }
  if (ctx._source.sla != null && ctx._source.sla.escalated != null && ctx._source.sla.escalated.contains(params.escalation_id)) { ctx.op = 'noop'; return; }
  if (params.require_unassigned == true && ctx._source.assigned_to != null && ctx._source.assigned_to != '') { ctx.op = 'noop'; return; }
  if (params.require_open == true && ctx._source.status != 'open') { ctx.op = 'noop'; return; }
  if (params.fields != null && params.fields.assigned_to != null && ctx._source.assigned_to == params.fields.assigned_to) { ctx.op = 'noop'; return; }
  if (params.fields != null && params.fields.severity != null && ctx._source.severity == params.fields.severity) { ctx.op = 'noop'; return; }
`;

// Same body as APPEND_HISTORY_SCRIPT_SOURCE (server/lib/history.ts) for a
// list of entries: the scanner records an assignment and the status change
// it implies as two history rows, like two route calls would.
const APPEND_ENTRIES = `
  if (ctx._source.history == null) { ctx._source.history = []; }
  for (entry in params.entries) { ctx._source.history.add(entry); }
  while (ctx._source.history.size() > 1000) { ctx._source.history.remove(0); }
  if (params.fields != null) {
    for (entry in params.fields.entrySet()) {
      ctx._source[entry.getKey()] = entry.getValue();
    }
  }
`;

/** Alert action write: guard + history entries + fields + reporting merge (the bulk-update route's shape). */
export const ALERT_ACTION_SCRIPT = ESCALATION_GUARD + APPEND_ENTRIES + REPORTING_MERGE_SCRIPT;
/** Case action write: guard + history entries + fields (the PUT /cases/{id} shape). */
export const CASE_ACTION_SCRIPT = ESCALATION_GUARD + APPEND_ENTRIES;

/** Marker push (only when absent) plus the closing history entries (`comment_added` when a comment was left, `sla_escalated`). */
export const ESCALATION_MARKER_SCRIPT = `
  if (ctx._source.sla == null) { ctx._source.sla = [:]; }
  if (ctx._source.sla.escalated == null) { ctx._source.sla.escalated = []; }
  if (ctx._source.sla.escalated.contains(params.escalation_id)) { ctx.op = 'noop'; return; }
  ctx._source.sla.escalated.add(params.escalation_id);
  if (ctx._source.history == null) { ctx._source.history = []; }
  for (entry in params.entries) { ctx._source.history.add(entry); }
  while (ctx._source.history.size() > 1000) { ctx._source.history.remove(0); }
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export interface TemplateVars {
  id: string;
  severity: string;
  due_at: string;
  escalation: string;
}

/** `{{id}}`, `{{severity}}`, `{{due_at}}`, `{{escalation}}`; unknown placeholders are left as typed. Rendered as text (escaped by the UI). */
export function renderEscalationTemplate(template: string, vars: TemplateVars): string {
  return String(template || '').replace(/\{\{\s*(id|severity|due_at|escalation)\s*\}\}/g, (_match, key: keyof TemplateVars) => vars[key] ?? '');
}

/** One band up, capped at critical; null when the severity is unknown or already critical. */
export function nextSeverityBand(severity: unknown): SlaBand | null {
  const index = BAND_ORDER.indexOf(severity as SlaBand);
  if (index < 0 || index === BAND_ORDER.length - 1) return null;
  return BAND_ORDER[index + 1];
}

function isConflict(error: any): boolean {
  return (error?.meta?.statusCode || error?.statusCode) === 409;
}

function isNotFound(error: any): boolean {
  return (error?.meta?.statusCode || error?.statusCode) === 404;
}

function errorMessage(e: any): string {
  return String(e?.message || e).slice(0, MAX_ERROR_LENGTH);
}

/** A thrown error for the status doc: type + HTTP status only (`sanitizeBackfillError`), never the raw text. */
export function sanitizeScannerError(e: any): string {
  return sanitizeBackfillError(e);
}

/** A bulk item failure for the status doc: the error type and HTTP status only, never `reason`. */
function sanitizeBulkFailure(detail: any): string {
  const type = typeof detail?.error?.type === 'string' && detail.error.type ? detail.error.type : 'bulk failure';
  const status = Number(detail?.status || 0);
  return status ? `${type} (HTTP ${status})` : type;
}

/**
 * Errors of one pass: the full messages (`errors`, for the log and the tick
 * result) and their sanitised twins (`reported`, for the status doc), both
 * capped at SLA_ESCALATION_STATUS_MAX_ERRORS entries; `failures` counts them all.
 */
export interface PassErrors {
  errors: string[];
  reported: string[];
  failures: number;
}

function newPassErrors(): PassErrors {
  return { errors: [], reported: [], failures: 0 };
}

function recordFailure(into: PassErrors, message: string, reported: string): void {
  into.failures += 1;
  if (into.errors.length < SLA_ESCALATION_STATUS_MAX_ERRORS) {
    into.errors.push(message.slice(0, MAX_ERROR_LENGTH));
    into.reported.push(reported.slice(0, MAX_ERROR_LENGTH));
  }
}

function mergeFailures(into: PassErrors, from: PassErrors): void {
  into.failures += from.failures;
  for (let i = 0; i < from.errors.length && into.errors.length < SLA_ESCALATION_STATUS_MAX_ERRORS; i += 1) {
    into.errors.push(from.errors[i]);
    into.reported.push(from.reported[i]);
  }
}

/** One aggregated warn line per pass instead of one line per failed record. */
function logPassFailures(logger: Logger | undefined, pass: string, errors: PassErrors): void {
  if (!errors.failures || !logger) return;
  const first = errors.errors[0] ? `, first: ${errors.errors[0]}` : '';
  logger.warn(`wazuh-alert-manager sla escalation: ${pass}: ${errors.failures} record failure(s)${first}`);
}

function severityOf(target: SlaEscalationTarget, source: any): string {
  if (target === 'case') return typeof source?.severity === 'string' ? source.severity : 'unknown';
  const band = severityBandOf(source);
  return band ? slaBandOf(band) : 'unknown';
}

/** The record's due date; for a case without `sla_due_at`, the instant 3.2 would have stored (needs the policy). */
function dueOf(target: SlaEscalationTarget, source: any, policy?: SlaPolicy | null): string | null {
  const value = target === 'alert' ? source?.reporting?.sla_due_at : source?.sla_due_at;
  if (typeof value === 'string' && value) return value;
  if (target === 'case' && policy) return computeCaseDueAt(source?.severity, source?.created_at, policy);
  return null;
}

interface Hit {
  _id: string;
  _index: string;
  _source: any;
  sort?: any[];
}

interface ScanResult {
  hits: Hit[];
  /** True when more records matched than `max` allowed this tick. */
  capped: boolean;
}

/**
 * Page through a read alias with search_after up to `max` hits; unmanaged
 * hits are refused. The last page asks for one hit more than needed so
 * `capped` is true only when a record is really left for the next tick.
 */
async function scan(client: any, target: SlaEscalationTarget, query: any, max: number): Promise<ScanResult> {
  const hits: Hit[] = [];
  let searchAfter: any[] | undefined;
  const sort = [{ [BASE_FIELD[target]]: { order: 'asc' } }, { [UID_FIELD[target]]: { order: 'asc' } }];
  for (;;) {
    const needed = max - hits.length;
    const size = Math.min(SLA_SCAN_PAGE_SIZE, needed + 1);
    const res: any = await client.search({
      index: READ_ALIAS[target],
      body: { size, query, sort, ...(searchAfter ? { search_after: searchAfter } : {}) },
    });
    const page: Hit[] = res?.body?.hits?.hits || [];
    for (const hit of page.slice(0, needed)) {
      if (!isManagedPhysicalIndex(hit._index, MANAGED_PREFIX[target])) {
        const error = new Error(`Alias ${READ_ALIAS[target]} resolved outside its managed family: ${hit._index}`);
        error.name = 'UnmanagedIndexError';
        throw error;
      }
      hits.push(hit);
    }
    if (page.length > needed) return { hits, capped: true };
    if (page.length < size) return { hits, capped: false };
    searchAfter = page[page.length - 1].sort;
    if (!searchAfter) return { hits, capped: false };
  }
}

/**
 * `create` one activity document per event under its deterministic id.
 * Returns the ids that are now written (201, or 409 = already there) and the
 * failures of the others.
 */
async function appendActivitiesOnce(
  client: any,
  events: Array<{ id: string; input: ActivityInput }>
): Promise<{ written: Set<string>; failures: Array<{ id: string; detail: any }> }> {
  const written = new Set<string>();
  const failures: Array<{ id: string; detail: any }> = [];
  if (!events.length) return { written, failures };
  const index = assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS);
  const body: any[] = [];
  for (const event of events) {
    body.push({ create: { _index: index, _id: event.id } });
    body.push(buildActivityEvent(event.input));
  }
  const res: any = await client.bulk({ body });
  const items: any[] = res?.body?.items || [];
  events.forEach((event, position) => {
    const detail = items[position]?.create || items[position]?.index;
    const status = Number(detail?.status || 0);
    if (detail?.error && status !== 409) failures.push({ id: event.id, detail });
    else written.add(event.id);
  });
  return { written, failures };
}

async function appendActivityOnceTolerant(client: any, id: string, input: ActivityInput): Promise<void> {
  try {
    await client.index({ index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS), id, op_type: 'create', body: buildActivityEvent(input) });
  } catch (error: any) {
    if (!isConflict(error)) throw error;
  }
}

// ---------------------------------------------------------------------------
// Breach pass
// ---------------------------------------------------------------------------

export interface BreachPassResult extends PassErrors {
  marked: number;
  capped: boolean;
  /** True when the lease renewal between pages failed and the pass stopped early. */
  leaseLost: boolean;
  /** Records stamped this pass whose due date passed before the notify grace window (no `sla.breached` sent). */
  notifySuppressed: number;
}

export interface BreachPassOptions {
  /** Renews the tick's lease between scan pages; the pass stops when it answers false. */
  renewLease?: () => Promise<boolean>;
  /**
   * `sla.breached` is not sent for a record whose due date passed more than
   * this long before `now` (`sla.escalation.breachNotifyGraceMinutes`); 0 =
   * always sent. Default SLA_BREACH_NOTIFY_GRACE_MINUTES.
   */
  notifyGraceMs?: number;
}

/** True when a breach notification for `dueAt` is still wanted at `now` (inside the grace window, or no window). */
export function breachNotifyWanted(dueAt: string | null | undefined, now: string, graceMs: number): boolean {
  if (!(graceMs > 0) || !dueAt) return true;
  const due = Date.parse(dueAt);
  if (!Number.isFinite(due)) return true;
  return Date.parse(now) - due <= graceMs;
}

export function breachActivityId(id: string): string {
  return `sla-breach:${id}`;
}

/**
 * Stamp every newly breached record of one target: per page, first the
 * `sla_breached` activity events (bulk `create`, 409 tolerated), then the
 * bulk scripted stamp of the records whose event is written. A record whose
 * event failed is left unstamped and retried next tick; a record whose stamp
 * failed after its event keeps the event (the next tick's create answers 409
 * and the stamp is retried).
 *
 * Notifications (step 1.3): the records a page stamped go to the emitter as
 * ONE batch (`emitSlaEvents`, bulk-written), minus the records whose due date
 * passed before the notify grace window (counted in `notifySuppressed` and
 * logged once per pass), so a first scan over an overdue backlog stamps
 * everything but never floods the channels. The lease is renewed before every
 * page after the first; when it is lost the pass stops (the remaining records
 * are the next holder's).
 */
export async function runBreachPass(
  client: any,
  target: SlaEscalationTarget,
  now: string,
  policy?: SlaPolicy | null,
  logger?: Logger,
  emitter?: SlaNotificationEmitter | null,
  options: BreachPassOptions = {}
): Promise<BreachPassResult> {
  const { renewLease } = options;
  const graceMs = typeof options.notifyGraceMs === 'number' ? options.notifyGraceMs : SLA_BREACH_NOTIFY_GRACE_MINUTES * 60000;
  const result: BreachPassResult = { ...newPassErrors(), marked: 0, capped: false, leaseLost: false, notifySuppressed: 0 };
  const { hits, capped } = await scan(client, target, breachQuery(target, now, policy), SLA_BREACH_MAX_PER_TICK);
  result.capped = capped;
  if (capped) logger?.warn(`wazuh-alert-manager sla escalation: breach pass capped at ${SLA_BREACH_MAX_PER_TICK} ${target}s this tick`);
  for (let offset = 0; offset < hits.length; offset += SLA_SCAN_PAGE_SIZE) {
    if (offset > 0 && renewLease && !(await renewLease())) {
      result.leaseLost = true;
      recordFailure(result, 'breach pass stopped: lease lost to another replica', 'breach pass stopped: lease lost to another replica');
      break;
    }
    const page = hits.slice(offset, offset + SLA_SCAN_PAGE_SIZE);
    const due = new Map<string, string | null>();
    for (const hit of page) due.set(hit._id, dueOf(target, hit._source, policy));
    const events = page.map((hit) => ({
      id: breachActivityId(hit._id),
      input: {
        targetType: target,
        targetId: hit._id,
        user: SLA_ESCALATION_ACTOR,
        action: SLA_BREACHED_ACTION,
        to: due.get(hit._id) ?? null,
        timestamp: now,
        source: SLA_ESCALATION_SOURCE,
      } as ActivityInput,
    }));
    const activities = await appendActivitiesOnce(client, events);
    for (const failure of activities.failures) {
      recordFailure(
        result,
        `activity ${failure.id}: ${failure.detail?.error?.reason || failure.detail?.error?.type || 'bulk failure'}`,
        `activity ${failure.id}: ${sanitizeBulkFailure(failure.detail)}`
      );
    }
    const stampable = page.filter((hit) => activities.written.has(breachActivityId(hit._id)));
    if (!stampable.length) continue;
    const body: any[] = [];
    for (const hit of stampable) {
      body.push({ update: { _index: assertManagedWriteTarget(hit._index), _id: hit._id } });
      body.push({
        script: {
          lang: 'painless',
          source: BREACH_SCRIPT,
          params: {
            breach_now: now,
            entry: buildHistoryEntry({ user: SLA_ESCALATION_ACTOR, action: SLA_BREACHED_ACTION, to: due.get(hit._id) ?? null }),
          },
        },
      });
    }
    const res: any = await client.bulk({ body });
    const items: any[] = res?.body?.items || [];
    const newlyStamped: Hit[] = [];
    stampable.forEach((hit, position) => {
      const detail = items[position]?.update;
      const status = Number(detail?.status || 0);
      if (detail?.result === 'updated') {
        result.marked += 1;
        newlyStamped.push(hit);
      }
      // A conflict (another replica stamped it) is finished by that replica
      // or re-run next tick; anything else is a failure of this record.
      if (detail?.error && status !== 409) {
        recordFailure(
          result,
          `${target} ${hit._id}: ${detail.error?.reason || detail.error?.type || 'breach update failed'}`,
          `${target} ${hit._id}: ${sanitizeBulkFailure(detail)}`
        );
      }
    });
    // Notifications (step 1.3): one `sla.breached` per record this pass
    // stamped (a noop = another replica's stamp, which that replica notifies),
    // the whole page in one batch, stale breaches left out. The emitter never
    // throws; a lost enqueue is logged, never retried.
    if (emitter && newlyStamped.length) {
      const batch = [];
      for (const hit of newlyStamped) {
        const dueAt = due.get(hit._id) ?? null;
        if (!breachNotifyWanted(dueAt, now, graceMs)) {
          result.notifySuppressed += 1;
          continue;
        }
        batch.push({
          target,
          record: { id: hit._id, source: { ...hit._source, sla: { ...(hit._source?.sla || {}), breached_at: now } } },
          dueAt,
          message: dueAt ? `SLA due ${dueAt} passed` : null,
          now: new Date(now),
        });
      }
      if (batch.length) await emitter.emitSlaEvents('sla.breached', batch);
    }
  }
  if (result.notifySuppressed) {
    logger?.info(
      `wazuh-alert-manager sla escalation: ${result.notifySuppressed} ${target}(s) breached more than ${Math.round(graceMs / 60000)} min ago stamped without an sla.breached notification`
    );
  }
  return result;
}

// ---------------------------------------------------------------------------
// Escalation pass
// ---------------------------------------------------------------------------

export interface AppliedActions {
  assignTo?: string;
  /** `{ from, to }` when the severity moved; null when it was already critical / unknown. */
  raiseSeverity?: { from: string; to: string } | null;
  /** True when a comment was left. */
  comment?: boolean;
  /** Channel ids the `sla.escalated` notification goes to (step 1.3) instead of the event's bound channels. */
  notify?: string[];
}

export function escalationActivityId(escalationId: string, recordId: string, suffix?: string): string {
  return `sla-escalation:${escalationId}:${recordId}${suffix ? `:${suffix}` : ''}`;
}

interface ApplyOptions {
  policy: SlaPolicy;
  now: string;
  /** Notification emitter (step 1.3); absent in most unit tests. */
  emitter?: SlaNotificationEmitter | null;
}

/**
 * Apply one escalation to one record. Returns true when the marker was
 * written by this call (the record counts as escalated), false when the
 * record was skipped (closed meanwhile, already marked, no longer matching
 * the rule's condition, or a version conflict: the next tick re-evaluates it
 * against fresh state).
 */
export async function applyEscalation(client: any, escalation: SlaEscalation, hit: Hit, options: ApplyOptions): Promise<boolean> {
  const { policy, now } = options;
  const target = escalation.target;
  const index = assertManagedWriteTarget(hit._index);
  const id = hit._id;
  const source = hit._source || {};
  const applied: AppliedActions = {};
  const actor = SLA_ESCALATION_ACTOR;
  const activityBase = { targetType: target, user: actor, timestamp: now, source: SLA_ESCALATION_SOURCE } as const;
  // The rule's condition travels with every action write so the script can
  // noop when the record stopped matching after the search.
  const params: Record<string, any> = {
    escalation_id: escalation.id,
    require_unassigned: escalation.condition === 'unassigned' || escalation.condition === 'untouched',
    require_open: escalation.condition === 'untouched',
  };
  let status: string = source.status;
  let assignedTo: string | null = source.assigned_to ?? null;
  let severity: string = source.severity;
  // Captured before any write: a search hit's `_source` may be the live
  // object in tests, and the notification below compares against the start.
  const initialAssignee = assignedTo;

  const write = async (script: string, body: Record<string, any>, extra: Record<string, any> = params): Promise<boolean> => {
    try {
      const res: any = await client.update({ index, id, body: { script: { lang: 'painless', source: script, params: { ...extra, ...body } } } });
      return res?.body?.result !== 'noop';
    } catch (error: any) {
      if (isConflict(error)) return false;
      throw error;
    }
  };

  // 1. assignTo: set the assignee, move an open record to in_progress, record
  //    the first assignment in `reporting` (alerts) exactly like the routes.
  if (escalation.actions.assignTo && assignedTo !== escalation.actions.assignTo) {
    const assignee = escalation.actions.assignTo;
    const nextStatus = status === 'open' ? 'in_progress' : null;
    const entries = [buildHistoryEntry({ user: actor, action: 'assignment_change', from: assignedTo, to: assignee })];
    if (nextStatus) entries.push(buildHistoryEntry({ user: actor, action: 'status_change', from: status, to: nextStatus }));
    const fields: Record<string, any> = { updated_at: now, updated_by: actor, assigned_to: assignee };
    if (nextStatus) {
      fields.status = nextStatus;
      if (target === 'case') fields.closed_at = null;
    }
    const body: Record<string, any> = { entries, fields };
    if (target === 'alert') body.reporting = buildReportingUpdate(source, { status: nextStatus, assignedTo: assignee }, now, policy);
    const written = await write(target === 'alert' ? ALERT_ACTION_SCRIPT : CASE_ACTION_SCRIPT, body);
    if (!written) return false;
    await appendActivityOnceTolerant(client, escalationActivityId(escalation.id, id, 'assignment'), {
      ...activityBase, targetId: id, action: 'assignment_change', from: assignedTo, to: assignee,
    });
    if (nextStatus) {
      await appendActivityOnceTolerant(client, escalationActivityId(escalation.id, id, 'status'), {
        ...activityBase, targetId: id, action: 'status_change', from: status, to: nextStatus,
      });
      status = nextStatus;
    }
    assignedTo = assignee;
    applied.assignTo = assignee;
  } else if (escalation.actions.assignTo) {
    applied.assignTo = escalation.actions.assignTo;
  }

  // 2. raiseSeverity (cases only): one band up, due date recomputed from
  //    created_at. The condition guards do not apply here: the rule's own
  //    assignment may have just landed on this record.
  if (escalation.actions.raiseSeverity && target === 'case') {
    const next = nextSeverityBand(severity);
    if (!next) {
      applied.raiseSeverity = null;
    } else {
      const entries = [buildHistoryEntry({ user: actor, action: 'case_updated', from: severity, to: next })];
      const fields = { updated_at: now, updated_by: actor, severity: next, sla_due_at: computeCaseDueAt(next, source.created_at, policy) };
      const written = await write(CASE_ACTION_SCRIPT, { entries, fields }, { escalation_id: escalation.id });
      if (!written) return false;
      await appendActivityOnceTolerant(client, escalationActivityId(escalation.id, id, 'severity'), {
        ...activityBase, targetId: id, action: 'case_updated', from: severity, to: next,
      });
      applied.raiseSeverity = { from: severity, to: next };
      severity = next;
    }
  }

  // 3. comment: a comment document under a deterministic id (text rendered
  //    from the template; the UI escapes it like any comment).
  const closingEntries: any[] = [];
  if (escalation.actions.comment) {
    const text = renderEscalationTemplate(escalation.actions.comment, {
      id,
      severity: target === 'case' ? severity || 'unknown' : severityOf(target, source),
      due_at: dueOf(target, source, policy) || '',
      escalation: escalation.name,
    });
    await appendActivityOnceTolerant(client, escalationActivityId(escalation.id, id, 'comment'), {
      ...activityBase, targetId: id, eventType: 'comment', action: 'comment_added', text,
    });
    closingEntries.push(buildHistoryEntry({ user: actor, action: 'comment_added' }));
    applied.comment = true;
  }

  // 4. notify: recorded on the activity event; the `sla.escalated`
  //    notification below goes to these channel ids instead of the bound ones.
  if (escalation.actions.notify?.length) applied.notify = [...escalation.actions.notify];

  // 5. the one sla_escalated activity event (create-once, 409 tolerated),
  //    THEN the marker + sla_escalated history row: a crash in between leaves
  //    an event without a marker, which the next tick finishes (409 + marker),
  //    never a marker without its event.
  await appendActivityOnceTolerant(client, escalationActivityId(escalation.id, id), {
    ...activityBase,
    targetId: id,
    action: SLA_ESCALATED_ACTION,
    from: escalation.id,
    to: escalation.name,
    details: {
      escalation: {
        id: escalation.id,
        name: escalation.name,
        target: escalation.target,
        thresholdPercent: escalation.thresholdPercent,
        condition: escalation.condition,
      },
      actions: applied,
      ...(applied.notify ? { notify: applied.notify } : {}),
    },
  });
  closingEntries.push(buildHistoryEntry({ user: actor, action: SLA_ESCALATED_ACTION, from: escalation.id, to: escalation.name }));
  const marked = await write(ESCALATION_MARKER_SCRIPT, { entries: closingEntries }, { escalation_id: escalation.id });
  // 6. notifications (step 1.3), only for the call that wrote the marker:
  //    `sla.escalated` (the escalation's `notify` ids, else the bound
  //    channels) and, for a case the escalation itself assigned or raised,
  //    the matching case events (its activity writes bypass the activity
  //    hook). The emitter never throws.
  if (marked && options.emitter) {
    const record = {
      ...source,
      status,
      assigned_to: assignedTo,
      ...(target === 'case' ? { severity, updated_at: now, updated_by: actor } : {}),
      sla: { ...(source.sla || {}), escalated: Array.from(new Set([...(Array.isArray(source.sla?.escalated) ? source.sla.escalated : []), escalation.id])) },
    };
    await options.emitter.emitSlaEvent('sla.escalated', {
      target,
      record: { id, source: record },
      escalation: { id: escalation.id, name: escalation.name },
      notify: applied.notify ?? null,
      message: describeEscalationActions(applied),
      now: new Date(now),
    });
    if (target === 'case') {
      const caseDoc = { ...record, id };
      if (applied.assignTo && applied.assignTo !== initialAssignee) {
        await options.emitter.emitCaseEvent('case.assigned', caseDoc, {
          actor,
          changes: { from: initialAssignee, to: applied.assignTo },
          key: escalationActivityId(escalation.id, id, 'assignment'),
          now: new Date(now),
        });
      }
      if (applied.raiseSeverity) {
        await options.emitter.emitCaseEvent('case.severity_raised', caseDoc, {
          actor,
          changes: { from: applied.raiseSeverity.from, to: applied.raiseSeverity.to },
          key: escalationActivityId(escalation.id, id, 'severity'),
          now: new Date(now),
        });
      }
    }
  }
  return marked;
}

export interface EscalationPassResult extends PassErrors {
  escalated: number;
  capped: boolean;
  /** True when the lease renewal failed and the pass stopped early. */
  leaseLost: boolean;
}

export interface EscalationPassOptions {
  logger?: Logger;
  /** Renews the tick's lease; the pass stops when it answers false. */
  renewLease?: () => Promise<boolean>;
  /** Notification emitter (step 1.3). */
  emitter?: SlaNotificationEmitter | null;
}

/**
 * Apply every enabled escalation to its candidates, at most
 * SLA_ESCALATION_MAX_ACTIONS_PER_TICK records per tick, renewing the lease
 * every SLA_ESCALATION_LEASE_RENEW_EVERY applied records.
 */
export async function runEscalationPass(client: any, policy: SlaPolicy, now: string, options: EscalationPassOptions = {}): Promise<EscalationPassResult> {
  const { logger, renewLease } = options;
  const result: EscalationPassResult = { ...newPassErrors(), escalated: 0, capped: false, leaseLost: false };
  let budget = SLA_ESCALATION_MAX_ACTIONS_PER_TICK;
  let sinceRenewal = 0;
  for (const escalation of policy.escalations || []) {
    if (!escalation.enabled) continue;
    if (budget <= 0) {
      result.capped = true;
      break;
    }
    let candidates: ScanResult;
    try {
      candidates = await scan(client, escalation.target, escalationQuery(escalation, policy, now), budget);
    } catch (e: any) {
      recordFailure(
        result,
        `escalation "${escalation.id}": candidate search failed: ${errorMessage(e)}`,
        `escalation "${escalation.id}": candidate search failed: ${sanitizeScannerError(e)}`
      );
      continue;
    }
    if (candidates.capped) result.capped = true;
    for (const hit of candidates.hits) {
      if (renewLease && sinceRenewal >= SLA_ESCALATION_LEASE_RENEW_EVERY) {
        sinceRenewal = 0;
        if (!(await renewLease())) {
          result.leaseLost = true;
          recordFailure(result, 'escalation pass stopped: lease lost to another replica', 'escalation pass stopped: lease lost to another replica');
          return result;
        }
      }
      budget -= 1;
      sinceRenewal += 1;
      try {
        if (await applyEscalation(client, escalation, hit, { policy, now, emitter: options.emitter })) result.escalated += 1;
      } catch (e: any) {
        recordFailure(
          result,
          `escalation "${escalation.id}" on ${escalation.target} ${hit._id}: ${errorMessage(e)}`,
          `escalation "${escalation.id}" on ${escalation.target} ${hit._id}: ${sanitizeScannerError(e)}`
        );
      }
    }
  }
  if (result.capped) {
    logger?.warn(`wazuh-alert-manager sla escalation: escalation pass capped at ${SLA_ESCALATION_MAX_ACTIONS_PER_TICK} records this tick; the rest follow next tick`);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Status doc
// ---------------------------------------------------------------------------

export const SLA_ESCALATION_STATUS_DOCUMENT_TYPE = 'sla_escalation_status';

function statusFromSource(source: any): SlaEscalationStatus | null {
  if (!source || source.document_type !== SLA_ESCALATION_STATUS_DOCUMENT_TYPE) return null;
  const count = (value: unknown) => (typeof value === 'number' && Number.isFinite(value) ? value : 0);
  const errors: SlaEscalationStatusError[] = Array.isArray(source.errors)
    ? source.errors
        .filter((entry: any) => entry && typeof entry.message === 'string')
        .map((entry: any) => ({ at: String(entry.at ?? ''), message: String(entry.message) }))
    : [];
  return {
    last_tick_at: String(source.last_tick_at ?? ''),
    holder: String(source.holder ?? ''),
    breached_alerts: count(source.breached_alerts),
    breached_cases: count(source.breached_cases),
    escalated: count(source.escalated),
    errors,
    capped: source.capped === true,
  };
}

export async function readSlaEscalationStatus(client: any): Promise<SlaEscalationStatus | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: SLA_ESCALATION_STATUS_DOC_ID });
    return statusFromSource(res?.body?._source);
  } catch (e: any) {
    if (isNotFound(e)) return null;
    throw e;
  }
}

async function writeStatus(client: any, status: SlaEscalationStatus): Promise<void> {
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: SLA_ESCALATION_STATUS_DOC_ID,
    body: { document_type: SLA_ESCALATION_STATUS_DOCUMENT_TYPE, ...status },
  });
}

// ---------------------------------------------------------------------------
// Tick + loop
// ---------------------------------------------------------------------------

export interface SlaEscalationTickOptions {
  holder: string;
  ttlMs: number;
  now?: Date;
  logger?: Logger;
  /** Test seam: replaces `getSlaPolicy`. */
  policy?: SlaPolicy;
  /** Notification emitter (step 1.3); without one the tick writes no outbox entry. */
  emitter?: SlaNotificationEmitter | null;
  /** `sla.escalation.breachNotifyGraceMinutes` in ms; default SLA_BREACH_NOTIFY_GRACE_MINUTES. */
  breachNotifyGraceMs?: number;
}

export interface SlaEscalationTickResult {
  acquired: boolean;
  breachedAlerts: number;
  breachedCases: number;
  escalated: number;
  /** Full error messages (first SLA_ESCALATION_STATUS_MAX_ERRORS per pass); what the log carries. */
  errors: string[];
  /** The sanitised twins of `errors`: what the status doc stores. */
  reported: string[];
  /** Every failure counted, including the ones past the message cap. */
  failures: number;
  capped: boolean;
}

/**
 * One scanner pass: lease, policy, breach pass (alerts, cases), lease
 * renewal, escalation pass (renewing the lease as it goes), status doc. Every
 * pass is isolated so one failure never stops the others; errors are
 * collected into the status doc (sanitised, last ten) and logged in full
 * (one line per pass).
 */
export async function tickSlaEscalation(client: any, options: SlaEscalationTickOptions): Promise<SlaEscalationTickResult> {
  const { holder, ttlMs, logger } = options;
  const nowDate = options.now || new Date();
  const now = nowDate.toISOString();
  const result: SlaEscalationTickResult = {
    acquired: false, breachedAlerts: 0, breachedCases: 0, escalated: 0, errors: [], reported: [], failures: 0, capped: false,
  };
  // The clock for lease renewals: the injected `now` in tests, wall clock otherwise.
  const leaseNow = () => (options.now ? nowDate.getTime() : Date.now());
  const renewLease = async () =>
    (await acquireOrRenewLease(client, { leaseId: SLA_ESCALATION_LEASE_ID, holder, ttlMs, now: leaseNow(), logger })).acquired;
  if (!(await renewLease())) return result;
  result.acquired = true;

  const policy = options.policy || (await getSlaPolicy(client, logger));
  const errors = newPassErrors();
  const passFailed = (pass: string, message: string, reported: string) => {
    const failure = newPassErrors();
    recordFailure(failure, `${pass}: ${message}`, `${pass}: ${reported}`);
    logPassFailures(logger, pass, failure);
    mergeFailures(errors, failure);
  };
  const passThrew = (pass: string, e: any) => passFailed(pass, errorMessage(e), sanitizeScannerError(e));

  const breachOptions: BreachPassOptions = { renewLease, notifyGraceMs: options.breachNotifyGraceMs };
  let leaseHeld = true;
  try {
    const alerts = await runBreachPass(client, 'alert', now, policy, logger, options.emitter, breachOptions);
    result.breachedAlerts = alerts.marked;
    result.capped = result.capped || alerts.capped;
    leaseHeld = !alerts.leaseLost;
    logPassFailures(logger, 'breach pass (alerts)', alerts);
    mergeFailures(errors, alerts);
  } catch (e: any) {
    passThrew('breach pass (alerts)', e);
  }
  if (!leaseHeld) {
    passFailed('breach pass (cases)', 'skipped: lease lost to another replica', 'skipped: lease lost to another replica');
  } else {
    try {
      const cases = await runBreachPass(client, 'case', now, policy, logger, options.emitter, breachOptions);
      result.breachedCases = cases.marked;
      result.capped = result.capped || cases.capped;
      leaseHeld = !cases.leaseLost;
      logPassFailures(logger, 'breach pass (cases)', cases);
      mergeFailures(errors, cases);
    } catch (e: any) {
      passThrew('breach pass (cases)', e);
    }
  }
  // The breach passes may have taken a while: renew before the escalation
  // pass, and skip it when another replica took the lease meanwhile.
  try {
    leaseHeld = leaseHeld && (await renewLease());
  } catch (e: any) {
    leaseHeld = false;
  }
  if (!leaseHeld) {
    passFailed('escalation pass', 'skipped: lease lost to another replica', 'skipped: lease lost to another replica');
  } else {
    try {
      const escalations = await runEscalationPass(client, policy, now, { logger, renewLease, emitter: options.emitter });
      result.escalated = escalations.escalated;
      result.capped = result.capped || escalations.capped;
      logPassFailures(logger, 'escalation pass', escalations);
      mergeFailures(errors, escalations);
      leaseHeld = !escalations.leaseLost;
    } catch (e: any) {
      passThrew('escalation pass', e);
    }
  }
  result.errors = errors.errors;
  result.reported = errors.reported;
  result.failures = errors.failures;

  // Only the holder writes the status doc; a replica that lost the lease
  // leaves it to the new holder.
  if (!leaseHeld) return result;
  try {
    let previous: SlaEscalationStatus | null = null;
    try {
      previous = await readSlaEscalationStatus(client);
    } catch (e: any) {
      logger?.debug(`wazuh-alert-manager sla escalation: previous status unreadable: ${errorMessage(e)}`);
    }
    const stored = [...(previous?.errors || []), ...result.reported.map((message) => ({ at: now, message }))].slice(-SLA_ESCALATION_STATUS_MAX_ERRORS);
    await writeStatus(client, {
      last_tick_at: now,
      holder,
      breached_alerts: result.breachedAlerts,
      breached_cases: result.breachedCases,
      escalated: result.escalated,
      errors: stored,
      capped: result.capped,
    });
  } catch (e: any) {
    logger?.warn(`wazuh-alert-manager sla escalation: status write failed: ${errorMessage(e)}`);
  }
  return result;
}

/** Lease TTL for a tick length: three ticks, at least two minutes. */
export function slaEscalationLeaseTtlMs(tickSeconds: number): number {
  return Math.max(tickSeconds * 3, 120) * 1000;
}

/**
 * Background loop next to the report scheduler: one tick every
 * `sla.escalation.tickSeconds`, overlapping ticks prevented, lease released
 * on stop. Returns the stop function.
 */
export function startSlaEscalationScanner(
  client: any,
  config: AlertManagerConfigType,
  logger: Logger,
  options: { emitter?: SlaNotificationEmitter | null } = {}
): () => void {
  setSlaEscalationRuntime(config);
  const emitter = options.emitter ?? null;
  const tickSeconds = config.sla?.escalation?.tickSeconds ?? 60;
  const breachNotifyGraceMs = (config.sla?.escalation?.breachNotifyGraceMinutes ?? SLA_BREACH_NOTIFY_GRACE_MINUTES) * 60000;
  const ttlMs = slaEscalationLeaseTtlMs(tickSeconds);
  const holder = holderId();
  let stopped = false;
  let running = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const schedule = () => {
    if (!stopped) timer = setTimeout(tick, tickSeconds * 1000);
  };

  const tick = async () => {
    if (stopped || running) return;
    running = true;
    try {
      const result = await tickSlaEscalation(client, { holder, ttlMs, logger, emitter, breachNotifyGraceMs });
      if (result.breachedAlerts || result.breachedCases || result.escalated) {
        logger.info(
          `wazuh-alert-manager sla escalation: breached ${result.breachedAlerts} alert(s), ${result.breachedCases} case(s); escalated ${result.escalated} record(s)`
        );
      }
    } catch (e: any) {
      logger.error(`wazuh-alert-manager sla escalation: unexpected error: ${errorMessage(e)}`);
    } finally {
      running = false;
      schedule();
    }
  };

  schedule();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    releaseLease(client, { leaseId: SLA_ESCALATION_LEASE_ID, holder, logger }).catch(() => {});
  };
}
