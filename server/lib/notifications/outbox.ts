import { randomUUID } from 'crypto';
import {
  NOTIFICATIONS_INDEX,
  NOTIFICATION_BACKOFF_SECONDS,
  NOTIFICATION_CLAIM_STALE_MS,
  NOTIFICATION_FORBIDDEN_HINT,
  NOTIFICATION_LAST_ERROR_MAX_LENGTH,
  NOTIFICATION_MAX_ATTEMPTS,
  NOTIFICATION_OUTBOX_LIST_MAX,
  NOTIFICATION_OUTBOX_PAGE,
  NOTIFICATION_STATUSES,
} from '../../../common/constants';
import type {
  NotificationChannel,
  NotificationChannelKind,
  NotificationDelivery,
  NotificationEvent,
  NotificationOutboxEntry,
  NotificationOutboxFilter,
  NotificationOutboxListResponse,
  NotificationSettings,
  NotificationStatus,
  NotificationTargetType,
} from '../../../common/types';
import { assertManagedWriteTarget } from '../index_namespace';
import { typedError } from '../plugin_settings';
import { NotificationPayload, renderSubject } from './render';
import { channelsForEvent } from './settings';

/**
 * Notification outbox (step 1.2): the durable queue between the emitters
 * (1.3 / 1.4) and the dispatcher. One document per (event, channel) delivery.
 *
 * - `enqueueNotification` writes with `op_type: create`, so a caller-chosen
 *   id (`notify:<rule>:<alert>`, `case.created:<case>:<channel>`) makes the
 *   enqueue idempotent: a duplicate is a silent no-op (`created: false`).
 * - `enqueueForEvent` fans one event out to every enabled channel bound to
 *   it (nothing when notifications are globally disabled); `enqueueMany`
 *   writes a batch in one bulk of `create` ops (the SLA breach pass).
 * - `claimDue` / `markSent` / `markFailed` are the dispatcher's state
 *   transitions, every write guarded by `if_seq_no` / `if_primary_term` so two
 *   replicas (or a stale claim and its reclaimer) never both deliver.
 * - `listOutbox` / `getOutboxEntry` / `retryOutboxEntry` / `countOutboxByStatus`
 *   back the routes.
 */

export interface OutboxDoc {
  id: string;
  event: NotificationEvent | 'test';
  channel_id: string;
  channel_kind: NotificationChannelKind;
  status: NotificationStatus;
  subject: string;
  payload: Record<string, any>;
  target_type: NotificationTargetType;
  target_id: string;
  attempts: number;
  created_at: string;
  next_attempt_at: string | null;
  sent_at: string | null;
  updated_at: string;
  claimed_by: string | null;
  claimed_at: string | null;
  last_error: string | null;
  last_status_code: number | null;
  delivery: NotificationDelivery | null;
  dedupe_key: string | null;
}

/** A claimed outbox document with the concurrency token of the claim. */
export interface ClaimedNotification {
  id: string;
  seqNo: number;
  primaryTerm: number;
  source: OutboxDoc;
}

export interface EnqueueInput {
  /** Caller-chosen id for idempotency; random when omitted. */
  id?: string;
  event: NotificationEvent | 'test';
  channelId: string;
  channelKind: NotificationChannelKind;
  targetType: NotificationTargetType;
  targetId: string;
  subject: string;
  payload: Record<string, any>;
  dedupeKey?: string | null;
  now?: Date;
  /** `wait_for` makes the entry searchable before returning (tests / e2e); default: the index's refresh interval. */
  refresh?: boolean | 'wait_for';
}

export interface EnqueueResult {
  id: string;
  created: boolean;
}

const STATUS_SET = new Set<string>(NOTIFICATION_STATUSES);

function isConflict(e: any): boolean {
  const status = e?.meta?.statusCode ?? e?.statusCode;
  return status === 409 || e?.body?.error?.type === 'version_conflict_engine_exception' || e?.meta?.body?.error?.type === 'version_conflict_engine_exception';
}

function isNotFound(e: any): boolean {
  const status = e?.meta?.statusCode ?? e?.statusCode;
  return status === 404 || e?.meta?.body?.error?.type === 'index_not_found_exception';
}

function iso(now?: Date): string {
  return (now || new Date()).toISOString();
}

export function boundError(message: unknown): string {
  const text = String(message ?? '').replace(/[\r\n]+/g, ' ').trim();
  return text.length > NOTIFICATION_LAST_ERROR_MAX_LENGTH ? `${text.slice(0, NOTIFICATION_LAST_ERROR_MAX_LENGTH - 3)}...` : text;
}

/** The `last_error` text of a failed attempt: a 403 from either transport gets the role hint appended, verbatim otherwise. */
export function describeFailure(error: unknown, statusCode: number | null | undefined): string {
  const base = boundError(error) || 'Delivery failed.';
  // The transports may already name the role (sendIndexerChannel's 403 text does): one hint, never two.
  if (statusCode === 403 && !base.includes(NOTIFICATION_FORBIDDEN_HINT) && !base.includes('wazuh_alert_manager_notify')) {
    return boundError(`${base} (hint: ${NOTIFICATION_FORBIDDEN_HINT})`);
  }
  return base;
}

/** Seconds to wait after `attempts` failed attempts (the table's last value past its end). */
export function backoffSeconds(attempts: number): number {
  const index = Math.max(0, Math.min(NOTIFICATION_BACKOFF_SECONDS.length - 1, attempts - 1));
  return NOTIFICATION_BACKOFF_SECONDS[index];
}

function buildOutboxDoc(input: EnqueueInput): OutboxDoc {
  const id = typeof input.id === 'string' && input.id.trim() ? input.id.trim() : randomUUID();
  const now = iso(input.now);
  return {
    id,
    event: input.event,
    channel_id: input.channelId,
    channel_kind: input.channelKind,
    status: 'pending',
    subject: String(input.subject || '').slice(0, 512),
    payload: input.payload && typeof input.payload === 'object' ? input.payload : {},
    target_type: input.targetType,
    target_id: String(input.targetId),
    attempts: 0,
    created_at: now,
    next_attempt_at: now,
    sent_at: null,
    updated_at: now,
    claimed_by: null,
    claimed_at: null,
    last_error: null,
    last_status_code: null,
    delivery: null,
    dedupe_key: input.dedupeKey ?? null,
  };
}

/** Write the entry; a duplicate id answers `created: false` and leaves the stored entry untouched. */
export async function enqueueNotification(client: any, input: EnqueueInput): Promise<EnqueueResult> {
  const doc = buildOutboxDoc(input);
  const { id } = doc;
  try {
    await client.index({
      index: assertManagedWriteTarget(NOTIFICATIONS_INDEX),
      id,
      op_type: 'create',
      body: doc,
      ...(input.refresh !== undefined ? { refresh: input.refresh } : {}),
    });
    return { id, created: true };
  } catch (e: any) {
    if (isConflict(e)) return { id, created: false };
    throw e;
  }
}

export interface EnqueueManyResult {
  /** Ids written by this call. */
  enqueued: string[];
  /** Ids that already existed (idempotent repeats). */
  duplicates: string[];
  /** Entries the bulk refused (anything but a 409), with the indexer's reason. */
  failures: Array<{ id: string; error: string }>;
}

function bulkItemError(detail: any): string {
  const error = detail?.error;
  if (!error) return `bulk item returned ${detail?.status ?? 'unknown'}`;
  return String(error.reason || error.type || 'bulk failure');
}

/**
 * Write many entries in one `client.bulk` of `create` ops (the SLA breach
 * pass: one page of records times its channels). A 409 per item is a
 * duplicate, any other item error a failure; a transport failure of the whole
 * bulk rejects. Empty input writes nothing.
 */
export async function enqueueMany(client: any, inputs: EnqueueInput[], options: { refresh?: boolean | 'wait_for' } = {}): Promise<EnqueueManyResult> {
  const result: EnqueueManyResult = { enqueued: [], duplicates: [], failures: [] };
  if (!inputs.length) return result;
  const index = assertManagedWriteTarget(NOTIFICATIONS_INDEX);
  const docs = inputs.map((input) => buildOutboxDoc(input));
  const body: any[] = [];
  for (const doc of docs) {
    body.push({ create: { _index: index, _id: doc.id } });
    body.push(doc);
  }
  const res: any = await client.bulk({ body, ...(options.refresh !== undefined ? { refresh: options.refresh } : {}) });
  const items: any[] = Array.isArray(res?.body?.items) ? res.body.items : [];
  docs.forEach((doc, position) => {
    const detail = items[position]?.create;
    const status = Number(detail?.status || 0);
    if (!detail) result.failures.push({ id: doc.id, error: 'bulk response item missing' });
    else if (status === 409 || detail.error?.type === 'version_conflict_engine_exception') result.duplicates.push(doc.id);
    else if (detail.error || status < 200 || status >= 300) result.failures.push({ id: doc.id, error: bulkItemError(detail) });
    else result.enqueued.push(doc.id);
  });
  return result;
}

export interface EnqueueForEventInput {
  targetType: NotificationTargetType;
  targetId: string;
  /** The allowlisted projection (`projectCaseEvent` / `projectAlertForNotification`); stored and sent as is. */
  payload: NotificationPayload | Record<string, any>;
  /** Stable id per channel for idempotency, e.g. `(channel) => \`case.created:${caseId}:${channel.id}\``. */
  idFactory: (channel: NotificationChannel) => string;
  /** Subject line per channel; default `renderSubject(event, payload)`. */
  subjectFactory?: (channel: NotificationChannel) => string;
  dedupeKey?: string | null;
  now?: Date;
  refresh?: boolean | 'wait_for';
}

export interface EnqueueForEventResult {
  /** Ids written by this call. */
  enqueued: string[];
  /** Ids that already existed (idempotent repeats). */
  duplicates: string[];
  /** Channels the event was fanned out to (0 when notifications are disabled or nothing is bound). */
  channels: number;
}

/**
 * Fan `event` out to every enabled channel bound to it. Skips everything when
 * `settings.enabled` is false. One failed write does not stop the others; the
 * first error is rethrown after the loop so the caller can log it.
 */
export async function enqueueForEvent(
  client: any,
  settings: NotificationSettings | null | undefined,
  event: NotificationEvent,
  input: EnqueueForEventInput
): Promise<EnqueueForEventResult> {
  const result: EnqueueForEventResult = { enqueued: [], duplicates: [], channels: 0 };
  const channels = channelsForEvent(settings, event);
  if (channels.length === 0) return result;
  result.channels = channels.length;
  let firstError: any = null;
  for (const channel of channels) {
    try {
      const subject = input.subjectFactory ? input.subjectFactory(channel) : renderSubject(event, input.payload as NotificationPayload);
      const written = await enqueueNotification(client, {
        id: input.idFactory(channel),
        event,
        channelId: channel.id,
        channelKind: channel.kind,
        targetType: input.targetType,
        targetId: input.targetId,
        subject,
        payload: input.payload as Record<string, any>,
        dedupeKey: input.dedupeKey,
        now: input.now,
        refresh: input.refresh,
      });
      (written.created ? result.enqueued : result.duplicates).push(written.id);
    } catch (e) {
      if (!firstError) firstError = e;
    }
  }
  if (firstError) throw firstError;
  return result;
}

export interface ClaimDueOptions {
  now?: Date;
  /** At most NOTIFICATION_OUTBOX_PAGE. */
  limit?: number;
  holder: string;
  /** Override of the stale-claim age (tests). */
  staleMs?: number;
}

/** The dispatcher's due query: pending / failed entries whose time has come, plus abandoned `sending` claims. */
export function dueQuery(now: string, staleBefore: string): any {
  return {
    bool: {
      should: [
        { bool: { filter: [{ terms: { status: ['pending', 'failed'] } }, { range: { next_attempt_at: { lte: now } } }] } },
        { bool: { filter: [{ term: { status: 'sending' } }, { range: { claimed_at: { lte: staleBefore } } }] } },
      ],
      minimum_should_match: 1,
    },
  };
}

export const CLAIM_SCRIPT = `
ctx._source.status = 'sending';
ctx._source.claimed_by = params.holder;
ctx._source.claimed_at = params.now;
ctx._source.updated_at = params.now;
`;

/**
 * Claim up to `limit` due entries for `holder`: a search sorted by
 * `next_attempt_at`, then one guarded scripted update per hit. A 409 means
 * another replica (or a stale claim's owner) took it: skipped, not an error.
 * A missing outbox index answers an empty list.
 */
export async function claimDue(client: any, options: ClaimDueOptions): Promise<ClaimedNotification[]> {
  const now = iso(options.now);
  const staleMs = typeof options.staleMs === 'number' ? options.staleMs : NOTIFICATION_CLAIM_STALE_MS;
  const staleBefore = new Date(new Date(now).getTime() - staleMs).toISOString();
  const size = Math.max(1, Math.min(NOTIFICATION_OUTBOX_PAGE, options.limit ?? NOTIFICATION_OUTBOX_PAGE));
  let hits: any[] = [];
  try {
    const res: any = await client.search({
      index: NOTIFICATIONS_INDEX,
      size,
      seq_no_primary_term: true,
      body: {
        query: dueQuery(now, staleBefore),
        sort: [{ next_attempt_at: { order: 'asc', missing: '_first' } }, { created_at: { order: 'asc' } }],
      },
    });
    hits = res?.body?.hits?.hits || [];
  } catch (e: any) {
    if (isNotFound(e)) return [];
    throw e;
  }
  const claimed: ClaimedNotification[] = [];
  const index = assertManagedWriteTarget(NOTIFICATIONS_INDEX);
  for (const hit of hits) {
    try {
      const res: any = await client.update({
        index,
        id: hit._id,
        if_seq_no: hit._seq_no,
        if_primary_term: hit._primary_term,
        body: { script: { source: CLAIM_SCRIPT, lang: 'painless', params: { holder: options.holder, now } } },
      });
      const source: OutboxDoc = { ...hit._source, status: 'sending', claimed_by: options.holder, claimed_at: now, updated_at: now };
      claimed.push({ id: hit._id, seqNo: res?.body?._seq_no ?? hit._seq_no, primaryTerm: res?.body?._primary_term ?? hit._primary_term, source });
    } catch (e: any) {
      if (isConflict(e)) continue;
      throw e;
    }
  }
  return claimed;
}

async function guardedUpdate(client: any, claimed: ClaimedNotification, doc: Partial<OutboxDoc>, now: string): Promise<boolean> {
  try {
    await client.update({
      index: assertManagedWriteTarget(NOTIFICATIONS_INDEX),
      id: claimed.id,
      if_seq_no: claimed.seqNo,
      if_primary_term: claimed.primaryTerm,
      body: { doc: { ...doc, updated_at: now } },
    });
    Object.assign(claimed.source, doc, { updated_at: now });
    return true;
  } catch (e: any) {
    // The claim went stale and another replica reclaimed the entry: its
    // outcome wins, ours is dropped.
    if (isConflict(e)) return false;
    throw e;
  }
}

/**
 * Give a claim back without an attempt: the entry returns to `pending`, due
 * now, attempts and last error untouched (the dispatcher lost its lease
 * mid-tick and leaves the rest of the batch to the new holder). Returns false
 * when the claim was lost (409).
 */
export async function releaseClaim(client: any, claimed: ClaimedNotification, options: { now?: Date } = {}): Promise<boolean> {
  const now = iso(options.now);
  return guardedUpdate(client, claimed, { status: 'pending', next_attempt_at: now, claimed_by: null, claimed_at: null }, now);
}

/** Record a successful delivery. Returns false when the claim was lost (409). */
export async function markSent(client: any, claimed: ClaimedNotification, delivery: NotificationDelivery, options: { now?: Date } = {}): Promise<boolean> {
  const now = iso(options.now);
  return guardedUpdate(
    client,
    claimed,
    {
      status: 'sent',
      attempts: (claimed.source.attempts || 0) + 1,
      sent_at: now,
      next_attempt_at: null,
      claimed_by: null,
      claimed_at: null,
      last_error: null,
      last_status_code: delivery.statusCode ?? null,
      delivery,
    },
    now
  );
}

export interface MarkFailedOptions {
  statusCode?: number | null;
  now?: Date;
  /** Replace the backoff table for this failure (e.g. one hour for a missing encryption key). */
  retryAfterMs?: number;
  /** Dead-letter now, whatever the attempt count (channel removed or disabled). */
  dead?: boolean;
  delivery?: NotificationDelivery | null;
}

export interface MarkFailedResult {
  /** False when the claim was lost (409) and nothing was written. */
  applied: boolean;
  status: NotificationStatus;
  attempts: number;
  next_attempt_at: string | null;
  last_error: string;
}

/**
 * Record a failed attempt: `attempts + 1`, the backoff table decides
 * `next_attempt_at` (`failed`) until NOTIFICATION_MAX_ATTEMPTS, then `dead`.
 * A 403 is recorded verbatim with the role hint and counts as an attempt.
 */
export async function markFailed(client: any, claimed: ClaimedNotification, error: unknown, options: MarkFailedOptions = {}): Promise<MarkFailedResult> {
  const now = iso(options.now);
  const attempts = (claimed.source.attempts || 0) + 1;
  const statusCode = typeof options.statusCode === 'number' ? options.statusCode : null;
  const lastError = describeFailure(error, statusCode);
  const dead = options.dead === true || attempts >= NOTIFICATION_MAX_ATTEMPTS;
  const delayMs = typeof options.retryAfterMs === 'number' ? options.retryAfterMs : backoffSeconds(attempts) * 1000;
  const nextAttemptAt = dead ? null : new Date(new Date(now).getTime() + delayMs).toISOString();
  const status: NotificationStatus = dead ? 'dead' : 'failed';
  const applied = await guardedUpdate(
    client,
    claimed,
    {
      status,
      attempts,
      next_attempt_at: nextAttemptAt,
      claimed_by: null,
      claimed_at: null,
      last_error: lastError,
      last_status_code: statusCode,
      ...(options.delivery !== undefined ? { delivery: options.delivery } : {}),
    },
    now
  );
  return { applied, status, attempts, next_attempt_at: nextAttemptAt, last_error: lastError };
}

// ---------------------------------------------------------------------------
// Route helpers
// ---------------------------------------------------------------------------

/** The list shape: everything but the payload (and the claim's internal fields are kept: the panel shows them). */
export function toOutboxEntry(id: string, source: any, options: { includePayload?: boolean } = {}): NotificationOutboxEntry {
  const s = source && typeof source === 'object' ? source : {};
  const entry: NotificationOutboxEntry = {
    id: String(s.id || id),
    event: s.event,
    channel_id: String(s.channel_id ?? ''),
    channel_kind: s.channel_kind,
    status: STATUS_SET.has(s.status) ? s.status : 'pending',
    subject: String(s.subject ?? ''),
    target_type: s.target_type,
    target_id: String(s.target_id ?? ''),
    attempts: typeof s.attempts === 'number' ? s.attempts : 0,
    created_at: String(s.created_at ?? ''),
    next_attempt_at: s.next_attempt_at ?? null,
    sent_at: s.sent_at ?? null,
    updated_at: String(s.updated_at ?? s.created_at ?? ''),
    last_error: s.last_error ?? null,
    last_status_code: typeof s.last_status_code === 'number' ? s.last_status_code : null,
    delivery: s.delivery && typeof s.delivery === 'object' ? s.delivery : null,
    dedupe_key: s.dedupe_key ?? null,
    claimed_by: s.claimed_by ?? null,
    claimed_at: s.claimed_at ?? null,
  };
  if (options.includePayload) entry.payload = s.payload && typeof s.payload === 'object' ? s.payload : {};
  return entry;
}

interface Cursor {
  created_at: string;
  id: string;
}

export function encodeOutboxCursor(cursor: Cursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64');
}

export function decodeOutboxCursor(raw: string | undefined | null): Cursor | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(String(raw), 'base64').toString('utf8'));
    if (parsed && typeof parsed === 'object' && typeof parsed.created_at === 'string' && typeof parsed.id === 'string' && parsed.created_at && parsed.id) {
      return { created_at: parsed.created_at, id: parsed.id };
    }
  } catch (e) {
    // fall through
  }
  throw typedError('Invalid outbox cursor.', 400);
}

export function outboxFilterQuery(filter: Pick<NotificationOutboxFilter, 'status' | 'channelId' | 'event'>): any {
  const must: any[] = [];
  if (filter.status) must.push({ term: { status: filter.status } });
  if (filter.channelId) must.push({ term: { channel_id: filter.channelId } });
  if (filter.event) must.push({ term: { event: filter.event } });
  return must.length ? { bool: { filter: must } } : { match_all: {} };
}

/** Newest first, `search_after` paging on (created_at, id). A missing index answers an empty page. */
export async function listOutbox(client: any, filter: NotificationOutboxFilter = {}): Promise<NotificationOutboxListResponse> {
  const limit = Math.max(1, Math.min(NOTIFICATION_OUTBOX_LIST_MAX, filter.limit ?? NOTIFICATION_OUTBOX_PAGE));
  const cursor = decodeOutboxCursor(filter.cursor);
  const body: any = {
    query: outboxFilterQuery(filter),
    sort: [{ created_at: { order: 'desc' } }, { id: { order: 'desc' } }],
    track_total_hits: true,
    _source: { excludes: ['payload'] },
  };
  if (cursor) body.search_after = [cursor.created_at, cursor.id];
  let res: any;
  try {
    res = await client.search({ index: NOTIFICATIONS_INDEX, size: limit + 1, body });
  } catch (e: any) {
    if (isNotFound(e)) return { items: [], next_cursor: null, total: 0 };
    throw e;
  }
  const hits: any[] = res?.body?.hits?.hits || [];
  const page = hits.slice(0, limit);
  const items = page.map((hit) => toOutboxEntry(hit._id, hit._source));
  const last = page[page.length - 1];
  const nextCursor = hits.length > limit && last ? encodeOutboxCursor({ created_at: String(last._source?.created_at ?? ''), id: String(last._source?.id || last._id) }) : null;
  const total = res?.body?.hits?.total;
  return { items, next_cursor: nextCursor, total: typeof total === 'number' ? total : typeof total?.value === 'number' ? total.value : items.length };
}

/** One entry with its payload; null when absent. */
export async function getOutboxEntry(client: any, id: string): Promise<NotificationOutboxEntry | null> {
  try {
    const res: any = await client.get({ index: NOTIFICATIONS_INDEX, id });
    if (!res?.body?.found && !res?.body?._source) return null;
    return toOutboxEntry(id, res.body._source, { includePayload: true });
  } catch (e: any) {
    if (isNotFound(e)) return null;
    throw e;
  }
}

/** Counts per status (zero for absent buckets, and for a missing index). */
export async function countOutboxByStatus(client: any): Promise<Record<NotificationStatus, number>> {
  const counts = {} as Record<NotificationStatus, number>;
  for (const status of NOTIFICATION_STATUSES) counts[status] = 0;
  try {
    const res: any = await client.search({
      index: NOTIFICATIONS_INDEX,
      size: 0,
      body: { aggs: { by_status: { terms: { field: 'status', size: NOTIFICATION_STATUSES.length } } } },
    });
    for (const bucket of res?.body?.aggregations?.by_status?.buckets || []) {
      if (STATUS_SET.has(bucket.key)) counts[bucket.key as NotificationStatus] = Number(bucket.doc_count) || 0;
    }
  } catch (e: any) {
    if (!isNotFound(e)) throw e;
  }
  return counts;
}

/**
 * Administrator retry: a `dead` or `failed` entry goes back to `pending`, due
 * now, attempts kept (so a persistent failure is dead again after one more
 * attempt). 404 when absent, 409 for any other status (a `pending` / `sending`
 * entry is already on its way; a `sent` one would be a duplicate delivery).
 */
export async function retryOutboxEntry(client: any, id: string, options: { now?: Date } = {}): Promise<NotificationOutboxEntry> {
  let current: any;
  try {
    current = await client.get({ index: NOTIFICATIONS_INDEX, id });
  } catch (e: any) {
    if (isNotFound(e)) throw typedError(`Outbox entry "${id}" was not found.`, 404);
    throw e;
  }
  const source = current?.body?._source;
  if (!source) throw typedError(`Outbox entry "${id}" was not found.`, 404);
  if (source.status !== 'dead' && source.status !== 'failed') {
    throw typedError(`Outbox entry "${id}" is ${source.status}; only failed or dead entries can be retried.`, 409);
  }
  const now = iso(options.now);
  const doc = { status: 'pending' as NotificationStatus, next_attempt_at: now, updated_at: now, claimed_by: null, claimed_at: null };
  try {
    await client.update({
      index: assertManagedWriteTarget(NOTIFICATIONS_INDEX),
      id,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      refresh: 'wait_for',
      body: { doc },
    });
  } catch (e: any) {
    if (isConflict(e)) throw typedError(`Outbox entry "${id}" changed while retrying; reload and try again.`, 409);
    throw e;
  }
  return toOutboxEntry(id, { ...source, ...doc }, { includePayload: true });
}
