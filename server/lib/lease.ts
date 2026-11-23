import * as os from 'os';
import * as crypto from 'crypto';
import { Logger } from '../../../../src/core/server';
import { META_INDEX } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';

/** Doc id prefix for every lease held in the meta index. */
export const LEASE_DOC_ID_PREFIX = 'lease:';

export interface LeaseDoc {
  /** Discriminator shared with the other typed meta docs (`source_state`, `retired_alert`, ...). */
  document_type: 'lease';
  lease_id: string;
  holder_id: string;
  expires_at: string;
  updated_at: string;
}

export interface AcquireLeaseOptions {
  /** Logical lease name, e.g. `sla-escalation`; becomes doc id `lease:<leaseId>`. */
  leaseId: string;
  /** Stable per-process identity from `holderId()`. */
  holder: string;
  /** How long a renewal keeps the lease before another holder may reclaim it. */
  ttlMs: number;
  /** Clock override for tests; defaults to `Date.now()`. */
  now?: number;
  /** Optional logger for unexpected OpenSearch failures (never thrown). */
  logger?: Logger;
}

export interface ReleaseLeaseOptions {
  leaseId: string;
  holder: string;
  logger?: Logger;
}

export interface LeaseResult {
  /** True when this holder owns the lease until the returned `expiresAt`. */
  acquired: boolean;
  /**
   * When acquired: this holder's new expiry. When not acquired: the current
   * holder's expiry if known (so callers can back off), otherwise null.
   */
  expiresAt: string | null;
}

/**
 * Unique per-process identity for lease holders, generated once per
 * scheduler at start (not per tick) so renewals and steals are recognisable
 * as coming from the same process. Same shape as the sync lock's holder id.
 */
export function holderId(): string {
  return `${os.hostname()}-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
}

export function leaseDocId(leaseId: string): string {
  const normalized = String(leaseId || '').trim();
  if (!normalized || /[\s,*/]/.test(normalized)) {
    throw new Error(`Invalid lease id: ${leaseId || '<empty>'}`);
  }
  return `${LEASE_DOC_ID_PREFIX}${normalized}`;
}

function isConflict(error: any): boolean {
  return error?.meta?.statusCode === 409 || error?.statusCode === 409;
}

function isNotFound(error: any): boolean {
  return error?.meta?.statusCode === 404 || error?.statusCode === 404;
}

/**
 * Acquires or renews a named lease so only one dashboard replica runs a given
 * scheduler at a time. Mirrors `sync_lock.ts`: mutual exclusion comes from
 * OpenSearch optimistic concurrency (create's conflict check, and
 * if_seq_no/if_primary_term on update); `expires_at` only decides how soon a
 * lease abandoned by a crashed holder is reclaimed, so clock drift between
 * replicas cannot make two holders believe they own it at once. Renewal is
 * allowed only when the stored holder matches or the lease has expired.
 * Never throws on OpenSearch failures; they are logged and reported as not
 * acquired. Invalid arguments (bad lease id, holder or ttl) do throw.
 */
export async function acquireOrRenewLease(client: any, options: AcquireLeaseOptions): Promise<LeaseResult> {
  const { leaseId, holder, ttlMs, logger } = options;
  const id = leaseDocId(leaseId);
  if (!holder || typeof holder !== 'string') {
    throw new Error('A lease holder id is required.');
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error(`Lease ttlMs must be a positive number of milliseconds, got ${ttlMs}`);
  }
  const index = assertManagedWriteTarget(META_INDEX);
  const now = typeof options.now === 'number' ? options.now : Date.now();
  const doc: LeaseDoc = {
    document_type: 'lease',
    lease_id: leaseId,
    holder_id: holder,
    expires_at: new Date(now + ttlMs).toISOString(),
    updated_at: new Date(now).toISOString(),
  };

  let current: any;
  try {
    current = await client.get({ index, id });
  } catch (e: any) {
    if (isNotFound(e)) {
      try {
        await client.create({ index, id, body: doc });
        return { acquired: true, expiresAt: doc.expires_at };
      } catch (createErr: any) {
        // Another replica created the doc first - it holds the lease this round.
        if (isConflict(createErr)) {
          return { acquired: false, expiresAt: null };
        }
        logger?.error(`wazuh-alert-manager lease ${leaseId}: failed to create lease doc: ${createErr.message}`);
        return { acquired: false, expiresAt: null };
      }
    }
    logger?.error(`wazuh-alert-manager lease ${leaseId}: failed to read lease doc: ${e.message}`);
    return { acquired: false, expiresAt: null };
  }

  const source = current?.body?._source || {};
  const isOwnHolder = source.holder_id === holder;
  const isExpired = !source.expires_at || new Date(source.expires_at).getTime() <= now;

  // Someone else holds a fresh lease - don't contend for it.
  if (!isOwnHolder && !isExpired) {
    return { acquired: false, expiresAt: String(source.expires_at) };
  }

  try {
    await client.update({
      index,
      id,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc },
    });
    return { acquired: true, expiresAt: doc.expires_at };
  } catch (e: any) {
    // Another replica renewed or stole the lease between our get and update.
    if (isConflict(e)) {
      return { acquired: false, expiresAt: null };
    }
    logger?.error(`wazuh-alert-manager lease ${leaseId}: failed to update lease doc: ${e.message}`);
    return { acquired: false, expiresAt: null };
  }
}

/**
 * Best-effort release on shutdown so the lease doesn't sit idle for the full
 * TTL. Deletes only when this holder still owns the doc, guarded by
 * if_seq_no/if_primary_term. Never throws; returns true only when the doc
 * was removed by this call.
 */
export async function releaseLease(client: any, options: ReleaseLeaseOptions): Promise<boolean> {
  const { leaseId, holder, logger } = options;
  try {
    const id = leaseDocId(leaseId);
    const index = assertManagedWriteTarget(META_INDEX);
    const current: any = await client.get({ index, id });
    const source = current?.body?._source || {};
    if (source.holder_id !== holder) {
      return false;
    }
    await client.delete({
      index,
      id,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
    });
    return true;
  } catch (e: any) {
    logger?.debug(`wazuh-alert-manager lease ${leaseId}: release skipped: ${e.message}`);
    return false;
  }
}
