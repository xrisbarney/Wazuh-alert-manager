import * as os from 'os';
import * as crypto from 'crypto';
import { Logger } from '../../../../src/core/server';
import { META_INDEX } from '../../common';

export const SYNC_LOCK_DOC_ID = 'sync_lock';

/**
 * Unique per-process identity for the sync lock. Generated once when the
 * sync job starts, not per tick, so a holder's renewals/steals are
 * recognizable as coming from the same process across the job's lifetime.
 */
export function generateHolderId(): string {
  return `${os.hostname()}-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
}

interface LockDoc {
  holder_id: string;
  expires_at: string;
  updated_at: string;
}

/**
 * Acquires or renews the single sync-job lease so only one dashboard
 * replica actively runs the sync tick at a time. Mutual exclusion comes
 * from OpenSearch's optimistic concurrency control (create's built-in
 * conflict check, and if_seq_no/if_primary_term on update) - the
 * expires_at/ttl handling below only decides how soon a lock abandoned by a
 * crashed/stopped holder gets reclaimed, so clock drift between replicas
 * can't cause two holders to both believe they hold the lock at once.
 */
export async function acquireOrRenewLock(
  client: any,
  holderId: string,
  ttlSeconds: number,
  logger: Logger
): Promise<boolean> {
  const now = Date.now();
  const doc: LockDoc = {
    holder_id: holderId,
    expires_at: new Date(now + ttlSeconds * 1000).toISOString(),
    updated_at: new Date(now).toISOString(),
  };

  let current: any;
  try {
    current = await client.get({ index: META_INDEX, id: SYNC_LOCK_DOC_ID });
  } catch (e: any) {
    if (e?.meta?.statusCode === 404) {
      try {
        await client.create({ index: META_INDEX, id: SYNC_LOCK_DOC_ID, body: doc });
        return true;
      } catch (createErr: any) {
        // Another replica created the doc first - it holds the lock this round.
        if (createErr?.meta?.statusCode === 409) {
          return false;
        }
        logger.error(`wazuh-alert-manager sync lock: failed to create lock doc: ${createErr.message}`);
        return false;
      }
    }
    logger.error(`wazuh-alert-manager sync lock: failed to read lock doc: ${e.message}`);
    return false;
  }

  const source = current?.body?._source || {};
  const isOwnHolder = source.holder_id === holderId;
  const isExpired = !source.expires_at || new Date(source.expires_at).getTime() <= now;

  // Someone else holds a fresh lock - don't contend for it.
  if (!isOwnHolder && !isExpired) {
    return false;
  }

  try {
    await client.update({
      index: META_INDEX,
      id: SYNC_LOCK_DOC_ID,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
      body: { doc },
    });
    return true;
  } catch (e: any) {
    // Another replica renewed or stole the lock between our get and update.
    if (e?.meta?.statusCode === 409) {
      return false;
    }
    logger.error(`wazuh-alert-manager sync lock: failed to update lock doc: ${e.message}`);
    return false;
  }
}

/**
 * Best-effort release on shutdown so the lock doesn't sit idle for the full
 * TTL. Never throws - if this fails for any reason, the lock simply expires
 * naturally and another replica reclaims it once the TTL elapses.
 */
export async function releaseLock(client: any, holderId: string, logger: Logger): Promise<void> {
  try {
    const current: any = await client.get({ index: META_INDEX, id: SYNC_LOCK_DOC_ID });
    const source = current?.body?._source || {};
    if (source.holder_id !== holderId) {
      return;
    }
    await client.delete({
      index: META_INDEX,
      id: SYNC_LOCK_DOC_ID,
      if_seq_no: current.body._seq_no,
      if_primary_term: current.body._primary_term,
    });
  } catch (e: any) {
    logger.debug(`wazuh-alert-manager sync lock: release skipped: ${e.message}`);
  }
}
