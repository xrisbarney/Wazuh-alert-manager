import { META_INDEX } from '../../common';
import { acquireOrRenewLease, holderId, leaseDocId, releaseLease } from './lease';

const NOW = Date.parse('2026-11-20T10:00:00.000Z');
const TTL_MS = 60_000;

function notFound() {
  return { meta: { statusCode: 404 }, message: 'not found' };
}

function conflict() {
  return { meta: { statusCode: 409 }, message: 'version conflict' };
}

function storedLease(holder: string, expiresAt: string, seqNo = 7, primaryTerm = 2) {
  return {
    body: {
      _seq_no: seqNo,
      _primary_term: primaryTerm,
      _source: {
        document_type: 'lease',
        lease_id: 'sla-escalation',
        holder_id: holder,
        expires_at: expiresAt,
        updated_at: expiresAt,
      },
    },
  };
}

function mockLogger() {
  return { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() } as any;
}

describe('generic lease', () => {
  test('holderId is stable in shape and unique per call', () => {
    const a = holderId();
    const b = holderId();
    expect(a).toMatch(/^.+-\d+-[0-9a-f]{8}$/);
    expect(a).not.toBe(b);
  });

  test('leaseDocId namespaces the doc and refuses unsafe ids', () => {
    expect(leaseDocId('sla-escalation')).toBe('lease:sla-escalation');
    expect(leaseDocId('report-schedules:1')).toBe('lease:report-schedules:1');
    for (const bad of ['', ' ', 'a b', 'a,b', 'a*', 'a/b']) {
      expect(() => leaseDocId(bad)).toThrow(/Invalid lease id/);
    }
  });

  test('creates the lease doc on the meta index when none exists', async () => {
    const client = {
      get: jest.fn(async () => {
        throw notFound();
      }),
      create: jest.fn(async () => ({ body: { result: 'created' } })),
      update: jest.fn(),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result).toEqual({ acquired: true, expiresAt: new Date(NOW + TTL_MS).toISOString() });
    expect(client.create).toHaveBeenCalledWith({
      index: META_INDEX,
      id: 'lease:sla-escalation',
      body: {
        document_type: 'lease',
        lease_id: 'sla-escalation',
        holder_id: 'host-1-aaaa',
        expires_at: new Date(NOW + TTL_MS).toISOString(),
        updated_at: new Date(NOW).toISOString(),
      },
    });
    expect(client.update).not.toHaveBeenCalled();
  });

  test('loses the create race when another replica created the doc first', async () => {
    const client = {
      get: jest.fn(async () => {
        throw notFound();
      }),
      create: jest.fn(async () => {
        throw conflict();
      }),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result).toEqual({ acquired: false, expiresAt: null });
  });

  test('renews its own fresh lease with optimistic concurrency', async () => {
    const stillFresh = new Date(NOW + 30_000).toISOString();
    const client = {
      get: jest.fn(async () => storedLease('host-1-aaaa', stillFresh, 11, 3)),
      create: jest.fn(),
      update: jest.fn(async () => ({ body: { result: 'updated' } })),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result).toEqual({ acquired: true, expiresAt: new Date(NOW + TTL_MS).toISOString() });
    expect(client.create).not.toHaveBeenCalled();
    const update = client.update.mock.calls[0][0] as any;
    expect(update.index).toBe(META_INDEX);
    expect(update.id).toBe('lease:sla-escalation');
    expect(update.if_seq_no).toBe(11);
    expect(update.if_primary_term).toBe(3);
    expect(update.body.doc.holder_id).toBe('host-1-aaaa');
    expect(update.body.doc.expires_at).toBe(new Date(NOW + TTL_MS).toISOString());
  });

  test('does not contend for a fresh lease held by another replica', async () => {
    const theirs = new Date(NOW + 30_000).toISOString();
    const client = {
      get: jest.fn(async () => storedLease('host-2-bbbb', theirs)),
      create: jest.fn(),
      update: jest.fn(),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result).toEqual({ acquired: false, expiresAt: theirs });
    expect(client.update).not.toHaveBeenCalled();
    expect(client.create).not.toHaveBeenCalled();
  });

  test('steals an expired lease from a dead holder', async () => {
    const expired = new Date(NOW - 1).toISOString();
    const client = {
      get: jest.fn(async () => storedLease('host-2-bbbb', expired, 5, 1)),
      update: jest.fn(async () => ({ body: { result: 'updated' } })),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result.acquired).toBe(true);
    const update = client.update.mock.calls[0][0] as any;
    expect(update.if_seq_no).toBe(5);
    expect(update.if_primary_term).toBe(1);
    expect(update.body.doc.holder_id).toBe('host-1-aaaa');
  });

  test('treats a doc without expires_at as expired', async () => {
    const client = {
      get: jest.fn(async () => ({
        body: { _seq_no: 1, _primary_term: 1, _source: { holder_id: 'host-2-bbbb' } },
      })),
      update: jest.fn(async () => ({ body: { result: 'updated' } })),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result.acquired).toBe(true);
  });

  test('loses the update race on a version conflict', async () => {
    const expired = new Date(NOW - 1).toISOString();
    const client = {
      get: jest.fn(async () => storedLease('host-2-bbbb', expired)),
      update: jest.fn(async () => {
        throw conflict();
      }),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
    });
    expect(result).toEqual({ acquired: false, expiresAt: null });
  });

  test('reports unexpected OpenSearch failures as not acquired and logs them', async () => {
    const logger = mockLogger();
    const client = {
      get: jest.fn(async () => {
        throw { meta: { statusCode: 503 }, message: 'cluster unavailable' };
      }),
    };
    const result = await acquireOrRenewLease(client, {
      leaseId: 'sla-escalation',
      holder: 'host-1-aaaa',
      ttlMs: TTL_MS,
      now: NOW,
      logger,
    });
    expect(result).toEqual({ acquired: false, expiresAt: null });
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('failed to read lease doc'));
  });

  test('rejects invalid arguments before touching OpenSearch', async () => {
    const client = { get: jest.fn(), create: jest.fn(), update: jest.fn() };
    await expect(
      acquireOrRenewLease(client, { leaseId: 'a b', holder: 'h', ttlMs: TTL_MS })
    ).rejects.toThrow(/Invalid lease id/);
    await expect(
      acquireOrRenewLease(client, { leaseId: 'ok', holder: '', ttlMs: TTL_MS })
    ).rejects.toThrow(/holder id is required/);
    await expect(acquireOrRenewLease(client, { leaseId: 'ok', holder: 'h', ttlMs: 0 })).rejects.toThrow(
      /ttlMs/
    );
    expect(client.get).not.toHaveBeenCalled();
  });

  test('independent lease ids do not share a doc', async () => {
    const client = {
      get: jest.fn(async () => {
        throw notFound();
      }),
      create: jest.fn(async () => ({ body: { result: 'created' } })),
    };
    await acquireOrRenewLease(client, { leaseId: 'sla-escalation', holder: 'h', ttlMs: TTL_MS, now: NOW });
    await acquireOrRenewLease(client, { leaseId: 'report-schedules', holder: 'h', ttlMs: TTL_MS, now: NOW });
    const ids = client.create.mock.calls.map(([req]: any[]) => req.id);
    expect(ids).toEqual(['lease:sla-escalation', 'lease:report-schedules']);
  });

  test('release deletes only an owned lease, guarded by seq_no/primary_term', async () => {
    const fresh = new Date(NOW + 30_000).toISOString();
    const client = {
      get: jest.fn(async () => storedLease('host-1-aaaa', fresh, 9, 4)),
      delete: jest.fn(async () => ({ body: { result: 'deleted' } })),
    };
    expect(await releaseLease(client, { leaseId: 'sla-escalation', holder: 'host-1-aaaa' })).toBe(true);
    expect(client.delete).toHaveBeenCalledWith({
      index: META_INDEX,
      id: 'lease:sla-escalation',
      if_seq_no: 9,
      if_primary_term: 4,
    });
  });

  test('release leaves another holder\'s lease alone', async () => {
    const fresh = new Date(NOW + 30_000).toISOString();
    const client = {
      get: jest.fn(async () => storedLease('host-2-bbbb', fresh)),
      delete: jest.fn(),
    };
    expect(await releaseLease(client, { leaseId: 'sla-escalation', holder: 'host-1-aaaa' })).toBe(false);
    expect(client.delete).not.toHaveBeenCalled();
  });

  test('release never throws', async () => {
    const logger = mockLogger();
    const client = {
      get: jest.fn(async () => {
        throw notFound();
      }),
      delete: jest.fn(),
    };
    expect(await releaseLease(client, { leaseId: 'sla-escalation', holder: 'host-1-aaaa', logger })).toBe(false);
    expect(client.delete).not.toHaveBeenCalled();
    expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('release skipped'));
  });
});
