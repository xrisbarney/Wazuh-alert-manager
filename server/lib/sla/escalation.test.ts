import {
  ACTIVITY_WRITE_ALIAS,
  ALERTS_READ_ALIAS,
  CASES_READ_ALIAS,
  META_INDEX,
  SLA_ESCALATION_ACTOR,
  SLA_ESCALATION_LEASE_ID,
  SLA_ESCALATION_MAX_ACTIONS_PER_TICK,
  SLA_ESCALATION_STATUS_DOC_ID,
} from '../../../common';
import type { SlaEscalation, SlaPolicy } from '../../../common';
import {
  applyEscalation,
  bandClause,
  breachActivityId,
  breachQuery,
  escalationActivityId,
  escalationQuery,
  getSlaEscalationRuntime,
  nextSeverityBand,
  readSlaEscalationStatus,
  renderEscalationTemplate,
  runBreachPass,
  sanitizeScannerError,
  setSlaEscalationRuntime,
  SLA_ESCALATION_LEASE_RENEW_EVERY,
  slaEscalationLeaseTtlMs,
  startSlaEscalationScanner,
  thresholdInstant,
  tickSlaEscalation,
  TOUCHED_HISTORY_CLAUSE,
  UNASSIGNED_CLAUSE,
} from './escalation';

const ALERT_INDEX = 'wazuh-alert-status-v2-000001';
const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';
const ACTIVITY_INDEX = 'wazuh-alert-manager-v2-activity-000001';
const NOW = '2026-11-21T12:00:00.000Z';
const HOLDER = 'test-holder';
const TTL = 180000;

const policy: SlaPolicy = {
  targets: {
    critical: { resolveMinutes: 60, assignMinutes: 15 },
    high: { resolveMinutes: 240, assignMinutes: 60 },
    medium: { resolveMinutes: 1440, assignMinutes: 360 },
    low: { resolveMinutes: 4320, assignMinutes: 1080 },
  },
  escalations: [],
};

const minutesAgo = (minutes: number) => new Date(Date.parse(NOW) - minutes * 60000).toISOString();
const minutesAhead = (minutes: number) => new Date(Date.parse(NOW) + minutes * 60000).toISOString();

// ---------------------------------------------------------------------------
// In-memory client: a minimal query evaluator for the clauses the scanner
// builds, plus a painless stand-in that applies the scanner's scripts by
// their params (breach_now / escalation_id + entries / marker).
// ---------------------------------------------------------------------------

function getPath(doc: any, path: string): any {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), doc);
}

function comparable(value: any): number {
  if (typeof value === 'number') return value;
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : Number(value);
}

function matches(doc: any, q: any): boolean {
  if (q.bool) {
    const b = q.bool;
    const list = (x: any) => (x == null ? [] : Array.isArray(x) ? x : [x]);
    for (const c of list(b.filter)) if (!matches(doc, c)) return false;
    for (const c of list(b.must)) if (!matches(doc, c)) return false;
    for (const c of list(b.must_not)) if (matches(doc, c)) return false;
    const should = list(b.should);
    if (should.length) {
      const hasOther = list(b.filter).length || list(b.must).length || list(b.must_not).length;
      const min = b.minimum_should_match ?? (hasOther ? 0 : 1);
      if (min > 0 && !should.some((c: any) => matches(doc, c))) return false;
    }
    return true;
  }
  if (q.term) {
    const [field, raw] = Object.entries<any>(q.term)[0];
    const value = raw && typeof raw === 'object' && 'value' in raw ? raw.value : raw;
    const actual = getPath(doc, field);
    return Array.isArray(actual) ? actual.includes(value) : actual === value;
  }
  if (q.terms) {
    const [field, values] = Object.entries<any>(q.terms)[0];
    const actual = getPath(doc, field);
    const arr = Array.isArray(actual) ? actual : [actual];
    return arr.some((a) => values.includes(a));
  }
  if (q.exists) {
    const actual = getPath(doc, q.exists.field);
    return actual !== undefined && actual !== null && !(Array.isArray(actual) && actual.length === 0);
  }
  if (q.range) {
    const [field, r] = Object.entries<any>(q.range)[0];
    const actual = getPath(doc, field);
    if (actual == null) return false;
    const n = comparable(actual);
    if (r.gte != null && !(n >= comparable(r.gte))) return false;
    if (r.lte != null && !(n <= comparable(r.lte))) return false;
    if (r.gt != null && !(n > comparable(r.gt))) return false;
    if (r.lt != null && !(n < comparable(r.lt))) return false;
    return true;
  }
  if (q.nested) {
    const items = getPath(doc, q.nested.path) || [];
    return items.some((item: any) => matches({ [q.nested.path]: item }, q.nested.query));
  }
  throw new Error(`unsupported clause ${JSON.stringify(q)}`);
}

function notFound() {
  return Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
}
function conflict() {
  return Object.assign(new Error('conflict'), { meta: { statusCode: 409 } });
}

interface Stored {
  index: string;
  id: string;
  source: any;
  seq: number;
}

interface ClientOptions {
  leaseHeldBy?: string;
  /** Doc ids whose scripted update must fail with this error (mutable: delete a key to let the next tick succeed). */
  failUpdates?: Record<string, { status: number; reason: string }>;
}

function makeClient(opts: ClientOptions = {}) {
  const docs = new Map<string, Stored>();
  const key = (index: string, id: string) => `${index}::${id}`;
  const put = (index: string, id: string, source: any) => {
    const existing = docs.get(key(index, id));
    docs.set(key(index, id), { index, id, source, seq: (existing?.seq ?? 0) + 1 });
  };
  const resolveIndex = (index: string) => (index === ACTIVITY_WRITE_ALIAS ? ACTIVITY_INDEX : index);
  const family = (index: string) => {
    if (index === ALERTS_READ_ALIAS) return (d: Stored) => d.index.startsWith('wazuh-alert-status-v2-');
    if (index === CASES_READ_ALIAS) return (d: Stored) => d.index.startsWith('wazuh-alert-manager-v2-cases-');
    return (d: Stored) => d.index === index;
  };
  if (opts.leaseHeldBy) {
    put(META_INDEX, `lease:${SLA_ESCALATION_LEASE_ID}`, {
      document_type: 'lease',
      lease_id: SLA_ESCALATION_LEASE_ID,
      holder_id: opts.leaseHeldBy,
      expires_at: minutesAhead(5),
      updated_at: NOW,
    });
  }

  const applyScript = (stored: Stored, script: any): 'updated' | 'noop' => {
    const src = stored.source;
    const params = script.params || {};
    const pushHistory = (entries: any[]) => {
      if (!src.history) src.history = [];
      src.history.push(...entries);
    };
    if (params.breach_now !== undefined) {
      if (!src.sla) src.sla = {};
      if (src.sla.breached_at != null) return 'noop';
      src.sla.breached_at = params.breach_now;
      pushHistory([params.entry]);
      return 'updated';
    }
    if (script.source.includes('escalated.add')) {
      if (!src.sla) src.sla = {};
      if (!src.sla.escalated) src.sla.escalated = [];
      if (src.sla.escalated.includes(params.escalation_id)) return 'noop';
      src.sla.escalated.push(params.escalation_id);
      pushHistory(params.entries);
      return 'updated';
    }
    if (params.escalation_id !== undefined) {
      // ESCALATION_GUARD: closed, marked, condition no longer met, or the value already set.
      if (src.status === 'closed') return 'noop';
      if (src.sla?.escalated?.includes(params.escalation_id)) return 'noop';
      if (params.require_unassigned === true && src.assigned_to != null && src.assigned_to !== '') return 'noop';
      if (params.require_open === true && src.status !== 'open') return 'noop';
      if (params.fields?.assigned_to != null && src.assigned_to === params.fields.assigned_to) return 'noop';
      if (params.fields?.severity != null && src.severity === params.fields.severity) return 'noop';
      pushHistory(params.entries);
      if (params.fields) Object.assign(src, params.fields);
      if (script.source.includes('ctx._source.reporting')) {
        if (!src.reporting) src.reporting = {};
        if (params.reporting) Object.assign(src.reporting, params.reporting);
      }
      return 'updated';
    }
    throw new Error(`unknown script ${script.source.slice(0, 60)}`);
  };

  // `freezeSearch()` makes every later search evaluate a snapshot of the
  // documents as they are now: what a real search sees within one tick when
  // the action writes are not refreshed.
  let frozen: Map<string, Stored> | null = null;
  const searchable = () => frozen || docs;

  const client: any = {
    docs,
    put,
    freezeSearch: () => {
      frozen = new Map(Array.from(docs.entries()).map(([k, d]) => [k, { ...d, source: JSON.parse(JSON.stringify(d.source)) }]));
    },
    get: jest.fn(async ({ index, id }: any) => {
      const stored = docs.get(key(resolveIndex(index), id));
      if (!stored) throw notFound();
      return { body: { _id: id, _index: stored.index, _source: stored.source, _seq_no: stored.seq, _primary_term: 1 } };
    }),
    create: jest.fn(async ({ index, id, body }: any) => {
      if (docs.has(key(resolveIndex(index), id))) throw conflict();
      put(resolveIndex(index), id, body);
      return { body: { result: 'created' } };
    }),
    index: jest.fn(async ({ index, id, body, op_type }: any) => {
      const target = resolveIndex(index);
      const docId = id || `auto-${docs.size + 1}`;
      if (op_type === 'create' && docs.has(key(target, docId))) throw conflict();
      put(target, docId, body);
      return { body: { _id: docId, result: 'created' } };
    }),
    delete: jest.fn(async ({ index, id }: any) => {
      docs.delete(key(resolveIndex(index), id));
      return { body: { result: 'deleted' } };
    }),
    update: jest.fn(async ({ index, id, body }: any) => {
      const stored = docs.get(key(resolveIndex(index), id));
      if (!stored) throw notFound();
      if (body.doc) {
        Object.assign(stored.source, body.doc);
        stored.seq += 1;
        return { body: { result: 'updated' } };
      }
      const failure = opts.failUpdates?.[id];
      if (failure) throw Object.assign(new Error(failure.reason), { meta: { statusCode: failure.status } });
      const result = applyScript(stored, body.script);
      if (result === 'updated') stored.seq += 1;
      return { body: { result } };
    }),
    bulk: jest.fn(async ({ body }: any) => {
      const items: any[] = [];
      for (let i = 0; i < body.length; i += 2) {
        const [op, payload] = [body[i], body[i + 1]];
        if (op.update) {
          const stored = docs.get(key(resolveIndex(op.update._index), op.update._id));
          const failure = opts.failUpdates?.[op.update._id];
          if (!stored) items.push({ update: { status: 404, error: { type: 'document_missing_exception', reason: 'missing' } } });
          else if (failure) items.push({ update: { status: failure.status, error: { type: 'failure', reason: failure.reason } } });
          else {
            const result = applyScript(stored, payload.script);
            if (result === 'updated') stored.seq += 1;
            items.push({ update: { status: 200, result } });
          }
        } else if (op.create) {
          const target = resolveIndex(op.create._index);
          if (docs.has(key(target, op.create._id))) items.push({ create: { status: 409, error: { type: 'version_conflict_engine_exception', reason: 'exists' } } });
          else {
            put(target, op.create._id, payload);
            items.push({ create: { status: 201, result: 'created' } });
          }
        } else {
          throw new Error(`unsupported bulk op ${JSON.stringify(op)}`);
        }
      }
      return { body: { errors: items.some((item) => (item.update || item.create)?.error), items } };
    }),
    search: jest.fn(async ({ index, body }: any) => {
      const inFamily = family(index);
      let hits = Array.from(searchable().values()).filter((d) => inFamily(d) && matches(d.source, body.query));
      const sort: Array<[string, string]> = (body.sort || []).map((entry: any) => {
        const [field, spec] = Object.entries<any>(entry)[0];
        return [field, spec.order || 'asc'];
      });
      const sortValues = (d: Stored) => sort.map(([field]) => getPath(d.source, field));
      const cmp = (a: Stored, b: Stored) => {
        for (let i = 0; i < sort.length; i += 1) {
          const [, order] = sort[i];
          const av = sortValues(a)[i];
          const bv = sortValues(b)[i];
          if (av === bv) continue;
          const diff = String(av) < String(bv) ? -1 : 1;
          return order === 'asc' ? diff : -diff;
        }
        return 0;
      };
      hits.sort(cmp);
      if (body.search_after) {
        const after = { source: Object.fromEntries(sort.map(([field], i) => [field, body.search_after[i]])) } as Stored;
        const flat = (d: Stored) => ({ ...d, source: Object.fromEntries(sort.map(([field]) => [field, getPath(d.source, field)])) });
        hits = hits.filter((d) => cmp(flat(d), after) > 0);
      }
      hits = hits.slice(0, body.size);
      return { body: { hits: { hits: hits.map((d) => ({ _id: d.id, _index: d.index, _source: d.source, sort: sortValues(d) })) } } };
    }),
  };
  return client;
}

function alertDoc(id: string, overrides: any = {}) {
  const timestamp = overrides['@timestamp'] || minutesAgo(10);
  return {
    alert_uid: id,
    '@timestamp': timestamp,
    status: 'open',
    rule: { id: '1', level: 7, description: 'rule' },
    reporting: { sla_due_at: minutesAhead(230), assign_due_at: minutesAhead(50) },
    ...overrides,
  };
}

function caseDoc(id: string, overrides: any = {}) {
  const created = overrides.created_at || minutesAgo(10);
  return {
    case_uid: id,
    title: `case ${id}`,
    severity: 'high',
    status: 'open',
    created_at: created,
    created_by: 'alice',
    sla_due_at: minutesAhead(230),
    history: [{ timestamp: created, user: 'alice', action: 'case_created', from: null, to: null }],
    ...overrides,
  };
}

function activityDocs(client: any, predicate: (source: any, id: string) => boolean = () => true) {
  return Array.from(client.docs.values() as Iterable<Stored>)
    .filter((d) => d.index === ACTIVITY_INDEX && predicate(d.source, d.id))
    .map((d) => ({ id: d.id, ...d.source }));
}

const tick = (client: any, extra: Partial<Parameters<typeof tickSlaEscalation>[1]> = {}) =>
  tickSlaEscalation(client, { holder: HOLDER, ttlMs: TTL, now: new Date(NOW), policy, ...extra });

const escalation = (overrides: Partial<SlaEscalation> = {}): SlaEscalation => ({
  id: 'first-response',
  name: 'First response',
  target: 'alert',
  thresholdPercent: 50,
  condition: 'unassigned',
  actions: { assignTo: 'bob' },
  enabled: true,
  ...overrides,
});

// ---------------------------------------------------------------------------

test('the runtime starts as "not started" (enabled null) until the scanner records its config', () => {
  expect(getSlaEscalationRuntime()).toEqual({ enabled: null, tickSeconds: 60 });
});

describe('breach pass', () => {
  test('stamps every newly breached alert and case once, with one history row and one activity event, across two ticks', async () => {
    const client = makeClient();
    client.put(ALERT_INDEX, 'a-breached', alertDoc('a-breached', { reporting: { sla_due_at: minutesAgo(1) }, updated_at: minutesAgo(20) }));
    client.put(ALERT_INDEX, 'a-in-progress', alertDoc('a-in-progress', { status: 'in_progress', reporting: { sla_due_at: minutesAgo(5) } }));
    client.put(ALERT_INDEX, 'a-future', alertDoc('a-future', { reporting: { sla_due_at: minutesAhead(1) } }));
    client.put(ALERT_INDEX, 'a-closed', alertDoc('a-closed', { status: 'closed', reporting: { sla_due_at: minutesAgo(60) } }));
    client.put(ALERT_INDEX, 'a-already', alertDoc('a-already', { reporting: { sla_due_at: minutesAgo(60) }, sla: { breached_at: minutesAgo(30) } }));
    client.put(CASE_INDEX, 'c-breached', caseDoc('c-breached', { sla_due_at: minutesAgo(1) }));
    client.put(CASE_INDEX, 'c-closed', caseDoc('c-closed', { status: 'closed', sla_due_at: minutesAgo(1) }));

    const first = await tick(client);
    expect(first.acquired).toBe(true);
    expect(first.breachedAlerts).toBe(2);
    expect(first.breachedCases).toBe(1);
    expect(first.errors).toEqual([]);

    const breached = client.docs.get(`${ALERT_INDEX}::a-breached`).source;
    expect(breached.sla.breached_at).toBe(NOW);
    expect(breached.updated_at).toBe(minutesAgo(20)); // the stamp never touches updated_at
    expect(breached.history).toEqual([
      expect.objectContaining({ user: SLA_ESCALATION_ACTOR, action: 'sla_breached', to: minutesAgo(1) }),
    ]);
    expect(client.docs.get(`${ALERT_INDEX}::a-future`).source.sla).toBeUndefined();
    expect(client.docs.get(`${ALERT_INDEX}::a-closed`).source.sla).toBeUndefined();
    expect(client.docs.get(`${ALERT_INDEX}::a-already`).source.history).toBeUndefined();
    expect(client.docs.get(`${CASE_INDEX}::c-breached`).source.sla.breached_at).toBe(NOW);

    const events = activityDocs(client, (s) => s.action === 'sla_breached');
    expect(events.map((e) => e.id).sort()).toEqual([breachActivityId('a-breached'), breachActivityId('a-in-progress'), breachActivityId('c-breached')]);
    expect(events.find((e) => e.id === breachActivityId('c-breached'))).toEqual(
      expect.objectContaining({ target_type: 'case', case_id: 'c-breached', user: SLA_ESCALATION_ACTOR, source: 'sla', timestamp: NOW })
    );

    const second = await tick(client);
    expect(second.breachedAlerts).toBe(0);
    expect(second.breachedCases).toBe(0);
    expect(activityDocs(client, (s) => s.action === 'sla_breached')).toHaveLength(3);
    expect(client.docs.get(`${ALERT_INDEX}::a-breached`).source.history).toHaveLength(1);
  });

  test('a failed stamp is reported without stopping the others; its event (written first) stays and the next tick finishes the stamp without a second event', async () => {
    const failUpdates: Record<string, { status: number; reason: string }> = { 'a-bad': { status: 500, reason: 'shard failure' } };
    const client = makeClient({ failUpdates });
    client.put(ALERT_INDEX, 'a-bad', alertDoc('a-bad', { reporting: { sla_due_at: minutesAgo(1) } }));
    client.put(ALERT_INDEX, 'a-ok', alertDoc('a-ok', { reporting: { sla_due_at: minutesAgo(1) } }));
    const result = await runBreachPass(client, 'alert', NOW);
    expect(result.marked).toBe(1);
    expect(result.failures).toBe(1);
    expect(result.errors).toEqual(['alert a-bad: shard failure']);
    expect(result.reported).toEqual(['alert a-bad: failure (HTTP 500)']); // what the status doc gets: no raw reason
    expect(activityDocs(client, (s) => s.action === 'sla_breached').map((e) => e.id).sort()).toEqual([breachActivityId('a-bad'), breachActivityId('a-ok')]);
    expect(client.docs.get(`${ALERT_INDEX}::a-bad`).source.sla).toBeUndefined();

    delete failUpdates['a-bad'];
    const again = await runBreachPass(client, 'alert', NOW);
    expect(again.marked).toBe(1);
    expect(again.errors).toEqual([]);
    expect(client.docs.get(`${ALERT_INDEX}::a-bad`).source.sla.breached_at).toBe(NOW);
    expect(activityDocs(client, (s) => s.action === 'sla_breached')).toHaveLength(2);
  });

  test('a failed activity bulk leaves the record unstamped (so it is retried), and the next tick writes the event and the stamp once', async () => {
    const client = makeClient();
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { reporting: { sla_due_at: minutesAgo(1) } }));
    const bulk = client.bulk;
    client.bulk = jest.fn(async (req: any) => {
      if (req.body[0]?.create) throw Object.assign(new Error('activity index unavailable'), { meta: { statusCode: 503, body: { error: { type: 'cluster_block_exception' } } } });
      return bulk(req);
    });
    const first = await tick(client);
    expect(first.breachedAlerts).toBe(0);
    expect(first.errors).toEqual(['breach pass (alerts): activity index unavailable']);
    expect(first.reported).toEqual(['breach pass (alerts): cluster_block_exception (HTTP 503)']);
    expect(client.docs.get(`${ALERT_INDEX}::a1`).source.sla).toBeUndefined();
    expect(activityDocs(client)).toHaveLength(0);
    expect((await readSlaEscalationStatus(client))?.errors).toEqual([{ at: NOW, message: 'breach pass (alerts): cluster_block_exception (HTTP 503)' }]);

    client.bulk = bulk;
    const second = await tick(client);
    expect(second.breachedAlerts).toBe(1);
    expect(client.docs.get(`${ALERT_INDEX}::a1`).source.sla.breached_at).toBe(NOW);
    expect(activityDocs(client, (s) => s.action === 'sla_breached').map((e) => e.id)).toEqual([breachActivityId('a1')]);

    // A bulk item failure on the activity create: the record is not stamped either.
    const client2 = makeClient();
    client2.put(ALERT_INDEX, 'a2', alertDoc('a2', { reporting: { sla_due_at: minutesAgo(1) } }));
    const bulk2 = client2.bulk;
    client2.bulk = jest.fn(async (req: any) => {
      if (req.body[0]?.create) return { body: { errors: true, items: [{ create: { status: 429, error: { type: 'es_rejected_execution_exception', reason: 'queue full on node x' } } }] } };
      return bulk2(req);
    });
    const result = await runBreachPass(client2, 'alert', NOW);
    expect(result.marked).toBe(0);
    expect(result.errors).toEqual([`activity ${breachActivityId('a2')}: queue full on node x`]);
    expect(result.reported).toEqual([`activity ${breachActivityId('a2')}: es_rejected_execution_exception (HTTP 429)`]);
    expect(client2.docs.get(`${ALERT_INDEX}::a2`).source.sla).toBeUndefined();
  });

  test('per-record failures are logged as one aggregated line per pass and capped in the result', async () => {
    const failUpdates: Record<string, { status: number; reason: string }> = {};
    const client = makeClient({ failUpdates });
    for (let i = 0; i < 12; i += 1) {
      const id = `a-bad-${String(i).padStart(2, '0')}`;
      failUpdates[id] = { status: 403, reason: `index [wazuh-alert-status-v2-000001] blocked by: [FORBIDDEN/8/index write (api)] ${i}` };
      client.put(ALERT_INDEX, id, alertDoc(id, { reporting: { sla_due_at: minutesAgo(1) } }));
    }
    const logger: any = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    const result = await tick(client, { logger });
    expect(result.failures).toBe(12);
    expect(result.errors).toHaveLength(10);
    expect(result.reported).toHaveLength(10);
    expect(result.reported[0]).toBe('alert a-bad-00: failure (HTTP 403)');
    expect(result.reported.join(' ')).not.toContain('wazuh-alert-status-v2');
    const warnings = logger.warn.mock.calls.map(([line]: any[]) => line);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^wazuh-alert-manager sla escalation: breach pass \(alerts\): 12 record failure\(s\), first: alert a-bad-00: index \[wazuh-alert-status-v2-000001\]/);
    const status = await readSlaEscalationStatus(client);
    expect(status?.errors).toHaveLength(10);
    expect(status?.errors.every((e) => !e.message.includes('wazuh-alert-status-v2'))).toBe(true);
  });

  test('cases written before 3.2 (no sla_due_at) breach by created_at plus the band resolve target when the policy is given', async () => {
    const client = makeClient();
    client.put(CASE_INDEX, 'c-old', caseDoc('c-old', { created_at: minutesAgo(300), sla_due_at: undefined }));
    client.put(CASE_INDEX, 'c-young', caseDoc('c-young', { created_at: minutesAgo(100), sla_due_at: undefined }));
    client.put(CASE_INDEX, 'c-low-old', caseDoc('c-low-old', { created_at: minutesAgo(300), severity: 'low', sla_due_at: undefined }));
    const result = await runBreachPass(client, 'case', NOW, policy);
    expect(result.marked).toBe(1);
    const old = client.docs.get(`${CASE_INDEX}::c-old`).source;
    expect(old.sla.breached_at).toBe(NOW);
    expect(old.history[1]).toEqual(expect.objectContaining({ action: 'sla_breached', to: minutesAgo(60) })); // created_at + 240 min
    expect(client.docs.get(`${CASE_INDEX}::c-young`).source.sla).toBeUndefined();
    expect(client.docs.get(`${CASE_INDEX}::c-low-old`).source.sla).toBeUndefined();
    expect(activityDocs(client, (s) => s.action === 'sla_breached')).toEqual([expect.objectContaining({ case_id: 'c-old', to: minutesAgo(60) })]);
    // Without a policy (the plain query) the record is not a candidate.
    expect((await runBreachPass(makeClient(), 'case', NOW)).marked).toBe(0);
    const q = breachQuery('case', NOW, policy);
    expect(q.bool.filter[1].bool.should[0]).toEqual({ range: { sla_due_at: { lte: NOW } } });
    expect(q.bool.filter[1].bool.should[2]).toEqual({
      bool: { filter: [{ term: { severity: 'high' } }, { range: { created_at: { lte: minutesAgo(240) } } }], must_not: [{ exists: { field: 'sla_due_at' } }] },
    });
    expect(breachQuery('alert', NOW, policy)).toEqual(breachQuery('alert', NOW));
  });

  test('breachQuery: active status, due date passed, no marker', () => {
    expect(breachQuery('alert', NOW)).toEqual({
      bool: {
        filter: [{ terms: { status: ['open', 'in_progress'] } }, { range: { 'reporting.sla_due_at': { lte: NOW } } }],
        must_not: [{ exists: { field: 'sla.breached_at' } }],
      },
    });
    expect(breachQuery('case', NOW).bool.filter[0]).toEqual({ bool: { must_not: [{ term: { status: 'closed' } }] } });
    expect(breachQuery('case', NOW).bool.filter[1]).toEqual({ range: { sla_due_at: { lte: NOW } } });
  });
});

describe('escalation query', () => {
  test('one threshold instant per band from the policy, base @timestamp for alerts and created_at for cases', () => {
    expect(thresholdInstant(policy, 'critical', 50, NOW)).toBe(minutesAgo(30));
    expect(thresholdInstant(policy, 'high', 25, NOW)).toBe(minutesAgo(60));
    expect(thresholdInstant(policy, 'low', 100, NOW)).toBe(minutesAgo(4320));

    const alertQuery = escalationQuery(escalation({ condition: 'any' }), policy, NOW);
    expect(alertQuery.bool.filter[0]).toEqual({ terms: { status: ['open', 'in_progress'] } });
    const bands = alertQuery.bool.filter[1].bool.should;
    expect(bands).toHaveLength(4);
    expect(bands[0].bool.filter[0]).toEqual(bandClause('alert', 'critical'));
    expect(bands[0].bool.filter[1]).toEqual({ range: { '@timestamp': { lte: minutesAgo(30) } } });
    expect(bands[1].bool.filter[1]).toEqual({ range: { '@timestamp': { lte: minutesAgo(120) } } });
    expect(alertQuery.bool.must_not).toEqual([{ term: { 'sla.escalated': 'first-response' } }]);
    expect(alertQuery.bool.filter).toHaveLength(2);

    const caseQuery = escalationQuery(escalation({ target: 'case', condition: 'any', thresholdPercent: 100 }), policy, NOW);
    expect(caseQuery.bool.filter[1].bool.should[0].bool.filter).toEqual([
      { term: { severity: 'critical' } },
      { range: { created_at: { lte: minutesAgo(60) } } },
    ]);
  });

  test('bandClause covers 4.x levels and 5.0 labels (informational folded into low)', () => {
    const high = bandClause('alert', 'high');
    expect(high.bool.should[0]).toEqual({ range: { 'rule.level': { gte: 7, lte: 11 } } });
    expect(high.bool.should[1].bool.filter[0].terms.severity_label).toEqual(expect.arrayContaining(['high']));
    expect(high.bool.should[1].bool.must_not).toEqual([{ exists: { field: 'rule.level' } }]);
    expect(bandClause('alert', 'critical').bool.should[0]).toEqual({ range: { 'rule.level': { gte: 12 } } });
    expect(bandClause('alert', 'low').bool.should[1].bool.filter[0].terms.severity_label).toEqual(expect.arrayContaining(['low', 'informational']));
  });

  test('condition filters: unassigned, untouched (open, never assigned, no analyst history), any', () => {
    const unassigned = escalationQuery(escalation({ condition: 'unassigned' }), policy, NOW);
    expect(unassigned.bool.filter[2]).toEqual(UNASSIGNED_CLAUSE);
    expect(unassigned.bool.must_not).toHaveLength(1);

    const untouched = escalationQuery(escalation({ condition: 'untouched' }), policy, NOW);
    expect(untouched.bool.filter[2]).toEqual(UNASSIGNED_CLAUSE);
    expect(untouched.bool.filter[3]).toEqual({ term: { status: 'open' } });
    expect(untouched.bool.must_not).toEqual([
      { term: { 'sla.escalated': 'first-response' } },
      { exists: { field: 'reporting.first_assigned_at' } },
      TOUCHED_HISTORY_CLAUSE,
    ]);

    const untouchedCase = escalationQuery(escalation({ condition: 'untouched', target: 'case' }), policy, NOW);
    expect(untouchedCase.bool.must_not).toEqual([{ term: { 'sla.escalated': 'first-response' } }, TOUCHED_HISTORY_CLAUSE]);
  });

  test('candidates: threshold per band, unassigned/untouched semantics, markers respected, 5.0 label-only records', async () => {
    const client = makeClient();
    const withPolicy = { ...policy, escalations: [escalation({ condition: 'untouched', actions: { assignTo: 'bob' } })] };
    // high (level 7), 50% of 240 min = 120 min: 130 min old qualifies, 100 min does not.
    client.put(ALERT_INDEX, 'a-high-old', alertDoc('a-high-old', { '@timestamp': minutesAgo(130) }));
    client.put(ALERT_INDEX, 'a-high-young', alertDoc('a-high-young', { '@timestamp': minutesAgo(100) }));
    // critical (level 12), 50% of 60 = 30 min.
    client.put(ALERT_INDEX, 'a-crit', alertDoc('a-crit', { '@timestamp': minutesAgo(31), rule: { level: 12 } }));
    // 5.0 label-only: "High" label, no numeric level -> the high band.
    client.put(ALERT_INDEX, 'a-v5-high', alertDoc('a-v5-high', { '@timestamp': minutesAgo(130), rule: { id: 'x', level: null }, severity_label: 'high' }));
    client.put(ALERT_INDEX, 'a-v5-low', alertDoc('a-v5-low', { '@timestamp': minutesAgo(130), rule: { id: 'x', level: null }, severity_label: 'informational' }));
    // Touched / assigned / marked / closed records are skipped.
    client.put(ALERT_INDEX, 'a-assigned', alertDoc('a-assigned', { '@timestamp': minutesAgo(130), assigned_to: 'carol' }));
    client.put(ALERT_INDEX, 'a-touched', alertDoc('a-touched', { '@timestamp': minutesAgo(130), history: [{ timestamp: NOW, user: 'carol', action: 'comment_added' }] }));
    client.put(ALERT_INDEX, 'a-breach-only', alertDoc('a-breach-only', { '@timestamp': minutesAgo(130), sla: { breached_at: NOW }, history: [{ timestamp: NOW, user: SLA_ESCALATION_ACTOR, action: 'sla_breached' }] }));
    client.put(ALERT_INDEX, 'a-marked', alertDoc('a-marked', { '@timestamp': minutesAgo(130), sla: { escalated: ['first-response'] } }));
    client.put(ALERT_INDEX, 'a-progress', alertDoc('a-progress', { '@timestamp': minutesAgo(130), status: 'in_progress' }));
    client.put(ALERT_INDEX, 'a-closed', alertDoc('a-closed', { '@timestamp': minutesAgo(130), status: 'closed' }));
    client.put(ALERT_INDEX, 'a-empty-assignee', alertDoc('a-empty-assignee', { '@timestamp': minutesAgo(130), assigned_to: '' }));

    const result = await tick(client, { policy: withPolicy });
    expect(result.errors).toEqual([]);
    const escalated = Array.from(client.docs.values() as Iterable<Stored>)
      .filter((d) => d.index === ALERT_INDEX && d.source.sla?.escalated?.includes('first-response') && d.source.assigned_to === 'bob')
      .map((d) => d.id)
      .sort();
    expect(escalated).toEqual(['a-breach-only', 'a-crit', 'a-empty-assignee', 'a-high-old', 'a-v5-high']);
    expect(result.escalated).toBe(5);
  });
});

describe('escalation actions', () => {
  test('assignTo + comment + notify on an alert go through the route write shape and are idempotent across ticks', async () => {
    const client = makeClient();
    const rule = escalation({
      actions: { assignTo: 'bob', comment: 'Escalation {{escalation}} on {{id}} ({{severity}}), due {{due_at}} {{unknown}}', notify: ['chan-1', 'chan-2'] },
    });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { '@timestamp': minutesAgo(130), reporting: { sla_due_at: minutesAhead(110), assign_due_at: minutesAgo(70) } }));

    const result = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(result.escalated).toBe(1);
    const doc = client.docs.get(`${ALERT_INDEX}::a1`).source;
    expect(doc.assigned_to).toBe('bob');
    expect(doc.status).toBe('in_progress');
    expect(doc.updated_by).toBe(SLA_ESCALATION_ACTOR);
    expect(doc.updated_at).toBe(NOW);
    expect(doc.reporting.first_assigned_at).toBe(NOW);
    expect(doc.reporting.assign_minutes).toBe(130);
    expect(doc.reporting.sla_due_at).toBe(minutesAhead(110)); // due dates are never carried by buildReportingUpdate
    expect(doc.sla.escalated).toEqual(['first-response']);
    expect(doc.history.map((h: any) => [h.action, h.from, h.to])).toEqual([
      ['assignment_change', null, 'bob'],
      ['status_change', 'open', 'in_progress'],
      ['comment_added', null, null],
      ['sla_escalated', 'first-response', 'First response'],
    ]);
    expect(doc.history.every((h: any) => h.user === SLA_ESCALATION_ACTOR)).toBe(true);

    const comment = activityDocs(client, (s) => s.event_type === 'comment');
    expect(comment).toEqual([
      expect.objectContaining({
        id: escalationActivityId('first-response', 'a1', 'comment'),
        alert_id: 'a1',
        author: SLA_ESCALATION_ACTOR,
        text: `Escalation First response on a1 (high), due ${minutesAhead(110)} {{unknown}}`,
      }),
    ]);
    const escalatedEvent = activityDocs(client, (s) => s.action === 'sla_escalated');
    expect(escalatedEvent).toEqual([
      expect.objectContaining({
        id: escalationActivityId('first-response', 'a1'),
        target_type: 'alert',
        to: 'First response',
        source: 'sla',
        details: {
          escalation: { id: 'first-response', name: 'First response', target: 'alert', thresholdPercent: 50, condition: 'unassigned' },
          actions: { assignTo: 'bob', comment: true, notify: ['chan-1', 'chan-2'] },
          notify: ['chan-1', 'chan-2'],
        },
      }),
    ]);
    expect(activityDocs(client, (s) => s.action === 'assignment_change')).toHaveLength(1);
    expect(activityDocs(client, (s) => s.action === 'status_change')).toHaveLength(1);

    // Second tick: the marker keeps the record out and nothing is written twice.
    const activityCount = activityDocs(client).length;
    const again = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(again.escalated).toBe(0);
    expect(activityDocs(client)).toHaveLength(activityCount);
    expect(client.docs.get(`${ALERT_INDEX}::a1`).source.history).toHaveLength(4);
  });

  test('a replay after a partial run finishes the record without duplicate comments or history', async () => {
    const client = makeClient();
    // `any`: an `unassigned` rule would no longer match the record once its
    // own assignment landed (documented limitation in escalation.ts).
    const rule = escalation({ condition: 'any', actions: { assignTo: 'bob', comment: 'hello' } });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { '@timestamp': minutesAgo(130) }));
    // Simulate a crash right after the assignment write: the comment, marker
    // and sla_escalated event are missing, and the assignment activity exists.
    const hit = { _id: 'a1', _index: ALERT_INDEX, _source: client.docs.get(`${ALERT_INDEX}::a1`).source };
    const failing = { ...client, index: jest.fn(async (req: any) => {
      if (String(req.id).endsWith(':comment')) throw new Error('boom');
      return client.index(req);
    }) };
    await expect(applyEscalation(failing, rule, hit, { policy, now: NOW })).rejects.toThrow('boom');
    expect(client.docs.get(`${ALERT_INDEX}::a1`).source.sla?.escalated).toBeUndefined();

    const result = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(result.escalated).toBe(1);
    const doc = client.docs.get(`${ALERT_INDEX}::a1`).source;
    // The assignee already matches, so the assignment write is skipped (no
    // duplicate history rows), the comment is created once under its
    // deterministic id, and the marker closes the record.
    expect(doc.assigned_to).toBe('bob');
    expect(doc.history.map((h: any) => h.action)).toEqual(['assignment_change', 'status_change', 'comment_added', 'sla_escalated']);
    expect(doc.sla.escalated).toEqual(['first-response']);
    expect(activityDocs(client, (s) => s.event_type === 'comment')).toHaveLength(1);
    expect(activityDocs(client, (s) => s.action === 'assignment_change')).toHaveLength(1);
    expect(activityDocs(client, (s) => s.action === 'sla_escalated')).toHaveLength(1);
  });

  test('a crash on the final sla_escalated create leaves no marker; the next tick writes the event once and completes the marker', async () => {
    const client = makeClient();
    const rule = escalation({ condition: 'any', actions: { assignTo: 'bob', notify: ['chan'] } });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { '@timestamp': minutesAgo(130) }));
    const index = client.index;
    client.index = jest.fn(async (req: any) => {
      if (req.id === escalationActivityId('first-response', 'a1')) throw new Error('boom');
      return index(req);
    });
    const first = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(first.escalated).toBe(0);
    expect(first.errors).toEqual(['escalation "first-response" on alert a1: boom']);
    expect(client.docs.get(`${ALERT_INDEX}::a1`).source.sla?.escalated).toBeUndefined();
    expect(activityDocs(client, (s) => s.action === 'sla_escalated')).toHaveLength(0);

    client.index = index;
    const second = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(second.escalated).toBe(1);
    const doc = client.docs.get(`${ALERT_INDEX}::a1`).source;
    expect(doc.sla.escalated).toEqual(['first-response']);
    expect(doc.history.map((h: any) => h.action)).toEqual(['assignment_change', 'status_change', 'sla_escalated']);
    expect(activityDocs(client, (s) => s.action === 'sla_escalated')).toHaveLength(1);
    expect(activityDocs(client, (s) => s.action === 'assignment_change')).toHaveLength(1);

    // The other way round (event written, marker write crashed): the next
    // tick's create answers 409 and the marker completes, still one event.
    const client2 = makeClient();
    client2.put(ALERT_INDEX, 'a2', alertDoc('a2', { '@timestamp': minutesAgo(130) }));
    const update = client2.update;
    client2.update = jest.fn(async (req: any) => {
      if (String(req.body?.script?.source || '').includes('escalated.add')) throw new Error('crash before marker');
      return update(req);
    });
    const third = await tick(client2, { policy: { ...policy, escalations: [rule] } });
    expect(third.escalated).toBe(0);
    expect(activityDocs(client2, (s) => s.action === 'sla_escalated')).toHaveLength(1);
    expect(client2.docs.get(`${ALERT_INDEX}::a2`).source.sla?.escalated).toBeUndefined();
    client2.update = update;
    const fourth = await tick(client2, { policy: { ...policy, escalations: [rule] } });
    expect(fourth.escalated).toBe(1);
    expect(client2.docs.get(`${ALERT_INDEX}::a2`).source.sla.escalated).toEqual(['first-response']);
    expect(activityDocs(client2, (s) => s.action === 'sla_escalated')).toHaveLength(1);
  });

  test('two unassigned rules at different thresholds in one tick: the second sees the stale hit and noops at write time (no duplicate history)', async () => {
    const client = makeClient();
    const first = escalation({ id: 'half', name: 'Half', thresholdPercent: 50, actions: { assignTo: 'bob' } });
    const second = escalation({ id: 'late', name: 'Late', thresholdPercent: 80, actions: { assignTo: 'carol', comment: 'still unassigned' } });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { '@timestamp': minutesAgo(300) }));
    client.freezeSearch();
    const result = await tick(client, { policy: { ...policy, escalations: [first, second] } });
    expect(result.errors).toEqual([]);
    expect(result.escalated).toBe(1);
    const doc = client.docs.get(`${ALERT_INDEX}::a1`).source;
    expect(doc.assigned_to).toBe('bob');
    expect(doc.sla.escalated).toEqual(['half']);
    expect(doc.history.map((h: any) => [h.action, h.to])).toEqual([
      ['assignment_change', 'bob'],
      ['status_change', 'in_progress'],
      ['sla_escalated', 'Half'],
    ]);
    expect(activityDocs(client, (s) => s.event_type === 'comment')).toHaveLength(0);
    expect(activityDocs(client, (s) => s.action === 'sla_escalated')).toHaveLength(1);

    // Next tick, fresh search: the record is assigned, so the second rule never matches it.
    const fresh = makeClient();
    fresh.put(ALERT_INDEX, 'a1', doc);
    const again = await tick(fresh, { policy: { ...policy, escalations: [first, second] } });
    expect(again.escalated).toBe(0);
    expect(fresh.docs.get(`${ALERT_INDEX}::a1`).source.history).toHaveLength(3);

    // untouched: a stale hit of a record that moved off `open` meanwhile is a noop too.
    const untouched = escalation({ id: 'ut', condition: 'untouched', actions: { assignTo: 'erin' } });
    const client3 = makeClient();
    client3.put(ALERT_INDEX, 'a3', alertDoc('a3', { '@timestamp': minutesAgo(300) }));
    const stale = { _id: 'a3', _index: ALERT_INDEX, _source: { ...client3.docs.get(`${ALERT_INDEX}::a3`).source } };
    client3.docs.get(`${ALERT_INDEX}::a3`).source.status = 'in_progress';
    client3.docs.get(`${ALERT_INDEX}::a3`).source.assigned_to = 'dave';
    expect(await applyEscalation(client3, untouched, stale, { policy, now: NOW })).toBe(false);
    expect(client3.docs.get(`${ALERT_INDEX}::a3`).source.history).toBeUndefined();
  });

  test('a stale hit whose assignee or severity was already written by another holder appends nothing (same rule, lease stolen mid-tick)', async () => {
    const client = makeClient();
    const rule = escalation({ id: 'case-bump', target: 'case', condition: 'any', thresholdPercent: 10, actions: { assignTo: 'bob', raiseSeverity: true } });
    client.put(CASE_INDEX, 'c1', caseDoc('c1', { created_at: minutesAgo(30) }));
    const stale = { _id: 'c1', _index: CASE_INDEX, _source: JSON.parse(JSON.stringify(client.docs.get(`${CASE_INDEX}::c1`).source)) };
    // The other holder completed the assignment and the severity raise but not the marker.
    expect(await applyEscalation(client, rule, stale, { policy, now: NOW })).toBe(true);
    const live = client.docs.get(`${CASE_INDEX}::c1`).source;
    live.sla.escalated = [];
    live.history = live.history.filter((h: any) => h.action !== 'sla_escalated');
    const before = live.history.length;
    // Re-apply from the stale hit: the assignment write noops (assignee equal) -> false, nothing appended.
    expect(await applyEscalation(client, rule, stale, { policy, now: NOW })).toBe(false);
    expect(client.docs.get(`${CASE_INDEX}::c1`).source.history).toHaveLength(before);
    expect(client.docs.get(`${CASE_INDEX}::c1`).source.history.map((h: any) => h.action)).toEqual(['case_created', 'assignment_change', 'status_change', 'case_updated']);
    // A stale hit that already carries the assignee but not the severity: the raise write noops.
    const staleAssigned = { ...stale, _source: { ...stale._source, assigned_to: 'bob', status: 'in_progress' } };
    expect(await applyEscalation(client, rule, staleAssigned, { policy, now: NOW })).toBe(false);
    expect(client.docs.get(`${CASE_INDEX}::c1`).source.history).toHaveLength(before);
  });

  test('cases: assignTo moves open -> in_progress like PUT /cases, raiseSeverity goes one band up and recomputes sla_due_at (capped at critical)', async () => {
    const client = makeClient();
    const rule = escalation({ id: 'case-bump', name: 'Case bump', target: 'case', condition: 'any', thresholdPercent: 10, actions: { assignTo: 'bob', raiseSeverity: true } });
    const created = minutesAgo(30);
    client.put(CASE_INDEX, 'c-high', caseDoc('c-high', { created_at: created, sla_due_at: minutesAhead(210) }));
    client.put(CASE_INDEX, 'c-crit', caseDoc('c-crit', { created_at: created, severity: 'critical', status: 'in_progress', assigned_to: 'bob', sla_due_at: minutesAhead(30) }));

    const result = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(result.errors).toEqual([]);
    expect(result.escalated).toBe(2);

    const high = client.docs.get(`${CASE_INDEX}::c-high`).source;
    expect(high.assigned_to).toBe('bob');
    expect(high.status).toBe('in_progress');
    expect(high.closed_at).toBeNull();
    expect(high.severity).toBe('critical');
    expect(high.sla_due_at).toBe(new Date(Date.parse(created) + 60 * 60000).toISOString());
    expect(high.reporting).toBeUndefined(); // cases never get the alert reporting object
    expect(high.history.map((h: any) => [h.action, h.from, h.to])).toEqual([
      ['case_created', null, null],
      ['assignment_change', null, 'bob'],
      ['status_change', 'open', 'in_progress'],
      ['case_updated', 'high', 'critical'],
      ['sla_escalated', 'case-bump', 'Case bump'],
    ]);
    expect(high.sla.escalated).toEqual(['case-bump']);

    const crit = client.docs.get(`${CASE_INDEX}::c-crit`).source;
    expect(crit.severity).toBe('critical');
    expect(crit.sla_due_at).toBe(minutesAhead(30));
    expect(crit.history.map((h: any) => h.action)).toEqual(['case_created', 'sla_escalated']);
    const critEvent = activityDocs(client, (s, id) => id === escalationActivityId('case-bump', 'c-crit'))[0];
    expect(critEvent.details.actions).toEqual({ assignTo: 'bob', raiseSeverity: null });
    const highEvent = activityDocs(client, (s, id) => id === escalationActivityId('case-bump', 'c-high'))[0];
    expect(highEvent.details.actions).toEqual({ assignTo: 'bob', raiseSeverity: { from: 'high', to: 'critical' } });
  });

  test('a record closed between the search and the write is skipped without a marker', async () => {
    const client = makeClient();
    const rule = escalation({ actions: { assignTo: 'bob' } });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { '@timestamp': minutesAgo(130) }));
    const stale = { _id: 'a1', _index: ALERT_INDEX, _source: { ...client.docs.get(`${ALERT_INDEX}::a1`).source } };
    client.docs.get(`${ALERT_INDEX}::a1`).source.status = 'closed';
    expect(await applyEscalation(client, rule, stale, { policy, now: NOW })).toBe(false);
    expect(client.docs.get(`${ALERT_INDEX}::a1`).source.sla).toBeUndefined();
    expect(activityDocs(client)).toHaveLength(0);
  });

  test('a version conflict on an action write is left for the next tick', async () => {
    const client = makeClient({ failUpdates: { a1: { status: 409, reason: 'conflict' } } });
    const rule = escalation({ actions: { assignTo: 'bob' } });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { '@timestamp': minutesAgo(130) }));
    const result = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(result.escalated).toBe(0);
    expect(result.errors).toEqual([]);
  });

  test('disabled escalations are skipped and an action failure is reported per record', async () => {
    const client = makeClient({ failUpdates: { 'a-bad': { status: 500, reason: 'shard failure' } } });
    const disabled = escalation({ id: 'off', enabled: false });
    const rule = escalation({ actions: { assignTo: 'bob' } });
    client.put(ALERT_INDEX, 'a-bad', alertDoc('a-bad', { '@timestamp': minutesAgo(130) }));
    client.put(ALERT_INDEX, 'a-ok', alertDoc('a-ok', { '@timestamp': minutesAgo(130) }));
    const result = await tick(client, { policy: { ...policy, escalations: [disabled, rule] } });
    expect(result.escalated).toBe(1);
    expect(result.errors).toEqual(['escalation "first-response" on alert a-bad: shard failure']);
    expect(result.reported).toEqual(['escalation "first-response" on alert a-bad: request failed (HTTP 500)']);
    expect(client.docs.get(`${ALERT_INDEX}::a-ok`).source.sla.escalated).toEqual(['first-response']);
    expect(client.docs.get(`${ALERT_INDEX}::a-bad`).source.sla?.escalated).toBeUndefined();
    const status = await readSlaEscalationStatus(client);
    expect(status?.errors).toEqual([{ at: NOW, message: 'escalation "first-response" on alert a-bad: request failed (HTTP 500)' }]);
  });

  test('helpers: template rendering and the severity ladder', () => {
    expect(renderEscalationTemplate('{{ id }}/{{severity}}/{{due_at}}/{{escalation}}/{{nope}}', { id: 'a', severity: 'high', due_at: 'd', escalation: 'E' })).toBe('a/high/d/E/{{nope}}');
    expect(renderEscalationTemplate('', { id: 'a', severity: 'high', due_at: 'd', escalation: 'E' })).toBe('');
    expect(nextSeverityBand('low')).toBe('medium');
    expect(nextSeverityBand('high')).toBe('critical');
    expect(nextSeverityBand('critical')).toBeNull();
    expect(nextSeverityBand('weird')).toBeNull();
    expect(sanitizeScannerError(Object.assign(new Error('Alias x resolved outside its managed family: wazuh-alerts-4.x-2026'), { name: 'UnmanagedIndexError' }))).toBe('UnmanagedIndexError');
    expect(sanitizeScannerError(Object.assign(new Error('raw'), { meta: { statusCode: 503, body: { error: { type: 'cluster_block_exception' } } } }))).toBe('cluster_block_exception (HTTP 503)');
  });
});

describe('tick', () => {
  test('does nothing when another replica holds a fresh lease', async () => {
    const client = makeClient({ leaseHeldBy: 'other' });
    client.put(ALERT_INDEX, 'a1', alertDoc('a1', { reporting: { sla_due_at: minutesAgo(1) } }));
    const result = await tick(client);
    expect(result.acquired).toBe(false);
    expect(client.search).not.toHaveBeenCalled();
    expect(client.docs.has(`${META_INDEX}::${SLA_ESCALATION_STATUS_DOC_ID}`)).toBe(false);
  });

  test('caps the escalation pass at SLA_ESCALATION_MAX_ACTIONS_PER_TICK and continues next tick; status doc shape', async () => {
    const client = makeClient();
    const rule = escalation({ condition: 'any', actions: { notify: ['chan'] } });
    const total = SLA_ESCALATION_MAX_ACTIONS_PER_TICK + 5;
    for (let i = 0; i < total; i += 1) {
      client.put(ALERT_INDEX, `a${String(i).padStart(4, '0')}`, alertDoc(`a${String(i).padStart(4, '0')}`, { '@timestamp': minutesAgo(200 + i) }));
    }
    const logger: any = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    const first = await tick(client, { policy: { ...policy, escalations: [rule] }, logger });
    expect(first.escalated).toBe(SLA_ESCALATION_MAX_ACTIONS_PER_TICK);
    expect(first.capped).toBe(true);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('capped'));

    const stored = client.docs.get(`${META_INDEX}::${SLA_ESCALATION_STATUS_DOC_ID}`).source;
    expect(stored).toEqual({
      document_type: 'sla_escalation_status',
      last_tick_at: NOW,
      holder: HOLDER,
      breached_alerts: 0,
      breached_cases: 0,
      escalated: SLA_ESCALATION_MAX_ACTIONS_PER_TICK,
      errors: [],
      capped: true,
    });
    expect(await readSlaEscalationStatus(client)).toEqual({
      last_tick_at: NOW,
      holder: HOLDER,
      breached_alerts: 0,
      breached_cases: 0,
      escalated: SLA_ESCALATION_MAX_ACTIONS_PER_TICK,
      errors: [],
      capped: true,
    });

    const second = await tick(client, { policy: { ...policy, escalations: [rule] }, logger });
    expect(second.escalated).toBe(5);
    expect(second.capped).toBe(false);
    expect(activityDocs(client, (s) => s.action === 'sla_escalated')).toHaveLength(total);
  });

  test('exactly the per-tick maximum of candidates is not reported as capped', async () => {
    const client = makeClient();
    const rule = escalation({ condition: 'any', actions: { notify: ['chan'] } });
    for (let i = 0; i < SLA_ESCALATION_MAX_ACTIONS_PER_TICK; i += 1) {
      client.put(ALERT_INDEX, `a${String(i).padStart(4, '0')}`, alertDoc(`a${String(i).padStart(4, '0')}`, { '@timestamp': minutesAgo(200 + i) }));
    }
    const logger: any = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    const result = await tick(client, { policy: { ...policy, escalations: [rule] }, logger });
    expect(result.escalated).toBe(SLA_ESCALATION_MAX_ACTIONS_PER_TICK);
    expect(result.capped).toBe(false);
    expect(logger.warn).not.toHaveBeenCalled();
    expect((await readSlaEscalationStatus(client))?.capped).toBe(false);
  });

  test('the lease is renewed between the passes: when another replica took it, the escalation pass is skipped and the status doc left alone', async () => {
    const client = makeClient();
    const rule = escalation({ condition: 'any', actions: { notify: ['chan'] } });
    client.put(ALERT_INDEX, 'a-due', alertDoc('a-due', { reporting: { sla_due_at: minutesAgo(1) } }));
    client.put(ALERT_INDEX, 'a-old', alertDoc('a-old', { '@timestamp': minutesAgo(300) }));
    const bulk = client.bulk;
    client.bulk = jest.fn(async (req: any) => {
      const res = await bulk(req);
      // Steal the lease during the breach pass.
      client.put(META_INDEX, `lease:${SLA_ESCALATION_LEASE_ID}`, { document_type: 'lease', lease_id: SLA_ESCALATION_LEASE_ID, holder_id: 'other', expires_at: minutesAhead(5), updated_at: NOW });
      return res;
    });
    const result = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(result.acquired).toBe(true);
    expect(result.breachedAlerts).toBe(1);
    expect(result.escalated).toBe(0);
    expect(result.errors).toEqual(['escalation pass: skipped: lease lost to another replica']);
    expect(client.docs.get(`${ALERT_INDEX}::a-old`).source.sla).toBeUndefined();
    expect(client.docs.has(`${META_INDEX}::${SLA_ESCALATION_STATUS_DOC_ID}`)).toBe(false);
  });

  test(`the escalation pass renews the lease every ${SLA_ESCALATION_LEASE_RENEW_EVERY} records and stops when the renewal is refused`, async () => {
    const client = makeClient();
    const rule = escalation({ condition: 'any', actions: { notify: ['chan'] } });
    const total = SLA_ESCALATION_LEASE_RENEW_EVERY + 10;
    for (let i = 0; i < total; i += 1) {
      client.put(ALERT_INDEX, `a${String(i).padStart(4, '0')}`, alertDoc(`a${String(i).padStart(4, '0')}`, { '@timestamp': minutesAgo(200 + i) }));
    }
    const update = client.update;
    let markers = 0;
    client.update = jest.fn(async (req: any) => {
      const res = await update(req);
      if (req.index === ALERT_INDEX && String(req.body?.script?.source || '').includes('escalated.add')) {
        markers += 1;
        if (markers === SLA_ESCALATION_LEASE_RENEW_EVERY) {
          client.put(META_INDEX, `lease:${SLA_ESCALATION_LEASE_ID}`, { document_type: 'lease', lease_id: SLA_ESCALATION_LEASE_ID, holder_id: 'other', expires_at: minutesAhead(5), updated_at: NOW });
        }
      }
      return res;
    });
    const result = await tick(client, { policy: { ...policy, escalations: [rule] } });
    expect(result.escalated).toBe(SLA_ESCALATION_LEASE_RENEW_EVERY);
    expect(result.errors).toEqual(['escalation pass stopped: lease lost to another replica']);
    expect(client.docs.has(`${META_INDEX}::${SLA_ESCALATION_STATUS_DOC_ID}`)).toBe(false);
    // Without interference the same set completes in one tick with the lease renewed in place.
    const calm = makeClient();
    for (let i = 0; i < total; i += 1) {
      calm.put(ALERT_INDEX, `a${String(i).padStart(4, '0')}`, alertDoc(`a${String(i).padStart(4, '0')}`, { '@timestamp': minutesAgo(200 + i) }));
    }
    const ok = await tick(calm, { policy: { ...policy, escalations: [rule] } });
    expect(ok.escalated).toBe(total);
    expect(calm.update.mock.calls.filter(([req]: any[]) => req.index === META_INDEX && req.id === `lease:${SLA_ESCALATION_LEASE_ID}`).length).toBeGreaterThanOrEqual(2);
  });

  test('status doc keeps the last ten errors across ticks; readSlaEscalationStatus ignores foreign docs', async () => {
    const client = makeClient({ failUpdates: { 'a-bad': { status: 500, reason: 'shard failure' } } });
    client.put(META_INDEX, SLA_ESCALATION_STATUS_DOC_ID, {
      document_type: 'sla_escalation_status',
      last_tick_at: minutesAgo(1),
      holder: 'old',
      breached_alerts: 1,
      breached_cases: 0,
      escalated: 0,
      errors: Array.from({ length: 10 }, (_, i) => ({ at: minutesAgo(10 - i), message: `old ${i}` })),
      capped: false,
    });
    client.put(ALERT_INDEX, 'a-bad', alertDoc('a-bad', { reporting: { sla_due_at: minutesAgo(1) } }));
    await tick(client);
    const status = await readSlaEscalationStatus(client);
    expect(status?.errors).toHaveLength(10);
    expect(status?.errors[0]).toEqual({ at: minutesAgo(9), message: 'old 1' });
    expect(status?.errors[9]).toEqual({ at: NOW, message: 'alert a-bad: failure (HTTP 500)' });

    client.put(META_INDEX, SLA_ESCALATION_STATUS_DOC_ID, { document_type: 'something_else' });
    expect(await readSlaEscalationStatus(client)).toBeNull();
    expect(await readSlaEscalationStatus(makeClient())).toBeNull();
  });

  test('an unmanaged hit behind the alias is refused and recorded as a pass error', async () => {
    const client = makeClient();
    client.put('wazuh-alerts-4.x-2026.11.21', 'native', alertDoc('native', { reporting: { sla_due_at: minutesAgo(1) } }));
    const search = client.search;
    client.search = jest.fn(async (req: any) => {
      const res = await search(req);
      if (req.index === ALERTS_READ_ALIAS && res.body.hits.hits.length === 0) {
        const stored = client.docs.get('wazuh-alerts-4.x-2026.11.21::native');
        return { body: { hits: { hits: [{ _id: 'native', _index: stored.index, _source: stored.source, sort: [] }] } } };
      }
      return res;
    });
    const result = await tick(client);
    expect(result.errors).toEqual([expect.stringContaining('outside its managed family')]);
    expect(result.reported).toEqual(['breach pass (alerts): UnmanagedIndexError']); // the status doc never names the index
    expect(client.bulk).not.toHaveBeenCalled();
  });
});

describe('scanner loop', () => {
  const flush = () => new Promise((resolve) => jest.requireActual('timers').setImmediate(resolve));

  afterEach(() => {
    jest.useRealTimers();
  });

  test('ticks every tickSeconds on the lease, records the runtime, and releases the lease on stop', async () => {
    jest.useFakeTimers();
    const client = makeClient();
    const logger: any = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    const config: any = { sla: { escalation: { enabled: true, tickSeconds: 15 } } };
    const stop = startSlaEscalationScanner(client, config, logger);
    expect(getSlaEscalationRuntime()).toEqual({ enabled: true, tickSeconds: 15 });
    expect(slaEscalationLeaseTtlMs(15)).toBe(120000);
    expect(slaEscalationLeaseTtlMs(60)).toBe(180000);
    expect(client.search).not.toHaveBeenCalled();

    jest.advanceTimersByTime(15000);
    for (let i = 0; i < 20; i += 1) await flush();
    expect(client.create).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: `lease:${SLA_ESCALATION_LEASE_ID}` }));
    expect(client.search).toHaveBeenCalledTimes(2); // breach alerts, breach cases; no escalations configured
    expect(client.docs.has(`${META_INDEX}::${SLA_ESCALATION_STATUS_DOC_ID}`)).toBe(true);

    jest.advanceTimersByTime(15000);
    for (let i = 0; i < 20; i += 1) await flush();
    expect(client.search).toHaveBeenCalledTimes(4);

    stop();
    for (let i = 0; i < 20; i += 1) await flush();
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: META_INDEX, id: `lease:${SLA_ESCALATION_LEASE_ID}` }));
    jest.advanceTimersByTime(60000);
    for (let i = 0; i < 20; i += 1) await flush();
    expect(client.search).toHaveBeenCalledTimes(4);
  });

  test('setSlaEscalationRuntime records a disabled scanner and the defaults', () => {
    setSlaEscalationRuntime({ sla: { escalation: { enabled: false, tickSeconds: 30 } } } as any);
    expect(getSlaEscalationRuntime()).toEqual({ enabled: false, tickSeconds: 30 });
    setSlaEscalationRuntime(undefined);
    expect(getSlaEscalationRuntime()).toEqual({ enabled: true, tickSeconds: 60 });
    setSlaEscalationRuntime(null);
    expect(getSlaEscalationRuntime()).toEqual({ enabled: null, tickSeconds: 60 });
  });
});

describe('notifications (step 1.3)', () => {
  const emitterMock = (): { emitSlaEvent: jest.Mock; emitSlaEvents: jest.Mock; emitCaseEvent: jest.Mock } => ({
    emitSlaEvent: jest.fn(async () => ({})),
    emitSlaEvents: jest.fn(async () => ({})),
    emitCaseEvent: jest.fn(async () => ({})),
  });

  test('breach pass: one sla.breached batch per target page with the records this tick stamped, none for an already stamped record, none on the next tick', async () => {
    const client = makeClient();
    client.put(ALERT_INDEX, 'a-breached', alertDoc('a-breached', { reporting: { sla_due_at: minutesAgo(1) } }));
    client.put(ALERT_INDEX, 'a-already', alertDoc('a-already', { reporting: { sla_due_at: minutesAgo(60) }, sla: { breached_at: minutesAgo(30) } }));
    client.put(CASE_INDEX, 'c-breached', caseDoc('c-breached', { sla_due_at: minutesAgo(1) }));
    const emitter = emitterMock();
    const result = await tick(client, { emitter });
    expect(result.breachedAlerts).toBe(1);
    expect(result.breachedCases).toBe(1);
    expect(emitter.emitSlaEvents).toHaveBeenCalledTimes(2);
    expect(emitter.emitSlaEvents).toHaveBeenCalledWith('sla.breached', [{
      target: 'alert',
      record: { id: 'a-breached', source: expect.objectContaining({ alert_uid: 'a-breached', sla: expect.objectContaining({ breached_at: NOW }) }) },
      dueAt: minutesAgo(1),
      message: `SLA due ${minutesAgo(1)} passed`,
      now: new Date(NOW),
    }]);
    expect(emitter.emitSlaEvents).toHaveBeenCalledWith('sla.breached', [expect.objectContaining({ target: 'case', record: expect.objectContaining({ id: 'c-breached' }), dueAt: minutesAgo(1) })]);
    // The breach pass never writes one entry at a time.
    expect(emitter.emitSlaEvent).not.toHaveBeenCalled();
    expect(emitter.emitCaseEvent).not.toHaveBeenCalled();

    emitter.emitSlaEvents.mockClear();
    await tick(client, { emitter });
    expect(emitter.emitSlaEvents).not.toHaveBeenCalled();
  });

  test('runBreachPass takes the emitter as its sixth argument and still stamps when one is given', async () => {
    const client = makeClient();
    client.put(ALERT_INDEX, 'a-breached', alertDoc('a-breached', { reporting: { sla_due_at: minutesAgo(1) } }));
    const emitter = emitterMock();
    const result = await runBreachPass(client, 'alert', NOW, policy, undefined, emitter);
    expect(result.marked).toBe(1);
    expect(client.docs.get(`${ALERT_INDEX}::a-breached`).source.sla.breached_at).toBe(NOW);
    expect(emitter.emitSlaEvents).toHaveBeenCalledTimes(1);
  });

  test('breach notify grace: a record overdue for longer than the window is stamped but not notified (default 24 h, configurable, 0 = always)', async () => {
    const client = makeClient();
    client.put(ALERT_INDEX, 'a-fresh', alertDoc('a-fresh', { reporting: { sla_due_at: minutesAgo(1) } }));
    client.put(ALERT_INDEX, 'a-stale', alertDoc('a-stale', { '@timestamp': minutesAgo(3000), reporting: { sla_due_at: minutesAgo(25 * 60) } }));
    client.put(ALERT_INDEX, 'a-nodue', alertDoc('a-nodue', { '@timestamp': minutesAgo(3000), reporting: { sla_due_at: minutesAgo(23 * 60) } }));
    const emitter = emitterMock();
    const logger: any = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };
    const result = await runBreachPass(client, 'alert', NOW, policy, logger, emitter);
    expect(result.marked).toBe(3);
    expect(result.notifySuppressed).toBe(1);
    expect(client.docs.get(`${ALERT_INDEX}::a-stale`).source.sla.breached_at).toBe(NOW);
    expect(emitter.emitSlaEvents).toHaveBeenCalledTimes(1);
    expect(emitter.emitSlaEvents.mock.calls[0][1].map((input: any) => input.record.id).sort()).toEqual(['a-fresh', 'a-nodue']);
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('1 alert(s) breached more than 1440 min ago stamped without an sla.breached notification'));

    // A one-hour window through the tick option (what the scanner passes from
    // `sla.escalation.breachNotifyGraceMinutes`) drops the 23 h one as well.
    const hourly = makeClient();
    hourly.put(ALERT_INDEX, 'a-fresh', alertDoc('a-fresh', { reporting: { sla_due_at: minutesAgo(1) } }));
    hourly.put(ALERT_INDEX, 'a-nodue', alertDoc('a-nodue', { '@timestamp': minutesAgo(3000), reporting: { sla_due_at: minutesAgo(23 * 60) } }));
    const hourlyEmitter = emitterMock();
    const ticked = await tick(hourly, { emitter: hourlyEmitter, breachNotifyGraceMs: 60 * 60000 });
    expect(ticked.breachedAlerts).toBe(2);
    expect(hourlyEmitter.emitSlaEvents.mock.calls[0][1].map((input: any) => input.record.id)).toEqual(['a-fresh']);

    // 0 disables the cut-off: every stamped record is notified.
    const always = makeClient();
    always.put(ALERT_INDEX, 'a-stale', alertDoc('a-stale', { '@timestamp': minutesAgo(3000), reporting: { sla_due_at: minutesAgo(25 * 60) } }));
    const alwaysEmitter = emitterMock();
    const unbounded = await runBreachPass(always, 'alert', NOW, policy, logger, alwaysEmitter, { notifyGraceMs: 0 });
    expect(unbounded.notifySuppressed).toBe(0);
    expect(alwaysEmitter.emitSlaEvents).toHaveBeenCalledTimes(1);
    // Nothing stamped: nothing emitted, nothing logged.
    expect(await runBreachPass(makeClient(), 'alert', NOW, policy, logger, emitterMock())).toEqual(expect.objectContaining({ marked: 0, notifySuppressed: 0 }));
  });

  test('breach pass renews the lease before every page after the first and stops when it is lost; the case pass is skipped afterwards', async () => {
    const client = makeClient();
    for (let i = 0; i < 501; i += 1) {
      const id = `a-${String(i).padStart(4, '0')}`;
      client.put(ALERT_INDEX, id, alertDoc(id, { '@timestamp': minutesAgo(1100 - i), reporting: { sla_due_at: minutesAgo(1 + i) } }));
    }
    client.put(CASE_INDEX, 'c-breached', caseDoc('c-breached', { sla_due_at: minutesAgo(1) }));
    const emitter = emitterMock();
    const renewLease = jest.fn(async () => true);
    const held = await runBreachPass(client, 'alert', NOW, policy, undefined, emitter, { renewLease, notifyGraceMs: 0 });
    expect(renewLease).toHaveBeenCalledTimes(1);
    expect(held).toEqual(expect.objectContaining({ marked: 501, leaseLost: false, failures: 0 }));
    expect(emitter.emitSlaEvents).toHaveBeenCalledTimes(2);
    expect(emitter.emitSlaEvents.mock.calls.map(([, batch]: any[]) => batch.length)).toEqual([500, 1]);

    const lost = makeClient();
    for (let i = 0; i < 501; i += 1) {
      const id = `a-${String(i).padStart(4, '0')}`;
      lost.put(ALERT_INDEX, id, alertDoc(id, { '@timestamp': minutesAgo(1100 - i), reporting: { sla_due_at: minutesAgo(1 + i) } }));
    }
    lost.put(CASE_INDEX, 'c-breached', caseDoc('c-breached', { sla_due_at: minutesAgo(1) }));
    const lostEmitter = emitterMock();
    const stopped = await runBreachPass(lost, 'alert', NOW, policy, undefined, lostEmitter, { renewLease: async () => false, notifyGraceMs: 0 });
    expect(stopped).toEqual(expect.objectContaining({ marked: 500, leaseLost: true, failures: 1 }));
    expect(stopped.errors[0]).toContain('lease lost');
    expect(lost.docs.get(`${ALERT_INDEX}::a-0500`).source.sla).toBeUndefined();
    expect(lostEmitter.emitSlaEvents).toHaveBeenCalledTimes(1);

    // Through the tick: the lease goes to another replica after the first page.
    const taken = makeClient();
    for (let i = 0; i < 501; i += 1) {
      const id = `a-${String(i).padStart(4, '0')}`;
      taken.put(ALERT_INDEX, id, alertDoc(id, { '@timestamp': minutesAgo(1100 - i), reporting: { sla_due_at: minutesAgo(1 + i) } }));
    }
    taken.put(CASE_INDEX, 'c-breached', caseDoc('c-breached', { sla_due_at: minutesAgo(1) }));
    const originalUpdate = taken.update;
    let leaseWrites = 0;
    taken.update = jest.fn(async (args: any) => {
      if (args.id === `lease:${SLA_ESCALATION_LEASE_ID}`) {
        leaseWrites += 1;
        if (leaseWrites >= 1) {
          // The renewal finds the lease owned by someone else from now on.
          taken.put(META_INDEX, `lease:${SLA_ESCALATION_LEASE_ID}`, { document_type: 'lease', lease_id: SLA_ESCALATION_LEASE_ID, holder_id: 'other', expires_at: minutesAhead(5), updated_at: NOW });
          throw conflict();
        }
      }
      return originalUpdate(args);
    });
    const result = await tick(taken, { emitter: emitterMock(), breachNotifyGraceMs: 0 });
    expect(result.acquired).toBe(true);
    expect(result.breachedAlerts).toBe(500);
    expect(result.breachedCases).toBe(0);
    expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining('breach pass stopped: lease lost'), expect.stringContaining('breach pass (cases): skipped: lease lost')]));
    expect(taken.docs.get(`${CASE_INDEX}::c-breached`).source.sla).toBeUndefined();
  });

  test('escalation on a case: sla.escalated carries the rule notify ids, the post-action record and the action summary; case.assigned and case.severity_raised follow; nothing on the next tick', async () => {
    const client = makeClient();
    const rule = escalation({
      id: 'case-bump', name: 'Case bump', target: 'case', condition: 'any', thresholdPercent: 10,
      actions: { assignTo: 'bob', raiseSeverity: true, comment: 'Escalated by {{escalation}}', notify: ['slack', 'pager'] },
    });
    const created = minutesAgo(30);
    client.put(CASE_INDEX, 'c-high', caseDoc('c-high', { created_at: created, sla_due_at: minutesAhead(210) }));
    const emitter = emitterMock();
    const result = await tick(client, { policy: { ...policy, escalations: [rule] }, emitter });
    expect(result.errors).toEqual([]);
    expect(result.escalated).toBe(1);

    expect(emitter.emitSlaEvent).toHaveBeenCalledTimes(1);
    expect(emitter.emitSlaEvent).toHaveBeenCalledWith('sla.escalated', {
      target: 'case',
      record: {
        id: 'c-high',
        source: expect.objectContaining({
          assigned_to: 'bob', status: 'in_progress', severity: 'critical', updated_at: NOW, updated_by: SLA_ESCALATION_ACTOR,
          sla: expect.objectContaining({ escalated: ['case-bump'] }),
        }),
      },
      escalation: { id: 'case-bump', name: 'Case bump' },
      notify: ['slack', 'pager'],
      message: 'assigned to bob; severity raised high -> critical; comment added',
      now: new Date(NOW),
    });
    expect(emitter.emitCaseEvent.mock.calls.map(([event]: any[]) => event)).toEqual(['case.assigned', 'case.severity_raised']);
    expect(emitter.emitCaseEvent).toHaveBeenCalledWith(
      'case.assigned',
      expect.objectContaining({ id: 'c-high', assigned_to: 'bob', status: 'in_progress' }),
      { actor: SLA_ESCALATION_ACTOR, changes: { from: null, to: 'bob' }, key: escalationActivityId('case-bump', 'c-high', 'assignment'), now: new Date(NOW) }
    );
    expect(emitter.emitCaseEvent).toHaveBeenCalledWith(
      'case.severity_raised',
      expect.objectContaining({ id: 'c-high', severity: 'critical' }),
      { actor: SLA_ESCALATION_ACTOR, changes: { from: 'high', to: 'critical' }, key: escalationActivityId('case-bump', 'c-high', 'severity'), now: new Date(NOW) }
    );

    emitter.emitSlaEvent.mockClear();
    emitter.emitCaseEvent.mockClear();
    await tick(client, { policy: { ...policy, escalations: [rule] }, emitter });
    expect(emitter.emitSlaEvent).not.toHaveBeenCalled();
    expect(emitter.emitCaseEvent).not.toHaveBeenCalled();
  });

  test('escalation on an alert without notify passes null (the bound channels) and no case event; a skipped record (already marked) emits nothing', async () => {
    const client = makeClient();
    const source = alertDoc('a-1');
    client.put(ALERT_INDEX, 'a-1', source);
    const rule = escalation({ actions: { assignTo: 'bob' } });
    const emitter = emitterMock();
    expect(await applyEscalation(client, rule, { _id: 'a-1', _index: ALERT_INDEX, _source: source }, { policy, now: NOW, emitter })).toBe(true);
    expect(emitter.emitSlaEvent).toHaveBeenCalledTimes(1);
    expect(emitter.emitSlaEvent).toHaveBeenCalledWith('sla.escalated', expect.objectContaining({
      target: 'alert',
      notify: null,
      message: 'assigned to bob',
      escalation: { id: 'first-response', name: 'First response' },
      record: { id: 'a-1', source: expect.objectContaining({ alert_uid: 'a-1', assigned_to: 'bob', status: 'in_progress', sla: { escalated: ['first-response'] } }) },
    }));
    expect(emitter.emitCaseEvent).not.toHaveBeenCalled();

    emitter.emitSlaEvent.mockClear();
    const stored = client.docs.get(`${ALERT_INDEX}::a-1`).source;
    expect(await applyEscalation(client, rule, { _id: 'a-1', _index: ALERT_INDEX, _source: stored }, { policy, now: NOW, emitter })).toBe(false);
    expect(emitter.emitSlaEvent).not.toHaveBeenCalled();

    // No emitter at all: the same code path, no call anywhere (the other suites run this way).
    const plain = makeClient();
    const other = alertDoc('a-2');
    plain.put(ALERT_INDEX, 'a-2', other);
    expect(await applyEscalation(plain, rule, { _id: 'a-2', _index: ALERT_INDEX, _source: other }, { policy, now: NOW })).toBe(true);
  });

  test('startSlaEscalationScanner hands the emitter to every tick', async () => {
    jest.useFakeTimers();
    try {
      const client = makeClient();
      // The scanner reads the real clock (no `now` override) and only notifies
      // a breach inside the 24 h grace window, so the due date is relative to
      // the real time, not the fixture's NOW (which falls out of the window
      // one day after it).
      client.put(CASE_INDEX, 'c-breached', caseDoc('c-breached', { sla_due_at: new Date(Date.now() - 60000).toISOString() }));
      const emitter = emitterMock();
      const logger: any = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };
      const stop = startSlaEscalationScanner(client, { sla: { escalation: { enabled: true, tickSeconds: 15 } } } as any, logger, { emitter });
      const flush = () => new Promise((resolve) => jest.requireActual('timers').setImmediate(resolve));
      jest.advanceTimersByTime(15_000);
      for (let i = 0; i < 30; i += 1) await flush();
      stop();
      for (let i = 0; i < 10; i += 1) await flush();
      expect(emitter.emitSlaEvents).toHaveBeenCalledWith('sla.breached', [expect.objectContaining({ target: 'case', record: expect.objectContaining({ id: 'c-breached' }) })]);
    } finally {
      jest.useRealTimers();
    }
  });
});
