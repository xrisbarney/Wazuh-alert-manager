import { ACTIVITY_READ_ALIAS, CASES_INDEX, CASE_TIMELINE_ALERTS_MAX, CASE_TIMELINE_PAGE } from '../../common';
import { queryCaseActivity } from './activity';
import {
  CASE_TIMELINE_LIMIT_MAX,
  activityEntry,
  alertEntry,
  collectCaseTimeline,
  compareTimelineEntries,
  decodeTimelineCursor,
  describeAuditEvent,
  encodeTimelineCursor,
  taskDueEntries,
} from './case_timeline';

const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';
const ALERT_INDEX = 'wazuh-alert-status-v2-000001';
const ts = (h: number, m = 0) => `2026-11-20T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00.000Z`;

const alertSource = (hour: number, extra: any = {}) => ({
  '@timestamp': ts(hour),
  status: 'open',
  agent: { id: '001', name: 'web-01' },
  rule: { id: '5710', level: 5, description: 'sshd: attempt to login using a non-existent user' },
  ...extra,
});

interface FakeOptions {
  caseSource?: any;
  found?: boolean;
  alerts?: Record<string, any>;
  /** Evidence rows to page (default: one per alert). */
  evidenceIds?: string[];
  evidenceTruncated?: boolean;
  activity?: any[];
}

function fakeClient(options: FakeOptions = {}) {
  const alerts = options.alerts ?? { a1: alertSource(1), a2: alertSource(2) };
  const evidenceIds = options.evidenceIds ?? Object.keys(alerts);
  const activity = options.activity ?? [];
  const caseSource = { title: 'Case', status: 'open', severity: 'high', alert_ids: evidenceIds, ...(options.caseSource || {}) };
  const search = jest.fn(async (request: any) => {
    const index = String(request.index);
    if (index === CASES_INDEX) {
      const found = options.found !== false;
      return { body: { hits: { total: { value: found ? 1 : 0 }, hits: found ? [{ _id: 'c1', _index: CASE_INDEX, _source: caseSource }] : [] } } };
    }
    if (index.startsWith('wazuh-alert-manager-v2-evidence')) {
      const size = request.body.size - 1;
      const after = request.body.search_after?.[1];
      const start = after ? evidenceIds.indexOf(after) + 1 : 0;
      const slice = evidenceIds.slice(start, start + size + 1);
      return {
        body: {
          hits: {
            total: { value: evidenceIds.length },
            hits: slice.map((id) => ({ _id: `ev-${id}`, _source: { case_id: 'c1', alert_id: id, relationship_state: 'linked', snapshot: alerts[id] }, sort: [1, id] })),
          },
        },
      };
    }
    if (index.startsWith('wazuh-alert-status-v2')) {
      const ids: string[] = request.body?.query?.ids?.values || [];
      return { body: { hits: { hits: ids.filter((id) => alerts[id]).map((id) => ({ _id: id, _index: ALERT_INDEX, _source: alerts[id] })) } } };
    }
    if (index === ACTIVITY_READ_ALIAS) {
      // `[created_at millis, event_uid]`, a missing event_uid (null) sorting first like `missing: '_first'`.
      const uid = (hit: any) => (hit.sort[1] == null ? '' : String(hit.sort[1]));
      const sorted = [...activity].sort((a, b) => (a.sort[0] - b.sort[0]) || uid(a).localeCompare(uid(b)));
      const after = request.body.search_after;
      const afterUid = after?.[1] == null ? '' : String(after[1]);
      const from = after ? sorted.findIndex((hit) => hit.sort[0] > after[0] || (hit.sort[0] === after[0] && uid(hit) > afterUid)) : 0;
      const slice = from < 0 ? [] : sorted.slice(from, from + request.body.size);
      return { body: { hits: { hits: slice } } };
    }
    throw new Error(`unexpected index ${index}`);
  });
  return { search, get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }) };
}

const activityHit = (id: string, hour: number, source: any) => ({
  _id: id,
  _source: { case_id: 'c1', event_uid: id, timestamp: ts(hour), created_at: ts(hour), ...source },
  sort: [Date.parse(ts(hour)), id],
});
/** A comment as `POST /comments` wrote it before step 2.3: `created_at` only, no `timestamp`, no `event_uid`. */
const legacyComment = (id: string, hour: number, minute: number, author: string, textValue: string) => ({
  _id: id,
  _source: { case_id: 'c1', event_type: 'comment', author, text: textValue, created_at: ts(hour, minute) },
  sort: [Date.parse(ts(hour, minute)), null],
});

const comment = (id: string, hour: number, author: string, textValue: string) =>
  activityHit(id, hour, { event_type: 'comment', author, user: author, text: textValue });
const audit = (id: string, hour: number, action: string, extra: any = {}) =>
  activityHit(id, hour, { event_type: 'audit', user: 'alice', action, from: null, to: null, ...extra });

describe('cursor', () => {
  test('round-trips as base64url JSON scoped to the case', () => {
    const cursor = encodeTimelineCursor({ case: 'c1', at: ts(3), id: 'activity:x1', sources: { activity_after: [1, 'x1'], alert_after: [ts(2), 'a2'] } });
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeTimelineCursor(cursor, 'c1')).toEqual({ v: 1, case: 'c1', at: ts(3), id: 'activity:x1', sources: { activity_after: [1, 'x1'], alert_after: [ts(2), 'a2'] } });
    expect(decodeTimelineCursor(undefined, 'c1')).toBeNull();
    expect(decodeTimelineCursor('', 'c1')).toBeNull();
  });

  test('rejects a cursor of another case and malformed cursors with 400', () => {
    const cursor = encodeTimelineCursor({ case: 'c1', at: ts(3), id: 'activity:x1', sources: {} });
    expect(() => decodeTimelineCursor(cursor, 'c2')).toThrow(expect.objectContaining({ statusCode: 400 }));
    expect(() => decodeTimelineCursor('not base64 json', 'c1')).toThrow(expect.objectContaining({ statusCode: 400 }));
    expect(() => decodeTimelineCursor(Buffer.from('{"v":2,"case":"c1","at":"x","id":"y","sources":{}}').toString('base64'), 'c1')).toThrow(/cursor/);
    expect(() => decodeTimelineCursor(Buffer.from('{"v":1,"case":"c1","at":"x","id":"y","sources":{"activity_after":[{}]}}').toString('base64'), 'c1')).toThrow(/cursor/);
    expect(() => decodeTimelineCursor(Buffer.from('{"v":1,"case":"c1","at":"x","id":"y"}').toString('base64'), 'c1')).toThrow(/cursor/);
  });
});

describe('entry builders', () => {
  test('alert entries carry the rule, agent and severity band', () => {
    expect(alertEntry({ id: 'a1', source: alertSource(1) })).toEqual({
      id: 'alert:a1', kind: 'alert', at: ts(1), actor: null,
      title: 'sshd: attempt to login using a non-existent user',
      details: 'rule 5710 · on web-01 · medium (5)',
      ref: { alert_id: 'a1' }, severity_band: 'medium',
    });
    expect(alertEntry({ id: 'f1', source: { '@timestamp': ts(2), severity_label: 'High', rule: { level: null } } })).toEqual(
      expect.objectContaining({ title: 'Alert f1', details: 'high', severity_band: 'high' })
    );
    expect(alertEntry({ id: 'x', source: {} })).toBeNull();
  });

  test('comments and audit events (every action) become entries; the audit wording matches the report', () => {
    expect(activityEntry(comment('cm1', 3, 'alice', 'Blocked'))).toEqual({
      id: 'activity:cm1', kind: 'comment', at: ts(3), actor: 'alice', title: 'Comment', details: 'Blocked', ref: { activity_id: 'cm1' },
    });
    expect(activityEntry(audit('au1', 7, 'status_change', { from: 'open', to: 'closed' }))).toEqual({
      id: 'activity:au1', kind: 'audit', at: ts(7), actor: 'alice', title: 'status change: open → closed', details: null, ref: { activity_id: 'au1' }, action: 'status_change',
    });
    expect(activityEntry(audit('au2', 8, 'task_added', { to: 'Collect logs', details: { task_id: 't1', title: 'Collect logs', owner: 'bob' } }))).toEqual(
      expect.objectContaining({ title: 'task added: Collect logs', details: 'owner bob', action: 'task_added' })
    );
    expect(activityEntry(audit('au3', 9, 'task_list_applied', { to: 'Phishing', details: { task_list_id: 'pb-1', name: 'Phishing', tasks_added: 2 } }))).toEqual(
      expect.objectContaining({ title: 'task list applied: Phishing', details: '2 tasks added' })
    );
    expect(activityEntry(audit('au4', 10, 'sla_breached', { to: ts(9) }))).toEqual(expect.objectContaining({ title: `sla breached: ${ts(9)}`, action: 'sla_breached' }));
    expect(activityEntry(audit('au5', 11, 'attachment_added', { to: 'link:PCAP' }))).toEqual(expect.objectContaining({ title: 'attachment added: link:PCAP' }));
    expect(activityEntry(audit('au6', 12, 'assignment_change', { from: 'alice' }))).toEqual(expect.objectContaining({ title: 'assignment change (was alice)' }));
    expect(activityEntry({ _id: 'bad', _source: { event_type: 'audit', action: 'x' } })).toBeNull();
    expect(describeAuditEvent({})).toBe('event');
  });

  test('task_due entries exist for open tasks with a due date only', () => {
    const tasks = [
      { id: 't1', title: 'Collect logs', owner: 'bob', due_at: ts(20), done: false },
      { id: 't2', title: 'Done one', due_at: ts(21), done: true },
      { id: 't3', title: 'No due', done: false },
      { id: 't4', title: 'Bad due', due_at: 'never', done: false },
    ];
    expect(taskDueEntries(tasks)).toEqual([
      { id: 'task_due:t1', kind: 'task_due', at: ts(20), actor: 'bob', title: 'Task due: Collect logs', details: 'owner bob', ref: { task_id: 't1' } },
    ]);
    expect(taskDueEntries(undefined)).toEqual([]);
  });

  test('ordering is by at then id', () => {
    const entries = [
      { at: ts(1), id: 'alert:b' }, { at: ts(1), id: 'activity:z' }, { at: ts(0), id: 'task_due:t' }, { at: ts(1), id: 'alert:a' },
    ];
    expect([...entries].sort(compareTimelineEntries).map((e) => e.id)).toEqual(['task_due:t', 'activity:z', 'alert:a', 'alert:b']);
  });
});

describe('queryCaseActivity', () => {
  test('reads every event of the case, sorted by created_at then the stored event_uid (never _id fielddata), with no action or event_type filter', async () => {
    const client = fakeClient({ activity: [comment('cm1', 1, 'alice', 'x'), audit('au1', 2, 'task_added'), audit('au2', 3, 'sla_escalated')] });
    const page = await queryCaseActivity(client, 'c1', { limit: 2 });
    const body = client.search.mock.calls[0][0].body;
    expect(client.search.mock.calls[0][0].index).toBe(ACTIVITY_READ_ALIAS);
    expect(body.size).toBe(3);
    expect(body.track_total_hits).toBe(false);
    expect(body.sort).toEqual([{ created_at: { order: 'asc' } }, { event_uid: { order: 'asc', missing: '_first' } }]);
    expect(body.query).toEqual({ bool: { filter: [{ term: { case_id: 'c1' } }] } });
    expect(body.search_after).toBeUndefined();
    expect(page.hits.map((hit: any) => hit._id)).toEqual(['cm1', 'au1']);
    expect(page.hasMore).toBe(true);
    expect(page.lastSort).toEqual([Date.parse(ts(2)), 'au1']);

    const next = await queryCaseActivity(client, 'c1', { after: page.lastSort, limit: 2 });
    expect(client.search.mock.calls[1][0].body.search_after).toEqual([Date.parse(ts(2)), 'au1']);
    expect(next.hits.map((hit: any) => hit._id)).toEqual(['au2']);
    expect(next.hasMore).toBe(false);
  });

  test('pages past a legacy event without event_uid using its null sort value', async () => {
    const client = fakeClient({ activity: [legacyComment('cm0', 1, 30, 'alice', 'old'), audit('au1', 2, 'task_added')] });
    const page = await queryCaseActivity(client, 'c1', { limit: 1 });
    expect(page.hits.map((hit: any) => hit._id)).toEqual(['cm0']);
    expect(page.lastSort).toEqual([Date.parse(ts(1, 30)), null]);
    const next = await queryCaseActivity(client, 'c1', { after: page.lastSort, limit: 1 });
    expect(client.search.mock.calls[1][0].body.search_after).toEqual([Date.parse(ts(1, 30)), null]);
    expect(next.hits.map((hit: any) => hit._id)).toEqual(['au1']);
  });
});

describe('collectCaseTimeline', () => {
  test('merges alerts, comments, audit events and task dues in order, ties broken by id', async () => {
    const client = fakeClient({
      alerts: { a1: alertSource(1), a2: alertSource(3) },
      caseSource: { tasks: [{ id: 't1', title: 'Collect logs', due_at: ts(3), done: false }, { id: 't0', title: 'Closed', due_at: ts(2), done: true }] },
      activity: [comment('cm1', 3, 'alice', 'Blocked the source'), audit('au1', 7, 'status_change', { from: 'open', to: 'closed' }), audit('au0', 3, 'task_added', { to: 'Collect logs' })],
    });
    const result = await collectCaseTimeline(client, 'c1');
    expect(result.entries.map((entry) => entry.id)).toEqual([
      'alert:a1', 'activity:au0', 'activity:cm1', 'alert:a2', 'task_due:t1', 'activity:au1',
    ]);
    expect(result.entries.map((entry) => entry.kind)).toEqual(['alert', 'audit', 'comment', 'alert', 'task_due', 'audit']);
    expect(result.next_cursor).toBeNull();
    expect(result.truncated_alerts).toBe(false);
    const activityCall = client.search.mock.calls.find(([request]: any[]) => request.index === ACTIVITY_READ_ALIAS);
    expect(activityCall[0].body.size).toBe(CASE_TIMELINE_PAGE + 1);
    expect(activityCall[0].body.query).toEqual({ bool: { filter: [{ term: { case_id: 'c1' } }] } });
  });

  test('pages with the cursor without repeating or skipping entries, whichever source fills a page', async () => {
    const activity = [comment('cm1', 2, 'alice', 'one'), audit('au1', 2, 'assignment_change', { to: 'bob' }), audit('au2', 5, 'status_change', { to: 'in_progress' }), audit('au3', 9, 'status_change', { to: 'closed' })];
    const client = fakeClient({
      alerts: { a1: alertSource(1), a2: alertSource(2), a3: alertSource(4), a4: alertSource(6) },
      caseSource: { tasks: [{ id: 't1', title: 'Due', due_at: ts(8), done: false }] },
      activity,
    });
    const ids: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page: any = await collectCaseTimeline(client, 'c1', { cursor, limit: 3 });
      pages += 1;
      expect(page.entries.length).toBeLessThanOrEqual(3);
      ids.push(...page.entries.map((entry: any) => entry.id));
      cursor = page.next_cursor;
      if (cursor) expect(decodeTimelineCursor(cursor, 'c1')!.id).toBe(page.entries[page.entries.length - 1].id);
    } while (cursor);
    expect(pages).toBe(3);
    expect(ids).toEqual(['alert:a1', 'activity:au1', 'activity:cm1', 'alert:a2', 'alert:a3', 'activity:au2', 'alert:a4', 'task_due:t1', 'activity:au3']);
    // Each page read the activity source with the limit, never everything.
    for (const [request] of client.search.mock.calls.filter(([r]: any[]) => r.index === ACTIVITY_READ_ALIAS)) {
      expect(request.body.size).toBe(4);
    }
    // The second page resumed the activity source after the last event served on the first page.
    const activityCalls = client.search.mock.calls.filter(([r]: any[]) => r.index === ACTIVITY_READ_ALIAS);
    expect(activityCalls[1][0].body.search_after).toEqual([Date.parse(ts(2)), 'cm1']);
  });

  test('a comment carrying only created_at (POST /comments before 2.3) is placed and paged by it, never dropped', async () => {
    // au1 10:00, cm1 10:30 (created_at only), au2 11:00, au3 12:00; two pages of two.
    const client = fakeClient({
      alerts: {},
      activity: [audit('au1', 10, 'status_change', { to: 'in_progress' }), legacyComment('cm1', 10, 30, 'bob', 'created_at only'), audit('au2', 11, 'assignment_change', { to: 'bob' }), audit('au3', 12, 'status_change', { to: 'closed' })],
    });
    const first = await collectCaseTimeline(client, 'c1', { limit: 2 });
    expect(first.entries.map((entry) => entry.id)).toEqual(['activity:au1', 'activity:cm1']);
    expect(first.entries[1]).toEqual(expect.objectContaining({ kind: 'comment', at: ts(10, 30), actor: 'bob', details: 'created_at only' }));
    expect(decodeTimelineCursor(first.next_cursor, 'c1')!.sources.activity_after).toEqual([Date.parse(ts(10, 30)), null]);
    const second = await collectCaseTimeline(client, 'c1', { cursor: first.next_cursor, limit: 2 });
    expect(second.entries.map((entry) => entry.id)).toEqual(['activity:au2', 'activity:au3']);
    expect(second.next_cursor).toBeNull();
  });

  test('alert entries come from the evidence snapshots; only legacy rows without a snapshot are looked up live, and never the archive', async () => {
    const client = fakeClient({ alerts: { a1: alertSource(1), a2: alertSource(2) }, evidenceIds: ['a1', 'a2', 'legacy-1', 'gone'] });
    // The evidence fake snapshots `alerts[id]`: the two legacy rows carry no snapshot.
    const result = await collectCaseTimeline(client, 'c1');
    expect(result.entries.map((entry) => entry.id)).toEqual(['alert:a1', 'alert:a2']);
    const alertCalls = client.search.mock.calls.filter(([r]: any[]) => String(r.index).startsWith('wazuh-alert-status-v2'));
    expect(alertCalls).toHaveLength(1);
    expect(alertCalls[0][0].body.query.ids.values).toEqual(['legacy-1', 'gone']);
    // No per-alert archive `get` (the only `get` here is the evidence backfill meta doc).
    expect(client.get.mock.calls.filter(([r]: any[]) => String(r.index).startsWith('wazuh-alert-status-v2'))).toHaveLength(0);

    // Rows whose snapshot sits at or before the cursor boundary are dropped before any lookup.
    const cursor = encodeTimelineCursor({ case: 'c1', at: ts(1), id: 'alert:a1', sources: {} });
    const next = await collectCaseTimeline(client, 'c1', { cursor });
    expect(next.entries.map((entry) => entry.id)).toEqual(['alert:a2']);
  });

  test('a page exactly filled with the last entries has no next cursor', async () => {
    const client = fakeClient({ alerts: { a1: alertSource(1), a2: alertSource(2) }, activity: [comment('cm1', 3, 'alice', 'x')] });
    const result = await collectCaseTimeline(client, 'c1', { limit: 3 });
    expect(result.entries).toHaveLength(3);
    expect(result.next_cursor).toBeNull();
  });

  test('a cursor of another case is a 400 and an unknown case a 404', async () => {
    const foreign = encodeTimelineCursor({ case: 'other', at: ts(1), id: 'alert:a1', sources: {} });
    await expect(collectCaseTimeline(fakeClient(), 'c1', { cursor: foreign })).rejects.toMatchObject({ statusCode: 400 });
    await expect(collectCaseTimeline(fakeClient({ found: false }), 'c1')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('caps the alert source at CASE_TIMELINE_ALERTS_MAX and flags the cut', async () => {
    const alerts: Record<string, any> = {};
    for (let i = 0; i < CASE_TIMELINE_ALERTS_MAX + 5; i += 1) {
      alerts[`a${String(i).padStart(5, '0')}`] = alertSource(0, { '@timestamp': new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString() });
    }
    const client = fakeClient({ alerts });
    const first = await collectCaseTimeline(client, 'c1', { limit: CASE_TIMELINE_LIMIT_MAX });
    expect(first.truncated_alerts).toBe(true);
    expect(first.entries).toHaveLength(CASE_TIMELINE_LIMIT_MAX);
    const second = await collectCaseTimeline(client, 'c1', { cursor: first.next_cursor, limit: CASE_TIMELINE_LIMIT_MAX });
    expect(second.entries).toHaveLength(CASE_TIMELINE_ALERTS_MAX - CASE_TIMELINE_LIMIT_MAX);
    expect(second.next_cursor).toBeNull();
    expect(second.truncated_alerts).toBe(true);
    const evidenceCalls = client.search.mock.calls.filter(([r]: any[]) => String(r.index).startsWith('wazuh-alert-manager-v2-evidence'));
    expect(evidenceCalls.length).toBeGreaterThan(0);
  });

  test('uses a pre-resolved case and alerts when given and clamps the limit', async () => {
    const client = fakeClient({ activity: [comment('cm1', 3, 'alice', 'x')] });
    const result = await collectCaseTimeline(client, 'c1', {
      limit: 10_000,
      caseDoc: { id: 'c1', index: CASE_INDEX, source: { tasks: [] } },
      alerts: { items: [{ id: 'z1', source: alertSource(1), availability: 'live' }], truncated: true },
    });
    expect(result.entries.map((entry) => entry.id)).toEqual(['alert:z1', 'activity:cm1']);
    expect(result.truncated_alerts).toBe(true);
    expect(client.search.mock.calls.map(([r]: any[]) => r.index)).toEqual([ACTIVITY_READ_ALIAS]);
    expect(client.search.mock.calls[0][0].body.size).toBe(CASE_TIMELINE_LIMIT_MAX + 1);
  });
});
