import { MIGRATION_INDEX, RULES_INDEX } from '../../common';
import { canonicalizeRuleSchema, migrateSavedRuleSchemas } from './rule_schema_migration';

describe('automation rule schema migration', () => {
  test('canonicalizes a legacy trigger entity without changing identity or runtime state', () => {
    const legacy = {
      id: 'rule-7',
      enabled: true,
      revision: 9,
      counters: { matchedAlerts: 41 },
      trigger: { type: 'burst', entity: 'srcip', threshold: 4, windowMinutes: 15 },
    };
    const canonical = canonicalizeRuleSchema(legacy);
    expect(canonical).toMatchObject({
      id: 'rule-7',
      enabled: true,
      revision: 9,
      counters: { matchedAlerts: 41 },
      schemaVersion: 2,
      trigger: {
        type: 'burst',
        threshold: 4,
        windowMinutes: 15,
        routing: 'separate_by_group',
        cooldown: { durationMinutes: 15 },
        rearm: { type: 'after_quiet_period', quietPeriodMinutes: 15 },
        entityExpression: {
          version: 1,
          groups: [{
            id: 'group-1',
            order: 0,
            predicates: [{ id: 'predicate-1', order: 0, entity: 'srcip', operator: 'exists' }],
          }],
        },
      },
    });
    expect(canonical.trigger.entity).toBeUndefined();
  });

  test('writes only canonical trigger fields and preserves existing structural IDs and ordering', () => {
    const canonical = canonicalizeRuleSchema({
      entity: 'agent',
      windowMinutes: 5,
      threshold: 2,
      caseSeverity: 'high',
      trigger: {
        type: 'burst',
        entityExpression: {
          version: 1,
          groups: [{ id: 'stable-group', order: 8, predicates: [{
            id: 'stable-predicate', order: 3, entity: 'process', operator: 'equals', value: ' SSHD ',
          }] }],
        },
        threshold: 7,
        windowMinutes: 30,
        routing: 'one_per_rule',
      },
    });
    expect(canonical.trigger.entityExpression.groups[0]).toMatchObject({
      id: 'stable-group',
      order: 8,
      predicates: [{ id: 'stable-predicate', order: 3, value: 'sshd' }],
    });
    expect(canonical.trigger).toMatchObject({ threshold: 7, windowMinutes: 30, routing: 'one_per_rule' });
    expect(canonical.actions).toEqual({ createCase: true, caseSeverity: 'high' });
    expect(canonical).not.toHaveProperty('entity');
    expect(canonical).not.toHaveProperty('windowMinutes');
    expect(canonical).not.toHaveProperty('threshold');
    expect(canonical).not.toHaveProperty('caseSeverity');
  });

  function migrationClient(sources: Record<string, any>, failAfterWrites = Infinity) {
    const rules = new Map(Object.entries(sources).map(([id, source], index) => [id, {
      _id: id, _source: source, _seq_no: index + 1, _primary_term: 1,
    }]));
    const docs = new Map<string, any>();
    let writes = 0;
    let scrollCalls = 0;
    const client: any = {
      create: jest.fn(async ({ index, id, body }: any) => {
        const key = `${index}/${id}`;
        if (docs.has(key)) {
          const error: any = new Error('conflict'); error.meta = { statusCode: 409 }; throw error;
        }
        docs.set(key, { _source: body, _seq_no: 1, _primary_term: 1 });
      }),
      get: jest.fn(async ({ index, id }: any) => {
        const value = index === RULES_INDEX ? rules.get(id) : docs.get(`${index}/${id}`);
        if (!value) { const error: any = new Error('missing'); error.meta = { statusCode: 404 }; throw error; }
        return { body: value };
      }),
      index: jest.fn(async (request: any) => {
        if (request.index === RULES_INDEX) {
          writes += 1;
          if (writes > failAfterWrites) throw new Error('interrupted');
          const current: any = rules.get(request.id);
          if (current._seq_no !== request.if_seq_no || current._primary_term !== request.if_primary_term) {
            const error: any = new Error('conflict'); error.meta = { statusCode: 409 }; throw error;
          }
          rules.set(request.id, { _id: request.id, _source: request.body, _seq_no: current._seq_no + 1, _primary_term: 1 });
          return {};
        }
        const key = `${request.index}/${request.id}`;
        const current = docs.get(key);
        docs.set(key, { _source: request.body, _seq_no: (current?._seq_no || 0) + 1, _primary_term: 1 });
        return {};
      }),
      delete: jest.fn(async ({ index, id }: any) => { docs.delete(`${index}/${id}`); }),
      search: jest.fn(async () => ({ body: {
        _scroll_id: 'rules-scroll',
        hits: { hits: [...rules.values()].map((hit: any) => ({ ...hit })) },
      } })),
      scroll: jest.fn(async () => {
        scrollCalls += 1;
        return { body: { _scroll_id: 'rules-scroll', hits: { hits: [] } } };
      }),
      clearScroll: jest.fn(async () => ({})),
    };
    return { client, rules, docs, writes: () => writes, scrollCalls: () => scrollCalls };
  }

  const logger: any = { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() };
  const legacyRule = (id: string) => ({
    id,
    name: `Rule ${id}`,
    enabled: true,
    revision: 7,
    created_by: 'owner',
    counters: { matchedAlerts: 12 },
    automation_execution_times: ['2026-08-28T00:00:00.000Z'],
    trigger: { type: 'burst', entity: 'srcip', threshold: 3, windowMinutes: 10 },
    actions: { createCase: true, caseSeverity: 'high' },
  });

  test('migrates primary rules once and preserves identity, ownership, revisions, and telemetry', async () => {
    const { client, rules, writes } = migrationClient({ one: legacyRule('one') });
    await migrateSavedRuleSchemas(client, logger);
    await migrateSavedRuleSchemas(client, logger);

    expect(writes()).toBe(1);
    expect(rules.get('one')!._source).toMatchObject({
      id: 'one', enabled: true, revision: 7, created_by: 'owner',
      counters: { matchedAlerts: 12 }, automation_execution_times: ['2026-08-28T00:00:00.000Z'],
      schemaVersion: 2,
    });
    expect(rules.get('one')!._source.trigger.entity).toBeUndefined();
    expect(client.search).toHaveBeenCalledWith(expect.objectContaining({
      index: RULES_INDEX, size: 200, scroll: '2m',
      body: expect.objectContaining({ sort: ['_doc'], seq_no_primary_term: true }),
    }));
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      index: RULES_INDEX, id: 'one', if_seq_no: 1, if_primary_term: 1,
    }));
  });

  test('resumes after interruption by replaying canonical writes idempotently', async () => {
    const harness = migrationClient({ one: legacyRule('one'), two: legacyRule('two') }, 1);
    await expect(migrateSavedRuleSchemas(harness.client, logger)).rejects.toThrow('interrupted');
    harness.client.index.mockImplementation(async (request: any) => {
      if (request.index === RULES_INDEX) {
        const current: any = harness.rules.get(request.id);
        harness.rules.set(request.id, { _id: request.id, _source: request.body, _seq_no: current._seq_no + 1, _primary_term: 1 });
        return {};
      }
      const key = `${request.index}/${request.id}`;
      const current = harness.docs.get(key);
      harness.docs.set(key, { _source: request.body, _seq_no: (current?._seq_no || 0) + 1, _primary_term: 1 });
      return {};
    });
    await migrateSavedRuleSchemas(harness.client, logger);
    expect(harness.rules.get('one')!._source.schemaVersion).toBe(2);
    expect(harness.rules.get('two')!._source.schemaVersion).toBe(2);
  });

  test('concurrent startup calls serialize through the migration lease', async () => {
    const { client, writes } = migrationClient({ one: legacyRule('one') });
    await Promise.all([migrateSavedRuleSchemas(client, logger), migrateSavedRuleSchemas(client, logger)]);
    expect(writes()).toBe(1);
    expect(client.search).toHaveBeenCalledTimes(1);
    expect(client.clearScroll).toHaveBeenCalledWith({ scrollId: 'rules-scroll' });
  });
});
