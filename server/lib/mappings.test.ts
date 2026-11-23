import {
  activityMapping,
  automationDlqMapping,
  automationExecutionMapping,
  automationQueueMapping,
  casesMapping,
  ruleExecutionStateProperties,
  rulesMapping,
} from './mappings';

describe('persisted automation mappings', () => {
  test('maps rule definitions, deterministic revisions, outbox state, and companion execution counters', () => {
    const properties: any = rulesMapping.properties;

    expect(properties).toMatchObject({
      revision: { type: 'long' },
      effective_from: { type: 'date' },
      state_epoch: { type: 'keyword' },
      schemaVersion: { type: 'integer' },
      priority: { type: 'integer' },
      sortOrder: { type: 'long' },
      processingMode: { type: 'keyword' },
      deleted_at: { type: 'date' },
      deleted_by: { type: 'keyword' },
      document_type: { type: 'keyword' },
      rule_id: { type: 'keyword' },
      snapshot: { type: 'object', enabled: false },
      operation_id: { type: 'keyword' },
      pending_operation: { type: 'object', enabled: false },
    });
    expect(properties.preconditions.properties.statuses).toEqual({ type: 'keyword' });
    expect(properties.safety.properties.rateLimit.properties.maxExecutions).toEqual({ type: 'integer' });
    expect(properties.trigger.properties).toMatchObject({
      routing: { type: 'keyword' },
      cooldown: { properties: { durationMinutes: { type: 'integer' } } },
      rearm: {
        properties: {
          type: { type: 'keyword' },
          quietPeriodMinutes: { type: 'integer' },
        },
      },
    });
    expect(properties.trigger.properties.entityExpression.properties.groups).toMatchObject({
      type: 'nested',
      properties: {
        id: { type: 'keyword' },
        order: { type: 'integer' },
        predicates: {
          type: 'nested',
          properties: {
            id: { type: 'keyword' },
            entity: { type: 'keyword' },
            operator: { type: 'keyword' },
            value: { type: 'keyword' },
          },
        },
      },
    });
    expect(Object.keys(properties.counters.properties)).toEqual(
      expect.arrayContaining(['matchedAlerts', 'actionsFailed', 'casesCreated', 'evidenceLinksWritten'])
    );
    expect(properties.counters).toBe(ruleExecutionStateProperties.counters);
    expect(activityMapping.properties).toMatchObject({
      operation_id: { type: 'keyword' },
      rule_revision: { type: 'long' },
      event_uid: { type: 'keyword' },
    });
  });

  test('defines each automation singleton mapping', () => {
    expect(automationQueueMapping.properties).toMatchObject({
      event_id: { type: 'keyword' },
      event_timestamp: { type: 'date' },
      state: { type: 'keyword' },
      available_at: { type: 'date' },
      payload: { type: 'object', enabled: false },
      ruleset_snapshot: { type: 'keyword' },
      rule_revisions: { type: 'object', enabled: false },
    });
    expect(automationDlqMapping.properties).toMatchObject({
      execution_id: { type: 'keyword' },
      stage: { type: 'keyword' },
      error: { type: 'object', enabled: false },
      ruleset_snapshot: { type: 'keyword' },
    });
    expect(automationExecutionMapping.properties).toMatchObject({
      execution_id: { type: 'keyword' },
      document_type: { type: 'keyword' },
      snapshot_sha256: { type: 'keyword' },
      rules_snapshot: { type: 'object', enabled: false },
      lease_expires_at: { type: 'date' },
      applied_rule_ids: { type: 'keyword' },
      counters: { properties: { matches: { type: 'long' }, skippedBySafety: { type: 'long' } } },
      last_error: { type: 'object', enabled: false },
    });
  });

  test('keeps an exact case evidence count beside the bounded compatibility preview', () => {
    expect(casesMapping.properties).toMatchObject({
      alert_ids: { type: 'keyword' },
      evidence_count: { type: 'long' },
    });
  });

  test('case tasks are a closed nested list with a denormalised open/done pair (step 2.1)', () => {
    const tasks: any = (casesMapping.properties as any).tasks;
    expect(tasks.type).toBe('nested');
    expect(tasks.dynamic).toBe(false);
    expect(Object.keys(tasks.properties).sort()).toEqual(
      ['created_at', 'created_by', 'done', 'done_at', 'done_by', 'due_at', 'id', 'order', 'owner', 'title'].sort()
    );
    expect(tasks.properties).toMatchObject({
      id: { type: 'keyword' },
      owner: { type: 'keyword' },
      due_at: { type: 'date' },
      done: { type: 'boolean' },
      done_by: { type: 'keyword' },
      done_at: { type: 'date' },
      created_by: { type: 'keyword' },
      created_at: { type: 'date' },
      order: { type: 'integer' },
    });
    expect((casesMapping.properties as any).task_counts).toEqual({
      properties: { open: { type: 'long' }, done: { type: 'long' } },
    });
  });
});

describe('task lists (step 2.2)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { taskListsMapping } = require('./mappings');

  test('the task lists index is closed, with a snake_case task template and audit fields', () => {
    expect(taskListsMapping.dynamic).toBe(false);
    expect(Object.keys(taskListsMapping.properties).sort()).toEqual(
      ['created_at', 'created_by', 'description', 'enabled', 'id', 'name', 'tasks', 'updated_at', 'updated_by']
    );
    expect(taskListsMapping.properties.tasks).toMatchObject({ type: 'object', dynamic: false });
    expect(taskListsMapping.properties.tasks.properties).toEqual({
      title: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
      owner: { type: 'keyword' },
      due_offset_minutes: { type: 'integer' },
      order: { type: 'integer' },
    });
    expect(taskListsMapping.properties).toMatchObject({
      id: { type: 'keyword' }, name: { type: 'keyword' }, description: { type: 'text' }, enabled: { type: 'boolean' },
      created_by: { type: 'keyword' }, created_at: { type: 'date' }, updated_by: { type: 'keyword' }, updated_at: { type: 'date' },
    });
  });

  test('cases carry the applied_task_lists marker and rules the applyTaskListId action', () => {
    expect((casesMapping.properties as any).applied_task_lists).toEqual({
      type: 'object',
      dynamic: false,
      properties: { task_list_id: { type: 'keyword' }, applied_at: { type: 'date' }, applied_by: { type: 'keyword' } },
    });
    expect((rulesMapping.properties as any).actions.properties.applyTaskListId).toEqual({ type: 'keyword' });
  });
});

describe('disposition (step 2.4)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { alertStatusMapping: alerts, casesMapping: cases, rulesMapping: rules } = require('./mappings');

  test('alerts and cases carry a keyword disposition and a text closure_reason with a keyword sub-field', () => {
    for (const mapping of [alerts, cases]) {
      expect(mapping.properties.disposition).toEqual({ type: 'keyword' });
      expect(mapping.properties.closure_reason).toEqual({ type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 512 } } });
    }
    expect(rules.properties.actions.properties.disposition).toEqual({ type: 'keyword' });
  });
});

describe('native case projection (step 2.6)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { alertStatusMapping: alerts } = require('./mappings');

  test('alerts carry a closed native_case object with keyword facets, a bounded title and a date', () => {
    expect(alerts.properties.native_case).toEqual({
      properties: {
        id: { type: 'keyword' },
        status: { type: 'keyword' },
        severity: { type: 'keyword' },
        priority: { type: 'keyword' },
        tlp: { type: 'keyword' },
        title: { type: 'keyword', ignore_above: 512 },
        tags: { type: 'keyword' },
        updated_at: { type: 'date' },
      },
    });
  });
});

describe('notification outbox (step 1.2)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { notificationsMapping } = require('./mappings');

  test('the outbox index is closed; payload and delivery are stored but never indexed', () => {
    expect(notificationsMapping.dynamic).toBe(false);
    expect(Object.keys(notificationsMapping.properties).sort()).toEqual(
      ['attempts', 'channel_id', 'channel_kind', 'claimed_at', 'claimed_by', 'created_at', 'dedupe_key', 'delivery', 'event', 'id', 'last_error', 'last_status_code', 'next_attempt_at', 'payload', 'sent_at', 'status', 'subject', 'target_id', 'target_type', 'updated_at']
    );
    expect(notificationsMapping.properties).toMatchObject({
      id: { type: 'keyword' },
      event: { type: 'keyword' },
      channel_id: { type: 'keyword' },
      channel_kind: { type: 'keyword' },
      status: { type: 'keyword' },
      subject: { type: 'keyword', ignore_above: 512 },
      payload: { type: 'object', enabled: false },
      delivery: { type: 'object', enabled: false },
      target_type: { type: 'keyword' },
      target_id: { type: 'keyword' },
      attempts: { type: 'integer' },
      created_at: { type: 'date' },
      next_attempt_at: { type: 'date' },
      sent_at: { type: 'date' },
      updated_at: { type: 'date' },
      claimed_at: { type: 'date' },
      last_error: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
      last_status_code: { type: 'integer' },
      dedupe_key: { type: 'keyword' },
    });
  });
});
