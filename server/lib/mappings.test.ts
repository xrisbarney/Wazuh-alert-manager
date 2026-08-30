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
});
