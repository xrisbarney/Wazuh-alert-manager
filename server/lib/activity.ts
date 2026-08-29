import { ACTIVITY_WRITE_ALIAS } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';

export interface ActivityInput {
  eventType?: 'audit' | 'comment';
  targetType: 'alert' | 'case' | 'rule' | 'system';
  targetId: string;
  user: string;
  action: string;
  from?: string | null;
  to?: string | null;
  timestamp?: string;
  source?: string;
  operationId?: string;
  ruleRevision?: number;
}

export interface ActivityFailureObserver {
  error(message: string): void;
  increment?(metric: 'automation_audit_write_failures'): void;
}

export function buildActivityEvent(input: ActivityInput) {
  const timestamp = input.timestamp || new Date().toISOString();
  return {
    event_type: input.eventType || 'audit',
    target_type: input.targetType,
    target_id: input.targetId,
    alert_id: input.targetType === 'alert' ? input.targetId : null,
    case_id: input.targetType === 'case' ? input.targetId : null,
    timestamp,
    created_at: timestamp,
    user: input.user,
    author: input.user,
    action: input.action,
    from: input.from ?? null,
    to: input.to ?? null,
    source: input.source || 'user',
    operation_id: input.operationId || null,
    rule_revision: input.ruleRevision ?? null,
  };
}

export async function appendActivity(client: any, input: ActivityInput) {
  const doc = buildActivityEvent(input);
  await client.index({ index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS), body: doc });
  return doc;
}

/** A deterministic activity write is safe to retry after an ambiguous failure. */
export async function appendActivityOnce(client: any, id: string, input: ActivityInput) {
  const doc = buildActivityEvent(input);
  try {
    await client.index({
      index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS),
      id,
      op_type: 'create',
      body: doc,
    });
  } catch (error: any) {
    if ((error?.meta?.statusCode || error?.statusCode) !== 409) throw error;
  }
  return doc;
}

export function reportActivityFailure(observer: ActivityFailureObserver, operationId: string, error: any) {
  observer.increment?.('automation_audit_write_failures');
  observer.error(
    `wazuh-alert-manager rules audit ${operationId} remains in the durable outbox: ${error?.message || String(error)}`
  );
}

export function pushActivityBulk(body: any[], input: ActivityInput) {
  body.push({ index: { _index: assertManagedWriteTarget(ACTIVITY_WRITE_ALIAS) } });
  body.push(buildActivityEvent(input));
}
