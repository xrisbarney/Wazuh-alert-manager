import React from 'react';
import { EuiText } from '@elastic/eui';
import { AuditEntry, DISPOSITION_LABELS } from '../../common';
import { formatAbsolute } from '../design';

const ACTION_LABELS: Record<string, string> = {
  status_change: 'changed status',
  status_and_case_change: 'changed status and case',
  case_link: 'linked to a case',
  case_unlink: 'removed from a case',
  case_created: 'created the case',
  case_updated: 'updated the case',
  comment_added: 'added a comment',
  assignment_change: 'changed the assignee',
  bulk_update: 'bulk-updated this alert',
  related_alert_linked: 'linked a related alert',
  related_alert_unlinked: 'unlinked a related alert',
  ai_analysis_generated: 'generated an AI analysis',
  // SLA escalation scanner (step 3.3); `to` carries the due date / escalation name.
  sla_breached: 'SLA breached (resolve target passed)',
  sla_escalated: 'applied an SLA escalation',
  // Case tasks (step 2.1); `to` carries the task title (`from` on removal).
  task_added: 'added a task',
  task_updated: 'updated a task',
  task_completed: 'completed a task',
  task_reopened: 'reopened a task',
  task_removed: 'removed a task',
  // TaskLists (step 2.2); `to` carries the task list name.
  task_list_applied: 'applied a task list',
  task_list_created: 'created a task list',
  task_list_updated: 'updated a task list',
  task_list_deleted: 'deleted a task list',
};

/** Human label for an audit action; falls back to the raw action name. */
export function historyActionLabel(action: string): string {
  return ACTION_LABELS[action] || action;
}

/**
 * Audit history of an alert or a case (the "History" section of both
 * flyouts). Rows sit on a two-column grid, time | actor + action, aligned
 * with the case timeline rows (step 8.1); newest first.
 */
export const HistoryList: React.FC<{ history?: AuditEntry[]; testSubj?: string }> = ({ history, testSubj = 'wamHistory' }) => {
  if (!history || history.length === 0) {
    return (
      <EuiText size="s" color="subdued" data-test-subj={`${testSubj}Empty`}>
        No history recorded yet.
      </EuiText>
    );
  }

  const sorted = [...history].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <ol className="wamHistoryList" data-test-subj={testSubj}>
      {sorted.map((entry, idx) => {
        const change = entry.from || entry.to
          ? `${entry.from ? `${entry.from} -> ` : ''}${entry.to || ''}${
              entry.disposition ? ` (${(DISPOSITION_LABELS as Record<string, string>)[entry.disposition] || entry.disposition})` : ''
            }`
          : null;
        return (
          <li key={idx} className="wamHistoryRow" data-test-subj={`${testSubj}Row`}>
            <span className="wamHistoryRow__time" title={entry.timestamp}>
              {formatAbsolute(entry.timestamp)}
            </span>
            <div className="wamHistoryRow__body">
              <EuiText size="s" className="wamHistoryRow__event">
                <span className="wamHistoryRow__actor">{entry.user}</span> <span className="wamHistoryRow__action">{historyActionLabel(entry.action)}</span>
              </EuiText>
              {change ? (
                <EuiText size="xs" color="subdued" className="wamHistoryRow__details">
                  {change}
                </EuiText>
              ) : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
};
