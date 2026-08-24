import React from 'react';
import { EuiCommentList, EuiComment, EuiText } from '@elastic/eui';
import { AuditEntry } from '../../common';

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
};

export const HistoryList: React.FC<{ history?: AuditEntry[] }> = ({ history }) => {
  if (!history || history.length === 0) {
    return (
      <EuiText size="s" color="subdued">
        No history recorded yet.
      </EuiText>
    );
  }

  const sorted = [...history].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <EuiCommentList>
      {sorted.map((entry, idx) => (
        <EuiComment
          key={idx}
          username={entry.user}
          timestamp={new Date(entry.timestamp).toLocaleString()}
          event={ACTION_LABELS[entry.action] || entry.action}
        >
          {entry.from || entry.to ? (
            <EuiText size="s">
              {entry.from ? `${entry.from} -> ` : ''}
              {entry.to || ''}
            </EuiText>
          ) : null}
        </EuiComment>
      ))}
    </EuiCommentList>
  );
};
