import React from 'react';
import { EuiToolTip } from '@elastic/eui';
import { Alert } from '../../common';
import { formatAbsolute, statusLabel, STATUS_HEX } from '../design';

export type LinkedAlert = Alert & { _evidence?: any };

interface Props {
  alerts: LinkedAlert[];
  canManageLifecycle: boolean;
  onView: (alert: LinkedAlert) => void;
  onSetHold: (alert: LinkedAlert) => void;
  onReleaseHold: (alert: LinkedAlert) => void;
  onRemove: (alert: LinkedAlert) => void;
}

// Relationship state, in the same words the evidence API and tooltips use.
function evidenceLabel(evidence: any): { label: string; tone: string; tip: string } {
  if (!evidence) return { label: 'Legacy link', tone: '', tip: 'Linked before evidence tracking' };
  if (evidence.hold_reason) return { label: 'Held', tone: 'held', tip: evidence.hold_reason };
  const state = evidence.relationship_state;
  const tip = evidence.archive_index ? `Trusted archive: ${evidence.archive_index}` : 'Live relationship snapshot';
  if (state === 'archived') return { label: 'Archived', tone: 'archived', tip };
  if (state === 'purged') return { label: 'Purged snapshot', tone: 'purged', tip };
  if (state === 'legacy') return { label: 'Legacy link', tone: '', tip };
  return { label: 'Live', tone: '', tip };
}

const Icon: React.FC<{ d: React.ReactNode }> = ({ d }) => (
  <svg viewBox="0 0 24 24" aria-hidden="true">{d}</svg>
);
const EYE = <><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>;
const LOCK = <><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></>;
const UNLOCK = <><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 7.5-2" /></>;
const UNLINK = <path d="M9 17H7a5 5 0 0 1 0-10h2M15 7h2a5 5 0 0 1 4 8M8 12h3M3 3l18 18" />;

/** The case's linked alerts in the console design, with the Wazuh rule ID on every row. */
export const LinkedAlertsTable: React.FC<Props> = ({ alerts, canManageLifecycle, onView, onSetHold, onReleaseHold, onRemove }) => (
  <div className="wamAg__tw">
    <table className="wamAg__at">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Rule ID</th>
          <th>Agent</th>
          <th>Status</th>
          <th>Evidence</th>
          <th className="wamAg__desc">Description</th>
          <th className="wamAg__r">Actions</th>
        </tr>
      </thead>
      <tbody>
        {alerts.length === 0 && (
          <tr><td colSpan={7} className="wamAg__none">No linked alerts.</td></tr>
        )}
        {alerts.map((alert) => {
          const src = alert._source || ({} as Alert['_source']);
          const ruleId = src.rule?.id;
          const ev = evidenceLabel(alert._evidence);
          const held = Boolean(alert._evidence?.hold_reason);
          const status = src.status as string | undefined;
          return (
            <tr key={alert._id}>
              <td className="wamAg__ts">{formatAbsolute(src['@timestamp'])}</td>
              <td>{ruleId != null && ruleId !== '' ? <span className="wamAg__rid" title="Wazuh rule ID">{String(ruleId)}</span> : '—'}</td>
              <td>{src.agent?.name || '—'}</td>
              <td>
                {status
                  ? <span className="wamAg__st" style={{ '--c': STATUS_HEX[status] || STATUS_HEX.closed } as React.CSSProperties}>{statusLabel(status)}</span>
                  : '—'}
              </td>
              <td>
                <EuiToolTip content={ev.tip}>
                  <span className={`wamAg__ev${ev.tone ? ` wamAg__ev--${ev.tone}` : ''}`} tabIndex={0}>{ev.label}</span>
                </EuiToolTip>
              </td>
              <td className="wamAg__desc">{src.rule?.description || '—'}</td>
              <td>
                <div className="wamAg__acts">
                  <button type="button" title="View" aria-label="View evidence" onClick={() => onView(alert)}><Icon d={EYE} /></button>
                  {alert._evidence && canManageLifecycle && (
                    <button
                      type="button"
                      title={held ? 'Release evidence hold' : 'Lock evidence'}
                      aria-label={held ? 'Release evidence hold' : 'Set evidence hold'}
                      onClick={() => (held ? onReleaseHold(alert) : onSetHold(alert))}
                    >
                      <Icon d={held ? UNLOCK : LOCK} />
                    </button>
                  )}
                  <button type="button" title="Unlink from case" aria-label="Remove from case" onClick={() => onRemove(alert)}><Icon d={UNLINK} /></button>
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
