import React, { useEffect, useState } from 'react';
import { EuiBadge, EuiToolTip } from '@elastic/eui';
import { SLA_DUE_SOON_MINUTES } from '../../common';
import { formatAbsolute } from '../design';

/**
 * Due-date countdown and breach badge (step 3.2), shared by the alert queue,
 * the alert flyout, the cases table and the case flyout.
 *
 * The relative text is computed from the `now` prop (milliseconds) so tests
 * are deterministic; views pass the value of `useNowTicker()` which refreshes
 * once a minute. Nothing is rendered for a closed record or when there is no
 * due date: a closed alert keeps its stored verdict (`reporting.sla_met`) and
 * is never "breached".
 */

export type SlaDueState = 'none' | 'breached' | 'due_soon' | 'on_track';

export interface SlaDueDescription {
  state: SlaDueState;
  /** Countdown text: "2h 14m left", "due in 3d", "-45m overdue"; empty for `none`. */
  text: string;
  /** Minutes until due (negative when overdue); null for `none`. */
  minutes: number | null;
}

function parts(totalMinutes: number): { d: number; h: number; m: number } {
  const total = Math.max(0, Math.round(totalMinutes));
  const d = Math.floor(total / 1440);
  const h = Math.floor((total % 1440) / 60);
  const m = total % 60;
  return { d, h, m };
}

/** "45m", "2h 14m", "3d", "3d 4h" from a non-negative minute count. */
export function formatDueSpan(totalMinutes: number): string {
  const { d, h, m } = parts(totalMinutes);
  if (d > 0) return h ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
}

/** Pure description of a due date relative to `now` (ms); exported for tests and the views' row classes. */
export function describeSlaDue(dueAt: string | null | undefined, status: string | null | undefined, now: number): SlaDueDescription {
  if (!dueAt || status === 'closed') return { state: 'none', text: '', minutes: null };
  const dueMs = Date.parse(dueAt);
  if (!Number.isFinite(dueMs)) return { state: 'none', text: '', minutes: null };
  const minutes = (dueMs - now) / 60000;
  if (minutes < 0) return { state: 'breached', text: `-${formatDueSpan(-minutes)} overdue`, minutes };
  if (minutes <= SLA_DUE_SOON_MINUTES) return { state: 'due_soon', text: `${formatDueSpan(minutes)} left`, minutes };
  const { d } = parts(minutes);
  return { state: 'on_track', text: d >= 1 ? `due in ${formatDueSpan(minutes)}` : `${formatDueSpan(minutes)} left`, minutes };
}

/** Ticks once per `intervalMs` (default 60 s) so countdowns stay current without a refetch. */
export function useNowTicker(intervalMs: number = 60 * 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

export interface SlaDueProps {
  dueAt?: string | null;
  status?: string | null;
  /** Reference time in milliseconds; defaults to the render time. */
  now?: number;
  /** Queue cells: badge + text on one line, no absolute time. */
  compact?: boolean;
  /** Label shown before the countdown in the flyouts (e.g. "Resolve"). */
  label?: string;
  testSubj?: string;
}

export const SlaDue: React.FC<SlaDueProps> = ({ dueAt, status, now, compact = false, label, testSubj = 'wamSlaDue' }) => {
  const reference = typeof now === 'number' ? now : Date.now();
  const due = describeSlaDue(dueAt, status, reference);
  if (due.state === 'none') {
    if (compact) return <span className="wamSlaDue wamSlaDue--none" data-test-subj={testSubj} data-sla-state="none">—</span>;
    return null;
  }
  const badge =
    due.state === 'breached' ? (
      <EuiBadge color="danger" className="wamSlaDue__badge" data-test-subj={`${testSubj}Badge`}>
        Breached
      </EuiBadge>
    ) : due.state === 'due_soon' ? (
      <EuiBadge color="warning" className="wamSlaDue__badge" data-test-subj={`${testSubj}Badge`}>
        Due soon
      </EuiBadge>
    ) : null;
  const body = (
    <span className={`wamSlaDue wamSlaDue--${due.state}`} data-test-subj={testSubj} data-sla-state={due.state}>
      {label && <span className="wamSlaDue__label">{label}</span>}
      {badge}
      <span className="wamSlaDue__text">{due.text}</span>
      {!compact && <span className="wamSlaDue__absolute">({formatAbsolute(dueAt)})</span>}
    </span>
  );
  return compact ? <EuiToolTip content={`Due ${formatAbsolute(dueAt)}`}>{body}</EuiToolTip> : body;
};
