import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLink,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import { CaseTimelineEntry, CaseTimelineEntryKind } from '../../common';
import { AlertsApiService } from '../services/api';
import { formatAbsolute, SEVERITY_BADGE_COLOR, SEVERITY_LABEL } from '../design';

/**
 * Case timeline (step 2.3): the "Timeline" tab of the case flyout. One
 * vertical list, grouped by day, of the linked alerts, comments, every audit
 * event of the case and the due dates of its open tasks, paged through the
 * case-scoped cursor of `GET /cases/{id}/timeline`. Alert rows open the alert
 * through the same handler the Alerts tab uses.
 */

interface Props {
  caseId: string;
  apiService: AlertsApiService;
  onError: (message: string) => void;
  /** Opens an alert of the case (live, archived or snapshot) exactly as the Alerts tab does. */
  onOpenAlert?: (alertId: string) => void;
  /** Page size override (tests); the server default applies when omitted. */
  pageSize?: number;
}

const KIND_META: Record<CaseTimelineEntryKind, { icon: string; label: string; color: string }> = {
  alert: { icon: 'bell', label: 'Alert', color: 'warning' },
  comment: { icon: 'editorComment', label: 'Comment', color: 'hollow' },
  audit: { icon: 'clock', label: 'Event', color: 'default' },
  task_due: { icon: 'checkInCircleFilled', label: 'Task due', color: 'primary' },
};

/** Audit events worth a stronger badge than the generic "Event". */
const ACTION_LABELS: Record<string, string> = {
  status_change: 'Status',
  assignment_change: 'Assignee',
  case_created: 'Created',
  case_updated: 'Updated',
  case_link: 'Alert linked',
  case_unlink: 'Alert unlinked',
  task_added: 'Task',
  task_updated: 'Task',
  task_completed: 'Task done',
  task_reopened: 'Task reopened',
  task_removed: 'Task removed',
  task_list_applied: 'Task list',
  sla_breached: 'SLA breached',
  sla_escalated: 'SLA escalated',
  attachment_added: 'Attachment',
  attachment_removed: 'Attachment',
  ai_analysis_generated: 'AI analysis',
  enrichment_lookup: 'Enrichment',
};

export function timelineDayKey(at: string): string {
  const d = new Date(at);
  if (isNaN(d.getTime())) return 'Unknown date';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

/** Consecutive runs of entries sharing a calendar day (entries arrive sorted by `at`). */
export function groupTimelineByDay(entries: CaseTimelineEntry[]): Array<{ day: string; entries: CaseTimelineEntry[] }> {
  const groups: Array<{ day: string; entries: CaseTimelineEntry[] }> = [];
  for (const entry of entries) {
    const day = timelineDayKey(entry.at);
    const last = groups[groups.length - 1];
    if (last && last.day === day) last.entries.push(entry);
    else groups.push({ day, entries: [entry] });
  }
  return groups;
}

function formatTime(at: string): string {
  const d = new Date(at);
  return isNaN(d.getTime()) ? '—' : d.toLocaleTimeString();
}

function errorMessage(e: any, fallback: string): string {
  return e?.body?.message || e?.message || fallback;
}

const EntryBadge: React.FC<{ entry: CaseTimelineEntry }> = ({ entry }) => {
  const meta = KIND_META[entry.kind] || KIND_META.audit;
  if (entry.kind === 'alert' && entry.severity_band) {
    return (
      <EuiBadge color={SEVERITY_BADGE_COLOR[entry.severity_band]} data-test-subj={`wamCaseTimelineBadge-${entry.id}`}>
        Alert · {SEVERITY_LABEL[entry.severity_band]}
      </EuiBadge>
    );
  }
  const label = entry.kind === 'audit' && entry.action ? ACTION_LABELS[entry.action] || meta.label : meta.label;
  const color = entry.kind === 'audit' && (entry.action === 'sla_breached' || entry.action === 'sla_escalated') ? 'danger' : meta.color;
  return (
    <EuiBadge color={color} data-test-subj={`wamCaseTimelineBadge-${entry.id}`}>
      {label}
    </EuiBadge>
  );
};

const TimelineRow: React.FC<{ entry: CaseTimelineEntry; onOpenAlert?: (alertId: string) => void }> = ({ entry, onOpenAlert }) => {
  const meta = KIND_META[entry.kind] || KIND_META.audit;
  const alertId = entry.kind === 'alert' ? entry.ref.alert_id : undefined;
  const title =
    alertId && onOpenAlert ? (
      <EuiLink onClick={() => onOpenAlert(alertId)} data-test-subj={`wamCaseTimelineOpenAlert-${entry.id}`}>
        {entry.title}
      </EuiLink>
    ) : (
      entry.title
    );
  return (
    <li className={`wamCaseTimelineRow wamCaseTimelineRow--${entry.kind}`} data-test-subj={`wamCaseTimelineRow-${entry.id}`}>
      <div className="wamCaseTimelineRow__marker">
        <EuiIcon type={meta.icon} size="m" aria-label={meta.label} />
      </div>
      <div className="wamCaseTimelineRow__body">
        <div className="wamCaseTimelineRow__head">
          <EuiToolTip content={formatAbsolute(entry.at)}>
            <span className="wamCaseTimelineRow__time" data-test-subj={`wamCaseTimelineTime-${entry.id}`}>
              {formatTime(entry.at)}
            </span>
          </EuiToolTip>
          <EntryBadge entry={entry} />
          {entry.actor ? (
            <span className="wamCaseTimelineRow__actor" data-test-subj={`wamCaseTimelineActor-${entry.id}`}>
              {entry.actor}
            </span>
          ) : null}
        </div>
        <EuiText size="s" className="wamCaseTimelineRow__title" data-test-subj={`wamCaseTimelineTitle-${entry.id}`}>
          {title}
        </EuiText>
        {entry.details ? (
          <EuiText size="xs" color="subdued" className="wamCaseTimelineRow__details" data-test-subj={`wamCaseTimelineDetails-${entry.id}`}>
            {entry.details}
          </EuiText>
        ) : null}
      </div>
    </li>
  );
};

export const CaseTimelineTab: React.FC<Props> = ({ caseId, apiService, onError, onOpenAlert, pageSize }) => {
  const [entries, setEntries] = useState<CaseTimelineEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [truncatedAlerts, setTruncatedAlerts] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  // The flyout mounts this tab only while it is selected, so a fetch may
  // outlive the component: every result is checked against the generation
  // that started it (bumped on unmount and on each fresh load).
  const loadGeneration = useRef(0);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  const fetchPage = useCallback(
    (cursor: string | null) => apiService.fetchCaseTimeline(caseId, { cursor, ...(pageSize ? { limit: pageSize } : {}) }),
    [apiService, caseId, pageSize]
  );

  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    try {
      const res = await fetchPage(null);
      if (generation !== loadGeneration.current) return;
      setEntries(res?.entries || []);
      setNextCursor(res?.next_cursor || null);
      setTruncatedAlerts(Boolean(res?.truncated_alerts));
      setLoadError(null);
    } catch (e: any) {
      if (generation !== loadGeneration.current) return;
      setLoadError(errorMessage(e, 'Failed to load the case timeline'));
    } finally {
      if (generation === loadGeneration.current) setLoading(false);
    }
  }, [fetchPage]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return;
    const generation = loadGeneration.current;
    setLoadingMore(true);
    try {
      const res = await fetchPage(nextCursor);
      if (generation !== loadGeneration.current) return;
      setEntries((current) => {
        const seen = new Set(current.map((entry) => entry.id));
        return [...current, ...(res?.entries || []).filter((entry) => !seen.has(entry.id))];
      });
      setNextCursor(res?.next_cursor || null);
      setTruncatedAlerts((current) => current || Boolean(res?.truncated_alerts));
    } catch (e: any) {
      if (generation !== loadGeneration.current) return;
      onErrorRef.current(errorMessage(e, 'Failed to load more of the case timeline'));
    } finally {
      if (generation === loadGeneration.current) setLoadingMore(false);
    }
  }, [fetchPage, nextCursor, loadingMore]);

  useEffect(() => {
    load();
    return () => {
      loadGeneration.current += 1;
    };
  }, [load]);

  if (loading) {
    return (
      <div className="wamCaseTimeline" data-test-subj="wamCaseTimelineLoading">
        <EuiLoadingSpinner size="l" />
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="wamCaseTimeline" data-test-subj="wamCaseTimeline">
        <EuiCallOut title="The timeline could not be loaded" color="danger" iconType="alert" data-test-subj="wamCaseTimelineError">
          <p>{loadError}</p>
          <EuiButton size="s" color="danger" onClick={load} data-test-subj="wamCaseTimelineRetry">
            Retry
          </EuiButton>
        </EuiCallOut>
      </div>
    );
  }

  const groups = groupTimelineByDay(entries);

  return (
    <div className="wamCaseTimeline" data-test-subj="wamCaseTimeline">
      {truncatedAlerts ? (
        <>
          <EuiCallOut size="s" color="warning" iconType="alert" title="This case links more alerts than the timeline shows" data-test-subj="wamCaseTimelineTruncatedAlerts">
            <p>Only the first linked alerts are placed on the timeline; the Alerts tab lists every one.</p>
          </EuiCallOut>
          <EuiSpacer size="s" />
        </>
      ) : null}
      {entries.length === 0 ? (
        <EuiText size="s" color="subdued" data-test-subj="wamCaseTimelineEmpty">
          Nothing on the timeline yet. Linked alerts, comments, case events and task due dates appear here as they happen.
        </EuiText>
      ) : (
        groups.map((group) => (
          <section key={group.day} className="wamCaseTimelineDay" data-test-subj={`wamCaseTimelineDay-${group.day}`}>
            <EuiText size="xs" className="wamCaseTimelineDay__label">
              <strong>{group.day}</strong>
            </EuiText>
            <ol className="wamCaseTimelineList">
              {group.entries.map((entry) => (
                <TimelineRow key={entry.id} entry={entry} onOpenAlert={onOpenAlert} />
              ))}
            </ol>
          </section>
        ))
      )}
      {nextCursor ? (
        <EuiFlexGroup justifyContent="center" responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="arrowDown" onClick={loadMore} isLoading={loadingMore} data-test-subj="wamCaseTimelineLoadMore">
              Load more
            </EuiButtonEmpty>
          </EuiFlexItem>
        </EuiFlexGroup>
      ) : null}
    </div>
  );
};
