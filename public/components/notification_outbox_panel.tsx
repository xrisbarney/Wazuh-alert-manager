import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLink,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiStat,
  EuiText,
  EuiTextColor,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { NOTIFICATION_OUTBOX_LIST_MAX, NOTIFICATION_OUTBOX_PAGE, NOTIFICATION_STATUSES, PLUGIN_NAME } from '../../common';
import type { NotificationOutboxEntry, NotificationStatus, NotificationStatusResponse } from '../../common';
import { AlertsApiService } from '../services/api';
import { CopyValueButton } from './indicator_list';

/**
 * Settings > Notifications: the delivery queue (step 1.2). Any signed-in
 * user sees the counts, the last dispatcher tick and the entries (event,
 * channel, target, attempts, status, last error); administrators also get the
 * lease holder and a Retry action on failed / dead entries. Refreshes the
 * first page and the status every `refreshMs` while mounted (the tab's
 * content is unmounted when another tab is selected).
 */

interface Props {
  apiService: AlertsApiService;
  isAdmin: boolean;
  onToast: (title: string, color: 'success' | 'danger', text?: string) => void;
  /** Auto-refresh interval; 0 disables it (tests). */
  refreshMs?: number;
}

export const OUTBOX_REFRESH_MS = 15 * 1000;
const LAST_ERROR_PREVIEW = 80;

export const OUTBOX_STATUS_LABELS: Record<NotificationStatus, string> = {
  pending: 'Pending',
  sending: 'Sending',
  sent: 'Sent',
  failed: 'Failed',
  dead: 'Dead',
};

export const OUTBOX_STATUS_COLORS: Record<NotificationStatus, string> = {
  pending: 'hollow',
  sending: 'primary',
  sent: 'success',
  failed: 'warning',
  dead: 'danger',
};

/** Deep link to the entry's target inside the workbench (the app opens the case / alert flyout from these params). */
export function outboxTargetPath(entry: Pick<NotificationOutboxEntry, 'target_type' | 'target_id'>): string | null {
  if (!entry.target_id) return null;
  if (entry.target_type === 'case') return `/app/${PLUGIN_NAME}?tab=cases&case=${encodeURIComponent(entry.target_id)}`;
  if (entry.target_type === 'alert') return `/app/${PLUGIN_NAME}?tab=alerts&alert=${encodeURIComponent(entry.target_id)}`;
  if (entry.target_type === 'report') return `/app/${PLUGIN_NAME}?tab=reports`;
  return null;
}

export function truncateError(text: string | null | undefined, max: number = LAST_ERROR_PREVIEW): string {
  if (!text) return '';
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function formatTime(value: string | null | undefined): string {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

/** Target column width (step 10.5c): ids truncate with an ellipsis instead of wrapping one character per line. */
export const OUTBOX_TARGET_WIDTH = '220px';

/** `type: id` truncated to the column, the full id in a tooltip, a copy button beside it. */
export const OutboxTargetCell: React.FC<{ entry: NotificationOutboxEntry; appUrl: (path: string) => string }> = ({ entry, appUrl }) => {
  const path = outboxTargetPath(entry);
  const label = `${entry.target_type}: ${entry.target_id}`;
  return (
    <span className="wamNotifOutboxTarget">
      <EuiToolTip content={label} position="top">
        {path ? (
          <EuiLink href={appUrl(path)} className="wamNotifOutboxTarget__label" title={label} data-test-subj="wamNotifOutboxTarget">
            {label}
          </EuiLink>
        ) : (
          <span className="wamNotifOutboxTarget__label" title={label} data-test-subj="wamNotifOutboxTarget">
            {label}
          </span>
        )}
      </EuiToolTip>
      {entry.target_id ? <CopyValueButton value={entry.target_id} label={`Copy ${entry.target_type} id ${entry.target_id}`} /> : null}
    </span>
  );
};

export const OutboxStatusBadge: React.FC<{ status: NotificationStatus }> = ({ status }) => (
  <EuiBadge color={OUTBOX_STATUS_COLORS[status] || 'default'} className={`wamNotifOutboxBadge wamNotifOutboxBadge--${status}`} data-test-subj="wamNotifOutboxStatusBadge">
    {OUTBOX_STATUS_LABELS[status] || status}
  </EuiBadge>
);

export const NotificationOutboxPanel: React.FC<Props> = ({ apiService, isAdmin, onToast, refreshMs = OUTBOX_REFRESH_MS }) => {
  const [status, setStatus] = useState<NotificationStatusResponse | null>(null);
  const [items, setItems] = useState<NotificationOutboxEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<NotificationStatus | ''>('');
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retrying, setRetrying] = useState<string | null>(null);
  const mounted = useRef(true);
  const filterRef = useRef(statusFilter);
  filterRef.current = statusFilter;
  const itemCountRef = useRef(0);
  itemCountRef.current = items.length;

  const load = useCallback(
    async (silent: boolean = false) => {
      if (!silent) setLoading(true);
      try {
        const filter = filterRef.current;
        // A silent refresh keeps the pages the reader appended with "Load
        // more": it refetches as many rows as are shown (capped by the route).
        const shown = silent ? Math.min(itemCountRef.current, NOTIFICATION_OUTBOX_LIST_MAX) : 0;
        const [nextStatus, page] = await Promise.all([
          apiService.fetchNotificationStatus(),
          apiService.fetchNotificationOutbox({ ...(filter ? { status: filter } : {}), ...(shown > NOTIFICATION_OUTBOX_PAGE ? { limit: shown } : {}) }),
        ]);
        if (!mounted.current) return;
        setStatus(nextStatus);
        setItems(page.items);
        setTotal(page.total);
        setNextCursor(page.next_cursor);
        setError(null);
      } catch (e: any) {
        if (!mounted.current) return;
        setError(e?.body?.message || e?.message || 'Failed to load the notification outbox');
      } finally {
        if (mounted.current && !silent) setLoading(false);
      }
    },
    [apiService]
  );

  useEffect(() => {
    mounted.current = true;
    load();
    return () => {
      mounted.current = false;
    };
  }, [load]);

  useEffect(() => {
    if (!refreshMs) return undefined;
    const timer = setInterval(() => load(true), refreshMs);
    return () => clearInterval(timer);
  }, [load, refreshMs]);

  const changeFilter = (value: string) => {
    const next = (NOTIFICATION_STATUSES as readonly string[]).includes(value) ? (value as NotificationStatus) : '';
    setStatusFilter(next);
    filterRef.current = next;
    load();
  };

  const loadMore = async () => {
    if (!nextCursor) return;
    setLoadingMore(true);
    try {
      const page = await apiService.fetchNotificationOutbox({ ...(statusFilter ? { status: statusFilter } : {}), cursor: nextCursor });
      if (!mounted.current) return;
      setItems((prev) => {
        const seen = new Set(prev.map((entry) => entry.id));
        return [...prev, ...page.items.filter((entry) => !seen.has(entry.id))];
      });
      setNextCursor(page.next_cursor);
      setTotal(page.total);
    } catch (e: any) {
      onToast('Failed to load more outbox entries', 'danger', e?.body?.message || e?.message);
    } finally {
      if (mounted.current) setLoadingMore(false);
    }
  };

  const retry = async (entry: NotificationOutboxEntry) => {
    setRetrying(entry.id);
    try {
      const res = await apiService.retryNotification(entry.id);
      if (!mounted.current) return;
      setItems((prev) => prev.map((row) => (row.id === entry.id ? { ...row, status: res.status, next_attempt_at: res.next_attempt_at, attempts: res.attempts } : row)));
      onToast('Notification queued for retry', 'success');
      load(true);
    } catch (e: any) {
      onToast('Retry failed', 'danger', e?.body?.message || e?.message);
    } finally {
      if (mounted.current) setRetrying(null);
    }
  };

  const counts = status?.counts;
  const tick = status?.status;

  const columns: any[] = [
    {
      field: 'event',
      name: 'Event',
      width: '150px',
      render: (event: string, entry: NotificationOutboxEntry) => (
        <EuiToolTip content={entry.subject}>
          <code data-test-subj="wamNotifOutboxEvent">{event}</code>
        </EuiToolTip>
      ),
    },
    {
      field: 'channel_id',
      name: 'Channel',
      width: '160px',
      render: (channelId: string, entry: NotificationOutboxEntry) => (
        <span data-test-subj="wamNotifOutboxChannel">
          {channelId} <EuiTextColor color="subdued">{entry.channel_kind === 'webhook' ? '(direct webhook)' : '(Notifications channel)'}</EuiTextColor>
        </span>
      ),
    },
    {
      field: 'target_id',
      name: 'Target',
      width: OUTBOX_TARGET_WIDTH,
      render: (targetId: string, entry: NotificationOutboxEntry) => <OutboxTargetCell entry={entry} appUrl={(path) => apiService.appUrl(path)} />,
    },
    { field: 'attempts', name: 'Attempts', width: '90px', align: 'right' },
    {
      field: 'status',
      name: 'Status',
      width: '110px',
      render: (value: NotificationStatus, entry: NotificationOutboxEntry) => (
        <EuiToolTip
          content={
            value === 'sent'
              ? `Sent ${formatTime(entry.sent_at)}`
              : value === 'failed' || value === 'pending'
              ? `Next attempt ${formatTime(entry.next_attempt_at)}`
              : value === 'sending'
              ? `Claimed ${formatTime(entry.claimed_at)}`
              : 'Gave up; an administrator can retry it'
          }
        >
          <span>
            <OutboxStatusBadge status={value} />
          </span>
        </EuiToolTip>
      ),
    },
    {
      field: 'last_error',
      name: 'Last error',
      render: (value: string | null, entry: NotificationOutboxEntry) =>
        value ? (
          <EuiToolTip content={value}>
            <span className="wamNotifOutboxError" data-test-subj="wamNotifOutboxError">
              {entry.last_status_code ? `HTTP ${entry.last_status_code}: ` : ''}
              {truncateError(value)}
            </span>
          </EuiToolTip>
        ) : (
          <EuiTextColor color="subdued">-</EuiTextColor>
        ),
    },
    { field: 'created_at', name: 'Created', width: '170px', render: (value: string) => formatTime(value) },
  ];
  if (isAdmin) {
    columns.push({
      name: 'Actions',
      width: '90px',
      render: (entry: NotificationOutboxEntry) =>
        entry.status === 'failed' || entry.status === 'dead' ? (
          <EuiButtonEmpty size="xs" iconType="refresh" isLoading={retrying === entry.id} onClick={() => retry(entry)} data-test-subj={`wamNotifOutboxRetry-${entry.id}`}>
            Retry
          </EuiButtonEmpty>
        ) : null,
    });
  }

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" className="wamNotifOutbox" data-test-subj="wamNotifOutbox">
      <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiTitle size="xs">
            <h4>Delivery outbox</h4>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty size="s" iconType="refresh" onClick={() => load()} isLoading={loading} data-test-subj="wamNotifOutboxRefresh">
            Refresh
          </EuiButtonEmpty>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiText size="s" color="subdued">
        <p>
          Every event bound to a channel is queued here and delivered by the dispatcher (one replica, every {status?.tickSeconds ?? 5} s). A failed
          delivery is retried with growing delays (30 s, 2 min, 10 min, 30 min, 1 h) and marked <strong>dead</strong> after five attempts; administrators
          can retry failed and dead entries.
        </p>
      </EuiText>
      <EuiSpacer size="m" />
      {error && (
        <>
          <EuiCallOut size="s" color="danger" iconType="alert" title="Failed to load the notification outbox" data-test-subj="wamNotifOutboxError-load">
            <p>{error}</p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      <EuiFlexGroup className="wamNotifOutboxStats" responsive={false} wrap data-test-subj="wamNotifOutboxStatus">
        {NOTIFICATION_STATUSES.map((value) => (
          <EuiFlexItem grow={false} key={value}>
            <EuiStat title={counts ? String(counts[value] ?? 0) : '-'} description={OUTBOX_STATUS_LABELS[value]} titleSize="s" data-test-subj={`wamNotifOutboxCount-${value}`} />
          </EuiFlexItem>
        ))}
        <EuiFlexItem grow={false}>
          <EuiStat title={tick ? formatTime(tick.last_tick_at) : status?.enabled === false ? 'disabled' : 'never'} description="Last dispatcher tick" titleSize="xs" data-test-subj="wamNotifOutboxLastTick" />
        </EuiFlexItem>
        {tick?.holder && (
          <EuiFlexItem grow={false}>
            <EuiStat title={tick.holder} description="Lease holder" titleSize="xs" data-test-subj="wamNotifOutboxHolder" />
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      {status?.enabled === false && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut size="s" color="warning" title="The dispatcher is disabled on this dashboard replica (wazuh_alert_manager.notifications.dispatcher.enabled: false); queued entries stay pending unless another replica delivers them." />
        </>
      )}
      {tick && tick.errors.length > 0 && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut size="s" color="warning" title={`Last dispatcher errors (${tick.errors.length})`} data-test-subj="wamNotifOutboxTickErrors">
            <ul className="wamNotifOutboxErrorList">
              {tick.errors.slice(-3).map((entry, index) => (
                <li key={`${entry.at}-${index}`}>
                  <code>{entry.at}</code> {entry.message}
                </li>
              ))}
            </ul>
          </EuiCallOut>
        </>
      )}
      <EuiSpacer size="m" />
      <EuiFlexGroup alignItems="center" responsive={false} gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiSelect
            compressed
            aria-label="Filter by status"
            options={[{ value: '', text: 'All statuses' }, ...NOTIFICATION_STATUSES.map((value) => ({ value, text: OUTBOX_STATUS_LABELS[value] }))]}
            value={statusFilter}
            onChange={(e) => changeFilter(e.target.value)}
            data-test-subj="wamNotifOutboxFilter"
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText size="xs" color="subdued" data-test-subj="wamNotifOutboxTotal">
            {total} {total === 1 ? 'entry' : 'entries'}
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiBasicTable
        className="wamNotifOutboxTable"
        items={items}
        columns={columns}
        rowProps={(entry: NotificationOutboxEntry) => ({ 'data-test-subj': `wamNotifOutboxRow-${entry.id}` })}
        loading={loading}
        noItemsMessage={loading ? 'Loading...' : statusFilter ? `No ${OUTBOX_STATUS_LABELS[statusFilter].toLowerCase()} entries.` : 'Nothing has been queued yet.'}
        tableLayout="auto"
      />
      {nextCursor && (
        <>
          <EuiSpacer size="s" />
          <EuiButton size="s" onClick={loadMore} isLoading={loadingMore} data-test-subj="wamNotifOutboxLoadMore">
            Load more
          </EuiButton>
        </>
      )}
    </EuiPanel>
  );
};
