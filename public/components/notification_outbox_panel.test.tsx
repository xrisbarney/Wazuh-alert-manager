/**
 * @jest-environment jsdom
 */
import React from 'react';
import { act, configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NotificationOutboxPanel, outboxTargetPath, truncateError } from './notification_outbox_panel';

configure({ testIdAttribute: 'data-test-subj' });

const NOW = '2026-11-21T10:00:00.000Z';

const entries = [
  { id: 'n-dead', event: 'case.created', channel_id: 'soc-slack', channel_kind: 'indexer_channel', status: 'dead', subject: 's', target_type: 'case', target_id: 'c1', attempts: 5, created_at: NOW, next_attempt_at: null, sent_at: null, updated_at: NOW, last_error: 'no permissions for [cluster:admin/opendistro/alerting/monitor/execute] (hint: map role wazuh_alert_manager_notify to the dashboard user)', last_status_code: 403, delivery: null, dedupe_key: null },
  { id: 'n-sent', event: 'sla.breached', channel_id: 'siem-hook', channel_kind: 'webhook', status: 'sent', subject: 's', target_type: 'alert', target_id: 'a1', attempts: 1, created_at: NOW, next_attempt_at: null, sent_at: NOW, updated_at: NOW, last_error: null, last_status_code: 200, delivery: { transport: 'webhook', deliveryId: 'd', statusCode: 200, durationMs: 5 }, dedupe_key: null },
];

const status = {
  enabled: true,
  tickSeconds: 5,
  status: { last_tick_at: NOW, holder: 'host-1-abcd', claimed: 2, sent: 1, failed: 0, dead: 1, errors: [{ at: NOW, message: 'n-dead (case.created -> soc-slack): no permissions' }] },
  counts: { pending: 3, sending: 0, sent: 10, failed: 1, dead: 2 },
};

function apiServiceWith(overrides: any = {}) {
  return {
    fetchNotificationStatus: jest.fn(async () => status),
    fetchNotificationOutbox: jest.fn(async (filter: any = {}) => (filter.cursor ? { items: [{ ...entries[1], id: 'n-more' }], next_cursor: null, total: 3 } : { items: entries, next_cursor: 'cursor-1', total: 3 })),
    retryNotification: jest.fn(async (id: string) => ({ id, status: 'pending', next_attempt_at: NOW, attempts: 5 })),
    appUrl: jest.fn((path: string) => `/base${path}`),
    ...overrides,
  } as any;
}

describe('NotificationOutboxPanel', () => {
  test('helpers: target paths and error truncation', () => {
    expect(outboxTargetPath({ target_type: 'case', target_id: 'c 1' })).toBe('/app/wazuh-alert-manager?tab=cases&case=c%201');
    expect(outboxTargetPath({ target_type: 'alert', target_id: 'a1' })).toBe('/app/wazuh-alert-manager?tab=alerts&alert=a1');
    expect(outboxTargetPath({ target_type: 'report', target_id: 'r1' })).toBe('/app/wazuh-alert-manager?tab=reports');
    expect(outboxTargetPath({ target_type: 'system', target_id: 'x' })).toBeNull();
    expect(outboxTargetPath({ target_type: 'case', target_id: '' })).toBeNull();
    expect(truncateError('abc', 5)).toBe('abc');
    expect(truncateError('abcdefgh', 5)).toBe('abcd…');
    expect(truncateError(null)).toBe('');
  });

  test('renders the status summary, the entries with badges, target links and the truncated error; Retry only for administrators on failed/dead entries', async () => {
    const api = apiServiceWith();
    render(<NotificationOutboxPanel apiService={api} isAdmin onToast={jest.fn()} refreshMs={0} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifOutboxRow-n-dead')).toBeTruthy());
    expect(screen.getByTestId('wamNotifOutboxCount-pending').textContent).toContain('3');
    expect(screen.getByTestId('wamNotifOutboxCount-dead').textContent).toContain('2');
    expect(screen.getByTestId('wamNotifOutboxHolder').textContent).toContain('host-1-abcd');
    expect(screen.getByTestId('wamNotifOutboxLastTick').textContent).not.toContain('never');
    expect(screen.getByTestId('wamNotifOutboxTickErrors').textContent).toContain('no permissions');
    expect(screen.getByTestId('wamNotifOutboxTotal').textContent).toBe('3 entries');

    const dead = screen.getByTestId('wamNotifOutboxRow-n-dead');
    expect(dead.textContent).toContain('case.created');
    expect(dead.textContent).toContain('soc-slack');
    expect(dead.textContent).toContain('Dead');
    expect(dead.textContent).toContain('HTTP 403: ');
    expect(dead.textContent).toContain('…');
    expect(dead.textContent).not.toContain('dashboard user)');
    expect(dead.querySelector('[data-test-subj="wamNotifOutboxTarget"]')!.getAttribute('href')).toBe('/base/app/wazuh-alert-manager?tab=cases&case=c1');
    expect(screen.getByTestId('wamNotifOutboxRetry-n-dead')).toBeTruthy();

    const sent = screen.getByTestId('wamNotifOutboxRow-n-sent');
    expect(sent.textContent).toContain('Sent');
    expect(sent.querySelector('[data-test-subj="wamNotifOutboxTarget"]')!.getAttribute('href')).toBe('/base/app/wazuh-alert-manager?tab=alerts&alert=a1');
    // Step 10.5c: the target truncates inside a 220px column, the full id is the title and a copy button sits beside it.
    const target = sent.querySelector('[data-test-subj="wamNotifOutboxTarget"]')!;
    expect(target.className).toContain('wamNotifOutboxTarget__label');
    expect(target.getAttribute('title')).toBe('alert: a1');
    expect(target.textContent).toBe('alert: a1');
    expect(sent.querySelector('.wamNotifOutboxTarget .wamIndicatorCopy')!.getAttribute('aria-label')).toBe('Copy alert id a1');
    const targetHeader = Array.from(document.querySelectorAll('th')).find((th) => th.textContent!.trim() === 'Target') as HTMLElement;
    expect(targetHeader.style.width).toBe('220px');
    expect(screen.queryByTestId('wamNotifOutboxRetry-n-sent')).toBeNull();
    expect(api.fetchNotificationOutbox).toHaveBeenCalledWith({});
  });

  test('non-administrators see no Retry action and no lease holder', async () => {
    const api = apiServiceWith({ fetchNotificationStatus: jest.fn(async () => ({ ...status, status: { ...status.status, holder: undefined } })) });
    render(<NotificationOutboxPanel apiService={api} isAdmin={false} onToast={jest.fn()} refreshMs={0} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifOutboxRow-n-dead')).toBeTruthy());
    expect(screen.queryByTestId('wamNotifOutboxRetry-n-dead')).toBeNull();
    expect(screen.queryByTestId('wamNotifOutboxHolder')).toBeNull();
  });

  test('Retry calls the route, updates the row and reloads; the status filter and Load more pass through', async () => {
    const api = apiServiceWith();
    const onToast = jest.fn();
    render(<NotificationOutboxPanel apiService={api} isAdmin onToast={onToast} refreshMs={0} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifOutboxRetry-n-dead')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamNotifOutboxRetry-n-dead'));
    await waitFor(() => expect(api.retryNotification).toHaveBeenCalledWith('n-dead'));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('Notification queued for retry', 'success'));

    fireEvent.change(screen.getByTestId('wamNotifOutboxFilter'), { target: { value: 'dead' } });
    await waitFor(() => expect(api.fetchNotificationOutbox).toHaveBeenCalledWith({ status: 'dead' }));

    fireEvent.click(screen.getByTestId('wamNotifOutboxLoadMore'));
    await waitFor(() => expect(api.fetchNotificationOutbox).toHaveBeenCalledWith({ status: 'dead', cursor: 'cursor-1' }));
    await waitFor(() => expect(screen.getByTestId('wamNotifOutboxRow-n-more')).toBeTruthy());
    expect(screen.queryByTestId('wamNotifOutboxLoadMore')).toBeNull();
  });

  test('auto-refreshes while mounted (keeping the pages loaded with "Load more") and stops on unmount; a load failure is shown inline', async () => {
    jest.useFakeTimers();
    try {
      // 60 rows on the first page (more than NOTIFICATION_OUTBOX_PAGE), 10 more behind the cursor; a silent refresh asks for all 70 shown rows.
      // (Rendering the 70-row EuiBasicTable three times takes 5-16 s, hence the explicit test timeout below.)
      const page1 = Array.from({ length: 60 }, (_, i) => ({ ...entries[1], id: `n-p1-${i}` }));
      const page2 = Array.from({ length: 10 }, (_, i) => ({ ...entries[1], id: `n-p2-${i}` }));
      const api = apiServiceWith({
        fetchNotificationOutbox: jest.fn(async (filter: any = {}) => {
          if (filter.cursor) return { items: page2, next_cursor: null, total: 70 };
          if (filter.limit) return { items: [...page1, ...page2].slice(0, filter.limit), next_cursor: filter.limit < 70 ? 'cursor-2' : null, total: 70 };
          return { items: page1, next_cursor: 'cursor-1', total: 70 };
        }),
      });
      const { unmount } = render(<NotificationOutboxPanel apiService={api} isAdmin onToast={jest.fn()} refreshMs={15000} />);
      await act(async () => {
        await Promise.resolve();
      });
      expect(api.fetchNotificationStatus).toHaveBeenCalledTimes(1);
      expect(api.fetchNotificationOutbox).toHaveBeenLastCalledWith({});
      fireEvent.click(screen.getByTestId('wamNotifOutboxLoadMore'));
      await act(async () => {
        await Promise.resolve();
      });
      expect(api.fetchNotificationOutbox).toHaveBeenLastCalledWith({ cursor: 'cursor-1' });
      expect(screen.getByTestId('wamNotifOutboxRow-n-p2-9')).toBeTruthy();
      await act(async () => {
        jest.advanceTimersByTime(15000);
        await Promise.resolve();
      });
      expect(api.fetchNotificationStatus).toHaveBeenCalledTimes(2);
      expect(api.fetchNotificationOutbox).toHaveBeenLastCalledWith({ limit: 70 });
      // The appended page survives the refresh.
      expect(screen.getByTestId('wamNotifOutboxRow-n-p2-9')).toBeTruthy();
      expect(screen.queryByTestId('wamNotifOutboxLoadMore')).toBeNull();
      unmount();
      await act(async () => {
        jest.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(api.fetchNotificationStatus).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }

    const failing = apiServiceWith({ fetchNotificationStatus: jest.fn(async () => { throw { body: { message: 'indexer unreachable' } }; }) });
    render(<NotificationOutboxPanel apiService={failing} isAdmin onToast={jest.fn()} refreshMs={0} />);
    await waitFor(() => expect(screen.getByTestId('wamNotifOutboxError-load').textContent).toContain('indexer unreachable'));
  }, 60_000);
});
