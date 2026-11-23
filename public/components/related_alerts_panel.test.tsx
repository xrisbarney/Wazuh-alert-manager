/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, waitFor } from '@testing-library/react';
import { RelatedAlertsPanel } from './related_alerts_panel';

configure({ testIdAttribute: 'data-test-subj' });

// The picker searches the API on mount; it is not what this test exercises.
jest.mock('./alert_multi_picker', () => ({ AlertMultiPicker: () => null }));

const linked = [
  { _id: 'a', _source: { '@timestamp': '2026-11-20T10:00:00.000Z', agent: { name: 'web-01' }, rule: { description: 'One' } } },
  { _id: 'b', _source: { '@timestamp': '2026-11-20T10:01:00.000Z', agent: { name: 'web-02' }, rule: { description: 'Two' } } },
];

function apiServiceWith(alerts: any[]) {
  return {
    fetchRelatedAlerts: jest.fn(async () => ({ alerts })),
    fetchSuggestedAlerts: jest.fn(async () => ({ alerts: [] })),
    updateRelatedAlerts: jest.fn(async () => ({})),
  } as any;
}

describe('RelatedAlertsPanel onCountChanged', () => {
  it('reports the linked total after the load and fetches once even when the callback is inline', async () => {
    const api = apiServiceWith(linked);
    const calls: number[] = [];
    const ui = (n: number) => (
      <RelatedAlertsPanel
        alertId="1"
        apiService={api}
        onError={() => {}}
        onOpenAlert={() => {}}
        onCountChanged={(total) => calls.push(total * 10 + n)}
      />
    );
    const { rerender } = render(ui(0));
    await waitFor(() => expect(screen.getAllByTestId('wamRelatedLinkedRow')).toHaveLength(2));
    expect(calls).toEqual([20]);

    // A host passing a new inline callback on every render must not re-key the load.
    rerender(ui(1));
    rerender(ui(2));
    await waitFor(() => expect(screen.getAllByTestId('wamRelatedLinkedRow')).toHaveLength(2));
    expect(api.fetchRelatedAlerts).toHaveBeenCalledTimes(1);
    expect(calls).toEqual([20]);
  });

  it('refetches and calls the latest callback when the alert id changes', async () => {
    const api = apiServiceWith(linked);
    const first = jest.fn();
    const second = jest.fn();
    const ui = (id: string, cb: (n: number) => void) => (
      <RelatedAlertsPanel alertId={id} apiService={api} onError={() => {}} onOpenAlert={() => {}} onCountChanged={cb} />
    );
    const { rerender } = render(ui('1', first));
    await waitFor(() => expect(first).toHaveBeenCalledWith(2));
    rerender(ui('2', second));
    await waitFor(() => expect(second).toHaveBeenCalledWith(2));
    expect(api.fetchRelatedAlerts).toHaveBeenCalledTimes(2);
    expect(api.fetchRelatedAlerts).toHaveBeenLastCalledWith('2');
  });
});
