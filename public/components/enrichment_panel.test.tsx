/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { EnrichmentPanel, EnrichmentLookupControls, EnrichmentLookupFn, isLookupableIndicator } from './enrichment_panel';

configure({ testIdAttribute: 'data-test-subj' });

jest.mock('../terminology', () => ({
  useTerminology: () => ({ unit: 'alert', units: 'alerts', Unit: 'Alert', Units: 'Alerts', wazuhMajor: 4 }),
}));

const indicators: any[] = [
  { type: 'ip', value: '10.0.2.15', fields: ['data.srcip'], tags: ['private'], verdictHints: [] },
  { type: 'hash', value: '2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376', fields: ['syscheck.sha256_after'], tags: [], verdictHints: [] },
  { type: 'user', value: 'root', fields: ['data.srcuser'], tags: [], verdictHints: [] },
];

const stored: any = {
  updated_at: '2026-11-22T00:16:25.000Z',
  items: [
    { type: 'hash', value: '2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376', source: 'misp-lab', verdict: 'malicious', score: null, tags: [], link: 'https://misp.internal/e/1', checked_at: '2026-11-22T00:16:25.000Z' },
  ],
};

describe('EnrichmentPanel table (step 10.5a)', () => {
  test('renders an auto-layout compressed table with no fixed column widths, the shared value cell and a right-aligned actions cell', async () => {
    const lookup: EnrichmentLookupFn = jest.fn(async () => ({ results: [] } as any));
    render(<EnrichmentPanel indicators={indicators} stored={stored} lookup={lookup} apiService={{ appUrl: (p: string) => p } as any} />);
    const panel = screen.getByTestId('wamEnrichmentPanel');
    const table = panel.querySelector('table')!;
    expect(table.className).toContain('euiTable--auto');
    expect(table.className).toContain('euiTable--compressed');
    const headers = Array.from(table.querySelectorAll('th')).map((th) => th.textContent!.trim());
    expect(headers).toEqual(['Type', 'Value', 'Native verdicts', 'Lookups', 'Actions']);
    for (const th of Array.from(table.querySelectorAll('th'))) {
      expect((th as HTMLElement).style.width).toBe('');
    }
    expect(screen.getAllByTestId('wamIndicatorValueCell')).toHaveLength(3);
    const hashRow = screen.getAllByRole('row').find((row) => row.textContent!.includes('2ce9f77d'))!;
    expect(hashRow.querySelector('.wamIndicatorTable__value')).toBeTruthy();
    expect(hashRow.querySelector('.wamIndicatorTable__badges .wamEnrichmentBadges')!.textContent).toContain('misp-lab: malicious');
    const actions = hashRow.querySelector('.wamIndicatorTable__actions')!;
    expect(actions.className).toContain('euiTableCellContent--alignRight');
    expect(actions.querySelector('.wamEnrichmentActions')).toBeTruthy();
    expect(actions.querySelector('[data-test-subj="wamEnrichmentLookup"]')).toBeTruthy();
    // A user indicator has no lookup source: n/a, not a button.
    const userRow = screen.getAllByRole('row').find((row) => row.textContent!.includes('root'))!;
    expect(userRow.querySelector('[data-test-subj="wamEnrichmentNotLookupable"]')).toBeTruthy();
    expect(screen.getByTestId('wamEnrichmentLookupAll').textContent).toContain('Lookup all (2)');
  });

  test('a lookup shows the session verdict in the Lookups cell', async () => {
    const lookup: EnrichmentLookupFn = jest.fn(async () => ({
      results: [{ sourceId: 'abuse', sourceName: 'AbuseIPDB', status: 'ok', cached: false, result: { source: 'abuse', verdict: 'clean', score: 0, tags: [], link: null, summary: 'ok', checkedAt: '2026-11-22T00:00:00.000Z' } }],
    } as any));
    render(<EnrichmentPanel indicators={indicators.slice(0, 1)} stored={null} lookup={lookup} apiService={{ appUrl: (p: string) => p } as any} />);
    fireEvent.click(screen.getByTestId('wamEnrichmentLookup'));
    await waitFor(() => expect(screen.getByTestId('wamEnrichmentBadges').textContent).toContain('AbuseIPDB: clean 0'));
    expect(lookup).toHaveBeenCalledWith('ip', '10.0.2.15', false);
  });

  test('lookup controls never wrap and path-only URLs are n/a', () => {
    expect(isLookupableIndicator('url', '/wp-login.php')).toBe(false);
    expect(isLookupableIndicator('ip', '1.2.3.4')).toBe(true);
    const { container } = render(<EnrichmentLookupControls type="ip" value="1.2.3.4" pending={false} onLookup={() => {}} ctiUrl={null} />);
    const group = container.querySelector('.wamEnrichmentActions')!;
    expect(group.className).not.toContain('euiFlexGroup--wrap');
    expect(group.className).toContain('euiFlexGroup--justifyContentFlexEnd');
  });
});
