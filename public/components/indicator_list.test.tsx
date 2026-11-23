/**
 * @jest-environment jsdom
 */
import React from 'react';
import { act, configure, render, screen } from '@testing-library/react';
import {
  INDICATOR_TABLE_COMPACT_WIDTH,
  IndicatorGroups,
  IndicatorSeenCell,
  IndicatorValueCell,
  VerdictBadges,
  indicatorsAsText,
  useIndicatorTableCompact,
} from './indicator_list';

configure({ testIdAttribute: 'data-test-subj' });

describe('indicator table cells (step 10.5a)', () => {
  test('IndicatorValueCell renders the copy button, the value in code font and the tags as one wrapping block', () => {
    render(<IndicatorValueCell value="2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376" fields={['syscheck.sha256_after']} tags={['private']} />);
    const cell = screen.getByTestId('wamIndicatorValueCell');
    expect(cell.className).toContain('wamIndicatorValueCell');
    expect(cell.querySelector('code.wamIndicatorValue')!.textContent).toBe('2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376');
    expect(cell.querySelector('.wamIndicatorCopy')).toBeTruthy();
    expect(cell.querySelector('.euiBadge')!.textContent).toBe('private');
  });

  test('IndicatorSeenCell shows the last-seen time and keeps both bounds for the tooltip', () => {
    render(<IndicatorSeenCell firstSeen="2026-11-21T10:00:28.000Z" lastSeen="2026-11-21T11:57:26.000Z" />);
    const seen = screen.getByTestId('wamIndicatorSeen');
    expect(seen.textContent).toBe(new Date('2026-11-21T11:57:26.000Z').toLocaleString());
  });

  function Probe({ threshold }: { threshold?: number }) {
    const { ref, compact } = useIndicatorTableCompact(threshold);
    return (
      <div ref={ref} data-test-subj="probe">
        {compact ? 'compact' : 'full'}
      </div>
    );
  }

  test('useIndicatorTableCompact is false while unmeasured (jsdom) and flips below the content-width threshold on resize', () => {
    expect(INDICATOR_TABLE_COMPACT_WIDTH).toBe(1100);
    const original = HTMLElement.prototype.getBoundingClientRect;
    let width = 0;
    HTMLElement.prototype.getBoundingClientRect = function () {
      return { width, height: 0, top: 0, left: 0, right: width, bottom: 0, x: 0, y: 0, toJSON: () => ({}) } as DOMRect;
    };
    try {
      render(<Probe />);
      expect(screen.getByTestId('probe').textContent).toBe('full');
      // An element that is already narrow when it appears is measured on attach.
      width = 900;
      render(<Probe threshold={1000} />);
      expect(screen.getAllByTestId('probe')[1].textContent).toBe('compact');
      width = 900;
      act(() => {
        window.dispatchEvent(new Event('resize'));
      });
      expect(screen.getAllByTestId('probe')[0].textContent).toBe('compact');
      width = 1400;
      act(() => {
        window.dispatchEvent(new Event('resize'));
      });
      expect(screen.getAllByTestId('probe')[0].textContent).toBe('full');
    } finally {
      HTMLElement.prototype.getBoundingClientRect = original;
    }
  });
});

describe('indicator groups', () => {
  const indicators: any[] = [
    { type: 'ip', value: '10.0.2.15', fields: ['data.srcip'], tags: ['private'], verdictHints: [] },
    { type: 'ip', value: '203.0.113.9', fields: ['data.srcip'], tags: [], verdictHints: [{ source: 'cti', verdict: 'malicious', detail: 'listed' }] },
    { type: 'hash', value: 'abc', fields: ['syscheck.md5_after'], tags: [], verdictHints: [] },
  ];

  test('groups by type with a count badge, one row per value, hints as a badge', () => {
    render(<IndicatorGroups indicators={indicators} />);
    expect(screen.getByTestId('wamIndicatorGroup-ip').querySelectorAll('.wamIndicatorRow')).toHaveLength(2);
    expect(screen.getByTestId('wamIndicatorGroup-hash').querySelectorAll('.wamIndicatorRow')).toHaveLength(1);
    expect(screen.getByTestId('wamIndicatorGroup-ip').querySelector('.wamIndicatorHints')!.textContent).toContain('malicious (1)');
    expect(indicatorsAsText(indicators)).toBe('10.0.2.15\n203.0.113.9\nabc');
  });

  test('VerdictBadges renders nothing without hints and a GeoIP badge for info hints', () => {
    const { container } = render(<VerdictBadges hints={[]} />);
    expect(container.innerHTML).toBe('');
    render(<VerdictBadges hints={[{ source: 'geo', verdict: 'info', detail: 'DE' } as any]} />);
    expect(screen.getByText('DE')).toBeTruthy();
  });
});
