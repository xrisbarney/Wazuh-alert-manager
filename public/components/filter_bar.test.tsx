/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, fireEvent } from '@testing-library/react';
import { FilterBar, AlertFilterState } from './filter_bar';

configure({ testIdAttribute: 'data-test-subj' });

const filters: AlertFilterState = {
  statuses: ['open', 'in_progress'],
  ruleIds: [],
  agentNames: [],
  alertTypes: [],
  assignedTo: [],
  q: '',
};

const renderBar = (overrides: Partial<React.ComponentProps<typeof FilterBar>> = {}) => {
  const onApply = jest.fn();
  const onToggleAutoRefresh = jest.fn();
  const utils = render(
    <FilterBar
      filters={filters}
      onChange={() => {}}
      timeRange={{ from: 'now-24h', to: 'now', mode: 'relative' }}
      onTimeRangeChange={() => {}}
      filterOptions={null}
      onApply={onApply}
      loading={false}
      autoRefreshEnabled={false}
      onToggleAutoRefresh={onToggleAutoRefresh}
      {...overrides}
    />
  );
  return { ...utils, onApply, onToggleAutoRefresh };
};

describe('FilterBar grid (step 8.4)', () => {
  test('the query row puts the search field, the time-range button and Apply at the same (m) height', () => {
    const { container } = renderBar();
    const query = container.querySelector('.wamQueryRow__query input') as HTMLInputElement;
    expect(query).not.toBeNull();
    expect(query.className).not.toContain('compressed');
    const timeButton = container.querySelector('.wamTimeRangeButton') as HTMLElement;
    expect(timeButton.className).not.toContain('euiButton--small');
    expect(timeButton.textContent).toContain('Last 24 hours');
    const apply = screen.getByRole('button', { name: 'Apply' });
    expect(apply.className).not.toContain('euiButton--small');
    expect(apply.className).toContain('euiButton--fill');
    // No compressed form rows on the query row: label spacing matches the m controls.
    expect(container.querySelectorAll('.wamQueryRow .euiFormRow--compressed').length).toBe(0);
  });

  test('the Lucene note is the query form row help text, not a loose paragraph', () => {
    const { container } = renderBar();
    const help = container.querySelector('.wamQueryRow__query .euiFormHelpText');
    expect(help).not.toBeNull();
    expect(help!.textContent).toContain('Lucene syntax');
    expect(container.querySelectorAll('.wamFilterBar > p').length).toBe(0);
  });

  test('the structured filters are one grid with the auto-refresh switch as its last cell', () => {
    const { container, onToggleAutoRefresh } = renderBar();
    const grid = container.querySelector('.wamStructuredFilters') as HTMLElement;
    const cells = Array.from(grid.children) as HTMLElement[];
    expect(cells.length).toBeGreaterThan(5);
    // Every cell carries a width class instead of an inline min-width.
    expect(cells.every((cell) => /wamStructuredFilters__(item|chips|refresh)/.test(cell.className))).toBe(true);
    expect(cells.every((cell) => !cell.getAttribute('style'))).toBe(true);
    const last = cells[cells.length - 1];
    expect(last.className).toContain('wamStructuredFilters__refresh');
    expect(last.querySelector('.euiFormRow--hasEmptyLabelSpace')).not.toBeNull();
    const toggle = last.querySelector('input[type="checkbox"], button[role="switch"]') as HTMLElement;
    expect(toggle).not.toBeNull();
    fireEvent.click(toggle);
    expect(onToggleAutoRefresh).toHaveBeenCalled();
    // The test subjects the Playwright specs use are unchanged.
    expect(screen.getByTestId('wamStatusFilter-open')).toBeTruthy();
    expect(screen.getByTestId('wamSlaFilter-breached')).toBeTruthy();
    expect(screen.getByTestId('wamEnrichmentVerdictFilter')).toBeTruthy();
    expect(screen.getByTestId('wamDispositionFilter')).toBeTruthy();
    expect(screen.getByTestId('wamAssetCriticalityFilter')).toBeTruthy();
  });

  test('Apply still reports through onApply', () => {
    const { onApply } = renderBar();
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect(onApply).toHaveBeenCalledTimes(1);
  });
});
