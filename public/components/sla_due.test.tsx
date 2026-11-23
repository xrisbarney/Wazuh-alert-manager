/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen } from '@testing-library/react';
import { SlaDue, describeSlaDue, formatDueSpan } from './sla_due';

configure({ testIdAttribute: 'data-test-subj' });

const NOW = Date.parse('2026-11-21T10:00:00.000Z');
const at = (minutes: number) => new Date(NOW + minutes * 60000).toISOString();

describe('describeSlaDue', () => {
  test('nothing without a due date, for a closed record or an unparsable date', () => {
    expect(describeSlaDue(null, 'open', NOW)).toEqual({ state: 'none', text: '', minutes: null });
    expect(describeSlaDue(undefined, 'open', NOW).state).toBe('none');
    expect(describeSlaDue(at(-30), 'closed', NOW).state).toBe('none');
    expect(describeSlaDue('yesterday', 'open', NOW).state).toBe('none');
  });

  test('breached when the due date has passed (open or in progress)', () => {
    expect(describeSlaDue(at(-45), 'open', NOW)).toMatchObject({ state: 'breached', text: '-45m overdue' });
    expect(describeSlaDue(at(-134), 'in_progress', NOW).text).toBe('-2h 14m overdue');
    expect(describeSlaDue(at(-3 * 1440), 'open', NOW).text).toBe('-3d overdue');
  });

  test('due soon within 60 minutes, on track beyond it', () => {
    expect(describeSlaDue(at(45), 'open', NOW)).toMatchObject({ state: 'due_soon', text: '45m left' });
    expect(describeSlaDue(at(60), 'open', NOW).state).toBe('due_soon');
    expect(describeSlaDue(at(134), 'open', NOW)).toMatchObject({ state: 'on_track', text: '2h 14m left' });
    expect(describeSlaDue(at(3 * 1440), 'open', NOW)).toMatchObject({ state: 'on_track', text: 'due in 3d' });
    expect(describeSlaDue(at(3 * 1440 + 120), 'open', NOW).text).toBe('due in 3d 2h');
  });

  test('formatDueSpan', () => {
    expect(formatDueSpan(0)).toBe('0m');
    expect(formatDueSpan(59.6)).toBe('1h');
    expect(formatDueSpan(1500)).toBe('1d 1h');
  });
});

describe('SlaDue component', () => {
  test('renders a danger "Breached" badge with the overdue text', () => {
    render(<SlaDue dueAt={at(-45)} status="open" now={NOW} compact />);
    const root = screen.getByTestId('wamSlaDue');
    expect(root.getAttribute('data-sla-state')).toBe('breached');
    expect(screen.getByTestId('wamSlaDueBadge').textContent).toBe('Breached');
    expect(root.textContent).toContain('-45m overdue');
  });

  test('renders a warning "Due soon" badge under 60 minutes', () => {
    render(<SlaDue dueAt={at(20)} status="in_progress" now={NOW} compact />);
    expect(screen.getByTestId('wamSlaDue').getAttribute('data-sla-state')).toBe('due_soon');
    expect(screen.getByTestId('wamSlaDueBadge').textContent).toBe('Due soon');
    expect(screen.getByTestId('wamSlaDue').textContent).toContain('20m left');
  });

  test('renders only the countdown when on track, with the absolute time outside compact mode', () => {
    render(<SlaDue dueAt={at(3 * 1440)} status="open" now={NOW} label="Resolve" />);
    const root = screen.getByTestId('wamSlaDue');
    expect(root.getAttribute('data-sla-state')).toBe('on_track');
    expect(screen.queryByTestId('wamSlaDueBadge')).toBeNull();
    expect(root.textContent).toContain('Resolve');
    expect(root.textContent).toContain('due in 3d');
    expect(root.querySelector('.wamSlaDue__absolute')).not.toBeNull();
  });

  test('renders nothing for a closed record and a dash in compact mode without a due date', () => {
    const { container } = render(<SlaDue dueAt={at(-45)} status="closed" now={NOW} />);
    expect(container.innerHTML).toBe('');
    render(<SlaDue dueAt={null} status="open" now={NOW} compact testSubj="wamAlertDue" />);
    expect(screen.getByTestId('wamAlertDue').textContent).toBe('—');
  });
});
