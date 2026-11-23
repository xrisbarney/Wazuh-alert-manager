/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen } from '@testing-library/react';
import { NotifyChannelOption, RuleNotifyChannels, notificationsSettingsHref } from './rule_notify_channels';

configure({ testIdAttribute: 'data-test-subj' });

const CHANNELS: NotifyChannelOption[] = [
  { id: 'soc-slack', name: 'SOC Slack', kind: 'indexer_channel', enabled: true },
  { id: 'old-hook', name: 'Old hook', kind: 'webhook', enabled: false },
];

describe('RuleNotifyChannels (step 1.4)', () => {
  test('renders the bound channels as a multi-select with the selection, labelling disabled and missing ids', () => {
    const onChange = jest.fn();
    render(<RuleNotifyChannels channels={CHANNELS} state="ready" selected={['soc-slack', 'old-hook', 'ghost']} onChange={onChange} />);
    expect(screen.getByTestId('wamRuleNotifyChannels')).toBeTruthy();
    expect(screen.getByText('Notify channels')).toBeTruthy();
    expect(screen.getByText('SOC Slack')).toBeTruthy();
    expect(screen.getByText('Old hook (disabled)')).toBeTruthy();
    expect(screen.getByText('ghost (missing)')).toBeTruthy();
    expect(screen.queryByTestId('wamRuleNotifyEmpty')).toBeNull();

    fireEvent.click(screen.getByLabelText(/Remove ghost \(missing\)/));
    expect(onChange).toHaveBeenCalledWith(['soc-slack', 'old-hook']);
  });

  test('shows the empty state with a link to Settings > Notifications when no channel is bound', () => {
    render(<RuleNotifyChannels channels={[]} state="ready" selected={[]} onChange={jest.fn()} />);
    expect(screen.getByTestId('wamRuleNotifyEmpty').textContent).toContain('No notification channels configured');
    expect(screen.getByTestId('wamRuleNotifySettingsLink').getAttribute('href')).toBe(notificationsSettingsHref());
    expect(notificationsSettingsHref()).toContain('?tab=settings&settingsTab=notifications');
    expect(screen.queryByTestId('wamRuleNotifyChannels')).toBeNull();
  });

  test('keeps a stored selection editable when the list is empty or could not be loaded', () => {
    const { rerender } = render(<RuleNotifyChannels channels={[]} state="ready" selected={['soc-slack']} onChange={jest.fn()} />);
    expect(screen.getByTestId('wamRuleNotifyChannels')).toBeTruthy();
    expect(screen.getByText('soc-slack (missing)')).toBeTruthy();
    rerender(<RuleNotifyChannels channels={[]} state="error" selected={[]} onChange={jest.fn()} />);
    expect(screen.getByTestId('wamRuleNotifyChannels')).toBeTruthy();
    expect(screen.getByText(/could not be loaded/)).toBeTruthy();
  });

  test('flags more than 20 selected channels', () => {
    const many = Array.from({ length: 21 }, (_, index) => `c${index}`);
    render(<RuleNotifyChannels channels={many.map((id) => ({ id, name: id, kind: 'webhook', enabled: true }))} state="ready" selected={many} onChange={jest.fn()} />);
    expect(screen.getByText('Select at most 20 channels.')).toBeTruthy();
  });
});
