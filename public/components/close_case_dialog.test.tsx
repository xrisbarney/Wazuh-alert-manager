/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen } from '@testing-library/react';
import { DISPOSITIONS, DISPOSITION_DESCRIPTIONS, DISPOSITION_LABELS } from '../../common';
import { CloseCaseDialog, DISPOSITION_SELECT_OPTIONS } from './close_case_dialog';
import { DispositionBadge } from './status_badge';

configure({ testIdAttribute: 'data-test-subj' });

describe('CloseCaseDialog (step 2.4)', () => {
  test('offers every disposition with its label and one-line description', () => {
    expect(DISPOSITION_SELECT_OPTIONS.map((option) => option.value)).toEqual([...DISPOSITIONS]);
    for (const value of DISPOSITIONS) {
      const option = DISPOSITION_SELECT_OPTIONS.find((item) => item.value === value)!;
      expect(option.inputDisplay).toBe(DISPOSITION_LABELS[value]);
      render(<>{option.dropdownDisplay}</>);
      expect(screen.getByTestId(`wamDispositionOption-${value}`).textContent).toContain(DISPOSITION_LABELS[value]);
      expect(screen.getByTestId(`wamDispositionOption-${value}`).textContent).toContain(DISPOSITION_DESCRIPTIONS[value]);
    }
  });

  test('defaults to undetermined, trims the reason and hands both to onConfirm; cancel never confirms', () => {
    const onConfirm = jest.fn();
    const onCancel = jest.fn();
    render(
      <CloseCaseDialog title="Close this case?" confirmLabel="Close case" onConfirm={onConfirm} onCancel={onCancel}>
        <div data-test-subj="extraBody">3 linked alerts</div>
      </CloseCaseDialog>
    );
    expect(screen.getByText('Close this case?')).toBeTruthy();
    expect(screen.getByTestId('extraBody').textContent).toBe('3 linked alerts');
    expect(screen.getByTestId('wamCloseDialogDisposition').textContent).toContain('Undetermined');
    fireEvent.change(screen.getByTestId('wamCloseDialogReason'), { target: { value: '  Scanner noise  ' } });
    fireEvent.click(screen.getByTestId('wamCloseDialogConfirm'));
    expect(onConfirm).toHaveBeenCalledWith({ disposition: 'undetermined', closureReason: 'Scanner noise' });
    fireEvent.click(screen.getByTestId('wamCloseDialogCancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  test('an empty reason is null and the initial disposition is honoured', () => {
    const onConfirm = jest.fn();
    render(<CloseCaseDialog title="Close 2 alerts?" confirmLabel="Close" initialDisposition="false_positive" onConfirm={onConfirm} onCancel={jest.fn()} testSubj="wamBulkClose" />);
    expect(screen.getByTestId('wamBulkCloseDisposition').textContent).toContain('False positive');
    fireEvent.click(screen.getByTestId('wamBulkCloseConfirm'));
    expect(onConfirm).toHaveBeenCalledWith({ disposition: 'false_positive', closureReason: null });
  });
});

describe('DispositionBadge', () => {
  test('renders the label with the colour of the value only on closed records', () => {
    const { container, unmount } = render(<DispositionBadge disposition="false_positive" status="closed" testSubj="badge" />);
    expect(screen.getByTestId('badge').textContent).toBe('False positive');
    expect(container.querySelector('.wamDispositionBadge--false_positive')).toBeTruthy();
    unmount();
    const open = render(<DispositionBadge disposition="false_positive" status="open" testSubj="badge" />);
    expect(open.container.innerHTML).toBe('');
    open.unmount();
    const none = render(<DispositionBadge disposition={null} status="closed" testSubj="badge" />);
    expect(none.container.innerHTML).toBe('');
    none.unmount();
    const unknown = render(<DispositionBadge disposition={'resolved' as any} status="closed" testSubj="badge" />);
    expect(unknown.container.innerHTML).toBe('');
  });
});
