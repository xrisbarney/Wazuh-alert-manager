/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen } from '@testing-library/react';
import { NativeCaseChip, NATIVE_CASES_APP_PATH, nativeCaseVisible, ownColor } from './native_case_chip';

configure({ testIdAttribute: 'data-test-subj' });

// The chip gates on TARGET_WAZUH_MAJOR from common/build_info at render time;
// the mock exposes it as a getter so one test file covers both build lines.
// eslint-disable-next-line no-var
var mockMajor = 5; // var: hoisted above the jest.mock factory, which runs during imports
jest.mock('../../common/build_info', () => ({
  ...(jest.requireActual('../../common/build_info') as object),
  get TARGET_WAZUH_MAJOR() {
    return mockMajor;
  },
}));

// `id` is reserved (rc2 writes no wazuh.case.id); the fixture fills it so the
// label path for a later Wazuh line that names cases stays covered.
const nativeCase = {
  id: 'case-7',
  status: 'acknowledged',
  severity: 'high',
  priority: 'p2',
  tlp: 'amber',
  title: 'Brute force on web-01',
  tags: ['ssh', 'brute-force'],
  updated_at: '2026-11-21T09:30:00.000Z',
};

describe('NativeCaseChip (step 2.6, read-only projection of wazuh.case.*)', () => {
  beforeEach(() => {
    mockMajor = 5;
  });

  test('on a 5.0 build renders the id, status/severity/priority/TLP badges, tags, title and the Cases deep link', () => {
    render(<NativeCaseChip nativeCase={nativeCase} appUrl={(path) => `/base${path}`} />);
    const chip = screen.getByTestId('wamNativeCase');
    expect(chip.getAttribute('data-native-status')).toBe('acknowledged');
    expect(screen.getByTestId('wamNativeCaseLabel').textContent).toContain('Native case case-7');
    expect(screen.getByTestId('wamNativeCaseStatus').textContent).toBe('Acknowledged');
    expect(screen.getByTestId('wamNativeCaseSeverity').textContent).toBe('High');
    expect(screen.getByTestId('wamNativeCasePriority').textContent).toBe('Priority p2');
    expect(screen.getByTestId('wamNativeCaseTlp').textContent).toBe('TLP AMBER');
    expect(screen.getByTestId('wamNativeCaseTitle').textContent).toBe('Brute force on web-01');
    expect(chip.textContent).toContain('ssh');
    expect(chip.textContent).toContain('brute-force');
    expect(chip.textContent).toContain('Read-only copy');
    const link = screen.getByTestId('wamNativeCaseLink');
    expect(link.getAttribute('href')).toBe(`/base${NATIVE_CASES_APP_PATH}`);
    expect(NATIVE_CASES_APP_PATH).toBe('/app/case-management#/overview/?tab=caseManagement&tabView=cases');
  });

  test('source-controlled status/severity/tlp named after Object.prototype members fall back to the default colours', () => {
    const hostile = { ...nativeCase, status: 'constructor', severity: 'constructor', tlp: 'constructor' };
    const { unmount } = render(<NativeCaseChip nativeCase={hostile} />);
    expect(screen.getByTestId('wamNativeCaseStatus').textContent).toBe('Constructor');
    expect(screen.getByTestId('wamNativeCaseSeverity').textContent).toBe('Constructor');
    expect(screen.getByTestId('wamNativeCaseTlp').textContent).toBe('TLP CONSTRUCTOR');
    expect(screen.getByTestId('wamNativeCaseStatus').className).toContain('euiBadge');
    unmount();
    for (const key of ['toString', 'valueOf', '__proto__']) {
      const { unmount: done } = render(<NativeCaseChip nativeCase={{ ...hostile, status: key, severity: key, tlp: key }} compact testSubj="wamCompact" />);
      expect(screen.getByTestId('wamCompact').textContent).toBe(`Native: ${key}`);
      done();
    }
    expect(ownColor({ active: 'primary' }, 'constructor')).toBeUndefined();
    expect(ownColor({ active: 'primary' }, 'active')).toBe('primary');
    expect(ownColor({ active: 'primary' }, null)).toBeUndefined();
  });

  test('renders without a link when no appUrl is given, and without an id falls back to the bare label', () => {
    render(<NativeCaseChip nativeCase={{ ...nativeCase, id: null, title: null, tags: [] }} />);
    expect(screen.queryByTestId('wamNativeCaseLink')).toBeNull();
    expect(screen.queryByTestId('wamNativeCaseTitle')).toBeNull();
    expect(screen.getByTestId('wamNativeCaseLabel').textContent).toBe('Native case');
  });

  test('compact mode is a single status badge for the queue row', () => {
    render(<NativeCaseChip nativeCase={nativeCase} compact testSubj="wamNativeCaseQueue" />);
    const badge = screen.getByTestId('wamNativeCaseQueue');
    expect(badge.textContent).toBe('Native: acknowledged');
    expect(badge.getAttribute('data-native-status')).toBe('acknowledged');
    expect(screen.queryByTestId('wamNativeCaseQueueTitle')).toBeNull();
  });

  test('renders nothing when the record has no native case, on either build', () => {
    for (const major of [4, 5]) {
      mockMajor = major;
      const { container, unmount } = render(<NativeCaseChip nativeCase={null} appUrl={(p) => p} />);
      expect(container.innerHTML).toBe('');
      expect(nativeCaseVisible(null)).toBe(false);
      expect(nativeCaseVisible(undefined)).toBe(false);
      unmount();
    }
  });

  test('is hidden on a 4.x build even when a record carries a projection (never a 5.0-only control on 4.x)', () => {
    mockMajor = 4;
    expect(nativeCaseVisible(nativeCase)).toBe(false);
    const full = render(<NativeCaseChip nativeCase={nativeCase} appUrl={(p) => p} />);
    expect(full.container.innerHTML).toBe('');
    full.unmount();
    const compact = render(<NativeCaseChip nativeCase={nativeCase} compact />);
    expect(compact.container.innerHTML).toBe('');
    mockMajor = 5;
    expect(nativeCaseVisible(nativeCase)).toBe(true);
  });
});
