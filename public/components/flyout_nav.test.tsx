/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, fireEvent } from '@testing-library/react';
import {
  FlyoutNav,
  FlyoutNavCountStyle,
  FlyoutNavGroup,
  FlyoutNavProps,
  buildFlyoutNavGroups,
  buildFlyoutNavItems,
  readNavCollapsed,
  useFlyoutNavCollapsed,
  writeNavCollapsed,
} from './flyout_nav';

configure({ testIdAttribute: 'data-test-subj' });

type Id = 'one' | 'two' | 'three' | 'four';
const SECTIONS: readonly Id[] = ['one', 'two', 'three', 'four'];
const GROUPS: readonly FlyoutNavGroup<Id>[] = [
  { id: 'first', items: ['one'] },
  { id: 'middle', items: ['two', 'three'] },
  { id: 'last', items: ['four'] },
];
const ICONS: Record<Id, string> = { one: 'inspect', two: 'link', three: 'list', four: 'history' };
const LABELS: Record<Id, string> = { one: 'One', two: 'Two things', three: 'Three', four: 'Four' };

function props(overrides: Partial<FlyoutNavProps<Id>> = {}): FlyoutNavProps<Id> {
  return {
    sections: SECTIONS,
    groups: GROUPS,
    icons: ICONS,
    label: (id) => LABELS[id],
    activeId: 'one',
    onSelect: () => {},
    testSubj: 'wamTestNav',
    ariaLabel: 'Test sections',
    ...overrides,
  };
}

describe('FlyoutNav', () => {
  test('renders every section in order per group, with icons, the heading and the active item selected', () => {
    const { container } = render(<FlyoutNav {...props({ activeId: 'three' })} />);
    const nav = screen.getByTestId('wamTestNav');
    expect(nav.className).toBe('wamTestNav');
    expect(nav.getAttribute('data-collapsed')).toBe('false');
    const subjects = Array.from(nav.querySelectorAll('[data-test-subj^="wamTestNav-"]')).map((node) => node.getAttribute('data-test-subj'));
    expect(subjects).toEqual(SECTIONS.map((id) => `wamTestNav-${id}`));
    expect(screen.getByTestId('wamTestNav-two').textContent).toContain('Two things');
    expect(screen.getByTestId('wamTestNav-three').className).toContain('isSelected');
    expect(screen.getByTestId('wamTestNav-one').className).not.toContain('isSelected');
    expect(screen.getByTestId('wamTestNav-one').querySelector('[class*="SideNavItemButton__icon"]')).not.toBeNull();
    expect(container.querySelector('.wamNavHeading')?.textContent).toBe('Sections');
    expect(container.querySelectorAll('.wamTestNav__rule')).toHaveLength(GROUPS.length - 1);
    expect(container.querySelectorAll('.wamTestNav__label')).toHaveLength(SECTIONS.length);
    const navs = Array.from(nav.querySelectorAll('nav'));
    expect(navs.map((node) => node.getAttribute('aria-label'))).toEqual(['Test sections', 'Test sections: middle', 'Test sections: last']);
    expect(screen.queryByTestId('wamTestNavToggle')).toBeNull();
  });

  test('a custom heading, CSS block and click reporting', () => {
    const onSelect = jest.fn();
    const { container } = render(<FlyoutNav {...props({ onSelect, block: 'wamOtherNav', heading: 'Parts' })} />);
    expect(screen.getByTestId('wamTestNav').className).toBe('wamOtherNav');
    expect(container.querySelector('.wamNavHeading')?.textContent).toBe('Parts');
    expect(container.querySelectorAll('.wamOtherNav__label')).toHaveLength(SECTIONS.length);
    fireEvent.click(screen.getByTestId('wamTestNav-four'));
    expect(onSelect).toHaveBeenCalledWith('four');
    fireEvent.click(screen.getByTestId('wamTestNav-two').querySelector('.wamOtherNav__label')!);
    expect(onSelect).toHaveBeenLastCalledWith('two');
  });

  test('counts render as badges only when the count function returns text; hollow style on request', () => {
    const count = (id: Id) => (id === 'two' ? '3' : id === 'three' ? '1/4' : null);
    const countStyle = (id: Id): FlyoutNavCountStyle => (id === 'three' ? 'hollow' : 'notification');
    render(<FlyoutNav {...props({ count, countStyle })} />);
    expect(screen.getByTestId('wamTestNavCount-two').textContent).toBe('3');
    expect(screen.getByTestId('wamTestNavCount-two').className).toContain('euiNotificationBadge');
    expect(screen.getByTestId('wamTestNavCount-three').textContent).toBe('1/4');
    expect(screen.getByTestId('wamTestNavCount-three').className).toContain('euiBadge');
    expect(screen.queryByTestId('wamTestNavCount-one')).toBeNull();
    expect(screen.queryByTestId('wamTestNavCount-four')).toBeNull();
  });

  test('builders expose the flat and grouped item lists', () => {
    const flat = buildFlyoutNavItems(props());
    expect(flat.map((item) => item.id)).toEqual([...SECTIONS]);
    expect(flat.every((item) => Boolean(item.icon))).toBe(true);
    expect(flat[0]['data-test-subj']).toBe('wamTestNav-one');
    expect(flat[1]['aria-label']).toBe('Two things');
    const groups = buildFlyoutNavGroups(props({ activeId: 'two' }));
    expect(groups.map((group) => group.id)).toEqual(['first', 'middle', 'last']);
    expect(groups[1].items.map((item) => item.id)).toEqual(['two', 'three']);
    expect(groups[1].items[0].isSelected).toBe(true);
    expect(groups[1].items[1].isSelected).toBe(false);
  });

  test('renders the toggle when the host owns the collapse state', () => {
    const onToggle = jest.fn();
    render(<FlyoutNav {...props({ onToggleCollapsed: onToggle })} />);
    const toggle = screen.getByTestId('wamTestNavToggle');
    expect(toggle.tagName).toBe('BUTTON');
    expect(toggle.getAttribute('aria-label')).toBe('Collapse navigation');
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    fireEvent.click(toggle);
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  test('collapsed rail keeps every subject, tooltips as labels, non-zero counts as dots and the expand toggle', () => {
    const onSelect = jest.fn();
    const count = (id: Id) => (id === 'one' ? '0' : id === 'two' ? '5' : null);
    render(<FlyoutNav {...props({ onSelect, count, activeId: 'two', collapsed: true, onToggleCollapsed: () => {} })} />);
    const nav = screen.getByTestId('wamTestNav');
    expect(nav.className).toBe('wamTestNav wamTestNav--collapsed');
    expect(nav.getAttribute('data-collapsed')).toBe('true');
    expect(nav.querySelector('.wamNavHeading')).toBeNull();
    const rail = nav.querySelector('nav.wamTestNav__rail');
    expect(rail?.getAttribute('aria-label')).toBe('Test sections');
    const subjects = Array.from(nav.querySelectorAll('[data-test-subj^="wamTestNav-"]')).map((node) => node.getAttribute('data-test-subj'));
    expect(subjects).toEqual(SECTIONS.map((id) => `wamTestNav-${id}`));
    for (const id of SECTIONS) {
      const button = screen.getByTestId(`wamTestNav-${id}`);
      expect(button.tagName).toBe('BUTTON');
      expect(button.getAttribute('aria-label')).toBe(LABELS[id]);
      expect(button.textContent).toBe('');
    }
    expect(nav.querySelectorAll('.wamTestNav__rule')).toHaveLength(GROUPS.length - 1);
    expect(screen.getByTestId('wamTestNav-two').getAttribute('aria-current')).toBe('page');
    expect(screen.getByTestId('wamTestNav-two').className).toContain('isSelected');
    expect(screen.getByTestId('wamTestNav-two').closest('.wamTestNav__railItem')?.className).toContain('wamTestNav__railItem--active');
    expect(screen.getByTestId('wamTestNav-one').getAttribute('aria-current')).toBeNull();
    // A known-but-zero count shows no dot.
    expect(screen.queryByTestId('wamTestNavCount-one')).toBeNull();
    const dot = screen.getByTestId('wamTestNavCount-two');
    expect(dot.className).toBe('wamTestNav__dot');
    expect(dot.getAttribute('title')).toBe('5');
    expect(dot.getAttribute('aria-label')).toBe('Two things: 5');
    const toggle = screen.getByTestId('wamTestNavToggle');
    expect(toggle.getAttribute('aria-label')).toBe('Expand navigation');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(screen.getByTestId('wamTestNav-four'));
    expect(onSelect).toHaveBeenCalledWith('four');
  });

  describe('collapsed-state persistence (one key per host)', () => {
    const store = new Map<string, string>();
    const mockStorage = {
      getItem: jest.fn((key: string) => (store.has(key) ? (store.get(key) as string) : null)),
      setItem: jest.fn((key: string, value: string) => { store.set(key, value); }),
      removeItem: jest.fn((key: string) => { store.delete(key); }),
      clear: jest.fn(() => store.clear()),
      key: jest.fn(),
      length: 0,
    };
    let original: PropertyDescriptor | undefined;

    beforeEach(() => {
      store.clear();
      mockStorage.getItem.mockClear();
      mockStorage.setItem.mockClear();
      original = Object.getOwnPropertyDescriptor(window, 'localStorage');
      Object.defineProperty(window, 'localStorage', { configurable: true, value: mockStorage });
    });

    afterEach(() => {
      if (original) Object.defineProperty(window, 'localStorage', original);
    });

    const Host: React.FC<{ storageKey: string; testSubj: string }> = ({ storageKey, testSubj }) => {
      const [collapsed, toggle] = useFlyoutNavCollapsed(storageKey);
      return <FlyoutNav {...props({ testSubj, collapsed, onToggleCollapsed: toggle })} />;
    };

    test('defaults to expanded, writes the toggle under its own key and restores it on the next mount', () => {
      expect(readNavCollapsed('wam.alertNav.collapsed')).toBe(false);
      const first = render(<Host storageKey="wam.alertNav.collapsed" testSubj="wamAlertNav" />);
      expect(mockStorage.getItem).toHaveBeenCalledWith('wam.alertNav.collapsed');
      expect(screen.getByTestId('wamAlertNav').getAttribute('data-collapsed')).toBe('false');
      fireEvent.click(screen.getByTestId('wamAlertNavToggle'));
      expect(mockStorage.setItem).toHaveBeenCalledWith('wam.alertNav.collapsed', 'true');
      expect(screen.getByTestId('wamAlertNav').className).toBe('wamAlertNav wamAlertNav--collapsed');
      first.unmount();

      // Another host with its own key is unaffected.
      const other = render(<Host storageKey="wam.caseNav.collapsed" testSubj="wamCaseNav" />);
      expect(screen.getByTestId('wamCaseNav').getAttribute('data-collapsed')).toBe('false');
      other.unmount();

      render(<Host storageKey="wam.alertNav.collapsed" testSubj="wamAlertNav" />);
      expect(screen.getByTestId('wamAlertNav').getAttribute('data-collapsed')).toBe('true');
      fireEvent.click(screen.getByTestId('wamAlertNavToggle'));
      expect(mockStorage.setItem).toHaveBeenLastCalledWith('wam.alertNav.collapsed', 'false');
      expect(screen.getByTestId('wamAlertNav').getAttribute('data-collapsed')).toBe('false');
    });

    test('reads only the literal "true" and survives a broken storage', () => {
      store.set('k', 'yes');
      expect(readNavCollapsed('k')).toBe(false);
      store.set('k', 'true');
      expect(readNavCollapsed('k')).toBe(true);
      mockStorage.getItem.mockImplementationOnce(() => { throw new Error('denied'); });
      expect(readNavCollapsed('k')).toBe(false);
      mockStorage.setItem.mockImplementationOnce(() => { throw new Error('quota'); });
      expect(() => writeNavCollapsed('k', true)).not.toThrow();
      render(<Host storageKey="k" testSubj="wamTestNav" />);
      expect(screen.getByTestId('wamTestNav').getAttribute('data-collapsed')).toBe('true');
    });
  });
});
