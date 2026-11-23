/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, fireEvent } from '@testing-library/react';
import {
  CASE_NAV_COLLAPSED_KEY,
  CASE_NAV_GROUPS,
  CASE_SECTION_ICONS,
  CASE_SECTION_IDS,
  CaseFlyoutNav,
  CaseSectionId,
  buildCaseNavGroups,
  caseSectionCount,
  caseSectionLabel,
  isCaseSectionId,
  readCaseNavCollapsed,
  useCaseNavCollapsed,
  writeCaseNavCollapsed,
} from './case_flyout_nav';

configure({ testIdAttribute: 'data-test-subj' });

describe('CaseFlyoutNav', () => {
  test('renders every section in order with its label and the active item selected', () => {
    const onSelect = jest.fn();
    render(<CaseFlyoutNav activeId="timeline" counts={{}} unitsLabel="findings" onSelect={onSelect} />);
    const nav = screen.getByTestId('wamCaseNav');
    const subjects = Array.from(nav.querySelectorAll('[data-test-subj^="wamCaseNav-"]')).map((node) => node.getAttribute('data-test-subj'));
    expect(subjects).toEqual(CASE_SECTION_IDS.map((id) => `wamCaseNav-${id}`));
    expect(screen.getByTestId('wamCaseNav-alerts').textContent).toContain('Linked findings');
    expect(screen.getByTestId('wamCaseNav-attack-path').textContent).toContain('Attack graph');
    expect(screen.getByTestId('wamCaseNav-timeline').className).toContain('isSelected');
    expect(screen.getByTestId('wamCaseNav-overview').className).not.toContain('isSelected');
  });

  test('clicking an item reports its id', () => {
    const onSelect = jest.fn();
    render(<CaseFlyoutNav activeId="overview" counts={{}} onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('wamCaseNav-tasks'));
    expect(onSelect).toHaveBeenCalledWith('tasks');
    fireEvent.click(screen.getByTestId('wamCaseNav-history'));
    expect(onSelect).toHaveBeenLastCalledWith('history');
  });

  test('shows counts only for the sections whose data is known', () => {
    render(
      <CaseFlyoutNav
        activeId="overview"
        counts={{ alerts: 0, tasks: { open: 2, done: 1 }, attachments: 4, comments: null }}
        onSelect={() => {}}
      />
    );
    expect(screen.getByTestId('wamCaseNavCount-alerts').textContent).toBe('0');
    expect(screen.getByTestId('wamCaseNavCount-tasks').textContent).toBe('1/3');
    expect(screen.getByTestId('wamCaseNavCount-attachments').textContent).toBe('4');
    expect(screen.queryByTestId('wamCaseNavCount-comments')).toBeNull();
    expect(screen.queryByTestId('wamCaseNavCount-overview')).toBeNull();
  });

  test('the Assets section (step 11.4) sits in the evidence group after the linked alerts with a storage icon and the agent count', () => {
    expect(CASE_SECTION_IDS.indexOf('assets')).toBe(CASE_SECTION_IDS.indexOf('alerts') + 1);
    expect(CASE_NAV_GROUPS.find((group) => group.id === 'evidence')!.items).toContain('assets');
    expect(CASE_SECTION_ICONS.assets).toBe('storage');
    expect(caseSectionLabel('assets')).toBe('Assets');
    expect(caseSectionCount('assets', { assets: 2 })).toBe('2');
    expect(caseSectionCount('assets', { assets: 0 })).toBeNull();
    expect(caseSectionCount('assets', {})).toBeNull();
    render(<CaseFlyoutNav activeId="overview" counts={{ assets: 3 }} onSelect={() => {}} />);
    expect(screen.getByTestId('wamCaseNav-assets').textContent).toContain('Assets');
    expect(screen.getByTestId('wamCaseNavCount-assets').textContent).toBe('3');
  });

  test('caseSectionCount hides empty task lists and zero attachments / comments', () => {
    expect(caseSectionCount('tasks', { tasks: { open: 0, done: 0 } })).toBeNull();
    expect(caseSectionCount('tasks', { tasks: null })).toBeNull();
    expect(caseSectionCount('attachments', { attachments: 0 })).toBeNull();
    expect(caseSectionCount('comments', { comments: 3 })).toBe('3');
    expect(caseSectionCount('alerts', {})).toBeNull();
    expect(caseSectionCount('alerts', { alerts: 12 })).toBe('12');
    expect(caseSectionCount('history', { alerts: 12 })).toBeNull();
  });

  test('labels follow the terminology and ids are validated', () => {
    expect(caseSectionLabel('alerts')).toBe('Linked alerts');
    expect(caseSectionLabel('alerts', 'findings')).toBe('Linked findings');
    expect(caseSectionLabel('ai')).toBe('AI analysis');
    expect(isCaseSectionId('attack-path')).toBe(true);
    expect(isCaseSectionId('nope')).toBe(false);
    expect(isCaseSectionId(null)).toBe(false);
  });

  test('groups cover every section exactly once, carry icons and are separated by rules', () => {
    const grouped = CASE_NAV_GROUPS.flatMap((group) => group.items);
    expect(grouped).toEqual([...CASE_SECTION_IDS]);
    expect(new Set(grouped).size).toBe(CASE_SECTION_IDS.length);
    for (const id of CASE_SECTION_IDS) expect(typeof CASE_SECTION_ICONS[id]).toBe('string');
    const groups = buildCaseNavGroups({ activeId: 'overview', counts: {}, onSelect: () => {} });
    expect(groups.map((group) => group.id)).toEqual(['overview', 'evidence', 'work', 'history']);
    expect(groups[1].items.map((item) => item.id)).toEqual(['alerts', 'assets', 'timeline', 'attack-path', 'indicators', 'ai']);
    expect(groups[1].items.every((item) => Boolean(item.icon))).toBe(true);

    const { container } = render(<CaseFlyoutNav activeId="overview" counts={{}} onSelect={() => {}} />);
    expect(container.querySelectorAll('.wamCaseNav__rule').length).toBe(CASE_NAV_GROUPS.length - 1);
    expect(container.querySelector('.wamNavHeading')?.textContent).toBe('Sections');
    expect(screen.getByTestId('wamCaseNav-overview').querySelector('[class*="SideNavItemButton__icon"]')).not.toBeNull();
    expect(screen.queryByTestId('wamCaseNavToggle')).toBeNull();
  });

  test('renders the toggle when the host owns the collapse state', () => {
    const onToggle = jest.fn();
    render(<CaseFlyoutNav activeId="overview" counts={{}} onSelect={() => {}} onToggleCollapsed={onToggle} />);
    const toggle = screen.getByTestId('wamCaseNavToggle');
    expect(toggle.tagName).toBe('BUTTON');
    expect(toggle.getAttribute('aria-label')).toBe('Collapse navigation');
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    fireEvent.click(toggle);
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  test('collapsed rail keeps every section subject, counts as dots and the expand toggle', () => {
    const onSelect = jest.fn();
    render(
      <CaseFlyoutNav
        activeId="tasks"
        counts={{ alerts: 3, tasks: { open: 1, done: 1 }, attachments: 0, comments: 2 }}
        onSelect={onSelect}
        collapsed
        onToggleCollapsed={() => {}}
      />
    );
    const nav = screen.getByTestId('wamCaseNav');
    expect(nav.className).toContain('wamCaseNav--collapsed');
    expect(nav.getAttribute('data-collapsed')).toBe('true');
    expect(nav.querySelector('.wamNavHeading')).toBeNull();
    const subjects = Array.from(nav.querySelectorAll('[data-test-subj^="wamCaseNav-"]')).map((node) => node.getAttribute('data-test-subj'));
    expect(subjects).toEqual(CASE_SECTION_IDS.map((id) => `wamCaseNav-${id}`));
    for (const id of CASE_SECTION_IDS) {
      const button = screen.getByTestId(`wamCaseNav-${id}`);
      expect(button.tagName).toBe('BUTTON');
      expect(button.getAttribute('aria-label')).toBe(caseSectionLabel(id as CaseSectionId));
      expect(button.textContent).toBe('');
    }
    expect(screen.getByTestId('wamCaseNav-tasks').getAttribute('aria-current')).toBe('page');
    expect(screen.getByTestId('wamCaseNav-tasks').className).toContain('isSelected');
    expect(screen.getByTestId('wamCaseNav-overview').getAttribute('aria-current')).toBeNull();
    expect(screen.getByTestId('wamCaseNavCount-alerts').getAttribute('title')).toBe('3');
    expect(screen.getByTestId('wamCaseNavCount-tasks').getAttribute('title')).toBe('1/2');
    expect(screen.getByTestId('wamCaseNavCount-comments').className).toContain('wamCaseNav__dot');
    expect(screen.queryByTestId('wamCaseNavCount-attachments')).toBeNull();
    const toggle = screen.getByTestId('wamCaseNavToggle');
    expect(toggle.getAttribute('aria-label')).toBe('Expand navigation');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(screen.getByTestId('wamCaseNav-history'));
    expect(onSelect).toHaveBeenCalledWith('history');
  });

  test('collapsed rail shows no dot for a known-but-zero alert count', () => {
    render(
      <CaseFlyoutNav
        activeId="overview"
        counts={{ alerts: 0, tasks: { open: 0, done: 0 }, attachments: 0, comments: 0 }}
        onSelect={() => {}}
        collapsed
        onToggleCollapsed={() => {}}
      />
    );
    expect(screen.getByTestId('wamCaseNav-alerts')).not.toBeNull();
    expect(screen.queryByTestId('wamCaseNavCount-alerts')).toBeNull();
    expect(screen.getByTestId('wamCaseNav').querySelectorAll('.wamCaseNav__dot')).toHaveLength(0);
  });

  test('the wrapper is not a landmark: EuiSideNav provides the navigation roles', () => {
    render(<CaseFlyoutNav activeId="overview" counts={{}} onSelect={() => {}} />);
    const wrapper = screen.getByTestId('wamCaseNav');
    expect(wrapper.tagName).toBe('DIV');
    const navs = Array.from(wrapper.querySelectorAll('nav'));
    expect(navs).toHaveLength(CASE_NAV_GROUPS.length);
    expect(navs[0].getAttribute('aria-label')).toBe('Case sections');
    expect(navs[1].getAttribute('aria-label')).toBe('Case sections: evidence');
    for (const nav of navs) expect(nav.querySelector('nav')).toBeNull();
  });

  describe('collapsed-state persistence', () => {
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

    const Host: React.FC = () => {
      const [collapsed, toggle] = useCaseNavCollapsed();
      return <CaseFlyoutNav activeId="overview" counts={{}} onSelect={() => {}} collapsed={collapsed} onToggleCollapsed={toggle} />;
    };

    test('defaults to expanded, writes the toggle and restores it on the next mount', () => {
      expect(readCaseNavCollapsed()).toBe(false);
      const first = render(<Host />);
      expect(mockStorage.getItem).toHaveBeenCalledWith(CASE_NAV_COLLAPSED_KEY);
      expect(screen.getByTestId('wamCaseNav').getAttribute('data-collapsed')).toBe('false');
      fireEvent.click(screen.getByTestId('wamCaseNavToggle'));
      expect(mockStorage.setItem).toHaveBeenCalledWith(CASE_NAV_COLLAPSED_KEY, 'true');
      expect(screen.getByTestId('wamCaseNav').getAttribute('data-collapsed')).toBe('true');
      first.unmount();

      render(<Host />);
      expect(screen.getByTestId('wamCaseNav').getAttribute('data-collapsed')).toBe('true');
      fireEvent.click(screen.getByTestId('wamCaseNavToggle'));
      expect(mockStorage.setItem).toHaveBeenLastCalledWith(CASE_NAV_COLLAPSED_KEY, 'false');
      expect(screen.getByTestId('wamCaseNav').getAttribute('data-collapsed')).toBe('false');
    });

    test('reads only the literal "true" and survives a broken storage', () => {
      store.set(CASE_NAV_COLLAPSED_KEY, 'yes');
      expect(readCaseNavCollapsed()).toBe(false);
      store.set(CASE_NAV_COLLAPSED_KEY, 'true');
      expect(readCaseNavCollapsed()).toBe(true);
      mockStorage.getItem.mockImplementationOnce(() => { throw new Error('denied'); });
      expect(readCaseNavCollapsed()).toBe(false);
      mockStorage.setItem.mockImplementationOnce(() => { throw new Error('quota'); });
      expect(() => writeCaseNavCollapsed(true)).not.toThrow();
      render(<Host />);
      expect(screen.getByTestId('wamCaseNav').getAttribute('data-collapsed')).toBe('true');
    });
  });
});
