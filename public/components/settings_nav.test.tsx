/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, fireEvent } from '@testing-library/react';
import {
  SETTINGS_NAV_COLLAPSED_KEY,
  SETTINGS_NAV_GROUPS,
  SETTINGS_SECTION_ICONS,
  SETTINGS_SECTION_IDS,
  SettingsNav,
  buildSettingsNavItems,
  isSettingsSectionId,
  settingsGroupHasHeading,
  settingsSectionLabel,
  useSettingsNavCollapsed,
} from './settings_nav';
import { initialSettingsSection } from './settings_view';

configure({ testIdAttribute: 'data-test-subj' });

describe('SettingsNav', () => {
  test('renders every section grouped in order with the active item selected', () => {
    render(<SettingsNav activeId="sla" onSelect={() => {}} />);
    const nav = screen.getByTestId('wamSettingsNav');
    const subjects = Array.from(nav.querySelectorAll('[data-test-subj^="wamSettingsNav-"]')).map((node) => node.getAttribute('data-test-subj'));
    expect(subjects).toEqual(SETTINGS_SECTION_IDS.map((id) => `wamSettingsNav-${id}`));
    expect(nav.textContent).toContain('Workflow');
    expect(nav.textContent).toContain('Intelligence');
    expect(nav.textContent).toContain('Data');
    expect(screen.getByTestId('wamSettingsNav-storage').textContent).toContain('Storage & lifecycle');
    expect(screen.getByTestId('wamSettingsNav-task-lists').textContent).toContain('Task lists');
    expect(screen.getByTestId('wamSettingsNav-sla').className).toContain('isSelected');
    expect(screen.getByTestId('wamSettingsNav-automation').className).not.toContain('isSelected');
  });

  test('clicking an item reports its id', () => {
    const onSelect = jest.fn();
    render(<SettingsNav activeId="automation" onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('wamSettingsNav-enrichment'));
    expect(onSelect).toHaveBeenCalledWith('enrichment');
    fireEvent.click(screen.getByTestId('wamSettingsNav-about'));
    expect(onSelect).toHaveBeenLastCalledWith('about');
  });

  test('groups cover every section exactly once and About stands alone', () => {
    const grouped = SETTINGS_NAV_GROUPS.flatMap((group) => group.items);
    expect([...grouped].sort()).toEqual([...SETTINGS_SECTION_IDS].sort());
    expect(new Set(grouped).size).toBe(SETTINGS_SECTION_IDS.length);
    const items = buildSettingsNavItems({ activeId: 'about', onSelect: () => {} });
    expect(items.map((item) => item.id)).toEqual(['group-workflow', 'group-intelligence', 'group-data', 'about']);
    expect(items[0].items?.map((item) => item.id)).toEqual(['automation', 'task-lists', 'sla', 'notifications']);
    expect(items[3].isSelected).toBe(true);
    expect(items[3]['data-test-subj']).toBe('wamSettingsNav-about');
  });

  test('labels and ids are stable for deep links', () => {
    expect(settingsSectionLabel('automation')).toBe('Automation rules');
    expect(settingsSectionLabel('sync')).toBe('Background sync');
    expect(isSettingsSectionId('task-lists')).toBe(true);
    expect(isSettingsSectionId('playbooks')).toBe(false);
    expect(isSettingsSectionId(null)).toBe(false);
    expect(initialSettingsSection('?tab=settings&settingsTab=storage')).toBe('storage');
    expect(initialSettingsSection('?tab=settings&settingsTab=nope')).toBe('automation');
    expect(initialSettingsSection('')).toBe('automation');
  });

  test('the wrapper is not a landmark: EuiSideNav provides the navigation roles', () => {
    render(<SettingsNav activeId="automation" onSelect={() => {}} />);
    const wrapper = screen.getByTestId('wamSettingsNav');
    expect(wrapper.tagName).toBe('DIV');
    const navs = Array.from(wrapper.querySelectorAll('nav'));
    expect(navs).toHaveLength(SETTINGS_NAV_GROUPS.length);
    expect(navs[0].getAttribute('aria-label')).toBe('Settings sections');
    expect(navs[1].getAttribute('aria-label')).toBe('Settings: Intelligence');
    for (const nav of navs) expect(nav.querySelector('nav')).toBeNull();
  });

  test('renders an uppercase heading per group, a rule between groups and an icon per item', () => {
    const { container } = render(<SettingsNav activeId="reports" onSelect={() => {}} />);
    const headings = Array.from(container.querySelectorAll('.wamNavHeading')).map((node) => node.textContent);
    expect(headings).toEqual(['Workflow', 'Intelligence', 'Data']);
    expect(settingsGroupHasHeading(SETTINGS_NAV_GROUPS[3])).toBe(false);
    expect(screen.getByTestId('wamSettingsNavGroup-workflow').tagName).toBe('H4');
    expect(container.querySelectorAll('.wamSettingsNav__rule').length).toBe(SETTINGS_NAV_GROUPS.length - 1);
    expect(container.querySelectorAll('.wamSettingsNav__group').length).toBe(SETTINGS_NAV_GROUPS.length);
    for (const id of SETTINGS_SECTION_IDS) {
      expect(typeof SETTINGS_SECTION_ICONS[id]).toBe('string');
      const item = screen.getByTestId(`wamSettingsNav-${id}`);
      expect(item.querySelector('[class*="SideNavItemButton__icon"]')).not.toBeNull();
      expect(item.textContent).toContain(settingsSectionLabel(id));
    }
    expect(screen.getByTestId('wamSettingsNav-reports').className).toContain('isSelected');
    expect(buildSettingsNavItems({ activeId: 'about', onSelect: () => {} })[0].items?.every((item) => Boolean(item.icon))).toBe(true);
  });

  test('renders no toggle and no rail unless the host owns the collapsed state', () => {
    render(<SettingsNav activeId="automation" onSelect={() => {}} />);
    const nav = screen.getByTestId('wamSettingsNav');
    expect(nav.className).toBe('wamSettingsNav');
    expect(nav.getAttribute('data-collapsed')).toBe('false');
    expect(screen.queryByTestId('wamSettingsNavToggle')).toBeNull();
    expect(nav.querySelector('.wamSettingsNav__rail')).toBeNull();
  });

  test('the toggle reads Collapse navigation when expanded and reports a click', () => {
    const onToggle = jest.fn();
    render(<SettingsNav activeId="automation" onSelect={() => {}} onToggleCollapsed={onToggle} />);
    const toggle = screen.getByTestId('wamSettingsNavToggle');
    expect(toggle.getAttribute('aria-label')).toBe('Collapse navigation');
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByTestId('wamSettingsNavGroup-workflow').tagName).toBe('H4');
    fireEvent.click(toggle);
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  test('collapsed: the icon rail keeps every subject, the dividers and tooltip labels, no headings', () => {
    const onSelect = jest.fn();
    const onToggle = jest.fn();
    const { container } = render(
      <SettingsNav activeId="sync" onSelect={onSelect} collapsed onToggleCollapsed={onToggle} />
    );
    const nav = screen.getByTestId('wamSettingsNav');
    expect(nav.className).toBe('wamSettingsNav wamSettingsNav--collapsed');
    expect(nav.getAttribute('data-collapsed')).toBe('true');
    expect(container.querySelector('.wamNavHeading')).toBeNull();
    expect(screen.queryByTestId('wamSettingsNavGroup-workflow')).toBeNull();
    expect(container.querySelectorAll('.euiSideNav').length).toBe(0);
    const rail = container.querySelector('nav.wamSettingsNav__rail');
    expect(rail).not.toBeNull();
    expect(rail!.getAttribute('aria-label')).toBe('Settings sections');
    expect(rail!.querySelectorAll('.wamSettingsNav__rule').length).toBe(SETTINGS_NAV_GROUPS.length - 1);
    const subjects = Array.from(rail!.querySelectorAll('[data-test-subj^="wamSettingsNav-"]')).map((node) =>
      node.getAttribute('data-test-subj')
    );
    expect(subjects).toEqual(SETTINGS_SECTION_IDS.map((id) => `wamSettingsNav-${id}`));
    for (const id of SETTINGS_SECTION_IDS) {
      const button = screen.getByTestId(`wamSettingsNav-${id}`);
      expect(button.tagName).toBe('BUTTON');
      expect(button.getAttribute('aria-label')).toBe(settingsSectionLabel(id));
      expect(button.textContent).toBe('');
    }
    const active = screen.getByTestId('wamSettingsNav-sync');
    expect(active.getAttribute('aria-current')).toBe('page');
    expect(active.className).toContain('isSelected');
    expect(active.closest('.wamSettingsNav__railItem')!.className).toContain('wamSettingsNav__railItem--active');
    expect(screen.getByTestId('wamSettingsNav-about').getAttribute('aria-current')).toBeNull();
    expect(container.querySelectorAll('.wamSettingsNav__dot').length).toBe(0);
    fireEvent.click(screen.getByTestId('wamSettingsNav-storage'));
    expect(onSelect).toHaveBeenCalledWith('storage');
    const toggle = screen.getByTestId('wamSettingsNavToggle');
    expect(toggle.getAttribute('aria-label')).toBe('Expand navigation');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  describe('collapsed-state persistence', () => {
    const store = new Map<string, string>();
    const mockStorage = {
      getItem: jest.fn((key: string) => (store.has(key) ? store.get(key)! : null)),
      setItem: jest.fn((key: string, value: string) => {
        store.set(key, value);
      }),
    };
    let original: PropertyDescriptor | undefined;

    beforeEach(() => {
      store.clear();
      mockStorage.getItem.mockReset();
      mockStorage.getItem.mockImplementation((key: string) => (store.has(key) ? store.get(key)! : null));
      mockStorage.setItem.mockReset();
      mockStorage.setItem.mockImplementation((key: string, value: string) => {
        store.set(key, value);
      });
      original = Object.getOwnPropertyDescriptor(window, 'localStorage');
      Object.defineProperty(window, 'localStorage', { configurable: true, value: mockStorage });
    });

    afterEach(() => {
      if (original) Object.defineProperty(window, 'localStorage', original);
    });

    const Host: React.FC = () => {
      const [collapsed, toggle] = useSettingsNavCollapsed();
      return <SettingsNav activeId="automation" onSelect={() => {}} collapsed={collapsed} onToggleCollapsed={toggle} />;
    };

    test('defaults to expanded, writes wam.settingsNav.collapsed on toggle and restores it on the next mount', () => {
      expect(SETTINGS_NAV_COLLAPSED_KEY).toBe('wam.settingsNav.collapsed');
      const first = render(<Host />);
      expect(mockStorage.getItem).toHaveBeenCalledWith('wam.settingsNav.collapsed');
      expect(screen.getByTestId('wamSettingsNav').getAttribute('data-collapsed')).toBe('false');
      fireEvent.click(screen.getByTestId('wamSettingsNavToggle'));
      expect(mockStorage.setItem).toHaveBeenCalledWith('wam.settingsNav.collapsed', 'true');
      expect(screen.getByTestId('wamSettingsNav').className).toBe('wamSettingsNav wamSettingsNav--collapsed');
      first.unmount();

      render(<Host />);
      expect(screen.getByTestId('wamSettingsNav').getAttribute('data-collapsed')).toBe('true');
      fireEvent.click(screen.getByTestId('wamSettingsNavToggle'));
      expect(mockStorage.setItem).toHaveBeenLastCalledWith('wam.settingsNav.collapsed', 'false');
      expect(screen.getByTestId('wamSettingsNav').getAttribute('data-collapsed')).toBe('false');
    });

    test('a throwing localStorage reads as expanded and the toggle still works for the mount', () => {
      mockStorage.getItem.mockImplementation(() => {
        throw new Error('SecurityError');
      });
      mockStorage.setItem.mockImplementation(() => {
        throw new Error('QuotaExceededError');
      });
      render(<Host />);
      expect(screen.getByTestId('wamSettingsNav').getAttribute('data-collapsed')).toBe('false');
      expect(() => fireEvent.click(screen.getByTestId('wamSettingsNavToggle'))).not.toThrow();
      expect(screen.getByTestId('wamSettingsNav').getAttribute('data-collapsed')).toBe('true');
      expect(screen.getByTestId('wamSettingsNav-automation').getAttribute('aria-current')).toBe('page');
    });
  });
});
