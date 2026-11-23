import React from 'react';
import { EuiHorizontalRule, EuiIcon, EuiSideNav, EuiTitle } from '@elastic/eui';
import type { EuiSideNavItemType } from '@elastic/eui';
import { FlyoutNavRail, FlyoutNavToggle, useFlyoutNavCollapsed } from './flyout_nav';

/**
 * Settings navigation (step 8.3, legibility pass in 10.1, collapsible in
 * 11.2): the eleven former horizontal tabs as a grouped left rail built from
 * `EuiSideNav` (the pattern Wazuh's own settings and server management pages
 * use). Each group gets a small uppercase heading and a rule before the next
 * one; every item carries an icon. Section ids are unchanged so the
 * `?settingsTab=` deep links keep working; every item carries
 * `data-test-subj="wamSettingsNav-<id>"`.
 *
 * Collapsed (host-owned `collapsed` / `onToggleCollapsed`, persisted under
 * `SETTINGS_NAV_COLLAPSED_KEY` through `useSettingsNavCollapsed`), the nav
 * is the same 48px icon rail the case and alert flyouts use
 * (`FlyoutNavRail` from `flyout_nav.tsx`): group dividers without headings,
 * `EuiToolTip` labels, the same `wamSettingsNav-<id>` subjects, and the
 * toggle `wamSettingsNavToggle` (aria-label Collapse / Expand navigation).
 */

/** `localStorage` key for the collapsed-rail preference (default expanded). */
export const SETTINGS_NAV_COLLAPSED_KEY = 'wam.settingsNav.collapsed';

/** Collapsed-rail state for the settings nav: the shared hook with this nav's key. */
export function useSettingsNavCollapsed(): [boolean, () => void] {
  return useFlyoutNavCollapsed(SETTINGS_NAV_COLLAPSED_KEY);
}

export const SETTINGS_SECTION_IDS = [
  'automation',
  'task-lists',
  'sla',
  'notifications',
  'ai',
  'enrichment',
  'assets',
  'reports',
  'sync',
  'storage',
  'about',
] as const;

export type SettingsSectionId = typeof SETTINGS_SECTION_IDS[number];

export const DEFAULT_SETTINGS_SECTION: SettingsSectionId = 'automation';

export function isSettingsSectionId(value: string | null | undefined): value is SettingsSectionId {
  return (SETTINGS_SECTION_IDS as readonly string[]).includes(String(value));
}

export interface SettingsNavGroup {
  id: string;
  name: string;
  items: SettingsSectionId[];
}

/** Group order and membership; `About` stands alone at the end. */
export const SETTINGS_NAV_GROUPS: readonly SettingsNavGroup[] = [
  { id: 'workflow', name: 'Workflow', items: ['automation', 'task-lists', 'sla', 'notifications'] },
  { id: 'intelligence', name: 'Intelligence', items: ['ai', 'enrichment', 'assets'] },
  { id: 'data', name: 'Data', items: ['reports', 'sync', 'storage'] },
  { id: 'about', name: 'About', items: ['about'] },
];

/**
 * One EUI icon per section. `sla` uses `clock` because the OSD EUI fork
 * (OUI 1.x) ships no `timer` glyph.
 */
export const SETTINGS_SECTION_ICONS: Record<SettingsSectionId, string> = {
  automation: 'bolt',
  'task-lists': 'list',
  sla: 'clock',
  notifications: 'email',
  ai: 'compute',
  enrichment: 'crosshairs',
  assets: 'node',
  reports: 'reportingApp',
  sync: 'refresh',
  storage: 'storage',
  about: 'iInCircle',
};

export function settingsSectionLabel(id: SettingsSectionId): string {
  switch (id) {
    case 'automation':
      return 'Automation rules';
    case 'task-lists':
      return 'Task lists';
    case 'sla':
      return 'SLA';
    case 'notifications':
      return 'Notifications';
    case 'ai':
      return 'AI analysis';
    case 'enrichment':
      return 'Enrichment';
    case 'assets':
      return 'Assets';
    case 'reports':
      return 'Reports';
    case 'sync':
      return 'Background sync';
    case 'storage':
      return 'Storage & lifecycle';
    case 'about':
      return 'About';
  }
}

export interface SettingsNavProps {
  activeId: SettingsSectionId;
  onSelect: (id: SettingsSectionId) => void;
  testSubj?: string;
  /** Icon-only rail when true; the host owns the state (see `useSettingsNavCollapsed`). */
  collapsed?: boolean;
  /** Renders the collapse / expand toggle (`<testSubj>Toggle`) when given. */
  onToggleCollapsed?: () => void;
}

function buildItem(id: SettingsSectionId, props: SettingsNavProps): EuiSideNavItemType<{}> {
  const { activeId, onSelect, testSubj = 'wamSettingsNav' } = props;
  return {
    id,
    name: settingsSectionLabel(id),
    icon: <EuiIcon type={SETTINGS_SECTION_ICONS[id]} size="s" />,
    isSelected: id === activeId,
    onClick: () => onSelect(id),
    'data-test-subj': `${testSubj}-${id}`,
  };
}

/** Pure item tree (groups with children, About alone) for `EuiSideNav`; exported for tests. */
export function buildSettingsNavItems(props: SettingsNavProps): Array<EuiSideNavItemType<{}>> {
  const testSubj = props.testSubj || 'wamSettingsNav';
  return SETTINGS_NAV_GROUPS.map((group) => {
    // A one-item group (About) is its own entry rather than a heading with a
    // single child, so it is clickable and reads as a sibling of the groups.
    if (group.items.length === 1 && group.items[0] === group.id) return buildItem(group.items[0], props);
    return {
      id: `group-${group.id}`,
      name: group.name,
      'data-test-subj': `${testSubj}Group-${group.id}`,
      items: group.items.map((id) => buildItem(id, props)),
    };
  });
}

/** A group is rendered with a heading unless it is a single section named like the group (About). */
export function settingsGroupHasHeading(group: SettingsNavGroup): boolean {
  return !(group.items.length === 1 && group.items[0] === group.id);
}

export const SettingsNav: React.FC<SettingsNavProps> = (props) => {
  const testSubj = props.testSubj || 'wamSettingsNav';
  const withSubj = { ...props, testSubj };
  const collapsed = Boolean(props.collapsed);
  const block = 'wamSettingsNav';
  return (
    <div
      className={`${block}${collapsed ? ` ${block}--collapsed` : ''}`}
      data-test-subj={testSubj}
      data-collapsed={collapsed ? 'true' : 'false'}
    >
      {props.onToggleCollapsed ? (
        <FlyoutNavToggle collapsed={collapsed} onToggle={props.onToggleCollapsed} testSubj={testSubj} block={block} />
      ) : null}
      {collapsed ? (
        <FlyoutNavRail<SettingsSectionId>
          sections={SETTINGS_SECTION_IDS}
          groups={SETTINGS_NAV_GROUPS}
          icons={SETTINGS_SECTION_ICONS}
          label={settingsSectionLabel}
          activeId={props.activeId}
          onSelect={props.onSelect}
          testSubj={testSubj}
          block={block}
          ariaLabel="Settings sections"
        />
      ) : (
        SETTINGS_NAV_GROUPS.map((group, index) => (
          <React.Fragment key={group.id}>
            {index > 0 ? <EuiHorizontalRule margin="xs" className="wamSettingsNav__rule" /> : null}
            {settingsGroupHasHeading(group) ? (
              <EuiTitle size="xxs" className="wamNavHeading">
                <h4 data-test-subj={`${testSubj}Group-${group.id}`}>{group.name}</h4>
              </EuiTitle>
            ) : null}
            <EuiSideNav
              // EuiSideNav renders its own <nav> landmark, so the wrapper is a
              // div: the first group carries the page-level label.
              aria-label={index === 0 ? 'Settings sections' : `Settings: ${group.name}`}
              className="wamSettingsNav__group"
              mobileBreakpoints={[]}
              items={group.items.map((id) => buildItem(id, withSubj))}
            />
          </React.Fragment>
        ))
      )}
    </div>
  );
};
