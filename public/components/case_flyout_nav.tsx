import React from 'react';
import type { EuiSideNavItemType } from '@elastic/eui';
import { CaseTaskCounts } from '../../common';
import {
  FlyoutNav,
  FlyoutNavGroup,
  FlyoutNavProps,
  buildFlyoutNavGroups,
  buildFlyoutNavItems,
  readNavCollapsed,
  useFlyoutNavCollapsed,
  writeNavCollapsed,
} from './flyout_nav';

/**
 * Case flyout section navigation (step 8.1, legibility pass in 10.1, shared
 * component in 11.1): the ten former horizontal tabs as a left rail. Since
 * 11.1 the rendering lives in `flyout_nav.tsx` (`FlyoutNav`); this module
 * keeps the case-specific section set, groups, icons, labels and counts and
 * every export the case flyout and its tests use. Section ids are unchanged
 * so `activeTab` state, deep links and the tab content keep working; every
 * item carries `data-test-subj="wamCaseNav-<id>"` in both the expanded list
 * and the collapsed icon rail, so the Playwright benches click the same
 * subjects whatever the analyst's saved preference is.
 *
 * Counts come only from data the flyout already holds (the case document,
 * the evidence page it loaded, or a list a tab has already fetched); the nav
 * never issues a request of its own.
 */

export const CASE_SECTION_IDS = [
  'overview',
  'alerts',
  'assets',
  'timeline',
  'attack-path',
  'indicators',
  'ai',
  'tasks',
  'attachments',
  'comments',
  'history',
] as const;

export type CaseSectionId = typeof CASE_SECTION_IDS[number];

export function isCaseSectionId(value: string | null | undefined): value is CaseSectionId {
  return (CASE_SECTION_IDS as readonly string[]).includes(String(value));
}

export type CaseNavGroup = FlyoutNavGroup<CaseSectionId>;

/**
 * Visual groups separated by a rule: the overview, the evidence sections,
 * the analyst's own work, and the audit trail. Membership covers every
 * section exactly once (asserted by the unit test).
 */
export const CASE_NAV_GROUPS: readonly CaseNavGroup[] = [
  { id: 'overview', items: ['overview'] },
  { id: 'evidence', items: ['alerts', 'assets', 'timeline', 'attack-path', 'indicators', 'ai'] },
  { id: 'work', items: ['tasks', 'attachments', 'comments'] },
  { id: 'history', items: ['history'] },
];

/**
 * One EUI icon per section. `comments` uses `editorComment` because the OSD
 * EUI fork (OUI 1.x) ships no `discuss` glyph.
 */
export const CASE_SECTION_ICONS: Record<CaseSectionId, string> = {
  overview: 'inspect',
  alerts: 'bell',
  assets: 'storage',
  timeline: 'clock',
  'attack-path': 'branch',
  indicators: 'crosshairs',
  ai: 'compute',
  tasks: 'checkInCircleFilled',
  attachments: 'paperClip',
  comments: 'editorComment',
  history: 'history',
};

/** `localStorage` key holding the analyst's collapsed-rail preference. */
export const CASE_NAV_COLLAPSED_KEY = 'wam.caseNav.collapsed';

/** Reads the saved preference; storage errors and missing values read as expanded. */
export function readCaseNavCollapsed(): boolean {
  return readNavCollapsed(CASE_NAV_COLLAPSED_KEY);
}

/** Persists the preference; a storage failure only means it is not remembered. */
export function writeCaseNavCollapsed(collapsed: boolean): void {
  writeNavCollapsed(CASE_NAV_COLLAPSED_KEY, collapsed);
}

/** Collapsed-rail state restored from `localStorage` on mount and written on every toggle. */
export function useCaseNavCollapsed(): [boolean, () => void] {
  return useFlyoutNavCollapsed(CASE_NAV_COLLAPSED_KEY);
}

export interface CaseSectionCounts {
  /** Authoritative evidence relationship total (first evidence page of the case). */
  alerts?: number | null;
  /** Distinct agents among the loaded linked alerts (step 11.4); shown when non-zero. */
  assets?: number | null;
  /** `case.task_counts`, kept consistent by the server. */
  tasks?: CaseTaskCounts | null;
  /** Known once the Attachments tab has fetched its list; null before that. */
  attachments?: number | null;
  /** Known once the Comments tab has fetched its thread; null before that. */
  comments?: number | null;
}

/** Section label; `unitsLabel` is the terminology plural ("alerts" / "findings"). */
export function caseSectionLabel(id: CaseSectionId, unitsLabel: string = 'alerts'): string {
  switch (id) {
    case 'overview':
      return 'Overview';
    case 'alerts':
      return `Linked ${unitsLabel}`;
    case 'assets':
      return 'Assets';
    case 'timeline':
      return 'Timeline';
    case 'attack-path':
      return 'Attack graph';
    case 'indicators':
      return 'Indicators';
    case 'ai':
      return 'AI analysis';
    case 'tasks':
      return 'Tasks';
    case 'attachments':
      return 'Attachments';
    case 'comments':
      return 'Comments';
    case 'history':
      return 'History';
  }
}

/**
 * Badge text for a section, or null when nothing is known / worth showing:
 * the evidence total is always shown once loaded (0 is meaningful), tasks
 * read `done/total` and only when the case has tasks, assets (distinct
 * agents), attachments and comments only once known and non-zero.
 */
export function caseSectionCount(id: CaseSectionId, counts: CaseSectionCounts): string | null {
  switch (id) {
    case 'alerts':
      return typeof counts.alerts === 'number' && Number.isFinite(counts.alerts) ? String(counts.alerts) : null;
    case 'tasks': {
      const open = Number(counts.tasks?.open ?? 0);
      const done = Number(counts.tasks?.done ?? 0);
      const total = open + done;
      return Number.isFinite(total) && total > 0 ? `${done}/${total}` : null;
    }
    case 'assets':
    case 'attachments':
    case 'comments': {
      const value = counts[id];
      return typeof value === 'number' && Number.isFinite(value) && value > 0 ? String(value) : null;
    }
    default:
      return null;
  }
}

export interface CaseFlyoutNavProps {
  activeId: CaseSectionId;
  counts: CaseSectionCounts;
  unitsLabel?: string;
  onSelect: (id: CaseSectionId) => void;
  testSubj?: string;
  /** Icon-only rail when true; the host owns the state (see `useCaseNavCollapsed`). */
  collapsed?: boolean;
  /** Renders the collapse / expand toggle when given. */
  onToggleCollapsed?: () => void;
}

/** Maps the case props onto the shared `FlyoutNav` props (CSS block stays `wamCaseNav`). */
export function toFlyoutNavProps(props: CaseFlyoutNavProps): FlyoutNavProps<CaseSectionId> {
  const { activeId, counts, unitsLabel = 'alerts', onSelect, testSubj = 'wamCaseNav', collapsed, onToggleCollapsed } = props;
  return {
    sections: CASE_SECTION_IDS,
    groups: CASE_NAV_GROUPS,
    icons: CASE_SECTION_ICONS,
    label: (id) => caseSectionLabel(id, unitsLabel),
    count: (id) => caseSectionCount(id, counts),
    countStyle: (id) => (id === 'tasks' ? 'hollow' : 'notification'),
    activeId,
    onSelect,
    testSubj,
    block: 'wamCaseNav',
    ariaLabel: 'Case sections',
    collapsed,
    onToggleCollapsed,
  };
}

/** Pure flat item list (every section in order) for `EuiSideNav`; exported for tests. */
export function buildCaseNavItems(props: CaseFlyoutNavProps): Array<EuiSideNavItemType<{}>> {
  return buildFlyoutNavItems(toFlyoutNavProps(props));
}

/** Item lists per visual group, in `CASE_NAV_GROUPS` order; exported for tests. */
export function buildCaseNavGroups(props: CaseFlyoutNavProps): Array<{ id: string; items: Array<EuiSideNavItemType<{}>> }> {
  return buildFlyoutNavGroups(toFlyoutNavProps(props));
}

export const CaseFlyoutNav: React.FC<CaseFlyoutNavProps> = (props) => <FlyoutNav {...toFlyoutNavProps(props)} />;
