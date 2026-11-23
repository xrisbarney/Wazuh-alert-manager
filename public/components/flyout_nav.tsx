import React, { useCallback, useState } from 'react';
import {
  EuiBadge,
  EuiButtonIcon,
  EuiHorizontalRule,
  EuiIcon,
  EuiNotificationBadge,
  EuiSideNav,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import type { EuiSideNavItemType } from '@elastic/eui';

/**
 * Shared flyout section rail (step 11.1): the case flyout's left navigation
 * (steps 8.1 / 10.1) generalised so the alert flyout can use the same
 * component. Sections, visual groups, icons, labels, counts, the storage key
 * and the test-subject prefix are all props; `case_flyout_nav.tsx` and
 * `alert_flyout.tsx` supply their own section sets.
 *
 * Rendering contract (what the unit tests and the Playwright benches rely on):
 * - wrapper `<div data-test-subj="<testSubj>" data-collapsed="true|false">`
 *   with the CSS block class `<block>` (default: the test subject) and the
 *   `<block>--collapsed` modifier;
 * - one `EuiSideNav` per group when expanded, items carrying
 *   `data-test-subj="<testSubj>-<id>"`, labels in `<block>__label`, counts
 *   as `<testSubj>Count-<id>` badges;
 * - an icon-only rail when collapsed, the same `<testSubj>-<id>` subjects on
 *   `EuiButtonIcon`s with `EuiToolTip` labels, non-zero counts as a dot
 *   (`<block>__dot`, `<testSubj>Count-<id>`, the count in `title`);
 * - the collapse toggle `<testSubj>Toggle` (`aria-label` "Collapse
 *   navigation" / "Expand navigation", `aria-expanded`) when the host passes
 *   `onToggleCollapsed`.
 *
 * The nav never issues a request of its own: counts come from data the host
 * already holds.
 */

export interface FlyoutNavGroup<Id extends string> {
  id: string;
  items: readonly Id[];
}

/** Badge style for a count: a notification pill (default) or a hollow badge (e.g. "done/total"). */
export type FlyoutNavCountStyle = 'notification' | 'hollow';

export interface FlyoutNavProps<Id extends string> {
  /** Every section id in display order (each must appear in exactly one group). */
  sections: readonly Id[];
  /** Visual groups separated by a rule, in display order. */
  groups: readonly FlyoutNavGroup<Id>[];
  /** EUI icon type per section. */
  icons: Record<Id, string>;
  /** Visible label per section (also the rail tooltip and the item's aria-label). */
  label: (id: Id) => string;
  /** Badge text per section, or null when nothing is known / worth showing. */
  count?: (id: Id) => string | null;
  /** Badge style per section; defaults to the notification pill. */
  countStyle?: (id: Id) => FlyoutNavCountStyle;
  activeId: Id;
  onSelect: (id: Id) => void;
  /** Test-subject prefix (`wamCaseNav`, `wamAlertNav`); also the CSS block unless `block` is given. */
  testSubj: string;
  /** CSS block class (`<block>__item`, `<block>--collapsed`, ...). Defaults to `testSubj`. */
  block?: string;
  /** Landmark label: the first group's `EuiSideNav` and the rail `<nav>` carry it, later groups get `<ariaLabel>: <group id>`. */
  ariaLabel: string;
  /** Heading above the expanded list; default "Sections". */
  heading?: string;
  /** Icon-only rail when true; the host owns the state (see `useFlyoutNavCollapsed`). */
  collapsed?: boolean;
  /** Renders the collapse / expand toggle when given. */
  onToggleCollapsed?: () => void;
}

/** Reads a saved collapsed-rail preference; storage errors and missing values read as expanded. */
export function readNavCollapsed(storageKey: string): boolean {
  try {
    return window.localStorage.getItem(storageKey) === 'true';
  } catch (e) {
    return false;
  }
}

/** Persists a collapsed-rail preference; a storage failure only means it is not remembered. */
export function writeNavCollapsed(storageKey: string, collapsed: boolean): void {
  try {
    window.localStorage.setItem(storageKey, collapsed ? 'true' : 'false');
  } catch (e) {
    /* storage unavailable (private mode, quota): the choice lasts for this mount only */
  }
}

/**
 * Collapsed-rail state restored from `localStorage` on mount and written on
 * every toggle. Default expanded.
 */
export function useFlyoutNavCollapsed(storageKey: string): [boolean, () => void] {
  const [collapsed, setCollapsed] = useState<boolean>(() => readNavCollapsed(storageKey));
  const toggle = useCallback(() => {
    setCollapsed((current) => {
      const next = !current;
      writeNavCollapsed(storageKey, next);
      return next;
    });
  }, [storageKey]);
  return [collapsed, toggle];
}

function itemName(
  id: string,
  label: string,
  count: string | null,
  style: FlyoutNavCountStyle,
  testSubj: string,
  block: string
): React.ReactNode {
  return (
    <span className={`${block}__item`}>
      <span className={`${block}__label`}>{label}</span>
      {count !== null ? (
        style === 'hollow' ? (
          <EuiBadge color="hollow" className={`${block}__count`} data-test-subj={`${testSubj}Count-${id}`}>
            {count}
          </EuiBadge>
        ) : (
          <EuiNotificationBadge size="m" color="subdued" className={`${block}__count`} data-test-subj={`${testSubj}Count-${id}`}>
            {count}
          </EuiNotificationBadge>
        )
      ) : null}
    </span>
  );
}

function buildItem<Id extends string>(id: Id, props: FlyoutNavProps<Id>): EuiSideNavItemType<{}> {
  const { activeId, onSelect, testSubj } = props;
  const block = props.block || testSubj;
  const label = props.label(id);
  const count = props.count ? props.count(id) : null;
  const style = props.countStyle ? props.countStyle(id) : 'notification';
  return {
    id,
    name: itemName(id, label, count, style, testSubj, block),
    icon: <EuiIcon type={props.icons[id]} size="s" />,
    isSelected: id === activeId,
    onClick: () => onSelect(id),
    'data-test-subj': `${testSubj}-${id}`,
    'aria-label': label,
  };
}

/** Pure flat item list (every section in order) for `EuiSideNav`; exported for tests. */
export function buildFlyoutNavItems<Id extends string>(props: FlyoutNavProps<Id>): Array<EuiSideNavItemType<{}>> {
  return props.sections.map((id) => buildItem(id, props));
}

/** Item lists per visual group, in group order; exported for tests. */
export function buildFlyoutNavGroups<Id extends string>(
  props: FlyoutNavProps<Id>
): Array<{ id: string; items: Array<EuiSideNavItemType<{}>> }> {
  return props.groups.map((group) => ({ id: group.id, items: group.items.map((id) => buildItem(id, props)) }));
}

/**
 * Collapse / expand toggle (`<testSubj>Toggle`). Exported so hosts with their
 * own expanded rendering (the settings nav, step 11.2) share the one toggle.
 */
export const FlyoutNavToggle: React.FC<{ collapsed: boolean; onToggle: () => void; testSubj: string; block: string }> = ({
  collapsed,
  onToggle,
  testSubj,
  block,
}) => {
  const label = collapsed ? 'Expand navigation' : 'Collapse navigation';
  return (
    <div className={`${block}__toggleRow`}>
      <EuiToolTip content={label} position="right" delay="long">
        <EuiButtonIcon
          iconType={collapsed ? 'menuRight' : 'menuLeft'}
          size="s"
          color="text"
          aria-label={label}
          aria-expanded={!collapsed}
          onClick={onToggle}
          data-test-subj={`${testSubj}Toggle`}
        />
      </EuiToolTip>
    </div>
  );
};

/**
 * Icon-only rail: the same subjects as the list, labels in tooltips, non-zero
 * counts as a dot. Exported for hosts that keep their own expanded list
 * (settings nav, step 11.2) and only borrow the collapsed state.
 */
export function FlyoutNavRail<Id extends string>(props: FlyoutNavProps<Id>): JSX.Element {
  const { activeId, onSelect, testSubj, ariaLabel } = props;
  const block = props.block || testSubj;
  return (
    <nav aria-label={ariaLabel} className={`${block}__rail`}>
      {props.groups.map((group, index) => (
        <React.Fragment key={group.id}>
          {index > 0 ? <EuiHorizontalRule margin="xs" className={`${block}__rule`} /> : null}
          {group.items.map((id) => {
            const label = props.label(id);
            const count = props.count ? props.count(id) : null;
            // The dot is an attention cue, so a known-but-zero count shows
            // nothing; the tooltip still carries it.
            const showDot = count !== null && count !== '0';
            const active = id === activeId;
            return (
              <div key={id} className={`${block}__railItem${active ? ` ${block}__railItem--active` : ''}`}>
                <EuiToolTip content={count !== null ? `${label} (${count})` : label} position="right">
                  <EuiButtonIcon
                    iconType={props.icons[id]}
                    size="s"
                    color={active ? 'primary' : 'text'}
                    aria-label={label}
                    aria-current={active ? 'page' : undefined}
                    onClick={() => onSelect(id)}
                    className={`${block}__railButton${active ? ' isSelected' : ''}`}
                    data-test-subj={`${testSubj}-${id}`}
                  />
                </EuiToolTip>
                {showDot ? (
                  <span
                    className={`${block}__dot`}
                    role="img"
                    aria-label={`${label}: ${count}`}
                    title={count}
                    data-test-subj={`${testSubj}Count-${id}`}
                  />
                ) : null}
              </div>
            );
          })}
        </React.Fragment>
      ))}
    </nav>
  );
}

export function FlyoutNav<Id extends string>(props: FlyoutNavProps<Id>): JSX.Element {
  const { testSubj, ariaLabel } = props;
  const block = props.block || testSubj;
  const collapsed = Boolean(props.collapsed);
  const heading = props.heading ?? 'Sections';
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
        <FlyoutNavRail {...props} />
      ) : (
        <>
          <EuiTitle size="xxs" className="wamNavHeading">
            <h4>{heading}</h4>
          </EuiTitle>
          {buildFlyoutNavGroups(props).map((group, index) => (
            <React.Fragment key={group.id}>
              {index > 0 ? <EuiHorizontalRule margin="xs" className={`${block}__rule`} /> : null}
              <EuiSideNav
                // EuiSideNav renders its own <nav> landmark, so the wrapper is
                // a div: the first group carries the page-level label.
                aria-label={index === 0 ? ariaLabel : `${ariaLabel}: ${group.id}`}
                className={`${block}__group`}
                mobileBreakpoints={[]}
                items={group.items}
              />
            </React.Fragment>
          ))}
        </>
      )}
    </div>
  );
}
