import React, { useState } from 'react';
import { EuiText } from '@elastic/eui';

/**
 * Overview meta grid (step 11.6): the read-only facts of the alert and case
 * flyouts as groups of two-column rows (label | value) under small uppercase
 * titles, with a 1px hairline between the rows of a group and `$euiSizeM` of
 * space between groups. Purely presentational; every rule lives in
 * `public/index.scss` under `wamMetaGrid*`.
 *
 * Markup (kept valid for the HTML content model so assistive tech exposes the
 * term / definition pairs): the grid is a plain `<div>`; each group is a
 * `<div role="group">` labelled by its title and holding ONE `<dl>` whose
 * direct children are the `<div class="wamMetaGrid__row">` wrappers, each with
 * exactly one `<dt>` and one `<dd>` (`dl > div > dt + dd` is the one wrapper
 * form the spec allows). The hairline rule is `.wamMetaGrid__row +
 * .wamMetaGrid__row`, so it needs the rows to be siblings, which they are.
 *
 * The label column width is the CSS variable `--wamMetaLabelWidth` (160px by
 * default, 120px inside the alert flyout, 140px inside the case flyout) so the
 * two flyouts keep their own proportions without a second component;
 * `labelWidth` sets it inline for a one-off instance.
 */
export interface MetaGridProps {
  className?: string;
  'data-test-subj'?: string;
  /** Tighter rows (24px pitch) for dense secondary lists. */
  compact?: boolean;
  /** Label column width in px, written as the `--wamMetaLabelWidth` variable on the grid. */
  labelWidth?: number;
  children?: React.ReactNode;
}

export const MetaGrid: React.FC<MetaGridProps> = ({ className, compact, labelWidth, children, ...rest }) => {
  const classes = ['wamMetaGrid'];
  if (compact) classes.push('wamMetaGrid--compact');
  if (className) classes.push(className);
  const style = typeof labelWidth === 'number' && Number.isFinite(labelWidth)
    ? ({ '--wamMetaLabelWidth': `${labelWidth}px` } as React.CSSProperties)
    : undefined;
  return (
    <div className={classes.join(' ')} style={style} data-test-subj={rest['data-test-subj']}>
      {children}
    </div>
  );
};

export interface MetaGroupProps {
  /** Small uppercase heading in the rail's "SECTIONS" style; omit for an untitled group. */
  title?: string;
  'data-test-subj'?: string;
  children?: React.ReactNode;
}

// Own counter rather than EUI's `htmlIdGenerator` (mocked to one constant id
// in the dashboard's Jest setup, which would make every group's
// `aria-labelledby` point at the first title).
let groupTitleSeq = 0;
const makeGroupTitleId = () => `wamMetaGroup-${++groupTitleSeq}`;

export const MetaGroup: React.FC<MetaGroupProps> = ({ title, children, ...rest }) => {
  const [titleId] = useState(makeGroupTitleId);
  return (
    <div
      className="wamMetaGrid__group"
      role="group"
      aria-labelledby={title ? titleId : undefined}
      data-test-subj={rest['data-test-subj']}
    >
      {title ? (
        <EuiText size="xs" color="subdued" className="wamMetaGrid__groupTitle">
          <span id={titleId}>{title}</span>
        </EuiText>
      ) : null}
      <dl className="wamMetaGrid__rows">{children}</dl>
    </div>
  );
};

export interface MetaRowProps {
  label: React.ReactNode;
  /** Goes on the value cell (`<dd>`), where the tests and the Playwright specs read the row's content. */
  'data-test-subj'?: string;
  /** Extra class on the value cell (`wamMetaList__inline`, `wamClosureReason`, `wamAlertId`, ...). */
  className?: string;
  children?: React.ReactNode;
}

/** One `dt` + `dd` pair; must be rendered inside a `MetaGroup` (its `<dl>`). */
export const MetaRow: React.FC<MetaRowProps> = ({ label, className, children, ...rest }) => (
  <div className="wamMetaGrid__row">
    <dt className="wamMetaGrid__label">
      <EuiText size="xs" color="subdued">
        <span>{label}</span>
      </EuiText>
    </dt>
    <dd className={`wamMetaGrid__value${className ? ` ${className}` : ''}`} data-test-subj={rest['data-test-subj']}>
      <EuiText size="s">
        <div className="wamMetaGrid__content">{children}</div>
      </EuiText>
    </dd>
  </div>
);
