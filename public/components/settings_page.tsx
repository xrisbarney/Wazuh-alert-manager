import React from 'react';
import { EuiFlexGroup, EuiFlexItem, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';

/**
 * Shared chrome for the settings pages (step 8.3): every page starts with the
 * same header block (title, one-line subdued description, optional
 * right-aligned primary action) and ends its forms with the same right-aligned
 * action row (Reset as `EuiButtonEmpty`, Save as `EuiButton fill size="s"`).
 */

export interface SettingsPageHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  /** Right-aligned primary action (New rule, New task list, Save, ...). */
  actions?: React.ReactNode;
  testSubj?: string;
}

export const SettingsPageHeader: React.FC<SettingsPageHeaderProps> = ({ title, description, actions, testSubj }) => (
  <>
    <EuiFlexGroup alignItems="flexStart" justifyContent="spaceBetween" gutterSize="m" responsive={false} className="wamSettingsPageHeader" data-test-subj={testSubj}>
      <EuiFlexItem className="wamSettingsPageHeader__text">
        <EuiTitle size="s">
          <h3>{title}</h3>
        </EuiTitle>
        {description ? (
          <EuiText size="s" color="subdued" className="wamSettingsPageHeader__description">
            <p>{description}</p>
          </EuiText>
        ) : null}
      </EuiFlexItem>
      {actions ? (
        <EuiFlexItem grow={false} className="wamSettingsPageHeader__actions">
          {actions}
        </EuiFlexItem>
      ) : null}
    </EuiFlexGroup>
    <EuiSpacer size="m" />
  </>
);

export interface SettingsFormActionsProps {
  /** Secondary controls (an "Add ..." button, a kind picker) kept at the left edge. */
  leading?: React.ReactNode;
  /** Subdued meta text (last saved by, counts) shown at the left edge, after `leading`. */
  meta?: React.ReactNode;
  /** Buttons, left to right; the primary Save goes last. */
  children: React.ReactNode;
  className?: string;
}

export const SettingsFormActions: React.FC<SettingsFormActionsProps> = ({ leading, meta, children, className }) => (
  <EuiFlexGroup alignItems="center" justifyContent="flexEnd" gutterSize="s" responsive={false} wrap className={`wamSettingsFormActions${className ? ` ${className}` : ''}`}>
    {leading ? (
      <EuiFlexItem grow={false} className="wamSettingsFormActions__leading">
        {leading}
      </EuiFlexItem>
    ) : null}
    {meta ? (
      <EuiFlexItem className="wamSettingsFormActions__meta">
        <EuiText size="xs" color="subdued">{meta}</EuiText>
      </EuiFlexItem>
    ) : leading ? (
      <EuiFlexItem />
    ) : null}
    {React.Children.map(children, (child, index) =>
      child === null || child === undefined || child === false ? null : (
        <EuiFlexItem grow={false} key={index}>{child}</EuiFlexItem>
      )
    )}
  </EuiFlexGroup>
);
