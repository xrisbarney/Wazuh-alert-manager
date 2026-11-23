import React from 'react';
import { EuiBadge, EuiLink, EuiText, EuiToolTip } from '@elastic/eui';
import { AlertNativeCase, TARGET_WAZUH_MAJOR } from '../../common';
import { CASE_SEVERITY_BADGE_COLOR } from '../design';

/**
 * "Native case" chip (step 2.6, decision Q6): the read-only projection of a
 * Wazuh 5.0 finding's `wazuh.case.*` fields, re-derived by every sync and
 * never written back. Rendered only on a 5.0 build (`TARGET_WAZUH_MAJOR === 5`)
 * and only when the record carries a projection; on a 4.x build nothing
 * renders, whatever the record holds (never show a 5.0-only control on 4.x).
 *
 * Deep link: the 5.0 dashboard registers the Cases app as `case-management`
 * (category threat-intelligence) and its module redirects to
 * `/overview/?tab=caseManagement&tabView=dashboard`; the cases list is the
 * `cases` tab of that module (verified in the bundled 5.0.0-rc2 `wazuh`
 * plugin sources). The app has no per-case route (a native case is the
 * finding itself; rc2 writes no `wazuh.case.id`, the field is reserved), so
 * the link opens the cases list.
 */
export const NATIVE_CASES_APP_PATH = '/app/case-management#/overview/?tab=caseManagement&tabView=cases';

/** Native status palette: the workflow ramp, label always shown. */
export const NATIVE_CASE_STATUS_COLOR: Record<string, string> = {
  active: 'primary',
  acknowledged: 'default',
  completed: 'success',
  error: 'danger',
  deleted: 'hollow',
  audit: 'hollow',
};

/** TLP uses its own well-known colours; the word is always shown. */
export const NATIVE_CASE_TLP_COLOR: Record<string, string> = {
  red: 'danger',
  amber: 'warning',
  'amber+strict': 'warning',
  green: 'success',
  clear: 'hollow',
  white: 'hollow',
};

/**
 * Own-property lookup for a source-controlled key: a native status such as
 * `constructor` or `toString` must fall back, never resolve to a function on
 * Object.prototype that EuiBadge would receive as a colour.
 */
export function ownColor(map: Record<string, string>, key: string | null | undefined): string | undefined {
  return key && Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

export function nativeCaseVisible(nativeCase: AlertNativeCase | null | undefined): nativeCase is AlertNativeCase {
  return Number(TARGET_WAZUH_MAJOR) === 5 && Boolean(nativeCase);
}

export function nativeCaseLabel(nativeCase: AlertNativeCase): string {
  return nativeCase.id ? `Native case ${nativeCase.id}` : 'Native case';
}

function capitalise(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

interface Props {
  nativeCase: AlertNativeCase | null | undefined;
  /** Queue rows: one badge carrying the status, no facets or title. */
  compact?: boolean;
  /** Prefix for the dashboard base path (apiService.appUrl); without it no link is rendered. */
  appUrl?: (path: string) => string;
  className?: string;
  testSubj?: string;
}

export const NativeCaseChip: React.FC<Props> = ({ nativeCase, compact = false, appUrl, className, testSubj = 'wamNativeCase' }) => {
  if (!nativeCaseVisible(nativeCase)) return null;
  const label = nativeCaseLabel(nativeCase);
  const status = nativeCase.status;
  const tooltip = [
    `${label}: read-only copy of the Wazuh Cases fields on this finding; edit it in the Wazuh Cases app`,
    status ? `Status ${status}` : null,
    nativeCase.severity ? `severity ${nativeCase.severity}` : null,
    nativeCase.priority ? `priority ${nativeCase.priority}` : null,
    nativeCase.tlp ? `TLP ${nativeCase.tlp}` : null,
    nativeCase.title ? `"${nativeCase.title}"` : null,
  ]
    .filter(Boolean)
    .join(', ');
  const href = appUrl ? appUrl(NATIVE_CASES_APP_PATH) : null;

  if (compact) {
    return (
      <EuiToolTip content={tooltip}>
        <EuiBadge
          color={ownColor(NATIVE_CASE_STATUS_COLOR, status) || 'hollow'}
          iconType="link"
          className={['wamNativeCaseQueueBadge', className].filter(Boolean).join(' ')}
          data-test-subj={testSubj}
          data-native-status={status || ''}
        >
          {status ? `Native: ${status}` : 'Native case'}
        </EuiBadge>
      </EuiToolTip>
    );
  }

  return (
    <div className={['wamNativeCaseChip', className].filter(Boolean).join(' ')} data-test-subj={testSubj} data-native-status={status || ''}>
      <span className="wamNativeCaseChip__badges">
        <EuiToolTip content={tooltip}>
          <EuiBadge color="hollow" iconType="link" data-test-subj={`${testSubj}Label`}>
            {label}
          </EuiBadge>
        </EuiToolTip>
        {status ? (
          <EuiBadge color={ownColor(NATIVE_CASE_STATUS_COLOR, status) || 'hollow'} data-test-subj={`${testSubj}Status`} title={`Native status ${status}`}>
            {capitalise(status)}
          </EuiBadge>
        ) : null}
        {nativeCase.severity ? (
          <EuiBadge color={ownColor(CASE_SEVERITY_BADGE_COLOR, nativeCase.severity) || 'default'} data-test-subj={`${testSubj}Severity`} title={`Native severity ${nativeCase.severity}`}>
            {capitalise(nativeCase.severity)}
          </EuiBadge>
        ) : null}
        {nativeCase.priority ? (
          <EuiBadge color="hollow" data-test-subj={`${testSubj}Priority`} title={`Native priority ${nativeCase.priority}`}>
            Priority {nativeCase.priority}
          </EuiBadge>
        ) : null}
        {nativeCase.tlp ? (
          <EuiBadge color={ownColor(NATIVE_CASE_TLP_COLOR, nativeCase.tlp.toLowerCase()) || 'hollow'} data-test-subj={`${testSubj}Tlp`} title={`TLP ${nativeCase.tlp}`}>
            TLP {nativeCase.tlp.toUpperCase()}
          </EuiBadge>
        ) : null}
        {nativeCase.tags.map((tag) => (
          <EuiBadge key={`nt-${tag}`} color="default" iconType="tag" title={`Native case tag ${tag}`}>
            {tag}
          </EuiBadge>
        ))}
      </span>
      {nativeCase.title ? (
        <EuiText size="s" className="wamNativeCaseChip__title" data-test-subj={`${testSubj}Title`}>
          {nativeCase.title}
        </EuiText>
      ) : null}
      <EuiText size="xs" color="subdued" className="wamNativeCaseChip__footer">
        Read-only copy of the Wazuh Cases fields; changes are made in the Wazuh Cases app and picked up by the next sync.
        {href ? (
          <>
            {' '}
            <EuiLink href={href} target="_blank" external data-test-subj={`${testSubj}Link`}>
              Open Wazuh Cases
            </EuiLink>
          </>
        ) : null}
      </EuiText>
    </div>
  );
};
