import React, { useEffect, useRef, useState } from 'react';
import { EuiBadge, EuiLink, EuiLoadingSpinner, EuiToolTip } from '@elastic/eui';
import type { AssetContextFamilyBase, AssetContextResponse } from '../../common';
import { AlertsApiService } from '../services/api';

/**
 * Asset context chips (step 6.4b): one compact row under the alert/case
 * header with OS, IPs, open ports, critical/high CVEs and SCA failures read
 * from the native `wazuh-states-*` families, plus deep links to IT Hygiene
 * and Vulnerability Detection. The row loads lazily after the flyout is on
 * screen and never blocks it: while loading it shows a spinner chip, and a
 * failed request becomes a single "unavailable" chip. Each family carries
 * its own status, so "no access" (missing role grant) and "no data" (agent
 * not inventoried) are shown per chip rather than hiding the whole row.
 */

interface Props {
  apiService: AlertsApiService;
  agentId?: string | null;
  agentName?: string | null;
  /** Shown before the chips (the case flyout lists several agents). */
  label?: string | null;
  testSubj?: string;
  /**
   * Reports the compact counts once the fetch settled (step 11.4): the case
   * flyout's Assets rows and header summary read them from here instead of
   * fetching a second time. A failed request reports `loaded: false`.
   */
  onLoaded?: (summary: AssetContextSummary) => void;
  /**
   * Controlled mode (step 11.4): the host already holds the context (the case
   * flyout caches one response per agent so a row survives remounts without a
   * second native read). When set, the chips render this state and never fetch.
   */
  source?: AssetContextSource;
}

/** State of one agent's context as a host passes it through `source`. */
export type AssetContextSource =
  | { status: 'loading' }
  | { status: 'ready'; context: AssetContextResponse }
  | { status: 'failed'; error: string };

/** Compact counts of one agent's context, as `onLoaded` reports them. */
export interface AssetContextSummary {
  /** True once a response arrived; false after a failed request. */
  loaded: boolean;
  /** The vulnerabilities family answered `ok` (the counts below are real, 0 included). */
  vulnKnown: boolean;
  vulnCritical: number;
  vulnHigh: number;
  /** The SCA family answered `ok` (not the case on Wazuh 4.x, where results are not indexed). */
  scaKnown: boolean;
  scaFailed: number;
  scaPassed: number;
}

export const EMPTY_ASSET_SUMMARY: AssetContextSummary = {
  loaded: false,
  vulnKnown: false,
  vulnCritical: 0,
  vulnHigh: 0,
  scaKnown: false,
  scaFailed: 0,
  scaPassed: 0,
};

/** Reduces a context response to its compact counts; `null` (a failed read) gives an unloaded summary. */
export function summarizeAssetContext(context: AssetContextResponse | null): AssetContextSummary {
  if (!context) return { ...EMPTY_ASSET_SUMMARY };
  const { vulnerabilities, sca } = context.families;
  const vulnKnown = vulnerabilities.status === 'ok';
  const scaKnown = sca.status === 'ok';
  return {
    loaded: true,
    vulnKnown,
    vulnCritical: vulnKnown ? Number(vulnerabilities.critical || 0) : 0,
    vulnHigh: vulnKnown ? Number(vulnerabilities.high || 0) : 0,
    scaKnown,
    scaFailed: scaKnown ? Number(sca.failed || 0) : 0,
    scaPassed: scaKnown ? Number(sca.passed || 0) : 0,
  };
}

/**
 * Sums the loaded summaries (the case header line aggregates across the agent
 * rows that have fetched); `loaded` is true when at least one of them has.
 */
export function aggregateAssetSummaries(summaries: AssetContextSummary[]): AssetContextSummary {
  const total = { ...EMPTY_ASSET_SUMMARY };
  for (const s of summaries) {
    if (!s.loaded) continue;
    total.loaded = true;
    total.vulnKnown = total.vulnKnown || s.vulnKnown;
    total.vulnCritical += s.vulnCritical;
    total.vulnHigh += s.vulnHigh;
    total.scaKnown = total.scaKnown || s.scaKnown;
    total.scaFailed += s.scaFailed;
    total.scaPassed += s.scaPassed;
  }
  return total;
}

/**
 * The compact count badges (critical / high vulnerabilities, failed SCA
 * checks) shown in the case header summary and on each Assets row title.
 * Renders nothing until the summary is loaded; a family that did not answer
 * `ok` has no badge rather than a misleading zero.
 */
export const AssetContextCountBadges: React.FC<{ summary: AssetContextSummary; testSubj?: string }> = ({
  summary,
  testSubj = 'wamAssetContextCounts',
}) => {
  if (!summary.loaded) return null;
  return (
    <span className="wamAssetContextCounts" data-test-subj={testSubj}>
      {summary.vulnKnown && (
        <EuiBadge
          color={summary.vulnCritical > 0 ? 'danger' : summary.vulnHigh > 0 ? 'warning' : 'hollow'}
          iconType="bug"
          className="wamAssetContextCount"
          data-test-subj={`${testSubj}-vuln`}
        >
          {summary.vulnCritical} critical / {summary.vulnHigh} high
        </EuiBadge>
      )}
      {summary.scaKnown && (
        <EuiBadge
          color={summary.scaFailed > 0 ? 'warning' : 'hollow'}
          iconType="checkInCircleFilled"
          className="wamAssetContextCount"
          data-test-subj={`${testSubj}-sca`}
        >
          {summary.scaFailed} SCA failed
        </EuiBadge>
      )}
    </span>
  );
};

interface ChipSpec {
  key: string;
  icon: string;
  title: string;
  family: AssetContextFamilyBase;
  /** Rendered when the family is `ok`; `null` means "no data". */
  value: React.ReactNode | null;
  tooltip?: string;
  color?: string;
  /** Chip text when the family is `not_available` (defaults to `n/a`). */
  unavailableText?: string;
}

export const FAMILY_STATUS_LABEL: Record<string, string> = {
  no_access: 'no access',
  not_available: 'n/a',
  error: 'unavailable',
};

export function familyStatusTooltip(family: AssetContextFamilyBase, title: string): string {
  if (family.status === 'no_access') {
    return `${title}: no read access to the Wazuh states index (map the wazuh_alert_manager_native_read role to this user).`;
  }
  if (family.status === 'not_available') return `${title}: ${family.reason || 'not available on this Wazuh line'}.`;
  if (family.status === 'error') return `${title}: ${family.reason === 'timeout' ? 'the read timed out' : family.reason || 'read failed'}.`;
  return title;
}

function chipList(context: AssetContextResponse): ChipSpec[] {
  const { system, networks, ports, vulnerabilities, sca } = context.families;
  const os = system.os;
  const osText = os ? [os.name, os.version].filter(Boolean).join(' ') : '';
  const ips = networks.ips || [];
  const critical = vulnerabilities.critical || 0;
  const high = vulnerabilities.high || 0;
  const topCves = (vulnerabilities.topCves || []).map((c) => `${c.id}${c.score != null ? ` (${c.score})` : ''}`);
  return [
    {
      key: 'os',
      icon: 'compute',
      title: 'Operating system',
      family: system,
      value: osText || null,
      tooltip: system.hostname ? `Host ${system.hostname}` : undefined,
    },
    {
      key: 'ips',
      icon: 'globe',
      title: 'IP addresses',
      family: networks,
      value: ips.length ? (ips.length > 3 ? `${ips.slice(0, 3).join(', ')} +${ips.length - 3}` : ips.join(', ')) : null,
      tooltip: ips.length ? ips.join(', ') : undefined,
    },
    {
      key: 'ports',
      icon: 'link',
      title: 'Open ports',
      family: ports,
      value: ports.open ? `${ports.open} open${ports.listening ? `, ${ports.listening} listening` : ''}` : null,
    },
    {
      key: 'cves',
      icon: 'bug',
      title: 'Vulnerabilities',
      family: vulnerabilities,
      value: vulnerabilities.total ? `${critical} critical / ${high} high` : null,
      tooltip: topCves.length ? `Top CVEs: ${topCves.join(', ')}` : undefined,
      color: critical > 0 ? 'danger' : high > 0 ? 'warning' : undefined,
    },
    {
      key: 'sca',
      icon: 'checkInCircleFilled',
      title: 'SCA checks',
      family: sca,
      value: sca.total ? `${sca.failed || 0} failed` : null,
      color: (sca.failed || 0) > 0 ? 'warning' : undefined,
      // 4.x keeps SCA results in the manager, not the indexer: say so instead of a bare n/a
      // and let the Configuration Assessment link beside the chips take the user there.
      unavailableText: context.links.configurationAssessment ? 'not indexed on 4.x' : undefined,
    },
  ];
}

/** The message a failed context read shows (shared with hosts that fetch themselves). */
export function assetContextErrorMessage(e: any): string {
  return e?.body?.message || e?.message || 'Asset context unavailable';
}

const Chip: React.FC<{ spec: ChipSpec }> = ({ spec }) => {
  const { family, title, icon, value } = spec;
  const ok = family.status === 'ok';
  const text = ok
    ? (value === null ? 'no data' : value)
    : (family.status === 'not_available' && spec.unavailableText) || FAMILY_STATUS_LABEL[family.status] || family.status;
  const tooltip = ok ? [title, spec.tooltip].filter(Boolean).join('. ') : familyStatusTooltip(family, title);
  const muted = !ok || value === null;
  return (
    <EuiToolTip content={tooltip}>
      <EuiBadge
        color={muted ? 'hollow' : spec.color || 'default'}
        iconType={icon}
        className={`wamAssetContextChip wamAssetContextChip--${ok ? (value === null ? 'empty' : 'ok') : family.status}`}
        data-test-subj={`wamAssetContextChip-${spec.key}`}
        data-status={ok ? (value === null ? 'no_data' : 'ok') : family.status}
      >
        <span className="wamAssetContextChipTitle">{title}:</span> {text}
      </EuiBadge>
    </EuiToolTip>
  );
};

export const AssetContextChips: React.FC<Props> = ({ apiService, agentId, agentName, label, testSubj, onLoaded, source }) => {
  const [ownContext, setOwnContext] = useState<AssetContextResponse | null>(null);
  const [ownFailed, setOwnFailed] = useState<string | null>(null);
  const [ownLoading, setOwnLoading] = useState(false);
  const target = agentId || agentName || null;
  // Read through a ref so a host passing a fresh closure each render does not restart the fetch.
  const onLoadedRef = useRef(onLoaded);
  onLoadedRef.current = onLoaded;
  const controlled = source !== undefined;

  useEffect(() => {
    if (!target || controlled) return;
    let cancelled = false;
    setOwnContext(null);
    setOwnFailed(null);
    setOwnLoading(true);
    apiService
      .fetchAssetContext({ agentId, agentName })
      .then((res) => {
        if (cancelled) return;
        setOwnContext(res);
        onLoadedRef.current?.(summarizeAssetContext(res));
      })
      .catch((e: any) => {
        if (cancelled) return;
        setOwnFailed(assetContextErrorMessage(e));
        onLoadedRef.current?.(summarizeAssetContext(null));
      })
      .finally(() => {
        if (!cancelled) setOwnLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // The lookup is per agent; the service instance is stable for the app's lifetime.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentId, agentName, controlled]);

  if (!target) return null;

  const loading = controlled ? source!.status === 'loading' : ownLoading;
  const failed = controlled ? (source!.status === 'failed' ? source!.error : null) : ownFailed;
  const context = controlled ? (source!.status === 'ready' ? source!.context : null) : ownContext;

  return (
    <div className="wamAssetContext" data-test-subj={testSubj || 'wamAssetContext'}>
      {label ? <span className="wamAssetContextLabel">{label}</span> : null}
      {loading && (
        <EuiBadge color="hollow" className="wamAssetContextChip wamAssetContextChip--loading" data-test-subj="wamAssetContextLoading">
          <EuiLoadingSpinner size="s" /> Loading asset context
        </EuiBadge>
      )}
      {!loading && failed && (
        <EuiToolTip content={failed}>
          <EuiBadge color="hollow" iconType="alert" className="wamAssetContextChip wamAssetContextChip--error" data-test-subj="wamAssetContextFailed">
            Asset context unavailable
          </EuiBadge>
        </EuiToolTip>
      )}
      {!loading && context && chipList(context).map((spec) => <Chip key={spec.key} spec={spec} />)}
      {!loading && context && (
        <span className="wamAssetContextLinks">
          {context.links.itHygiene && (
            <EuiLink href={apiService.appUrl(context.links.itHygiene)} target="_blank" external data-test-subj="wamAssetContextLinkHygiene">
              IT Hygiene
            </EuiLink>
          )}
          <EuiLink href={apiService.appUrl(context.links.vulnerabilityDetection)} target="_blank" external data-test-subj="wamAssetContextLinkVuln">
            Vulnerability Detection
          </EuiLink>
          {context.links.configurationAssessment && (
            <EuiLink href={apiService.appUrl(context.links.configurationAssessment)} target="_blank" external data-test-subj="wamAssetContextLinkSca">
              Configuration Assessment
            </EuiLink>
          )}
        </span>
      )}
    </div>
  );
};
