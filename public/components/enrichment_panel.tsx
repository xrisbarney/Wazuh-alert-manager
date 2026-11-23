import React, { useCallback, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLink,
  EuiPanel,
  EuiText,
  EuiTitle,
  EuiToolTip,
  EuiSpacer,
} from '@elastic/eui';
import {
  AlertEnrichment,
  AlertEnrichmentItem,
  CTI_EXPLORER_APP_PATH,
  ENRICHMENT_LOOKUP_TYPES,
  EnrichmentLookupItem,
  EnrichmentLookupResponse,
  EnrichmentLookupType,
  EnrichmentVerdict,
  IndicatorType,
  VerdictHint,
  canonicalUrl,
  enrichmentItemsFor,
} from '../../common';
import { AlertsApiService } from '../services/api';
import { formatAbsolute } from '../design';
import { useTerminology } from '../terminology';
import {
  INDICATOR_ACTIONS_CELL,
  INDICATOR_BADGE_CELL,
  INDICATOR_NARROW_CELL,
  INDICATOR_TYPE_LABELS,
  INDICATOR_VALUE_CELL,
  IndicatorValueCell,
  VerdictBadges,
} from './indicator_list';

/** The subset of an indicator row (alert or case) the enrichment UI needs. */
export interface LookupableIndicator {
  type: IndicatorType;
  value: string;
  verdictHints: VerdictHint[];
  tags: string[];
  fields?: string[];
}

/** Runs one lookup; the alert flyout persists it, the case tab does not. */
export type EnrichmentLookupFn = (type: EnrichmentLookupType, value: string, refresh?: boolean) => Promise<EnrichmentLookupResponse>;

const VERDICT_COLORS: Record<EnrichmentVerdict, string> = {
  malicious: 'danger',
  suspicious: 'warning',
  clean: 'success',
  unknown: 'hollow',
};

export function isLookupType(type: string): type is EnrichmentLookupType {
  return (ENRICHMENT_LOOKUP_TYPES as readonly string[]).includes(type);
}

/**
 * Whether a lookup can be run for this indicator. 4.x `data.url` values are
 * often path-only (`/wp-login.php`) and are kept verbatim as `url` rows for
 * the analyst; the server's canonical form needs a scheme and host, so those
 * rows are shown as n/a instead of a guaranteed 400.
 */
export function isLookupableIndicator(type: string, value: string): boolean {
  if (!isLookupType(type)) return false;
  if (type === 'url') return canonicalUrl(value) !== null;
  return true;
}

/** Message shown for a session lookup that no enabled source could answer. */
export const NO_SOURCE_MESSAGE = 'No enrichment source is enabled for this type (Settings > Enrichment).';

export function lookupKey(type: string, value: string): string {
  return `${type}:${value}`;
}

/**
 * Browser URL of the Wazuh 5.0 CTI Explorer for an indicator, or null on 4.x
 * builds. The explorer has no documented record-level query parameter yet
 * (PLAN.md 6.2 deferred it to the 6.7 verification pass), so the link opens
 * the app and the analyst pastes the value; the copy button sits beside it.
 */
export function ctiExplorerUrlFor(apiService: Pick<AlertsApiService, 'appUrl'>, wazuhMajor: number | undefined, value: string): string | null {
  if (wazuhMajor !== 5 || !value) return null;
  return apiService.appUrl(CTI_EXPLORER_APP_PATH);
}

interface LookupState {
  results: Record<string, EnrichmentLookupResponse>;
  errors: Record<string, string>;
  pending: Record<string, true>;
}

/**
 * Session-scoped lookup state keyed by `type:value`. One in-flight lookup per
 * indicator; "Lookup all" runs the lookupable indicators with a small
 * concurrency so a case with hundreds of IPs does not fan out at once. The
 * alert flyout passes `concurrency: 1` because each of its lookups also
 * writes the alert record; the case tab (session-only) keeps the default 3.
 */
export function useEnrichmentLookups(lookup: EnrichmentLookupFn, options: { concurrency?: number } = {}) {
  const concurrency = Math.max(1, options.concurrency ?? 3);
  const [state, setState] = useState<LookupState>({ results: {}, errors: {}, pending: {} });
  const [runningAll, setRunningAll] = useState(false);
  const inFlight = useRef(new Set<string>());

  const run = useCallback(
    async (type: EnrichmentLookupType, value: string, refresh = false) => {
      const key = lookupKey(type, value);
      if (inFlight.current.has(key)) return;
      inFlight.current.add(key);
      setState((prev) => ({ ...prev, pending: { ...prev.pending, [key]: true } }));
      try {
        const res = await lookup(type, value, refresh);
        setState((prev) => {
          const errors = { ...prev.errors };
          delete errors[key];
          const pending = { ...prev.pending };
          delete pending[key];
          return { results: { ...prev.results, [key]: res }, errors, pending };
        });
      } catch (e: any) {
        const message = e?.body?.message || e?.message || 'Lookup failed';
        setState((prev) => {
          const pending = { ...prev.pending };
          delete pending[key];
          return { ...prev, errors: { ...prev.errors, [key]: message }, pending };
        });
      } finally {
        inFlight.current.delete(key);
      }
    },
    [lookup]
  );

  const runAll = useCallback(
    async (indicators: Array<Pick<LookupableIndicator, 'type' | 'value'>>, refresh = false) => {
      const targets = indicators.filter((item) => isLookupableIndicator(item.type, item.value));
      if (!targets.length) return;
      setRunningAll(true);
      try {
        const queue = targets.slice();
        const worker = async () => {
          while (queue.length) {
            const next = queue.shift()!;
            await run(next.type as EnrichmentLookupType, next.value, refresh);
          }
        };
        await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
      } finally {
        setRunningAll(false);
      }
    },
    [run, concurrency]
  );

  return { ...state, run, runAll, runningAll };
}

type SourceBadge =
  | { source: string; kind: 'stored'; item: AlertEnrichmentItem }
  | { source: string; kind: 'session'; entry: EnrichmentLookupItem };

function badgesFor(stored: AlertEnrichmentItem[], session?: EnrichmentLookupResponse): SourceBadge[] {
  const bySource = new Map<string, SourceBadge>();
  for (const item of stored) bySource.set(item.source, { source: item.source, kind: 'stored', item });
  // A fresh session result supersedes the stored one for the same source;
  // a session error is shown beside whatever is stored.
  for (const entry of session?.results || []) {
    const source = entry.result?.source || entry.sourceId;
    if (entry.status === 'ok' && entry.result) bySource.set(source, { source, kind: 'session', entry });
    else if (!bySource.has(source)) bySource.set(source, { source, kind: 'session', entry });
    else bySource.set(`${source}\u0000error`, { source, kind: 'session', entry });
  }
  return Array.from(bySource.values());
}

function scoreText(score: number | null | undefined): string {
  return typeof score === 'number' && Number.isFinite(score) ? ` ${Math.round(score)}` : '';
}

/** One badge per source: stored verdicts, session verdicts and per-source errors, each with a link out when the source gave one. */
export function EnrichmentVerdictBadges({ stored, session }: { stored: AlertEnrichmentItem[]; session?: EnrichmentLookupResponse }) {
  const badges = useMemo(() => badgesFor(stored, session), [stored, session]);
  // A session response with no results means no enabled source supports the
  // type: say so, otherwise the analyst sees "not looked up" after clicking.
  const noSource = session && (session.results?.length ?? 0) === 0;
  if (!badges.length) {
    return (
      <EuiText size="xs" color={noSource ? 'warning' : 'subdued'} data-test-subj={noSource ? 'wamEnrichmentNoSource' : undefined}>
        <span>{noSource ? NO_SOURCE_MESSAGE : 'not looked up'}</span>
      </EuiText>
    );
  }
  return (
    <span className="wamEnrichmentBadges" data-test-subj="wamEnrichmentBadges">
      {badges.map((badge) => {
        if (badge.kind === 'session' && badge.entry.status !== 'ok') {
          return (
            <EuiToolTip key={`${badge.source}-error`} content={badge.entry.error || 'Lookup failed'}>
              <EuiBadge color="hollow" iconType="alert">
                {badge.entry.sourceName || badge.source}: error
              </EuiBadge>
            </EuiToolTip>
          );
        }
        const verdict: EnrichmentVerdict = badge.kind === 'stored' ? badge.item.verdict : badge.entry.result!.verdict;
        const score = badge.kind === 'stored' ? badge.item.score : badge.entry.result!.score;
        const tags = badge.kind === 'stored' ? badge.item.tags : badge.entry.result!.tags;
        const link = badge.kind === 'stored' ? badge.item.link : badge.entry.result!.link;
        const checkedAt = badge.kind === 'stored' ? badge.item.checked_at : badge.entry.result!.checkedAt;
        const label = badge.kind === 'session' ? badge.entry.sourceName || badge.source : badge.source;
        const summary = badge.kind === 'session' ? badge.entry.result!.summary : '';
        const tooltip = [
          `${label}: ${verdict}${scoreText(score)}`,
          summary,
          tags.length ? `tags: ${tags.join(', ')}` : '',
          checkedAt ? `checked ${formatAbsolute(checkedAt)}${badge.kind === 'session' && badge.entry.cached ? ' (cached)' : ''}` : '',
          badge.kind === 'stored' ? 'stored on the record' : '',
        ].filter(Boolean);
        return (
          <span key={badge.source} className="wamEnrichmentBadge">
            <EuiToolTip
              content={
                <div>
                  {tooltip.map((line, i) => (
                    <div key={i}>{line}</div>
                  ))}
                </div>
              }
            >
              <EuiBadge color={VERDICT_COLORS[verdict] || 'hollow'} className={`wamEnrichmentVerdict wamEnrichmentVerdict--${verdict}`}>
                {label}: {verdict}
                {scoreText(score)}
              </EuiBadge>
            </EuiToolTip>
            {link && (
              <EuiToolTip content={`Open ${label} report in a new tab`}>
                <EuiButtonIcon
                  size="s"
                  iconType="popout"
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`Open ${label} report for this indicator`}
                  data-test-subj="wamEnrichmentLinkOut"
                />
              </EuiToolTip>
            )}
          </span>
        );
      })}
      {noSource && (
        <EuiText size="xs" color="warning" data-test-subj="wamEnrichmentNoSource">
          <span>{NO_SOURCE_MESSAGE}</span>
        </EuiText>
      )}
    </span>
  );
}

interface LookupControlsProps {
  type: IndicatorType;
  value: string;
  pending: boolean;
  onLookup: (refresh: boolean) => void;
  ctiUrl: string | null;
}

/** Lookup button (refresh on a second click when a result is shown) and the 5.0 CTI Explorer link. */
export function EnrichmentLookupControls({ type, value, pending, onLookup, ctiUrl }: LookupControlsProps) {
  if (!isLookupableIndicator(type, value)) {
    const reason = isLookupType(type) ? 'Path-only URL: no host to look up' : 'This indicator type has no lookup sources';
    return (
      <EuiToolTip content={reason}>
        <EuiText size="xs" color="subdued" data-test-subj="wamEnrichmentNotLookupable">
          <span>n/a</span>
        </EuiText>
      </EuiToolTip>
    );
  }
  return (
    <EuiFlexGroup gutterSize="xs" alignItems="center" justifyContent="flexEnd" responsive={false} wrap={false} className="wamEnrichmentActions">
      <EuiFlexItem grow={false}>
        <EuiButtonEmpty
          size="xs"
          iconType="search"
          isLoading={pending}
          onClick={() => onLookup(false)}
          aria-label={`Look up ${value}`}
          data-test-subj="wamEnrichmentLookup"
        >
          Lookup
        </EuiButtonEmpty>
      </EuiFlexItem>
      <EuiFlexItem grow={false}>
        <EuiToolTip content="Bypass the cache and ask every source again">
          <EuiButtonIcon
            size="s"
            iconType="refresh"
            isDisabled={pending}
            onClick={() => onLookup(true)}
            aria-label={`Refresh lookup for ${value}`}
          />
        </EuiToolTip>
      </EuiFlexItem>
      {ctiUrl && (
        <EuiFlexItem grow={false}>
          <EuiToolTip content={`Open the Wazuh CTI Explorer and search the local catalog for ${value}`}>
            <EuiLink href={ctiUrl} target="_blank" external data-test-subj="wamEnrichmentCtiLink">
              CTI Explorer
            </EuiLink>
          </EuiToolTip>
        </EuiFlexItem>
      )}
    </EuiFlexGroup>
  );
}

interface EnrichmentPanelProps {
  indicators: LookupableIndicator[];
  /** Stored object on the alert record (null before the first lookup). */
  stored: AlertEnrichment | null | undefined;
  lookup: EnrichmentLookupFn;
  apiService: Pick<AlertsApiService, 'appUrl'>;
  emptyMessage?: string;
}

/** Alert flyout "Enrichment" tab: every indicator with native hints, stored / session verdicts and lookup controls. */
export function EnrichmentPanel({ indicators, stored, lookup, apiService, emptyMessage }: EnrichmentPanelProps) {
  const terms = useTerminology();
  // Each flyout lookup also writes the alert record: run "Lookup all" serially.
  const lookups = useEnrichmentLookups(lookup, { concurrency: 1 });
  const lookupable = indicators.filter((item) => isLookupableIndicator(item.type, item.value));
  const anyPending = Object.keys(lookups.pending).length > 0 || lookups.runningAll;

  return (
    <EuiPanel hasBorder paddingSize="m" className="wamEnrichmentPanel" data-test-subj="wamEnrichmentPanel">
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} className="wamPanelHeader">
        <EuiFlexItem>
          <EuiTitle size="xs">
            <h3>Enrichment lookups</h3>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size="s"
            iconType="search"
            isLoading={lookups.runningAll}
            isDisabled={!lookupable.length || anyPending}
            onClick={() => lookups.runAll(lookupable)}
            data-test-subj="wamEnrichmentLookupAll"
          >
            Lookup all ({lookupable.length})
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>
          {stored?.updated_at
            ? `Last updated ${formatAbsolute(stored.updated_at)} (${stored.items?.length ?? 0} stored verdict${(stored.items?.length ?? 0) === 1 ? '' : 's'}).`
            : 'No lookups stored on this record yet.'}{' '}
          Lookups run through the configured enrichment sources and are stored on the {terms.unit} record.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiBasicTable<LookupableIndicator>
        className="wamIndicatorTable wamEnrichmentTable"
        compressed
        tableLayout="auto"
        items={indicators}
        itemId={(row) => lookupKey(row.type, row.value)}
        noItemsMessage={emptyMessage || 'No indicators could be extracted from this record.'}
        columns={[
          {
            field: 'type',
            name: 'Type',
            className: INDICATOR_NARROW_CELL,
            render: (type: IndicatorType) => <EuiBadge color="hollow">{INDICATOR_TYPE_LABELS[type]}</EuiBadge>,
          },
          {
            field: 'value',
            name: 'Value',
            className: INDICATOR_VALUE_CELL,
            render: (value: string, row: LookupableIndicator) => <IndicatorValueCell value={value} fields={row.fields} tags={row.tags} />,
          },
          {
            field: 'verdictHints',
            name: 'Native verdicts',
            className: INDICATOR_BADGE_CELL,
            render: (hints: VerdictHint[]) => (hints.length ? <VerdictBadges hints={hints} /> : <EuiText size="xs" color="subdued">none</EuiText>),
          },
          {
            name: 'Lookups',
            className: INDICATOR_BADGE_CELL,
            render: (row: LookupableIndicator) => {
              const key = lookupKey(row.type, row.value);
              const error = lookups.errors[key];
              return (
                <div>
                  <EnrichmentVerdictBadges stored={enrichmentItemsFor(stored, row.type, row.value)} session={lookups.results[key]} />
                  {error && (
                    <EuiText size="xs" color="danger" data-test-subj="wamEnrichmentLookupError">
                      <span>{error}</span>
                    </EuiText>
                  )}
                </div>
              );
            },
          },
          {
            name: 'Actions',
            align: 'right',
            className: INDICATOR_ACTIONS_CELL,
            render: (row: LookupableIndicator) => (
              <EnrichmentLookupControls
                type={row.type}
                value={row.value}
                pending={Boolean(lookups.pending[lookupKey(row.type, row.value)])}
                onLookup={(refresh) => lookups.run(row.type as EnrichmentLookupType, row.value, refresh)}
                ctiUrl={ctiExplorerUrlFor(apiService, terms.wazuhMajor, row.value)}
              />
            ),
          },
        ]}
      />
    </EuiPanel>
  );
}
