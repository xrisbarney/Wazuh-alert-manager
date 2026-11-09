import { SourceFamily, WazuhSourceProfile } from '../source_profile';
import { WAZUH4_ALERT_ADAPTER } from './wazuh4_alert_adapter';
import { WAZUH5_FINDING_ADAPTER } from './wazuh5_finding_adapter';

/** Sync-time filter inputs an adapter may honour. */
export interface SourceQueryOptions {
  windowFrom: string;
  windowTo: string;
  /** 4.x numeric `rule.level` floor. Families without numeric levels ignore it. */
  minRuleLevel?: number | null;
  /** 5.0 severity-label floor (`wazuh.rule.level`). Families with numeric levels ignore it. */
  minSeverityLabel?: string | null;
}

/**
 * One adapter per source family. It builds the read query and normalizes a
 * raw hit into the bounded canonical projection consumed by everything else
 * in the plugin. Adapters never write, never accept an index from a client,
 * and never widen what the profile's matchers allow.
 */
export interface SourceAdapter {
  readonly profile: WazuhSourceProfile;
  /** `query` for the sync search (a `bool` clause). */
  buildQuery(options: SourceQueryOptions): any;
  /** Sort used with PIT + search_after. `_doc` is the tiebreaker everywhere. */
  sortSpec(): any[];
  /** Canonical bounded projection of a raw source hit. */
  project(hit: any, now?: string): any;
  /** Whether `minRuleLevel` is meaningful for this family. */
  readonly supportsNumericLevelFilter: boolean;
}

const ADAPTERS: Readonly<Record<SourceFamily, SourceAdapter>> = Object.freeze({
  wazuh4_alerts: WAZUH4_ALERT_ADAPTER,
  wazuh5_findings: WAZUH5_FINDING_ADAPTER,
});

export function sourceAdapter(family: SourceFamily): SourceAdapter {
  const adapter = ADAPTERS[family];
  if (!adapter) throw new Error(`No source adapter for family ${String(family)}`);
  return adapter;
}
