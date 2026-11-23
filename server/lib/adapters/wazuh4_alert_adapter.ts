import { WAZUH4_ALERTS_PROFILE } from '../source_profile';
import { projectOperationalAlert, ProjectionContext } from '../operational_projection';
import type { SourceAdapter, SourceQueryOptions } from './source_adapter';

/**
 * Wazuh 4.x `wazuh-alerts-*` adapter. This is the v2 behaviour, unchanged:
 * the query, sort and projection are exactly what v2.0.x used, plus the two
 * additive provenance fields every canonical record now carries.
 */
export const WAZUH4_ALERT_ADAPTER: SourceAdapter = Object.freeze({
  profile: WAZUH4_ALERTS_PROFILE,
  supportsNumericLevelFilter: true,
  buildQuery(options: SourceQueryOptions): any {
    const must: any[] = [{ range: { '@timestamp': { gte: options.windowFrom, lte: options.windowTo } } }];
    if (options.minRuleLevel != null) {
      must.push({ range: { 'rule.level': { gte: options.minRuleLevel } } });
    }
    return { bool: { must } };
  },
  sortSpec(): any[] {
    // PIT freezes the shard view while _doc is the sortable, efficient
    // tie-breaker supported by the OpenSearch versions shipped by Wazuh.
    return [{ '@timestamp': { order: 'asc' } }, { _doc: { order: 'asc' } }];
  },
  project(hit: any, now?: string, context?: ProjectionContext | null): any {
    const doc = projectOperationalAlert(hit, now ?? new Date().toISOString(), context);
    doc.source_family = WAZUH4_ALERTS_PROFILE.family;
    doc.source_profile_version = WAZUH4_ALERTS_PROFILE.profileVersion;
    // 4.x severity is the numeric rule.level already carried in rule.level.
    doc.severity_label = null;
    // Step 2.6: native cases exist only on 5.0 findings; a 4.x record never
    // carries one, whatever the source document contains.
    doc.native_case = null;
    return doc;
  },
});
