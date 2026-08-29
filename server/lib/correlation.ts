import { CorrelationEntity, CorrelationRule } from '../../common';

export type RuleMatchResult =
  | { supported: true; matched: boolean }
  | { supported: false; matched: false; reason: 'all_mode_requires_burst' };

// The OpenSearch field an alert is grouped by for a given entity type. agent is
// the most reliable (agent.name is explicitly keyword-mapped); srcip/user come
// from opportunistic decoder fields, which fresh installs map to keyword via the
// dynamic_templates in mappings.ts. Callers wrap aggregations in try/catch so a
// text-mapped field on an older index degrades to "no matches" rather than error.
export function entityField(entity: CorrelationEntity): string {
  switch (entity) {
    case 'srcip':
      return 'data.srcip';
    case 'dstip':
      return 'data.dstip';
    case 'user':
      return 'data.srcuser';
    case 'dstuser':
      return 'data.dstuser';
    case 'process':
      return 'data.process.name';
    case 'agent':
    default:
      return 'agent.name';
  }
}

export function entityValueFromAlert(entity: CorrelationEntity, source: any): string | null {
  const data = source?.data && typeof source.data === 'object' ? source.data : {};
  let v: any;
  switch (entity) {
    case 'srcip':
      v = data.srcip;
      break;
    case 'dstip':
      v = data.dstip;
      break;
    case 'user':
      v = data.srcuser;
      break;
    case 'dstuser':
      v = data.dstuser;
      break;
    case 'process':
      v = data?.process?.name ?? data?.process;
      break;
    case 'agent':
    default:
      v = source?.agent?.name;
      break;
  }
  if (Array.isArray(v)) v = v[0];
  if (v == null) return null;
  const s = String(v);
  // Filter out the placeholder / super-node values Wazuh emits.
  if (!s || s === '0.0.0.0' || s === '127.0.0.1' || s === '-' || s.toLowerCase() === 'localhost') return null;
  return s;
}

/**
 * The filter clauses for a rule's match predicate. Shared by the dry-run preview
 * and the ingest-time evaluator so they can never disagree about what a rule
 * matches. Returns an array to drop into a bool query's `filter`.
 */
export function buildMatchFilters(match: CorrelationRule['match']): any[] {
  const filter: any[] = [];
  if (match.ruleGroups?.length) filter.push({ terms: { 'rule.groups': match.ruleGroups } });
  if (match.ruleIds?.length) filter.push({ terms: { 'rule.id': match.ruleIds.map(String) } });
  if (match.agentNames?.length) filter.push({ terms: { 'agent.name': match.agentNames } });
  if (match.minLevel != null) filter.push({ range: { 'rule.level': { gte: match.minLevel } } });
  return filter;
}

/** True when any populated match section uses entity/window co-occurrence. */
export function usesAllMatchMode(match: CorrelationRule['match']): boolean {
  return (
    (match.ruleIdsMode === 'all' && !!match.ruleIds?.length) ||
    (match.ruleGroupsMode === 'all' && !!match.ruleGroups?.length) ||
    (match.agentNamesMode === 'all' && !!match.agentNames?.length)
  );
}

/**
 * Evaluate the document-level portion of a rule match. `all` is window
 * co-occurrence and is therefore supported only for burst triggers. For a burst,
 * this deliberately performs the Any pre-filter; coverageRequirements performs
 * the corresponding All check over the complete entity window.
 */
export function evaluateAlertMatch(rule: CorrelationRule, source: any): RuleMatchResult {
  if (rule.trigger?.type !== 'burst' && usesAllMatchMode(rule.match)) {
    return { supported: false, matched: false, reason: 'all_mode_requires_burst' };
  }
  const m = rule.match;
  if (m.minLevel != null && !(Number(source?.rule?.level ?? 0) >= m.minLevel)) return { supported: true, matched: false };
  if (m.ruleIds?.length && !m.ruleIds.map(String).includes(String(source?.rule?.id))) {
    return { supported: true, matched: false };
  }
  if (m.agentNames?.length && !m.agentNames.includes(source?.agent?.name)) {
    return { supported: true, matched: false };
  }
  if (m.ruleGroups?.length) {
    const groups: string[] = Array.isArray(source?.rule?.groups) ? source.rule.groups : [];
    if (!m.ruleGroups.some((g) => groups.includes(g))) return { supported: true, matched: false };
  }
  return { supported: true, matched: true };
}

/** Does one already-fetched alert source satisfy a supported rule predicate? */
export function alertMatchesRule(rule: CorrelationRule, source: any): boolean {
  return evaluateAlertMatch(rule, source).matched;
}

/**
 * When a section is in 'all' mode, every listed value must be present (co-occur)
 * on the entity within the window. Returns the sets that must all be covered;
 * empty arrays mean "no coverage requirement" (the default 'any' behaviour,
 * already handled by the OR filter in buildMatchFilters).
 */
export function coverageRequirements(
  match: CorrelationRule['match']
): { ids: string[]; groups: string[]; agents: string[] } {
  return {
    ids: match.ruleIdsMode === 'all' ? (match.ruleIds || []).map(String) : [],
    groups: match.ruleGroupsMode === 'all' ? match.ruleGroups || [] : [],
    agents: match.agentNamesMode === 'all' ? match.agentNames || [] : [],
  };
}

export const correlationKey = (ruleId: string, entityValue: string) => `${ruleId}|${entityValue}`;
