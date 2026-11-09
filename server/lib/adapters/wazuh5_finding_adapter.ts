import { WAZUH5_FINDINGS_PROFILE } from '../source_profile';
import { alertUid } from '../operational_projection';
import { SEVERITY_BANDS, bandFromLabel } from '../../../common/severity';
import type { SourceAdapter, SourceQueryOptions } from './source_adapter';

/**
 * Wazuh 5.0 `wazuh-findings-v5-*` adapter (PROVISIONAL: field choices come
 * from the Beta 5 live finding plus the rc2 index template; they are
 * re-validated against live rc2 documents in Phase 1 and this header is
 * updated when that evidence lands).
 *
 * A finding is a WCS document: ECS at the root plus a `wazuh.*` namespace.
 * Observed so far:
 *   - identity: `wazuh.agent.{id,name,groups,version}`, `wazuh.agent.host.*`
 *     (Beta 5 live); the rc2 template also declares root `agent.*`, so both
 *     are read, `wazuh.agent.*` first.
 *   - rule: `wazuh.rule.{id,sigma_id,title,tags,level,compliance,mitre}`;
 *     `wazuh.rule.level` is a LABEL (`low`, `medium`, `high`, ...), never the
 *     4.x 0-16 integer. It is stored verbatim in `severity_label` and is never
 *     coerced to a number; `rule.level` stays null for 5.x records.
 *   - entities: ECS `source.ip/port`, `destination.ip/port`, `user.name`,
 *     `source.user.name`, `destination.user.name`, `process.name`.
 *   - provenance: `event.index` + `event.doc_id` name the underlying event in
 *     a `.ds-wazuh-events-*` backing index. They are stored verbatim and
 *     validated again by the profile's evidence matcher before any read.
 *   - the hit's own `_index` is the physical `.ds-wazuh-findings-v5-<cat>-N`
 *     backing index; with `_id` it forms the stable alert_uid exactly as 4.x
 *     does (sha256 of index + id).
 */

const MAX_DESCRIPTION = 1000;
const MAX_LOCATION = 1024;
const MAX_LOG_EXCERPT = 2000;
const MAX_PROVENANCE = 512;

function truncate(value: any, max: number): string | null {
  if (value == null) return null;
  const s = String(value);
  if (!s) return null;
  return s.length > max ? `${s.slice(0, max)}… [truncated]` : s;
}

function strings(value: any): string[] {
  if (value == null) return [];
  return (Array.isArray(value) ? value : [value]).map(String).filter(Boolean);
}

function scalar(value: any): string | null {
  const values = strings(value);
  return values.length ? values[0] : null;
}

function port(value: any): number | null {
  const raw = scalar(value);
  if (raw == null) return null;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 65535 ? parsed : null;
}

function obj(value: any): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function first(...values: any[]): string | null {
  for (const value of values) {
    const s = scalar(value);
    if (s != null) return s;
  }
  return null;
}

/** Numeric only when the source really is a number; a label is never coerced. */
function numericLevel(value: any): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && /^\d{1,2}$/.test(value.trim())) return Number(value.trim());
  return null;
}

/**
 * Live rc2 findings nest MITRE as `technique.{id,name}`, `subtechnique.{id,name}`
 * and `tactic.{id,name}` (arrays). The canonical 4.x shape is flat: `id` =
 * technique IDs, `technique` = technique names, `tactic` = tactic names. Both
 * shapes are accepted; sub-technique IDs/names are appended so a rule written
 * against `T1136.001` still matches.
 */
function canonicalMitre(raw: Record<string, any>): { id: any; technique: any; tactic: any } {
  const technique = raw.technique;
  const tactic = raw.tactic;
  const nested =
    (technique && typeof technique === 'object' && !Array.isArray(technique)) ||
    (tactic && typeof tactic === 'object' && !Array.isArray(tactic));
  if (!nested) return { id: raw.id, technique: raw.technique, tactic: raw.tactic };
  const sub = obj(raw.subtechnique);
  return {
    id: [...strings(obj(technique).id), ...strings(sub.id)],
    technique: [...strings(obj(technique).name), ...strings(sub.name)],
    tactic: strings(obj(tactic).name),
  };
}

function severityLabel(value: any): string | null {
  if (value == null) return null;
  if (typeof value === 'number') return null;
  const s = String(value).trim().toLowerCase();
  if (!s || /^\d{1,2}$/.test(s)) return null;
  return s.slice(0, 32);
}

export function projectFinding(hit: any, now = new Date().toISOString()): any {
  const source = obj(hit?._source);
  const wazuh = obj(source.wazuh);
  const wAgent = obj(wazuh.agent);
  const rAgent = obj(source.agent);
  const wAgentHost = obj(wAgent.host);
  const wRule = obj(wazuh.rule);
  const rRule = obj(source.rule);
  const mitre = canonicalMitre(obj(wRule.mitre).technique != null || obj(wRule.mitre).id != null ? obj(wRule.mitre) : obj(rRule.mitre));
  const src = obj(source.source);
  const dst = obj(source.destination);
  const user = obj(source.user);
  const process = obj(source.process);
  const event = obj(source.event);
  const integration = obj(wazuh.integration);
  const cluster = obj(wazuh.cluster);
  const protocol = obj(wazuh.protocol);
  const sourceIndex = String(hit?._index || '');
  const sourceId = String(hit?._id || '');

  const level = wRule.level != null ? wRule.level : rRule.level;
  const agentId = first(wAgent.id, rAgent.id);
  const agentName = first(wAgent.name, rAgent.name, wAgentHost.hostname, obj(source.host).hostname);
  const agentIp = first(wAgentHost.ip, rAgent.ip, obj(source.host).ip);
  const ruleId = first(wRule.id, wRule.sigma_id, rRule.id, rRule.uuid);
  const ruleTitle = first(wRule.title, wRule.name, rRule.name, rRule.description, wRule.description);
  const tags = strings(wRule.tags).length ? strings(wRule.tags) : strings(rRule.tags ?? source.tags);
  const hasAgent = agentId != null || agentName != null;
  const hasRule = ruleId != null || ruleTitle != null;

  return {
    alert_uid: alertUid(sourceIndex, sourceId),
    source_index: sourceIndex,
    source_id: sourceId,
    source_resolved: Boolean(sourceIndex && sourceId),
    source_family: WAZUH5_FINDINGS_PROFILE.family,
    source_profile_version: WAZUH5_FINDINGS_PROFILE.profileVersion,
    '@timestamp': source['@timestamp'],
    ingested_at: now,
    state_version: 1,
    status: 'open',
    case_id: null,
    assigned_to: null,
    related_alert_ids: [],
    agent: hasAgent ? { id: agentId, name: agentName, ip: agentIp } : null,
    manager: cluster.node != null || cluster.name != null ? { name: first(cluster.node, cluster.name) } : null,
    rule: hasRule
      ? {
          id: ruleId,
          level: numericLevel(level),
          description: truncate(ruleTitle, MAX_DESCRIPTION),
          groups: tags,
          mitre:
            mitre.id != null || mitre.technique != null || mitre.tactic != null
              ? { id: strings(mitre.id), technique: strings(mitre.technique), tactic: strings(mitre.tactic) }
              : null,
        }
      : null,
    severity_label: severityLabel(level),
    data: {
      srcip: scalar(src.ip),
      dstip: scalar(dst.ip),
      srcport: port(src.port),
      dstport: port(dst.port),
      srcuser: first(obj(src.user).name, user.name),
      dstuser: scalar(obj(dst.user).name),
      process: scalar(process.name) ? { name: scalar(process.name) } : null,
    },
    decoder: integration.name != null ? { name: scalar(integration.name) } : null,
    location: truncate(first(protocol.location, obj(source.log).file && obj(obj(source.log).file).path), MAX_LOCATION),
    full_log_excerpt: truncate(first(event.original, source.message), MAX_LOG_EXCERPT),
    event_index: truncate(scalar(event.index), MAX_PROVENANCE),
    event_doc_id: truncate(scalar(event.doc_id), MAX_PROVENANCE),
    space: scalar(obj(wazuh.space).name),
  };
}

export const WAZUH5_FINDING_ADAPTER: SourceAdapter = Object.freeze({
  profile: WAZUH5_FINDINGS_PROFILE,
  // 5.0 severity is a label; a numeric floor has no meaning here and is
  // ignored rather than translated.
  supportsNumericLevelFilter: false,
  buildQuery(options: SourceQueryOptions): any {
    const must: any[] = [{ range: { '@timestamp': { gte: options.windowFrom, lte: options.windowTo } } }];
    // A label floor is applied at the source as the set of labels at or above
    // it (the 5.0 counterpart of the 4.x numeric floor). Labels are matched
    // in the case Wazuh writes them (lower case, as observed on rc2).
    const floor = bandFromLabel(options.minSeverityLabel);
    if (floor) {
      const labels = SEVERITY_BANDS.filter((band) => SEVERITY_BANDS.indexOf(band) >= SEVERITY_BANDS.indexOf(floor));
      must.push({ terms: { 'wazuh.rule.level': labels } });
    }
    return { bool: { must } };
  },
  sortSpec(): any[] {
    // Findings map @timestamp as date_nanos (live rc2: 2026-10-31T15:58:01.648289905Z).
    // A bare sort returns the epoch in NANOseconds as a long, which exceeds
    // JavaScript's safe-integer range and would silently corrupt the persisted
    // search_after cursor. OpenSearch 3.6 rejects a sort `format`, so cast the
    // key to milliseconds with numeric_type; equal-millisecond findings are
    // ordered by _doc, and search_after compares the same cast keys, so a PIT
    // walk is complete and duplicate-free (verified on rc2: 47/47 unique).
    return [
      { '@timestamp': { order: 'asc', numeric_type: 'date' } },
      { _doc: { order: 'asc' } },
    ];
  },
  project(hit: any, now?: string): any {
    return now ? projectFinding(hit, now) : projectFinding(hit);
  },
});
