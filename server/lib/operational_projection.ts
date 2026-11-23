import crypto from 'crypto';
import {
  MAX_GEO_HINTS,
  MAX_THREAT_MATCHES,
  NATIVE_CASE_TAGS_MAX,
  NATIVE_CASE_TAG_MAX_LENGTH,
  NATIVE_CASE_TITLE_MAX_LENGTH,
  NATIVE_CASE_VALUE_MAX_LENGTH,
} from '../../common/constants';
import { GeoEntity, canonicalExecutable, isCdbIocRuleId } from '../../common/indicators';
import type { AlertAsset, AlertNativeCase, SlaPolicy } from '../../common/types';
import type { AssetMatcher } from './assets/matcher';
import { boundedGroups, boundedLabels } from './assets/matcher';
import { computeDueFields, AlertDueFields } from './reporting_fields';

const MAX_DESCRIPTION = 1000;
const MAX_LOCATION = 1024;
const MAX_LOG_EXCERPT = 2000;
const MAX_URL = 2048;
const MAX_PATH = 1024;
const MAX_DETAIL = 512;

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
  const parsed = Number(scalar(value));
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 65535 ? parsed : null;
}

function obj(value: any): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function finite(value: any): number | null {
  const n = typeof value === 'string' ? Number(value.trim()) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}

/** Trim and bound a free-text value without the truncation marker (ids/urls). */
function bounded(value: any, max: number): string | null {
  const s = scalar(value);
  return s == null ? null : s.slice(0, max);
}

// ---------------------------------------------------------------------------
// Native context ingested for indicator extraction (step 6.1). Shared by both
// adapters; every emitted field is mapped in alertStatusMapping.
// ---------------------------------------------------------------------------

export interface ProjectedThreatMatch {
  source: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  matched_field: string | null;
  detail: string | null;
  link: string | null;
  indicator: {
    id: string | null;
    name: string | null;
    type: string | null;
    provider: string | null;
    feed: string | null;
    confidence: string | null;
    tags: string[];
    software: string | null;
  };
}

export interface ProjectedThreat {
  matches: ProjectedThreatMatch[];
  total: number;
  truncated: boolean;
  /** 4.x sibling alerts: the alert id the integration enriched. */
  sibling_of: string | null;
  /** 4.x `data.integration` name when the record is an integration output. */
  integration: string | null;
}

export interface ProjectedGeoHint {
  entity: GeoEntity;
  ip: string | null;
  country_name: string | null;
  region_name: string | null;
  city_name: string | null;
  location: { lat: number; lon: number } | null;
  as: { number: number | null; organization: string | null } | null;
  provider: string;
}

type ThreatMatchInput = Omit<Partial<ProjectedThreatMatch>, 'indicator'> & {
  indicator?: { [K in keyof ProjectedThreatMatch['indicator']]?: any };
};

export function threatMatch(input: ThreatMatchInput): ProjectedThreatMatch {
  const indicator = input.indicator || {};
  const confidence = indicator.confidence;
  return {
    source: bounded(input.source, 64) || 'native',
    verdict: input.verdict || 'malicious',
    matched_field: bounded(input.matched_field, 256),
    detail: bounded(input.detail, MAX_DETAIL),
    link: bounded(input.link, MAX_URL),
    indicator: {
      id: bounded(indicator.id, 256),
      name: bounded(indicator.name, MAX_URL),
      type: bounded(indicator.type, 64),
      provider: bounded(indicator.provider, 128),
      feed: bounded(indicator.feed, 128),
      confidence: confidence == null ? null : String(confidence).slice(0, 32),
      tags: strings(indicator.tags).slice(0, 10).map((t) => t.slice(0, 64)),
      software: bounded(indicator.software, 128),
    },
  };
}

/** Bound a match list to MAX_THREAT_MATCHES and record whether it was cut. */
export function boundedThreat(
  matches: ProjectedThreatMatch[],
  extra: Partial<Pick<ProjectedThreat, 'sibling_of' | 'integration'>> = {}
): ProjectedThreat | null {
  if (!matches.length && !extra.sibling_of && !extra.integration) return null;
  return {
    matches: matches.slice(0, MAX_THREAT_MATCHES),
    total: matches.length,
    truncated: matches.length > MAX_THREAT_MATCHES,
    sibling_of: extra.sibling_of ?? null,
    integration: extra.integration ?? null,
  };
}

type GeoHintInput = Omit<Partial<ProjectedGeoHint>, 'location' | 'as'> & { location?: any; as?: any };

export function geoHint(input: GeoHintInput): ProjectedGeoHint | null {
  const loc = obj(input.location);
  const lat = finite(loc.lat);
  const lon = finite(loc.lon);
  const asn = obj(input.as);
  const asNumber = finite(asn.number);
  const asOrg = bounded(obj(asn.organization).name ?? asn.organization, 256);
  const hint: ProjectedGeoHint = {
    entity: input.entity || 'unattributed',
    ip: bounded(input.ip, 64),
    country_name: bounded(input.country_name, 128),
    region_name: bounded(input.region_name, 128),
    city_name: bounded(input.city_name, 128),
    location: lat != null && lon != null ? { lat, lon } : null,
    as: asNumber != null || asOrg ? { number: asNumber, organization: asOrg } : null,
    provider: input.provider || 'unknown',
  };
  if (!hint.country_name && !hint.region_name && !hint.city_name && !hint.location && !hint.as) return null;
  return hint;
}

export function boundedGeo(hints: Array<ProjectedGeoHint | null>): ProjectedGeoHint[] | null {
  const kept = hints.filter((h): h is ProjectedGeoHint => Boolean(h)).slice(0, MAX_GEO_HINTS);
  return kept.length ? kept : null;
}

/** 4.x VirusTotal (`data.virustotal`) / Maltiverse (`data.maltiverse`) sibling alerts and CDB IOC rules. */
export function projectThreat4x(source: any): ProjectedThreat | null {
  const data = obj(source.data);
  const integration = bounded(data.integration, 64);
  const matches: ProjectedThreatMatch[] = [];
  let siblingOf: string | null = null;

  const vt = obj(data.virustotal);
  if (integration === 'virustotal' || Object.keys(vt).length) {
    const vtSource = obj(vt.source);
    siblingOf = bounded(vtSource.alert_id, 256);
    const positives = finite(vt.positives);
    const total = finite(vt.total);
    const found = finite(vt.found);
    const malicious = finite(vt.malicious);
    const verdict: ProjectedThreatMatch['verdict'] =
      malicious === 1 || (positives != null && positives > 0)
        ? 'malicious'
        : found === 0
        ? 'unknown'
        : found === 1
        ? 'clean'
        : 'unknown';
    const detail =
      positives != null && total != null
        ? `VirusTotal ${positives}/${total} engines flagged${vtSource.file ? ` ${vtSource.file}` : ''}`
        : found === 0
        ? 'VirusTotal: hash not found'
        : vt.description != null
        ? String(vt.description)
        : 'VirusTotal lookup';
    const hashes: Array<[string, any]> = [
      ['sha1', vt.sha1 ?? vtSource.sha1],
      ['md5', vtSource.md5],
      ['sha256', vtSource.sha256],
    ];
    for (const [type, value] of hashes) {
      if (value == null) continue;
      matches.push(threatMatch({
        source: 'virustotal', verdict, detail, link: vt.permalink, matched_field: `data.virustotal.source.${type}`,
        indicator: { name: value, type, provider: 'VirusTotal' },
      }));
    }
  }

  // maltiverse.py (shipped 4.x integration, `maltiverse_alert()`) writes
  // `data.alert_id`, the raw IoC document under `data.maltiverse.source` and
  // an ECS-style `data.threat.indicator.{name,type,description,provider,
  // confidence,reference}` (+ `data.threat.software.*`). The ECS indicator
  // is the primary match; the IoC document supplies classification, feed
  // descriptions and tags, and is the fallback when the ECS block is absent.
  const mv = obj(data.maltiverse);
  const ecsThreat = obj(data.threat);
  const ecsIndicator = obj(ecsThreat.indicator);
  if (integration === 'maltiverse' || Object.keys(mv).length) {
    const ioc = obj(mv.source);
    siblingOf = siblingOf || bounded(data.alert_id ?? ioc.alert_id, 256);
    const classification = String(ioc.classification ?? mv.classification ?? '').toLowerCase();
    const verdict: ProjectedThreatMatch['verdict'] =
      classification === 'malicious'
        ? 'malicious'
        : classification === 'suspicious'
        ? 'suspicious'
        : classification === 'whitelist' || classification === 'neutral'
        ? 'clean'
        : 'unknown';
    const blacklist = Array.isArray(ioc.blacklist) ? ioc.blacklist : Array.isArray(mv.blacklist) ? mv.blacklist : [];
    const descriptions = blacklist.map((b: any) => obj(b).description).filter(Boolean).slice(0, 3).join('; ');
    const software = obj(ecsThreat.software);
    const detail =
      bounded(ecsIndicator.description, MAX_DETAIL) ||
      descriptions ||
      `Maltiverse classification: ${classification || 'unknown'}`;
    const tags = ioc.tag ?? mv.tag;
    const link = bounded(ecsIndicator.reference, MAX_URL);
    const confidence = ecsIndicator.confidence;
    const ecsType = String(ecsIndicator.type || '').toLowerCase();
    const ecsName = bounded(ecsIndicator.name ?? ecsIndicator.ip, MAX_URL);
    if (ecsName) {
      const type =
        ecsType === 'ipv4-addr' || ecsType === 'ipv6-addr' || ecsType === 'ip'
          ? 'ip'
          : ecsType === 'domain-name' || ecsType === 'hostname' || ecsType === 'domain'
          ? 'domain'
          : ecsType === 'url'
          ? 'url'
          : ecsType === 'file' || ecsType === 'sample' || ecsType === 'hash'
          ? 'hash'
          : ecsType || 'unknown';
      matches.push(threatMatch({
        source: 'maltiverse', verdict, detail, link, matched_field: 'data.threat.indicator.name',
        indicator: {
          name: ecsName, type, provider: bounded(ecsIndicator.provider, 128) || 'Maltiverse',
          confidence, tags, software: software.name,
        },
      }));
    } else {
      const candidates: Array<[string, string, any]> = [
        ['ip', 'ip_addr', ioc.ip_addr ?? mv.ip_addr],
        ['domain', 'hostname', ioc.hostname ?? mv.hostname],
        ['url', 'url', ioc.url ?? mv.url],
        ['sha256', 'sha256', ioc.sha256 ?? mv.sha256],
        ['md5', 'md5', ioc.md5 ?? mv.md5],
        ['sha1', 'sha1', ioc.sha1 ?? mv.sha1],
      ];
      for (const [type, field, value] of candidates) {
        if (value == null) continue;
        matches.push(threatMatch({
          source: 'maltiverse', verdict, detail, link, matched_field: `data.maltiverse.source.${field}`,
          indicator: { name: value, type, provider: 'Maltiverse', confidence, tags, software: software.name },
        }));
      }
    }
  }

  const rule = obj(source.rule);
  if (isCdbIocRuleId(rule.id)) {
    matches.push(threatMatch({
      source: 'cdb_ioc', verdict: 'malicious', matched_field: null,
      detail: `CDB IOC list rule ${rule.id}${rule.description ? `: ${String(rule.description).slice(0, 200)}` : ''}`,
      indicator: { id: String(rule.id), type: 'cdb_list', provider: 'Wazuh CDB' },
    }));
  }

  return boundedThreat(matches, { sibling_of: siblingOf, integration });
}

/** 4.x indexer-pipeline `GeoLocation.*` (stale database, last IP wins, unattributed). */
export function projectGeo4x(source: any): ProjectedGeoHint[] | null {
  const geo = obj(source.GeoLocation);
  if (!Object.keys(geo).length) return null;
  return boundedGeo([
    geoHint({
      entity: 'unattributed',
      country_name: geo.country_name,
      region_name: geo.region_name,
      city_name: geo.city_name,
      location: geo.location,
      provider: 'wazuh4_indexer_pipeline',
    }),
  ]);
}

// ---------------------------------------------------------------------------
// Native case projection (step 2.6, Q6). A Wazuh 5.0 finding may carry a
// `wazuh.case.*` object maintained by the native Case Management app. It is
// copied read-only onto the canonical record through this bounded allowlist,
// re-derived on every resync and reconciled by native_case_reconcile.ts when
// the case changes later (so native edits flow through), and therefore must
// NOT be in PLUGIN_OWNED_FIELDS. The plugin never writes it back.
// ---------------------------------------------------------------------------

const NATIVE_CASE_SCALARS = ['id', 'status', 'severity', 'priority', 'tlp'] as const;

/**
 * Bounded copy of a raw `wazuh.case` value. Null when the value is absent or
 * not an object, or when nothing in the allowlist survives coercion (so an
 * empty object never becomes an empty chip). Unknown keys are dropped; every
 * value is coerced to a string or a list of strings.
 */
export function boundedNativeCase(raw: unknown): AlertNativeCase | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const source = raw as Record<string, unknown>;
  const result: AlertNativeCase = {
    id: null,
    status: null,
    severity: null,
    priority: null,
    tlp: null,
    title: null,
    tags: [],
    updated_at: null,
  };
  for (const key of NATIVE_CASE_SCALARS) {
    const value = scalarText(source[key]);
    result[key] = value == null ? null : value.slice(0, NATIVE_CASE_VALUE_MAX_LENGTH);
  }
  const title = scalarText(source.title);
  result.title = title == null ? null : title.slice(0, NATIVE_CASE_TITLE_MAX_LENGTH);
  const rawTags = Array.isArray(source.tags) ? source.tags : [source.tags];
  // De-duplicated after trimming/truncation (the chip keys badges by value)
  // and before the cap, so a repeated tag never costs a slot.
  result.tags = Array.from(
    new Set(
      rawTags
        .filter(isScalar)
        .map((t) => String(t).trim().slice(0, NATIVE_CASE_TAG_MAX_LENGTH))
        .filter(Boolean)
    )
  ).slice(0, NATIVE_CASE_TAGS_MAX);
  const updatedAt = scalarText(source.updated_at);
  result.updated_at =
    updatedAt != null && Number.isFinite(Date.parse(updatedAt)) ? new Date(updatedAt).toISOString() : null;
  const populated =
    NATIVE_CASE_SCALARS.some((key) => result[key] != null) || result.title != null || result.tags.length > 0;
  return populated ? result : null;
}

function isScalar(value: unknown): value is string | number | boolean {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

/** First scalar of a value, trimmed; objects and empty strings yield null. */
function scalarText(value: unknown): string | null {
  const candidate = Array.isArray(value) ? value.find(isScalar) : value;
  if (!isScalar(candidate)) return null;
  const s = String(candidate).trim();
  return s ? s : null;
}

// ---------------------------------------------------------------------------
// Asset context (step 6.4a). Stamped on every projected record, so it is
// re-derived on every resync and must NOT be in PLUGIN_OWNED_FIELDS (that
// protection is top-level only and would freeze stale values).
// ---------------------------------------------------------------------------

/**
 * Per-batch inputs the sync job hands to the adapters. Everything is optional:
 * without a matcher the record still carries an `asset` object with
 * `criticality: null`, so the field is always present and filterable.
 */
export interface ProjectionContext {
  /** Settings-derived matcher, loaded once per sync batch. */
  assets?: AssetMatcher | null;
  /** 4.x only: cached Wazuh API agent groups keyed by agent id. */
  agentGroups?: ReadonlyMap<string, string[]> | null;
  /**
   * Stored SLA policy (step 3.2), read once per sync tick, for the due
   * timestamps stamped at first projection. Absent = the built-in targets.
   */
  slaPolicy?: SlaPolicy | null;
}

/**
 * `reporting` object of a freshly projected record: only the due timestamps
 * (step 3.2). The sync upsert seeds them when the stored document has none
 * (`REPORTING_DUE_SEED_SCRIPT`) and never touches the other reporting fields.
 */
export function projectReportingDue(doc: any, now: string, context?: ProjectionContext | null): AlertDueFields {
  return computeDueFields(doc, context?.slaPolicy ?? null, now);
}

export interface AssetProjectionInput {
  agentId: string | null;
  agentName: string | null;
  /** Groups carried by the record itself (5.0 `wazuh.agent.groups`). */
  groups?: unknown;
  /** 4.x `agent.labels` object when present. */
  labels?: unknown;
}

export function projectAsset(input: AssetProjectionInput, context?: ProjectionContext | null): AlertAsset {
  const recordGroups = boundedGroups(input.groups);
  const cached = input.agentId && context?.agentGroups ? context.agentGroups.get(input.agentId) : undefined;
  const groups = recordGroups.length ? recordGroups : boundedGroups(cached);
  const labels = boundedLabels(input.labels);
  const resolved = context?.assets ? context.assets.resolve({ agentName: input.agentName, groups, labels }) : null;
  return {
    criticality: resolved?.criticality ?? null,
    tags: resolved?.tags ? [...resolved.tags] : [],
    groups,
    labels,
    matched_id: resolved?.matchedId ?? null,
    matched_by: resolved?.matchedBy ?? null,
  };
}

export function alertUid(sourceIndex: string, sourceId: string): string {
  return crypto.createHash('sha256').update(`${sourceIndex}\u0000${sourceId}`, 'utf8').digest('hex');
}

export function legacyAlertUid(legacyId: string): string {
  return crypto.createHash('sha256').update(`legacy\u0000${legacyId}`, 'utf8').digest('hex');
}

/**
 * Fixed operational projection used for search, correlation and workflow.
 * This is intentionally separate from the AI egress projection: it stays
 * inside the deployment, but still avoids cloning arbitrary Wazuh fields.
 */
export function projectOperationalAlert(
  hit: any,
  now = new Date().toISOString(),
  context?: ProjectionContext | null
): any {
  const source = hit?._source || {};
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  const processValue = data.process;
  const processName =
    processValue && typeof processValue === 'object'
      ? scalar(processValue.name)
      : scalar(data.process_name ?? processValue);
  const sourceIndex = String(hit?._index || '');
  const sourceId = String(hit?._id || '');
  const syscheck = obj(source.syscheck);
  const winIp = bounded(obj(obj(data.win).eventdata).ipAddress, 64);
  // auditd SYSCALL records: the resolved binary path (step 9.4 indicator),
  // stored in the same canonical form extractIndicators shows (the decoder's
  // surrounding quotes on an AVC record dropped) so a term query built from
  // the displayed value hits the stored keyword.
  const auditExe = canonicalExecutable(bounded(obj(data.audit).exe, MAX_PATH));
  const agent = obj(source.agent);

  const doc: any = {
    alert_uid: alertUid(sourceIndex, sourceId),
    source_index: sourceIndex,
    source_id: sourceId,
    source_resolved: Boolean(sourceIndex && sourceId),
    '@timestamp': source['@timestamp'],
    ingested_at: now,
    state_version: 1,
    status: 'open',
    case_id: null,
    assigned_to: null,
    related_alert_ids: [],
    agent: source.agent
      ? { id: scalar(source.agent.id), name: scalar(source.agent.name), ip: scalar(source.agent.ip) }
      : null,
    manager: source.manager ? { name: scalar(source.manager.name) } : null,
    rule: source.rule
      ? {
          id: scalar(source.rule.id),
          level: Number.isFinite(Number(source.rule.level)) ? Number(source.rule.level) : 0,
          description: truncate(source.rule.description, MAX_DESCRIPTION),
          groups: strings(source.rule.groups),
          mitre: source.rule.mitre
            ? {
                id: strings(source.rule.mitre.id),
                technique: strings(source.rule.mitre.technique),
                tactic: strings(source.rule.mitre.tactic),
              }
            : null,
        }
      : null,
    data: {
      srcip: scalar(data.srcip),
      dstip: scalar(data.dstip),
      srcport: port(data.srcport),
      dstport: port(data.dstport),
      srcuser: scalar(data.srcuser),
      dstuser: scalar(data.dstuser),
      process: processName ? { name: processName } : null,
      url: bounded(data.url, MAX_URL),
      hostname: bounded(data.hostname, 253),
      win: winIp ? { eventdata: { ipAddress: winIp } } : null,
      audit: auditExe ? { exe: auditExe } : null,
    },
    syscheck:
      syscheck.md5_after != null || syscheck.sha1_after != null || syscheck.sha256_after != null
        ? {
            path: bounded(syscheck.path, MAX_PATH),
            md5_after: bounded(syscheck.md5_after, 64),
            sha1_after: bounded(syscheck.sha1_after, 64),
            sha256_after: bounded(syscheck.sha256_after, 64),
          }
        : null,
    related: null,
    threat: projectThreat4x(source),
    geo: projectGeo4x(source),
    decoder: source.decoder ? { name: scalar(source.decoder.name) } : null,
    location: truncate(source.location, MAX_LOCATION),
    full_log_excerpt: truncate(source.full_log, MAX_LOG_EXCERPT),
    // 4.x has no native case object (security-analytics is not in the 4.x
    // bundle); always null so the field exists on every record (step 2.6).
    native_case: null,
    // 4.x alerts carry no groups; they come from the sync job's cached Wazuh
    // API lookup (context.agentGroups) when wazuhCore is available.
    asset: projectAsset(
      { agentId: scalar(agent.id), agentName: scalar(agent.name), groups: agent.groups, labels: agent.labels },
      context
    ),
  };
  doc.reporting = projectReportingDue(doc, now, context);
  return doc;
}

/** Build a compact v2 document from a legacy wazuh-alert-status hit. */
export function projectLegacyOperationalAlert(
  legacyHit: any,
  resolvedSource?: { index: string; id: string } | null,
  now = new Date().toISOString(),
  context?: ProjectionContext | null
): any {
  const syntheticHit = {
    _index: resolvedSource?.index || '',
    _id: resolvedSource?.id || legacyHit._id,
    _source: legacyHit._source,
  };
  // `context.slaPolicy` makes a migrated alert's due timestamps follow the
  // stored policy instead of the built-in defaults (step 3.2).
  const projected = projectOperationalAlert(syntheticHit, now, context);
  const source = legacyHit._source || {};
  if (!resolvedSource) {
    projected.alert_uid = legacyAlertUid(legacyHit._id);
    projected.source_index = null;
    projected.source_id = legacyHit._id;
    projected.source_resolved = false;
  }
  projected.status = source.status || 'open';
  projected.case_id = source.case_id ?? null;
  projected.assigned_to = source.assigned_to ?? null;
  projected.related_alert_ids = Array.isArray(source.related_alert_ids) ? source.related_alert_ids : [];
  projected.ai_analysis = source.ai_analysis;
  projected.updated_at = source.updated_at;
  projected.updated_by = source.updated_by;
  return projected;
}
