import crypto from 'crypto';

const MAX_DESCRIPTION = 1000;
const MAX_LOCATION = 1024;
const MAX_LOG_EXCERPT = 2000;

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
export function projectOperationalAlert(hit: any, now = new Date().toISOString()): any {
  const source = hit?._source || {};
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  const processValue = data.process;
  const processName =
    processValue && typeof processValue === 'object'
      ? scalar(processValue.name)
      : scalar(data.process_name ?? processValue);
  const sourceIndex = String(hit?._index || '');
  const sourceId = String(hit?._id || '');

  return {
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
    },
    decoder: source.decoder ? { name: scalar(source.decoder.name) } : null,
    location: truncate(source.location, MAX_LOCATION),
    full_log_excerpt: truncate(source.full_log, MAX_LOG_EXCERPT),
  };
}

/** Build a compact v2 document from a legacy wazuh-alert-status hit. */
export function projectLegacyOperationalAlert(
  legacyHit: any,
  resolvedSource?: { index: string; id: string } | null,
  now = new Date().toISOString()
): any {
  const syntheticHit = {
    _index: resolvedSource?.index || '',
    _id: resolvedSource?.id || legacyHit._id,
    _source: legacyHit._source,
  };
  const projected = projectOperationalAlert(syntheticHit, now);
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
