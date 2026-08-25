// The network boundary for anything that leaves this deployment to a third
// party (currently only the AI providers). NOTHING may cross that boundary
// except the branded projection types produced here.
//
// Why branded: our alert index is `dynamic: true`, so an alert `_source` is an
// open-ended set of fields - full_log, command lines, and any credential that
// happened to land in a log line all live in it. The original AI feature sent
// the entire `_source` (and every linked alert's `_source` plus 200 comment
// bodies) to the provider. To make that class of mistake a COMPILE error, the
// only values `generateAiAnalysis` accepts are `ProjectedAlert` / `ProjectedCase`,
// and the only way to obtain one is the projection functions below - which copy
// a fixed allowlist of fields and truncate free text. The brand is a
// compile-time-only unique symbol (no runtime property, so JSON.stringify never
// serialises it), so external code cannot fabricate one without an `as any`
// cast, which the security gate greps for.

declare const projectedAlertBrand: unique symbol;
declare const projectedCaseBrand: unique symbol;

export interface ProjectedAlert {
  readonly [projectedAlertBrand]: true;
  timestamp: string | null;
  rule_id: string | null;
  rule_level: number | null;
  rule_description: string | null;
  rule_groups: string[];
  agent_name: string | null;
  agent_ip: string | null;
  decoder: string | null;
  location: string | null;
  log_excerpt: string | null;
}

export interface ProjectedCase {
  readonly [projectedCaseBrand]: true;
  case_title: string | null;
  case_severity: string | null;
  case_status: string | null;
  case_description_excerpt: string | null;
  linked_alerts: ProjectedAlert[];
  linked_alert_count: number;
  comment_count: number;
  note: string;
}

// Caps. full_log is the alert's primary human-readable content and is genuinely
// useful for triage analysis, so it is included but truncated - a credential
// pasted into a log line is still a risk, so the excerpt is deliberately short
// and everything else (raw data.*, syscheck.*, previous_output) is excluded.
const MAX_LOG_EXCERPT = 1500;
const MAX_DESCRIPTION = 3000;
const MAX_ALERTS_PER_CASE = 50;

function str(v: any): string | null {
  if (v == null) return null;
  const s = String(v);
  return s.length ? s : null;
}

function truncate(v: any, max: number): string | null {
  const s = str(v);
  if (s == null) return null;
  return s.length > max ? `${s.slice(0, max)}… [truncated]` : s;
}

function asStringArray(v: any): string[] {
  if (v == null) return [];
  return (Array.isArray(v) ? v : [v]).map((x) => String(x)).filter(Boolean);
}

/** Allowlist-projects one alert `_source` into the only shape allowed to leave the network. */
export function projectAlert(source: any): ProjectedAlert {
  const s = source || {};
  const data = s.data && typeof s.data === 'object' ? s.data : {};
  return {
    timestamp: str(s['@timestamp']),
    rule_id: str(s.rule?.id),
    rule_level: typeof s.rule?.level === 'number' ? s.rule.level : null,
    rule_description: truncate(s.rule?.description, 500),
    rule_groups: asStringArray(s.rule?.groups),
    agent_name: str(s.agent?.name),
    agent_ip: str(s.agent?.ip),
    decoder: str(s.decoder?.name ?? data.decoder),
    location: truncate(s.location, 300),
    log_excerpt: truncate(s.full_log, MAX_LOG_EXCERPT),
  } as ProjectedAlert;
}

/**
 * Projects a case plus its linked alerts. Comment BODIES are deliberately never
 * included - comment threads are exactly where analysts paste credentials and
 * internal detail - only a count crosses the boundary. Linked alerts are capped.
 */
export function projectCase(
  caseDoc: any,
  alertSources: any[],
  totalLinkedAlerts: number,
  commentCount: number
): ProjectedCase {
  const capped = alertSources.slice(0, MAX_ALERTS_PER_CASE);
  const truncatedNote =
    totalLinkedAlerts > capped.length
      ? `Showing ${capped.length} of ${totalLinkedAlerts} linked alerts. Comment bodies are withheld for privacy; ${commentCount} exist.`
      : `Comment bodies are withheld for privacy; ${commentCount} exist.`;
  return {
    case_title: truncate(caseDoc?.title, 500),
    case_severity: str(caseDoc?.severity),
    case_status: str(caseDoc?.status),
    case_description_excerpt: truncate(caseDoc?.description, MAX_DESCRIPTION),
    linked_alerts: capped.map(projectAlert),
    linked_alert_count: totalLinkedAlerts,
    comment_count: commentCount,
    note: truncatedNote,
  } as ProjectedCase;
}
