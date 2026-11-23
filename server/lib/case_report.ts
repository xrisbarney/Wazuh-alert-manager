import {
  ACTIVITY_READ_ALIAS,
  ATTACHMENTS_INDEX,
  CASE_REPORT_LISTED_ALERTS,
  CASE_REPORT_TIMELINE_LIMIT,
  CASE_TIMELINE_ALERTS_MAX,
  ENRICHMENT_VERDICTS,
  MAX_CASE_REPORT_ALERTS,
} from '../../common';
import { AlertEnrichmentItem, CaseTimelineEntry as TimelineEntry, EnrichmentVerdict } from '../../common/types';
import { CaseIndicator, aggregateIndicators } from '../../common/indicators';
import { AttackGraph, buildAttackGraph } from './attack_graph';
import { AttackGraphLayoutDropped, layoutAttackGraph, renderAttackGraphSvg } from './attack_graph_svg';
import { ResolvedCaseDocument, resolveCase } from './case_index_resolution';
import { CASE_TIMELINE_LIMIT_MAX, collectCaseTimeline as collectCaseTimelinePage } from './case_timeline';
import { collectCaseEvidence } from './evidence';
import { ResolvedCaseAlert, resolveCaseAlerts } from './index_resolution';

/**
 * Case report (PLAN.md step 5.2): one read-only pass over a case and
 * everything linked to it, rendered to GitHub-flavoured Markdown or a
 * self-contained printable HTML document. Nothing here writes.
 */

export type CaseReportFormat = 'markdown' | 'html';

export interface CaseReportAlert {
  id: string;
  timestamp: string | null;
  status: string | null;
  assignee: string | null;
  ruleId: string | null;
  ruleDescription: string | null;
  /** 4.x numeric level; null for 5.0 findings. */
  level: number | null;
  /** 5.0 label severity kept verbatim; null on 4.x. */
  severityLabel: string | null;
  agentName: string | null;
  agentId: string | null;
  srcip: string | null;
  dstip: string | null;
  availability: ResolvedCaseAlert['availability'];
}

export interface CaseReportTask {
  id: string | null;
  title: string;
  owner: string | null;
  dueAt: string | null;
  done: boolean;
  doneBy: string | null;
  doneAt: string | null;
}

export type CaseTimelineKind = 'alert' | 'comment' | 'audit' | 'task';

export interface CaseTimelineEntry {
  timestamp: string;
  kind: CaseTimelineKind;
  /** Alert id, comment id or audit event id. */
  refId: string | null;
  actor: string | null;
  summary: string;
}

export interface CaseTimelineResult {
  entries: CaseTimelineEntry[];
  limit: number;
  truncated: boolean;
}

export interface CaseReportEnrichmentRow extends AlertEnrichmentItem {
  /** Alerts carrying this (source, type, value) verdict. */
  alertCount: number;
}

export interface CaseReportAttachment {
  id: string;
  kind: string | null;
  name: string;
  url: string | null;
  contentType: string | null;
  size: number | null;
  sha256: string | null;
  createdBy: string | null;
  createdAt: string | null;
}

export interface CaseReportComment {
  id: string | null;
  author: string | null;
  createdAt: string | null;
  text: string;
}

export interface CaseReportMitreRow {
  tactic: string;
  techniqueId: string;
  technique: string;
  alertCount: number;
}

export interface CaseReportData {
  generatedAt: string;
  case: {
    id: string;
    uid: string | null;
    title: string;
    status: string | null;
    severity: string | null;
    assignee: string | null;
    createdBy: string | null;
    createdAt: string | null;
    updatedAt: string | null;
    closedAt: string | null;
    description: string | null;
    disposition: string | null;
    closureReason: string | null;
  };
  tasks: CaseReportTask[] | null;
  timeline: CaseTimelineResult;
  alerts: {
    /** Every resolved alert (up to `CASE_REPORT_LISTED_ALERTS`, which equals the evidence cap), oldest first. */
    listed: CaseReportAlert[];
    /** Alerts resolved for the aggregations (indicators, graph, MITRE). */
    included: number;
    /** Evidence relationships paged (before the cap). */
    totalRelationships: number;
    /** True when the case links more alerts than `MAX_CASE_REPORT_ALERTS`. */
    truncated: boolean;
    limit: number;
    listedLimit: number;
  };
  indicators: CaseIndicator[];
  enrichment: CaseReportEnrichmentRow[];
  attachments: { items: CaseReportAttachment[]; available: boolean };
  comments: { items: CaseReportComment[]; truncated: boolean };
  graph: AttackGraph;
  graphSvg: string;
  /** Nodes left out of the drawing because a layer exceeded `maxNodesPerLayer` (the graph itself is complete). */
  graphDropped: AttackGraphLayoutDropped[];
  mitre: CaseReportMitreRow[];
}

export interface CaseReportRenderOptions {
  /** HTML only: embed the inline `window.print()` trigger. */
  print?: boolean;
  /** HTML only: CSP nonce stamped on the inline script so the route can forbid every other script. */
  nonce?: string;
}

/** Hard cap on comments rendered in the report. */
export const CASE_REPORT_COMMENT_LIMIT = 500;
/** Attachment rows read for the report. */
export const CASE_REPORT_ATTACHMENT_LIMIT = 100;
/** Bytes of one comment or description shown before truncation. */
const TEXT_LIMIT = 20000;

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/** Escape for an HTML text node or double-quoted attribute value. */
export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Make a value safe inside a GitHub-flavoured Markdown table cell: pipes are
 * escaped, line breaks collapse to `<br>` (GFM renders it) and raw HTML
 * angle brackets are neutralised so a comment cannot inject markup.
 */
export function escapeMarkdownCell(value: unknown): string {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r\n|\r|\n/g, '<br>');
}

/** Inline Markdown text (headings, paragraphs): neutralise HTML and leading markup characters. */
export function escapeMarkdownText(value: unknown): string {
  return String(value ?? '')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/^([#>\-+*]|\d+\.)(\s)/gm, '\\$1$2');
}

function text(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null;
}

function clampText(value: string | null): string | null {
  if (value == null) return null;
  return value.length > TEXT_LIMIT ? `${value.slice(0, TEXT_LIMIT)}… [truncated]` : value;
}

function asArray<T>(v: T | T[] | null | undefined): T[] {
  if (v == null) return [];
  return Array.isArray(v) ? v.filter((x) => x != null) : [v];
}

function enrichmentVerdict(value: unknown): EnrichmentVerdict {
  return (ENRICHMENT_VERDICTS as readonly string[]).includes(String(value)) ? (value as EnrichmentVerdict) : 'unknown';
}

/** Stored lookup fields are untrusted index data: coerce every one to its declared shape. */
function normaliseEnrichmentItem(item: any): Pick<AlertEnrichmentItem, 'verdict' | 'score' | 'tags' | 'link' | 'checked_at'> {
  return {
    verdict: enrichmentVerdict(item.verdict),
    score: typeof item.score === 'number' && Number.isFinite(item.score) ? item.score : null,
    tags: asArray<unknown>(item.tags).map(String),
    link: typeof item.link === 'string' ? item.link : null,
    checked_at: String(item.checked_at ?? ''),
  };
}

function numberOrNull(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return null;
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

export function projectReportAlert(item: { id: string; source: any; availability: ResolvedCaseAlert['availability'] }): CaseReportAlert {
  const s = item.source || {};
  const data = s.data && typeof s.data === 'object' ? s.data : {};
  return {
    id: item.id,
    timestamp: text(s['@timestamp']),
    status: text(s.status),
    assignee: text(s.assigned_to),
    ruleId: text(s.rule?.id),
    ruleDescription: text(s.rule?.description),
    level: numberOrNull(s.rule?.level),
    severityLabel: text(s.severity_label),
    agentName: text(s.agent?.name),
    agentId: text(s.agent?.id),
    srcip: text(asArray<any>(data.srcip)[0]),
    dstip: text(asArray<any>(data.dstip)[0]),
    availability: item.availability,
  };
}

export function projectTasks(raw: unknown): CaseReportTask[] | null {
  if (!Array.isArray(raw)) return null;
  const tasks: Array<{ order: number; index: number; task: CaseReportTask }> = [];
  raw.forEach((task, index) => {
    if (!task || typeof task !== 'object') return;
    tasks.push({
      order: numberOrNull((task as any).order) ?? index,
      index,
      task: {
        id: text((task as any).id),
        title: text((task as any).title) || '(untitled task)',
        owner: text((task as any).owner),
        dueAt: text((task as any).due_at),
        done: Boolean((task as any).done),
        doneBy: text((task as any).done_by),
        doneAt: text((task as any).done_at),
      },
    });
  });
  tasks.sort((a, b) => a.order - b.order || a.index - b.index);
  return tasks.map((item) => item.task);
}

/** Aggregate stored lookup verdicts (`enrichment.items`) across the alerts: one row per (source, type, value), newest wins. */
export function collectEnrichmentRows(alerts: Array<{ _id: string; _source: any }>): CaseReportEnrichmentRow[] {
  const rows = new Map<string, CaseReportEnrichmentRow & { seen: Set<string> }>();
  for (const alert of alerts) {
    const items = alert?._source?.enrichment?.items;
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      if (!item || typeof item !== 'object' || typeof item.value !== 'string') continue;
      const key = `${item.source}\u0000${item.type}\u0000${item.value}`;
      const existing = rows.get(key);
      if (existing) {
        if (!existing.seen.has(alert._id)) {
          existing.seen.add(alert._id);
          existing.alertCount += 1;
        }
        if (String(item.checked_at || '') > String(existing.checked_at || '')) {
          Object.assign(existing, normaliseEnrichmentItem(item));
        }
      } else {
        rows.set(key, {
          type: item.type,
          value: item.value,
          source: String(item.source ?? ''),
          ...normaliseEnrichmentItem(item),
          alertCount: 1,
          seen: new Set([alert._id]),
        });
      }
    }
  }
  const order: Record<string, number> = { malicious: 0, suspicious: 1, clean: 2, unknown: 3 };
  return Array.from(rows.values())
    .map(({ seen, ...row }) => row)
    .sort((a, b) => {
      const oa = order[a.verdict] ?? 9;
      const ob = order[b.verdict] ?? 9;
      if (oa !== ob) return oa - ob;
      return a.value.localeCompare(b.value) || a.source.localeCompare(b.source);
    });
}

/** Tactic x technique rows with the number of alerts that carry the pair, in kill-chain order of the graph. */
export function collectMitreRows(alerts: Array<{ _id: string; _source: any }>, graph: AttackGraph): CaseReportMitreRow[] {
  const rows = new Map<string, CaseReportMitreRow>();
  for (const alert of alerts) {
    const mitre = alert?._source?.rule?.mitre;
    if (!mitre || typeof mitre !== 'object') continue;
    const ids = asArray<any>(mitre.id).map(String);
    const names = asArray<any>(mitre.technique).map(String);
    const tactics = asArray<any>(mitre.tactic).map(String).filter(Boolean);
    const techniques = ids.length ? ids.map((id, i) => ({ id, name: names[i] || id })) : names.map((name) => ({ id: '', name }));
    if (!techniques.length && !tactics.length) continue;
    const tacticList = tactics.length ? tactics : ['(no tactic)'];
    const techniqueList = techniques.length ? techniques : [{ id: '', name: '(no technique)' }];
    for (const tactic of tacticList) {
      for (const technique of techniqueList) {
        const key = `${tactic}\u0000${technique.id}\u0000${technique.name}`;
        const existing = rows.get(key);
        if (existing) existing.alertCount += 1;
        else rows.set(key, { tactic, techniqueId: technique.id, technique: technique.name, alertCount: 1 });
      }
    }
  }
  const tacticOrder = new Map(graph.killChain.map((phase, index) => [phase.tactic, index]));
  return Array.from(rows.values()).sort((a, b) => {
    const oa = tacticOrder.get(a.tactic) ?? Number.MAX_SAFE_INTEGER;
    const ob = tacticOrder.get(b.tactic) ?? Number.MAX_SAFE_INTEGER;
    if (oa !== ob) return oa - ob;
    if (a.tactic !== b.tactic) return a.tactic.localeCompare(b.tactic);
    if (b.alertCount !== a.alertCount) return b.alertCount - a.alertCount;
    return a.techniqueId.localeCompare(b.techniqueId) || a.technique.localeCompare(b.technique);
  });
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

function isNotFound(error: any): boolean {
  const status = error?.meta?.statusCode ?? error?.statusCode;
  return status === 404 || error?.meta?.body?.error?.type === 'index_not_found_exception';
}

function describeAlert(alert: CaseReportAlert): string {
  const parts = [alert.ruleId ? `rule ${alert.ruleId}` : null, alert.ruleDescription, alert.agentName ? `on ${alert.agentName}` : null].filter(Boolean);
  return parts.length ? `Alert ${alert.id}: ${parts.join(' — ')}` : `Alert ${alert.id}`;
}

export interface CollectCaseTimelineOptions {
  limit?: number;
  /** Already-resolved alerts of the case (and whether their evidence walk was cut); paged and resolved here when omitted. */
  alerts?: { items: ResolvedCaseAlert[]; truncated: boolean };
  /** Already-resolved case document; resolved here when omitted. */
  caseDoc?: ResolvedCaseDocument;
}

/**
 * The report's timeline section, read through the step 2.3 timeline module
 * (`server/lib/case_timeline.ts`): at most two pages of `ceil(limit / 2)`
 * entries each (default `CASE_REPORT_TIMELINE_LIMIT` = 500), so the cap is
 * honoured by paging rather than by loading everything; a remaining cursor
 * after the second page is reported as `truncated`. Alert summaries are
 * worded from the report's own projection so the section reads as before.
 */
export async function collectCaseTimeline(
  client: any,
  caseId: string,
  options: CollectCaseTimelineOptions = {}
): Promise<CaseTimelineResult> {
  const limit = Math.max(1, Math.min(options.limit ?? CASE_REPORT_TIMELINE_LIMIT, 2 * CASE_TIMELINE_LIMIT_MAX));
  const pageSize = Math.min(CASE_TIMELINE_LIMIT_MAX, Math.ceil(limit / 2));
  const caseDoc = options.caseDoc ?? (await resolveCase(client, caseId));
  let alerts = options.alerts;
  if (!alerts) {
    const { evidence, truncated } = await collectCaseEvidence(client, caseDoc.id, caseDoc.source?.alert_ids, { limit: CASE_TIMELINE_ALERTS_MAX });
    const locations = evidence.length ? await resolveCaseAlerts(client, evidence) : new Map<string, ResolvedCaseAlert>();
    alerts = { items: Array.from(locations.values()), truncated };
  }
  const byAlertId = new Map<string, CaseReportAlert>();
  for (const item of alerts.items) byAlertId.set(item.id, projectReportAlert(item));

  const entries: CaseTimelineEntry[] = [];
  let cursor: string | null = null;
  let truncated = alerts.truncated;
  for (let page = 0; page < 2; page += 1) {
    const result = await collectCaseTimelinePage(client, caseDoc.id, { cursor, limit: pageSize, caseDoc, alerts });
    for (const entry of result.entries) {
      if (entries.length >= limit) {
        truncated = true;
        break;
      }
      entries.push(projectTimelineEntry(entry, byAlertId));
    }
    cursor = result.next_cursor;
    if (!cursor || entries.length >= limit) break;
  }
  if (cursor) truncated = true;
  return { entries, limit, truncated };
}

function projectTimelineEntry(entry: TimelineEntry, alerts: Map<string, CaseReportAlert>): CaseTimelineEntry {
  if (entry.kind === 'alert') {
    const alertId = entry.ref.alert_id || '';
    const alert = alerts.get(alertId);
    return { timestamp: entry.at, kind: 'alert', refId: alertId || null, actor: null, summary: alert ? describeAlert(alert) : entry.title };
  }
  if (entry.kind === 'comment') {
    return { timestamp: entry.at, kind: 'comment', refId: entry.ref.activity_id || null, actor: entry.actor ?? null, summary: entry.details || '' };
  }
  if (entry.kind === 'task_due') {
    return { timestamp: entry.at, kind: 'task', refId: entry.ref.task_id || null, actor: entry.actor ?? null, summary: entry.title };
  }
  return { timestamp: entry.at, kind: 'audit', refId: entry.ref.activity_id || null, actor: entry.actor ?? null, summary: entry.title };
}

/** Attachments of the case; the index may not exist before step 5.3 (404 is "no attachments"). */
export async function readCaseAttachments(client: any, caseId: string): Promise<{ items: CaseReportAttachment[]; available: boolean }> {
  try {
    const result: any = await client.search({
      index: ATTACHMENTS_INDEX,
      body: {
        size: CASE_REPORT_ATTACHMENT_LIMIT,
        track_total_hits: false,
        sort: [{ created_at: { order: 'asc' } }],
        query: { bool: { filter: [{ term: { case_id: caseId } }] } },
        _source: { excludes: ['data'] },
      },
    });
    const hits: any[] = result?.body?.hits?.hits || [];
    return {
      available: true,
      items: hits.map((hit) => {
        const s = hit._source || {};
        return {
          id: String(hit._id || ''),
          kind: text(s.kind),
          name: text(s.name) || '(unnamed)',
          url: text(s.url),
          contentType: text(s.content_type),
          size: numberOrNull(s.size),
          sha256: text(s.sha256),
          createdBy: text(s.created_by),
          createdAt: text(s.created_at),
        };
      }),
    };
  } catch (error: any) {
    if (isNotFound(error)) return { items: [], available: false };
    throw error;
  }
}

async function readCaseComments(client: any, caseId: string): Promise<{ items: CaseReportComment[]; truncated: boolean }> {
  const result: any = await client.search({
    index: ACTIVITY_READ_ALIAS,
    body: {
      size: CASE_REPORT_COMMENT_LIMIT + 1,
      track_total_hits: false,
      sort: [{ created_at: { order: 'asc' } }, { _doc: { order: 'asc' } }],
      query: { bool: { filter: [{ term: { event_type: 'comment' } }, { term: { case_id: caseId } }] } },
    },
  });
  const hits: any[] = result?.body?.hits?.hits || [];
  return {
    truncated: hits.length > CASE_REPORT_COMMENT_LIMIT,
    items: hits.slice(0, CASE_REPORT_COMMENT_LIMIT).map((hit) => ({
      id: text(hit._id),
      author: text(hit._source?.author) || text(hit._source?.user),
      createdAt: text(hit._source?.created_at),
      text: clampText(text(hit._source?.text)) || '',
    })),
  };
}

/**
 * Read everything the report shows. Evidence is paged once (cap
 * `MAX_CASE_REPORT_ALERTS`) and resolved once; the indicator, enrichment,
 * graph and MITRE sections all derive from those resolved records, exactly
 * as `GET /cases/{id}/indicators` and `/attack-path` compute them.
 */
export async function collectCaseReportData(client: any, caseId: string, now: Date = new Date()): Promise<CaseReportData> {
  const caseRes = await resolveCase(client, caseId);
  const source = caseRes.source || {};
  const { evidence, truncated } = await collectCaseEvidence(client, caseId, source.alert_ids, { limit: MAX_CASE_REPORT_ALERTS });
  const locations = evidence.length ? await resolveCaseAlerts(client, evidence) : new Map<string, ResolvedCaseAlert>();
  const resolved = Array.from(locations.values());
  const withSource = resolved.filter((item) => item.source).map((item) => ({ _id: item.id, _source: item.source }));
  const projected = resolved.map(projectReportAlert).sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')) || a.id.localeCompare(b.id));
  const graph = buildAttackGraph(withSource);
  const graphLayout = layoutAttackGraph(graph);
  const [timeline, attachments, comments] = await Promise.all([
    collectCaseTimeline(client, caseId, { caseDoc: caseRes, alerts: { items: resolved, truncated }, limit: CASE_REPORT_TIMELINE_LIMIT }),
    readCaseAttachments(client, caseId),
    readCaseComments(client, caseId),
  ]);
  return {
    generatedAt: now.toISOString(),
    case: {
      id: caseRes.id,
      uid: text(source.case_uid),
      title: text(source.title) || '(untitled case)',
      status: text(source.status),
      severity: text(source.severity),
      assignee: text(source.assigned_to),
      createdBy: text(source.created_by),
      createdAt: text(source.created_at),
      updatedAt: text(source.updated_at),
      closedAt: text(source.closed_at),
      description: clampText(text(source.description)),
      disposition: text(source.disposition),
      closureReason: clampText(text(source.closure_reason)),
    },
    tasks: projectTasks(source.tasks),
    timeline,
    alerts: {
      listed: projected.slice(0, CASE_REPORT_LISTED_ALERTS),
      included: withSource.length,
      totalRelationships: evidence.length,
      truncated,
      limit: MAX_CASE_REPORT_ALERTS,
      listedLimit: CASE_REPORT_LISTED_ALERTS,
    },
    indicators: aggregateIndicators(withSource),
    enrichment: collectEnrichmentRows(withSource),
    attachments,
    comments,
    graph,
    graphSvg: renderAttackGraphSvg(graph),
    graphDropped: graphLayout.dropped,
    mitre: collectMitreRows(withSource, graph),
  };
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

function severityText(alert: CaseReportAlert): string {
  if (alert.level != null) return String(alert.level);
  return alert.severityLabel || '';
}

function formatSize(size: number | null): string {
  if (size == null) return '';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`;
}

function graphDroppedText(dropped: AttackGraphLayoutDropped[]): string {
  const parts = dropped.map((d) => `${d.count} more ${d.count === 1 ? d.type : `${d.type}s`}`);
  return `The drawing shows the entities with the most alerts per layer; ${parts.join(', ')} not drawn.`;
}

function verdictHintsText(indicator: CaseIndicator): string {
  const hints = (indicator.verdictHints || []).map((hint) => `${hint.source}: ${hint.verdict}`);
  const stored = (indicator.enrichment || []).map((item) => `${item.source}: ${item.verdict}`);
  return Array.from(new Set([...stored, ...hints])).join(', ');
}

/** `wam-case-<id>-<YYYY-MM-DD>.<md|html>`; the id is sanitised again by `downloadResponse`. */
export function caseReportFilename(caseId: string, format: CaseReportFormat, now: Date = new Date()): string {
  const safeId = String(caseId || 'case').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 64);
  return `wam-case-${safeId}-${now.toISOString().slice(0, 10)}.${format === 'markdown' ? 'md' : 'html'}`;
}

export function caseReportContentType(format: CaseReportFormat): string {
  return format === 'markdown' ? 'text/markdown; charset=utf-8' : 'text/html; charset=utf-8';
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

function mdTable(headers: string[], rows: unknown[][]): string {
  const head = `| ${headers.map(escapeMarkdownCell).join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((row) => `| ${row.map(escapeMarkdownCell).join(' | ')} |`);
  return [head, sep, ...body].join('\n');
}

function mdValue(value: unknown): string {
  return escapeMarkdownText(value == null || value === '' ? '—' : value);
}

export function renderCaseReportMarkdown(data: CaseReportData): string {
  const c = data.case;
  const out: string[] = [];
  out.push(`# Case report: ${escapeMarkdownText(c.title)}`);
  out.push('');
  out.push(`Generated ${data.generatedAt} by Wazuh Alert Manager.`);
  out.push('');
  out.push('## Summary');
  out.push('');
  out.push(
    mdTable(
      ['Field', 'Value'],
      [
        ['Case id', c.id],
        ['Status', c.status ?? ''],
        ['Severity', c.severity ?? ''],
        ['Assignee', c.assignee ?? '(unassigned)'],
        ['Created', c.createdAt ? `${c.createdAt}${c.createdBy ? ` by ${c.createdBy}` : ''}` : ''],
        ['Updated', c.updatedAt ?? ''],
        ['Closed', c.closedAt ?? ''],
        ['Linked alerts', `${data.alerts.totalRelationships}${data.alerts.truncated ? `+ (report capped at ${data.alerts.limit})` : ''}`],
      ]
    )
  );
  out.push('');
  if (c.description) {
    out.push('### Description');
    out.push('');
    out.push(escapeMarkdownText(c.description));
    out.push('');
  }
  if (c.disposition || c.closureReason) {
    out.push('## Disposition');
    out.push('');
    if (c.disposition) out.push(`- Disposition: ${mdValue(c.disposition)}`);
    if (c.closureReason) out.push(`- Closure reason: ${mdValue(c.closureReason)}`);
    out.push('');
  }
  if (data.tasks && data.tasks.length) {
    out.push('## Tasks');
    out.push('');
    for (const task of data.tasks) {
      const extra = [task.owner ? `owner ${task.owner}` : null, task.dueAt ? `due ${task.dueAt}` : null, task.done && task.doneAt ? `done ${task.doneAt}${task.doneBy ? ` by ${task.doneBy}` : ''}` : null]
        .filter(Boolean)
        .join(', ');
      out.push(`- [${task.done ? 'x' : ' '}] ${escapeMarkdownText(task.title)}${extra ? ` (${escapeMarkdownText(extra)})` : ''}`);
    }
    out.push('');
  }
  out.push('## Timeline');
  out.push('');
  if (data.timeline.entries.length) {
    out.push(
      mdTable(
        ['Time', 'Kind', 'Actor', 'Event'],
        data.timeline.entries.map((entry) => [entry.timestamp, entry.kind, entry.actor ?? '', entry.summary])
      )
    );
  } else {
    out.push('_No timeline entries._');
  }
  if (data.timeline.truncated) out.push(`\n_Timeline capped at ${data.timeline.limit} entries._`);
  out.push('');
  out.push(`## Linked alerts (${data.alerts.totalRelationships}${data.alerts.truncated ? '+' : ''})`);
  out.push('');
  if (data.alerts.listed.length) {
    out.push(
      mdTable(
        ['Time', 'Alert id', 'Rule', 'Description', 'Severity', 'Agent', 'Source IP', 'Status', 'Record'],
        data.alerts.listed.map((alert) => [
          alert.timestamp ?? '',
          alert.id,
          alert.ruleId ?? '',
          alert.ruleDescription ?? '',
          severityText(alert),
          alert.agentName ?? alert.agentId ?? '',
          alert.srcip ?? '',
          alert.status ?? '',
          alert.availability,
        ])
      )
    );
    const rest = data.alerts.totalRelationships - data.alerts.listed.length;
    if (rest > 0) out.push(`\n_${rest} more alert${rest === 1 ? '' : 's'} not listed (the report lists at most ${data.alerts.listedLimit})._`);
    if (data.alerts.truncated) out.push(`\n_The case links more than ${data.alerts.limit} alerts; the list and aggregations cover the first ${data.alerts.limit}._`);
  } else {
    out.push('_No alerts are linked to this case._');
  }
  out.push('');
  out.push('## Indicators');
  out.push('');
  if (data.indicators.length) {
    out.push(
      mdTable(
        ['Type', 'Value', 'Alerts', 'First seen', 'Last seen', 'Verdicts'],
        data.indicators.map((ind) => [ind.type, ind.value, ind.count, ind.first_seen ?? '', ind.last_seen ?? '', verdictHintsText(ind)])
      )
    );
  } else {
    out.push('_No indicators extracted._');
  }
  out.push('');
  out.push('## Enrichment verdicts');
  out.push('');
  if (data.enrichment.length) {
    out.push(
      mdTable(
        ['Indicator', 'Type', 'Source', 'Verdict', 'Score', 'Tags', 'Checked', 'Alerts'],
        data.enrichment.map((row) => [row.value, row.type, row.source, row.verdict, row.score ?? '', row.tags.join(', '), row.checked_at, row.alertCount])
      )
    );
  } else {
    out.push('_No stored lookups._');
  }
  out.push('');
  out.push('## MITRE ATT&CK');
  out.push('');
  if (data.mitre.length) {
    out.push(mdTable(['Tactic', 'Technique id', 'Technique', 'Alerts'], data.mitre.map((row) => [row.tactic, row.techniqueId, row.technique, row.alertCount])));
  } else {
    out.push('_No MITRE mappings on the linked alerts._');
  }
  out.push('');
  out.push('## Attack graph');
  out.push('');
  if (data.graph.nodes.length) {
    out.push(mdTable(['Entity', 'Type', 'Alerts'], data.graph.nodes.map((node) => [node.label, node.type, node.alertCount])));
    out.push('');
    out.push('_The HTML report embeds the graph drawing; this Markdown lists its entities._');
    if (data.graphDropped.length) out.push(`\n_${escapeMarkdownText(graphDroppedText(data.graphDropped))}_`);
  } else {
    out.push('_No graph entities._');
  }
  out.push('');
  out.push('## Attachments');
  out.push('');
  if (!data.attachments.available) {
    out.push('_Attachments are not available on this installation._');
  } else if (data.attachments.items.length) {
    out.push(
      mdTable(
        ['Name', 'Kind', 'Type', 'Size', 'SHA-256', 'Added'],
        data.attachments.items.map((att) => [att.name, att.kind ?? '', att.contentType ?? '', formatSize(att.size), att.sha256 ?? '', att.createdAt ? `${att.createdAt}${att.createdBy ? ` by ${att.createdBy}` : ''}` : ''])
      )
    );
  } else {
    out.push('_No attachments._');
  }
  out.push('');
  out.push('## Comments');
  out.push('');
  if (data.comments.items.length) {
    for (const comment of data.comments.items) {
      out.push(`**${escapeMarkdownText(comment.author ?? 'unknown')}** — ${escapeMarkdownText(comment.createdAt ?? '')}`);
      out.push('');
      out.push(escapeMarkdownText(comment.text).split(/\r?\n/).map((line) => `> ${line}`).join('\n'));
      out.push('');
    }
    if (data.comments.truncated) out.push(`_Comments capped at ${CASE_REPORT_COMMENT_LIMIT}._\n`);
  } else {
    out.push('_No comments._');
    out.push('');
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

const HTML_STYLE = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1a1a1a; background: #fff; }
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 28px 0 8px; border-bottom: 1px solid #ddd; padding-bottom: 4px; page-break-after: avoid; }
h3 { font-size: 15px; margin: 16px 0 6px; }
.wam-report-meta { color: #555; font-size: 12px; margin-bottom: 16px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 12px; page-break-inside: auto; }
th, td { border: 1px solid #ccc; padding: 4px 6px; text-align: left; vertical-align: top; word-break: break-word; }
th { background: #f3f4f6; }
tr { page-break-inside: avoid; }
.wam-report-empty { color: #666; font-style: italic; }
.wam-report-note { color: #555; font-size: 12px; }
.wam-report-pre { white-space: pre-wrap; word-break: break-word; background: #f8f9fa; border: 1px solid #e5e7eb; padding: 8px; border-radius: 4px; }
.wam-report-badge { display: inline-block; padding: 1px 6px; border-radius: 10px; font-size: 11px; background: #eef; }
.wam-report-badge--closed { background: #e6e6e6; }
.wam-report-badge--open, .wam-report-badge--in_progress { background: #e6f1fa; }
.wam-report-badge--critical, .wam-report-badge--malicious { background: #f8d7da; }
.wam-report-badge--high, .wam-report-badge--suspicious { background: #ffe5cc; }
.wam-report-badge--medium { background: #fff3cd; }
.wam-report-badge--low, .wam-report-badge--clean { background: #d4edda; }
.wam-report-comment { border-left: 3px solid #ccc; padding: 4px 10px; margin: 8px 0; page-break-inside: avoid; }
.wam-report-comment-head { font-size: 12px; color: #555; }
.wam-report-task-done { text-decoration: line-through; color: #666; }
.wam-report-graph { overflow-x: auto; }
.wam-report-graph svg { max-width: 100%; height: auto; }
.wam-report-actions { float: right; font-size: 12px; }
@media print {
  body { padding: 0; font-size: 11px; }
  main { max-width: none; }
  h2 { page-break-after: avoid; }
  table { font-size: 10px; }
  .wam-report-actions { display: none; }
  a { color: inherit; text-decoration: none; }
}
`;

function h(value: unknown): string {
  return escapeHtml(value);
}

/**
 * Markup this module built itself. Only an instance of this private class is
 * emitted unescaped by `htmlTable`; a plain object read from an index document
 * can never satisfy the `instanceof` test, whatever keys it carries.
 */
class RawHtml {
  constructor(readonly html: string) {}
}

function htmlTable(headers: string[], rows: unknown[][], className = ''): string {
  const cls = className ? ` class="${h(className)}"` : '';
  const head = `<thead><tr>${headers.map((header) => `<th>${h(header)}</th>`).join('')}</tr></thead>`;
  const body = `<tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell instanceof RawHtml ? cell.html : h(cell)}</td>`).join('')}</tr>`).join('')}</tbody>`;
  return `<table${cls}>${head}${body}</table>`;
}

function badge(value: string | null | undefined, extra = ''): RawHtml {
  if (!value) return new RawHtml('');
  const slug = String(value).toLowerCase().replace(/[^a-z0-9_]+/g, '_');
  return new RawHtml(`<span class="wam-report-badge wam-report-badge--${h(slug)}${extra ? ` ${h(extra)}` : ''}">${h(value)}</span>`);
}

function empty(message: string): string {
  return `<p class="wam-report-empty">${h(message)}</p>`;
}

function paragraphs(value: string): string {
  return `<div class="wam-report-pre">${h(value)}</div>`;
}

export function renderCaseReportHtml(data: CaseReportData, options: CaseReportRenderOptions = {}): string {
  const c = data.case;
  const sections: string[] = [];

  sections.push(`<h1>Case report: ${h(c.title)}</h1>`);
  sections.push(`<div class="wam-report-meta">Generated ${h(data.generatedAt)} by Wazuh Alert Manager. Case ${h(c.id)}${c.uid ? ` (uid ${h(c.uid)})` : ''}.</div>`);

  sections.push('<h2>Summary</h2>');
  sections.push(
    htmlTable(
      ['Field', 'Value'],
      [
        ['Case id', c.id],
        ['Status', badge(c.status)],
        ['Severity', badge(c.severity)],
        ['Assignee', c.assignee ?? '(unassigned)'],
        ['Created', c.createdAt ? `${c.createdAt}${c.createdBy ? ` by ${c.createdBy}` : ''}` : ''],
        ['Updated', c.updatedAt ?? ''],
        ['Closed', c.closedAt ?? ''],
        ['Linked alerts', `${data.alerts.totalRelationships}${data.alerts.truncated ? `+ (report capped at ${data.alerts.limit})` : ''}`],
      ],
      'wam-report-summary'
    )
  );
  if (c.description) {
    sections.push('<h3>Description</h3>');
    sections.push(paragraphs(c.description));
  }

  if (c.disposition || c.closureReason) {
    sections.push('<h2>Disposition</h2>');
    const rows: unknown[][] = [];
    if (c.disposition) rows.push(['Disposition', badge(c.disposition)]);
    if (c.closureReason) rows.push(['Closure reason', c.closureReason]);
    sections.push(htmlTable(['Field', 'Value'], rows, 'wam-report-disposition'));
  }

  if (data.tasks && data.tasks.length) {
    sections.push('<h2>Tasks</h2>');
    sections.push(
      `<ul class="wam-report-tasks">${data.tasks
        .map((task) => {
          const extra = [task.owner ? `owner ${task.owner}` : null, task.dueAt ? `due ${task.dueAt}` : null, task.done && task.doneAt ? `done ${task.doneAt}${task.doneBy ? ` by ${task.doneBy}` : ''}` : null]
            .filter(Boolean)
            .join(', ');
          return `<li class="${task.done ? 'wam-report-task-done' : ''}">${task.done ? '&#9745;' : '&#9744;'} ${h(task.title)}${extra ? ` <span class="wam-report-note">(${h(extra)})</span>` : ''}</li>`;
        })
        .join('')}</ul>`
    );
  }

  sections.push('<h2>Timeline</h2>');
  if (data.timeline.entries.length) {
    sections.push(
      htmlTable(
        ['Time', 'Kind', 'Actor', 'Event'],
        data.timeline.entries.map((entry) => [entry.timestamp, badge(entry.kind), entry.actor ?? '', entry.summary]),
        'wam-report-timeline'
      )
    );
  } else {
    sections.push(empty('No timeline entries.'));
  }
  if (data.timeline.truncated) sections.push(`<p class="wam-report-note">Timeline capped at ${data.timeline.limit} entries.</p>`);

  sections.push(`<h2>Linked alerts (${data.alerts.totalRelationships}${data.alerts.truncated ? '+' : ''})</h2>`);
  if (data.alerts.listed.length) {
    sections.push(
      htmlTable(
        ['Time', 'Alert id', 'Rule', 'Description', 'Severity', 'Agent', 'Source IP', 'Status', 'Record'],
        data.alerts.listed.map((alert) => [
          alert.timestamp ?? '',
          alert.id,
          alert.ruleId ?? '',
          alert.ruleDescription ?? '',
          severityText(alert),
          alert.agentName ?? alert.agentId ?? '',
          alert.srcip ?? '',
          badge(alert.status),
          alert.availability,
        ]),
        'wam-report-alerts'
      )
    );
    const rest = data.alerts.totalRelationships - data.alerts.listed.length;
    if (rest > 0) sections.push(`<p class="wam-report-note">${rest} more alert${rest === 1 ? '' : 's'} not listed (the report lists at most ${data.alerts.listedLimit}).</p>`);
    if (data.alerts.truncated) sections.push(`<p class="wam-report-note">The case links more than ${data.alerts.limit} alerts; the list and aggregations cover the first ${data.alerts.limit}.</p>`);
  } else {
    sections.push(empty('No alerts are linked to this case.'));
  }

  sections.push('<h2>Indicators</h2>');
  if (data.indicators.length) {
    sections.push(
      htmlTable(
        ['Type', 'Value', 'Alerts', 'First seen', 'Last seen', 'Verdicts'],
        data.indicators.map((ind) => [ind.type, ind.value, ind.count, ind.first_seen ?? '', ind.last_seen ?? '', verdictHintsText(ind)]),
        'wam-report-indicators'
      )
    );
  } else {
    sections.push(empty('No indicators extracted.'));
  }

  sections.push('<h2>Enrichment verdicts</h2>');
  if (data.enrichment.length) {
    sections.push(
      htmlTable(
        ['Indicator', 'Type', 'Source', 'Verdict', 'Score', 'Tags', 'Checked', 'Alerts'],
        data.enrichment.map((row) => [row.value, row.type, row.source, badge(row.verdict), row.score ?? '', row.tags.join(', '), row.checked_at, row.alertCount]),
        'wam-report-enrichment'
      )
    );
  } else {
    sections.push(empty('No stored lookups.'));
  }

  sections.push('<h2>MITRE ATT&amp;CK</h2>');
  if (data.mitre.length) {
    sections.push(htmlTable(['Tactic', 'Technique id', 'Technique', 'Alerts'], data.mitre.map((row) => [row.tactic, row.techniqueId, row.technique, row.alertCount]), 'wam-report-mitre'));
  } else {
    sections.push(empty('No MITRE mappings on the linked alerts.'));
  }

  sections.push('<h2>Attack graph</h2>');
  sections.push(`<div class="wam-report-graph">${data.graphSvg}</div>`);
  if (data.graphDropped.length) sections.push(`<p class="wam-report-note">${h(graphDroppedText(data.graphDropped))}</p>`);

  sections.push('<h2>Attachments</h2>');
  if (!data.attachments.available) {
    sections.push(empty('Attachments are not available on this installation.'));
  } else if (data.attachments.items.length) {
    sections.push(
      htmlTable(
        ['Name', 'Kind', 'Type', 'Size', 'SHA-256', 'Added'],
        data.attachments.items.map((att) => [att.name, att.kind ?? '', att.contentType ?? '', formatSize(att.size), att.sha256 ?? '', att.createdAt ? `${att.createdAt}${att.createdBy ? ` by ${att.createdBy}` : ''}` : '']),
        'wam-report-attachments'
      )
    );
  } else {
    sections.push(empty('No attachments.'));
  }

  sections.push('<h2>Comments</h2>');
  if (data.comments.items.length) {
    for (const comment of data.comments.items) {
      sections.push(
        `<div class="wam-report-comment"><div class="wam-report-comment-head"><strong>${h(comment.author ?? 'unknown')}</strong> — ${h(comment.createdAt ?? '')}</div>${paragraphs(comment.text)}</div>`
      );
    }
    if (data.comments.truncated) sections.push(`<p class="wam-report-note">Comments capped at ${CASE_REPORT_COMMENT_LIMIT}.</p>`);
  } else {
    sections.push(empty('No comments.'));
  }

  const nonceAttr = options.nonce ? ` nonce="${h(options.nonce)}"` : '';
  const printScript = options.print ? `<script${nonceAttr}>window.addEventListener("load",function(){window.print();});</script>` : '';
  return (
    '<!DOCTYPE html>' +
    `<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<meta name="referrer" content="no-referrer"><title>${h(`Case report: ${c.title}`)}</title><style>${HTML_STYLE}</style></head>` +
    `<body><main class="wam-report">${sections.join('\n')}</main>${printScript}</body></html>`
  );
}

export function renderCaseReport(data: CaseReportData, format: CaseReportFormat, options: CaseReportRenderOptions = {}): string {
  return format === 'markdown' ? renderCaseReportMarkdown(data) : renderCaseReportHtml(data, options);
}
