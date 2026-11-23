import { DISPOSITIONS, DISPOSITION_LABELS, PLUGIN_VERSION, REPORT_RUN_MARKDOWN_MAX_BYTES, SLA_BANDS } from '../../../common';
import type { ReportExportFormat, ReportSchedule, ReportSummaryData } from '../../../common';
import { SEVERITY_BANDS, bandLevelRange } from '../../../common/severity';
import type { SeverityBand } from '../../../common/severity';
import { toCsvLine } from '../http_download';

/**
 * Rendering of a SOC summary (step 5.4 Markdown, step 10.3 HTML / CSV / JSON).
 * Pure: it takes the figures `collectReportSummary` produced and never
 * touches OpenSearch, so it is unit-tested on a fixture object. Every
 * format is built from one section model (`buildReportSummaryDocument`) so
 * a scheduled Markdown summary, the HTML export and the CSV export never
 * disagree on a figure. Every value is escaped per format so a rule
 * description or agent name cannot break a row or inject HTML.
 */

export interface RenderSummaryOptions {
  schedule: Pick<ReportSchedule, 'name' | 'cadence' | 'rangeDays'>;
  from: string;
  to: string;
  generatedAt: string;
  /**
   * Replaces the cadence sentence ("Weekly SOC summary covering the 7 days")
   * for an ad-hoc export whose window is a picker expression, not a schedule.
   */
  intro?: string;
  /** Shown in the document header when known (the exporting user). */
  generatedBy?: string;
}

export interface RenderSummaryHtmlOptions extends RenderSummaryOptions {
  /** Embed the inline `window.print()` trigger (print view only). */
  print?: boolean;
  /** CSP nonce stamped on the inline script so the route can forbid every other script. */
  nonce?: string;
  /** Footer version; defaults to the build's `PLUGIN_VERSION`. */
  pluginVersion?: string;
}

export function escapeMarkdown(value: unknown): string {
  return String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/`/g, '\\`');
}

/** Escape for an HTML text node or double-quoted attribute value. */
export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** "Low (0-3)" etc., the numeric range taken from the shared band table. */
export function bandLabel(band: SeverityBand): string {
  const name = band.charAt(0).toUpperCase() + band.slice(1);
  const range = bandLevelRange(band);
  if (!range) return name;
  return range.max == null ? `${name} (${range.min}+)` : `${name} (${range.min}-${range.max})`;
}

/**
 * Swatch colours of the severity bands in the HTML export: the same hex
 * values as `SEVERITY_HEX` in `public/design.ts` (the server cannot import
 * the browser bundle), so the page and the export agree on a band's colour.
 */
export const SEVERITY_BAND_HEX: Record<string, string> = {
  informational: '#D3DAE6',
  low: '#98A2B3',
  medium: '#FEC514',
  high: '#F5892E',
  critical: '#BD271E',
};

const STATUS_LABELS: Record<string, string> = { open: 'Open', in_progress: 'In progress', closed: 'Closed' };

// ---------------------------------------------------------------------------
// Section model
// ---------------------------------------------------------------------------

export interface SummaryRun {
  text: string;
  strong?: boolean;
}

/** A table cell; the object form carries a severity band for the HTML swatch. */
export type SummaryCell = string | number | null | undefined | { text: string; band: string };

export type SummaryBlock =
  | { kind: 'paragraph'; runs: SummaryRun[] }
  | { kind: 'note'; text: string }
  | { kind: 'subheading'; text: string }
  | { kind: 'table'; headers: string[]; rows: SummaryCell[][] };

export interface SummarySection {
  id: string;
  title: string;
  blocks: SummaryBlock[];
}

export interface SummaryDocument {
  title: string;
  subtitle: SummaryRun[];
  from: string;
  to: string;
  generatedAt: string;
  generatedBy?: string;
  sections: SummarySection[];
}

function cellText(cell: SummaryCell): string {
  if (cell == null) return '-';
  if (typeof cell === 'object') return cell.text;
  return String(cell);
}

function minutes(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  if (value < 60) return `${Math.round(value)} min`;
  if (value < 60 * 24) return `${(value / 60).toFixed(1)} h`;
  return `${(value / (60 * 24)).toFixed(1)} d`;
}

function percent(value: number | null | undefined): string {
  return value == null || !Number.isFinite(value) ? 'n/a' : `${value.toFixed(1)}%`;
}

function day(iso: string): string {
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}

function bandCell(band: string): SummaryCell {
  return { text: bandLabel(band as SeverityBand), band };
}

/** The figures of a summary as titled sections, the one source every format renders. */
export function buildReportSummaryDocument(data: ReportSummaryData, options: RenderSummaryOptions): SummaryDocument {
  const { metrics, extras } = data;
  const { schedule, from, to, generatedAt } = options;
  const intro =
    options.intro ??
    `${schedule.cadence === 'weekly' ? 'Weekly' : 'Daily'} SOC summary covering the ${schedule.rangeDays} day${schedule.rangeDays === 1 ? '' : 's'}`;
  const subtitle: SummaryRun[] = [
    { text: `${intro} from ` },
    { text: from, strong: true },
    { text: ' to ' },
    { text: to, strong: true },
    { text: ` (UTC). Generated ${generatedAt}${options.generatedBy ? ` by ${options.generatedBy}` : ''}.` },
  ];
  const sections: SummarySection[] = [];
  const section = (id: string, title: string): SummaryBlock[] => {
    const blocks: SummaryBlock[] = [];
    sections.push({ id, title, blocks });
    return blocks;
  };
  const table = (headers: string[], rows: SummaryCell[][]): SummaryBlock => ({ kind: 'table', headers, rows });
  const note = (text: string): SummaryBlock => ({ kind: 'note', text });
  const sub = (text: string): SummaryBlock => ({ kind: 'subheading', text });
  const para = (...runs: SummaryRun[]): SummaryBlock => ({ kind: 'paragraph', runs });

  const volume = section('alert-volume', 'Alert volume');
  volume.push(para({ text: 'Alerts in range: ' }, { text: String(metrics.totalAlerts), strong: true }, { text: '.' }));
  volume.push(table(['Severity band', 'Alerts'], SEVERITY_BANDS.map((band) => [bandCell(band), extras.severityBands?.[band] ?? 0])));
  if (metrics.alertsPerDay && metrics.alertsPerDay.length) {
    volume.push(sub('Per day'));
    volume.push(table(['Day', 'Alerts'], metrics.alertsPerDay.map((row) => [day(row.date), row.count])));
  }

  const status = section('status-breakdown', 'Status breakdown');
  status.push(
    table(
      ['Status', 'Alerts'],
      Object.keys(STATUS_LABELS).map((key) => [STATUS_LABELS[key], (metrics.statusBreakdown as any)?.[key] ?? 0])
    )
  );

  if (metrics.dispositions || metrics.falsePositiveByRule) {
    const blocks = section('dispositions', 'Dispositions');
    const dispositions = metrics.dispositions;
    const closedInRange = dispositions ? DISPOSITIONS.reduce((sum, value) => sum + (dispositions[value] ?? 0), 0) : 0;
    blocks.push(para({ text: 'Alerts closed in range: ' }, { text: String(closedInRange), strong: true }, { text: '.' }));
    if (dispositions) {
      blocks.push(table(['Disposition', 'Alerts closed'], DISPOSITIONS.map((value) => [DISPOSITION_LABELS[value], dispositions[value] ?? 0])));
    }
    blocks.push(sub('False-positive rate by rule'));
    const byRule = metrics.falsePositiveByRule || [];
    blocks.push(
      byRule.length
        ? table(
            ['Rule', 'Description', 'Closed', 'False positives', 'Rate'],
            byRule.map((row) => [row.rule_id, row.description, row.closed, row.false_positive, percent(row.rate * 100)])
          )
        : note('No alerts closed in range.')
    );
  }

  const sla = section('sla-summary', 'SLA summary');
  sla.push(
    table(
      ['Measure', 'Value'],
      [
        ['SLA compliance (resolved alerts)', percent(metrics.slaCompliancePct)],
        ['Mean time to assign', minutes(metrics.meanTimeToAssignMinutes)],
        ['Mean time to resolve', minutes(metrics.meanTimeToResolveMinutes)],
        ['Alerts assigned', String(metrics.assignedCount ?? 0)],
        ['Alerts resolved', String(metrics.resolvedCount ?? 0)],
        ['SLA breached (resolved in range)', extras.breachedCount == null ? 'n/a' : String(extras.breachedCount)],
      ]
    )
  );
  if (metrics.slaBreakdown && metrics.slaBreakdown.length) {
    sla.push(table(['Tier', 'Met', 'Breached'], metrics.slaBreakdown.map((tier) => [tier.label, tier.met, tier.breached])));
  }
  if (metrics.slaCurrentlyBreached || metrics.slaBreachesInPeriod || metrics.slaEscalationsInPeriod) {
    sla.push(sub('SLA enforcement'));
    const breached = metrics.slaCurrentlyBreached;
    const breaches = metrics.slaBreachesInPeriod;
    const escalations = metrics.slaEscalationsInPeriod;
    sla.push(
      table(
        ['Measure', 'Value'],
        [
          ['Currently breached alerts (now)', breached ? String(breached.alerts) : 'n/a'],
          ['Currently breached cases (now)', breached ? String(breached.cases) : 'n/a'],
          ['SLA breaches in period', breaches ? `${breaches.total} (${breaches.alerts} alerts, ${breaches.cases} cases)` : 'n/a'],
          ['Escalations in period', escalations ? String(escalations.total) : 'n/a'],
        ]
      )
    );
    if (breached) {
      sla.push(table(['Severity', 'Currently breached'], SLA_BANDS.map((band) => [bandCell(band), breached.byBand?.[band] ?? 0])));
    }
    if (escalations) {
      sla.push(
        escalations.byEscalation.length
          ? table(['Escalation', 'Id', 'Applied'], escalations.byEscalation.map((e) => [e.name, e.id, e.count]))
          : note('No escalations applied in range.')
      );
    }
  }
  const coverage = metrics.coverage;
  if (coverage && (coverage.closedMissingReporting > 0 || coverage.assignedMissingReporting > 0)) {
    sla.push(
      note(
        `${coverage.closedMissingReporting} closed and ${coverage.assignedMissingReporting} assigned alerts predate the reporting fields and are not in the timing figures yet.`
      )
    );
  }

  section('top-rules', 'Top rules').push(
    extras.topRules.length
      ? table(['Rule', 'Description', 'Alerts'], extras.topRules.map((rule) => [rule.id, rule.description, rule.count]))
      : note('No alerts in range.')
  );

  section('top-agents', 'Top agents').push(
    extras.topAgents.length
      ? table(['Agent', 'Id', 'Alerts'], extras.topAgents.map((agent) => [agent.name, agent.id, agent.count]))
      : note('No alerts in range.')
  );

  const casesBlocks = section('cases', 'Cases');
  const cases = metrics.cases;
  casesBlocks.push(
    para(
      { text: 'Cases opened in range: ' },
      { text: String(cases?.totalCases ?? 0), strong: true },
      {
        text:
          ` (open ${cases?.statusBreakdown?.open ?? 0}, in progress ${cases?.statusBreakdown?.in_progress ?? 0}, closed ${cases?.statusBreakdown?.closed ?? 0}). ` +
          `Mean time to close: ${minutes(cases?.meanTimeToCloseMinutes)}.`,
      }
    )
  );
  casesBlocks.push(sub('Open cases by severity (now)'));
  casesBlocks.push(
    table(
      ['Severity', 'Open cases'],
      Object.keys(extras.openCasesBySeverity || {}).map((severity) => [{ text: severity, band: severity }, extras.openCasesBySeverity[severity]])
    )
  );

  if (metrics.analysts && metrics.analysts.length) {
    section('analyst-workload', 'Analyst workload').push(
      table(
        ['Analyst', 'Open', 'In progress', 'Closed', 'Mean time to resolve'],
        metrics.analysts.slice(0, 10).map((a) => [a.assignee, a.open, a.in_progress, a.closed, minutes(a.meanTimeToResolveMinutes)])
      )
    );
  }

  return { title: schedule.name, subtitle, from, to, generatedAt, generatedBy: options.generatedBy, sections };
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

function mdTable(headers: string[], rows: SummaryCell[][]): string {
  const lines = [`| ${headers.map(escapeMarkdown).join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`];
  for (const row of rows) lines.push(`| ${row.map((cell) => escapeMarkdown(cellText(cell))).join(' | ')} |`);
  return lines.join('\n');
}

function mdRuns(runs: SummaryRun[]): string {
  return runs.map((run) => (run.strong ? `**${escapeMarkdown(run.text)}**` : escapeMarkdown(run.text))).join('');
}

export const TRUNCATION_NOTE = '\n\n_Report truncated at the stored size cap._\n';

/** Full Markdown document; see `truncateMarkdown` for the stored size cap. */
export function renderReportSummaryMarkdown(data: ReportSummaryData, options: RenderSummaryOptions): string {
  const doc = buildReportSummaryDocument(data, options);
  const parts: string[] = [`# ${escapeMarkdown(doc.title)}`, mdRuns(doc.subtitle)];
  for (const section of doc.sections) {
    parts.push(`## ${escapeMarkdown(section.title)}`);
    for (const block of section.blocks) {
      if (block.kind === 'paragraph') parts.push(mdRuns(block.runs));
      else if (block.kind === 'note') parts.push(`_${escapeMarkdown(block.text)}_`);
      else if (block.kind === 'subheading') parts.push(`### ${escapeMarkdown(block.text)}`);
      else parts.push(mdTable(block.headers, block.rows));
    }
  }
  return `${parts.join('\n\n')}\n`;
}

/**
 * Cut a document at `maxBytes` of UTF-8 (never inside a multi-byte
 * sequence) and append `TRUNCATION_NOTE`. Returns the text unchanged when it fits.
 */
export function truncateMarkdown(markdown: string, maxBytes = REPORT_RUN_MARKDOWN_MAX_BYTES): { markdown: string; truncated: boolean } {
  if (Buffer.byteLength(markdown, 'utf8') <= maxBytes) return { markdown, truncated: false };
  const budget = Math.max(0, maxBytes - Buffer.byteLength(TRUNCATION_NOTE, 'utf8'));
  let cut = Buffer.from(markdown, 'utf8').subarray(0, budget).toString('utf8');
  // A partial multi-byte sequence decodes to U+FFFD; drop it.
  cut = cut.replace(/�+$/, '');
  return { markdown: `${cut}${TRUNCATION_NOTE}`, truncated: true };
}

// ---------------------------------------------------------------------------
// HTML (step 10.3): self-contained, inline CSS, no script unless `print`
// ---------------------------------------------------------------------------

const HTML_STYLE = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1a1a1a; background: #fff; }
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 28px 0 8px; border-bottom: 1px solid #ddd; padding-bottom: 4px; page-break-after: avoid; break-after: avoid; }
h3 { font-size: 15px; margin: 16px 0 6px; page-break-after: avoid; break-after: avoid; }
.wam-report-meta { color: #555; font-size: 12px; margin-bottom: 16px; }
.wam-report-footer { color: #555; font-size: 11px; margin-top: 32px; border-top: 1px solid #ddd; padding-top: 6px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 12px; page-break-inside: auto; }
th, td { border: 1px solid #ccc; padding: 4px 6px; text-align: left; vertical-align: top; word-break: break-word; }
th { background: #f3f4f6; }
tr { page-break-inside: avoid; break-inside: avoid; }
.wam-report-note { color: #555; font-size: 12px; font-style: italic; }
.wam-report-band { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: middle; border: 1px solid rgba(0,0,0,.15); }
.wam-report-section { page-break-inside: auto; }
@media print {
  @page { margin: 14mm; }
  body { padding: 0; font-size: 11px; }
  main { max-width: none; }
  .wam-report-section { page-break-before: always; break-before: page; }
  .wam-report-section:first-of-type { page-break-before: auto; break-before: auto; }
  table { font-size: 10px; }
  thead { display: table-header-group; }
  a { color: inherit; text-decoration: none; }
}
`;

function htmlCell(cell: SummaryCell, tag: 'td' | 'th' = 'td'): string {
  if (cell != null && typeof cell === 'object') {
    const hex = SEVERITY_BAND_HEX[cell.band];
    const swatch = hex ? `<span class="wam-report-band" style="background:${hex}" aria-hidden="true"></span>` : '';
    return `<${tag}>${swatch}${escapeHtml(cell.text)}</${tag}>`;
  }
  const numeric = typeof cell === 'number';
  return `<${tag}${numeric ? ' class="wam-report-num"' : ''}>${escapeHtml(cellText(cell))}</${tag}>`;
}

function htmlTable(headers: string[], rows: SummaryCell[][]): string {
  const head = `<thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join('')}</tr></thead>`;
  const body = `<tbody>${rows.map((row) => `<tr>${row.map((cell) => htmlCell(cell)).join('')}</tr>`).join('')}</tbody>`;
  return `<table>${head}${body}</table>`;
}

function htmlRuns(runs: SummaryRun[]): string {
  return runs.map((run) => (run.strong ? `<strong>${escapeHtml(run.text)}</strong>` : escapeHtml(run.text))).join('');
}

/**
 * Self-contained HTML page of the summary: inline CSS, every value escaped,
 * and no script at all unless `print` is set, in which case one inline
 * `window.print()` trigger carrying the route's CSP nonce is embedded. The
 * print stylesheet starts every section on a new page.
 */
export function renderReportSummaryHtml(data: ReportSummaryData, options: RenderSummaryHtmlOptions): string {
  const doc = buildReportSummaryDocument(data, options);
  const parts: string[] = [];
  parts.push(`<header class="wam-report-header"><h1>${escapeHtml(doc.title)}</h1><p class="wam-report-meta">${htmlRuns(doc.subtitle)}</p></header>`);
  for (const section of doc.sections) {
    const body: string[] = [`<h2>${escapeHtml(section.title)}</h2>`];
    for (const block of section.blocks) {
      if (block.kind === 'paragraph') body.push(`<p>${htmlRuns(block.runs)}</p>`);
      else if (block.kind === 'note') body.push(`<p class="wam-report-note">${escapeHtml(block.text)}</p>`);
      else if (block.kind === 'subheading') body.push(`<h3>${escapeHtml(block.text)}</h3>`);
      else body.push(htmlTable(block.headers, block.rows));
    }
    parts.push(`<section class="wam-report-section" id="${escapeHtml(section.id)}">${body.join('\n')}</section>`);
  }
  const version = options.pluginVersion ?? PLUGIN_VERSION;
  parts.push(`<footer class="wam-report-footer">Wazuh Alert Manager ${escapeHtml(version)} &middot; window ${escapeHtml(doc.from)} to ${escapeHtml(doc.to)} &middot; generated ${escapeHtml(doc.generatedAt)}</footer>`);
  const nonceAttr = options.nonce ? ` nonce="${escapeHtml(options.nonce)}"` : '';
  const printScript = options.print ? `<script${nonceAttr}>window.addEventListener("load",function(){window.print();});</script>` : '';
  return (
    '<!DOCTYPE html>' +
    `<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<meta name="referrer" content="no-referrer"><title>${escapeHtml(doc.title)}</title><style>${HTML_STYLE}</style></head>` +
    `<body><main class="wam-report">${parts.join('\n')}</main>${printScript}</body></html>`
  );
}

// ---------------------------------------------------------------------------
// CSV (step 10.3): one file, each section a titled block; BOM for Excel
// ---------------------------------------------------------------------------

export const CSV_BOM = '﻿';

/**
 * One CSV file: a title block, then each section as a `# <title>` line,
 * its paragraphs / notes as single-cell rows and its tables as header +
 * rows, blocks separated by an empty line. Every cell goes through the
 * formula guard in `toCsvLine`. Starts with a UTF-8 BOM so Excel decodes it.
 */
export function renderReportSummaryCsv(data: ReportSummaryData, options: RenderSummaryOptions): string {
  const doc = buildReportSummaryDocument(data, options);
  const out: string[] = [];
  out.push(toCsvLine([doc.title]));
  out.push(toCsvLine([doc.subtitle.map((run) => run.text).join('')]));
  out.push(toCsvLine(['From', doc.from]));
  out.push(toCsvLine(['To', doc.to]));
  out.push(toCsvLine(['Generated at', doc.generatedAt]));
  if (doc.generatedBy) out.push(toCsvLine(['Generated by', doc.generatedBy]));
  for (const section of doc.sections) {
    out.push(toCsvLine([]));
    out.push(toCsvLine([`# ${section.title}`]));
    for (const block of section.blocks) {
      if (block.kind === 'paragraph') out.push(toCsvLine([block.runs.map((run) => run.text).join('')]));
      else if (block.kind === 'note') out.push(toCsvLine([block.text]));
      else if (block.kind === 'subheading') out.push(toCsvLine([`## ${block.text}`]));
      else {
        out.push(toCsvLine(block.headers));
        for (const row of block.rows) out.push(toCsvLine(row.map((cell) => (cell != null && typeof cell === 'object' ? cell.text : cell ?? ''))));
      }
    }
  }
  return CSV_BOM + out.join('');
}

// ---------------------------------------------------------------------------
// JSON (step 10.3)
// ---------------------------------------------------------------------------

export interface ReportExportJson {
  generated_at: string;
  generated_by: string | null;
  plugin_version: string;
  window: { from: string; to: string };
  metrics: ReportSummaryData['metrics'];
  extras: ReportSummaryData['extras'];
}

export function renderReportSummaryJson(data: ReportSummaryData, options: RenderSummaryOptions & { pluginVersion?: string }): string {
  const body: ReportExportJson = {
    generated_at: options.generatedAt,
    generated_by: options.generatedBy ?? null,
    plugin_version: options.pluginVersion ?? PLUGIN_VERSION,
    window: { from: options.from, to: options.to },
    metrics: data.metrics,
    extras: data.extras,
  };
  return `${JSON.stringify(body, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Export helpers shared by the route
// ---------------------------------------------------------------------------

const EXPORT_EXTENSION: Record<ReportExportFormat, string> = { html: 'html', markdown: 'md', csv: 'csv', json: 'json' };
const EXPORT_CONTENT_TYPE: Record<ReportExportFormat, string> = {
  html: 'text/html; charset=utf-8',
  markdown: 'text/markdown; charset=utf-8',
  csv: 'text/csv; charset=utf-8',
  json: 'application/json; charset=utf-8',
};

export function reportExportContentType(format: ReportExportFormat): string {
  return EXPORT_CONTENT_TYPE[format];
}

/** A window bound as a file-name token: an ISO instant becomes its day, date math keeps its letters/digits. */
function windowToken(bound: string): string {
  const iso = /^(\d{4}-\d{2}-\d{2})/.exec(bound);
  if (iso) return iso[1];
  return String(bound || '').replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'x';
}

/** `wam-report-<YYYY-MM-DD>-<from>_<to>.<ext>`, e.g. `wam-report-2026-11-21-now-7d_now.html`; sanitised again by `downloadResponse`. */
export function reportExportFilename(format: ReportExportFormat, from: string, to: string, now: Date = new Date()): string {
  return `wam-report-${now.toISOString().slice(0, 10)}-${windowToken(from)}_${windowToken(to)}.${EXPORT_EXTENSION[format]}`;
}

/** Render a summary in one export format; the route picks the headers. */
export function renderReportSummary(data: ReportSummaryData, format: ReportExportFormat, options: RenderSummaryHtmlOptions): string {
  switch (format) {
    case 'html':
      return renderReportSummaryHtml(data, options);
    case 'csv':
      return renderReportSummaryCsv(data, options);
    case 'json':
      return renderReportSummaryJson(data, options);
    default:
      return renderReportSummaryMarkdown(data, options);
  }
}
