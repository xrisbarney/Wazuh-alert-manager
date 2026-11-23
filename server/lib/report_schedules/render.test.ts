import type { ReportSummaryData } from '../../../common';
import {
  bandLabel,
  buildReportSummaryDocument,
  CSV_BOM,
  escapeHtml,
  escapeMarkdown,
  renderReportSummary,
  renderReportSummaryCsv,
  renderReportSummaryHtml,
  renderReportSummaryJson,
  renderReportSummaryMarkdown,
  reportExportContentType,
  reportExportFilename,
  SEVERITY_BAND_HEX,
  truncateMarkdown,
  TRUNCATION_NOTE,
} from './render';
import { severityBandFilters } from './metrics';
import { SEVERITY_BANDS, bandFromLabel, bandFromLevel, labelsOfBand } from '../../../common/severity';

describe('severity bands come from the shared model', () => {
  test('bandLabel shows the numeric range of the shared table', () => {
    expect(bandLabel('informational')).toBe('Informational');
    expect(bandLabel('low')).toBe('Low (0-3)');
    expect(bandLabel('medium')).toBe('Medium (4-6)');
    expect(bandLabel('high')).toBe('High (7-11)');
    expect(bandLabel('critical')).toBe('Critical (12+)');
  });

  test('severityBandFilters matches every label alias and the numeric ranges, each exactly one band', () => {
    const filters = severityBandFilters();
    expect(Object.keys(filters)).toEqual([...SEVERITY_BANDS]);
    const labelsIn = (band: string): string[] => filters[band].bool.should.find((c: any) => c.terms)?.terms.severity_label;
    const rangeIn = (band: string): any => filters[band].bool.should.find((c: any) => c.range)?.range['rule.level'];
    for (const label of ['info', 'informational', 'minor', 'low', 'moderate', 'medium', 'major', 'high', 'severe', 'critical']) {
      const bands = SEVERITY_BANDS.filter((band) => labelsIn(band).includes(label));
      expect(bands).toEqual([bandFromLabel(label)]);
    }
    expect(labelsIn('informational')).toEqual(labelsOfBand('informational'));
    expect(rangeIn('informational')).toBeUndefined();
    expect(rangeIn('low')).toEqual({ gte: 0, lte: 3 });
    expect(rangeIn('critical')).toEqual({ gte: 12 });
    for (const level of [0, 3, 4, 6, 7, 11, 12, 16]) {
      const bands = SEVERITY_BANDS.filter((band) => {
        const range = rangeIn(band);
        return range && level >= range.gte && (range.lte == null || level <= range.lte);
      });
      expect(bands).toEqual([bandFromLevel(level)]);
    }
  });
});

const fixture: ReportSummaryData = {
  metrics: {
    from: '2026-11-13T08:00:00.000Z',
    to: '2026-11-20T08:00:00.000Z',
    totalAlerts: 120,
    exact: true,
    alertBasis: 'exact_cohort',
    timingBasis: 'exact_cohort',
    caseBasis: 'exact_cohort',
    coverage: { closedMissingReporting: 2, assignedMissingReporting: 0 },
    statusBreakdown: { open: 50, in_progress: 20, closed: 50 },
    alertsPerDay: [
      { date: '2026-11-19T00:00:00.000Z', count: 60 },
      { date: '2026-11-20T00:00:00.000Z', count: 60 },
    ],
    resolvedCount: 48,
    assignedCount: 70,
    meanTimeToResolveMinutes: 95.4,
    meanTimeToAssignMinutes: 12.2,
    slaCompliancePct: 87.5,
    slaBreakdown: [
      { label: 'critical', met: 10, breached: 2 },
      { label: 'high', met: 30, breached: 4 },
    ],
    slaPolicy: [],
    analysts: [
      { assignee: 'alice', total: 40, open: 10, in_progress: 5, closed: 25, resolvedCount: 25, meanTimeToResolveMinutes: 1500 },
      { assignee: 'bob|pipe', total: 30, open: 20, in_progress: 5, closed: 5, resolvedCount: 5, meanTimeToResolveMinutes: null },
    ],
    caseAnalysts: [],
    cases: {
      totalCases: 7,
      statusBreakdown: { open: 3, in_progress: 2, closed: 2 },
      severityBreakdown: { low: 1, medium: 2, high: 3, critical: 1 },
      meanTimeToCloseMinutes: 4000,
      closedCount: 2,
    },
  },
  extras: {
    severityBands: { informational: 0, low: 40, medium: 50, high: 25, critical: 5 },
    topRules: [
      { id: '5710', description: 'sshd: Attempt to login using a non-existent user', count: 33 },
      { id: '100002', description: '<script>alert(1)</script> | evil', count: 9 },
    ],
    topAgents: [
      { id: '001', name: 'web-01', count: 70 },
      { id: null, name: 'db-02', count: 50 },
    ],
    openCasesBySeverity: { low: 0, medium: 1, high: 3, critical: 1 },
    breachedCount: 6,
  },
};

const options = {
  schedule: { name: 'Weekly SOC summary', cadence: 'weekly' as const, rangeDays: 7 },
  from: fixture.metrics.from,
  to: fixture.metrics.to,
  generatedAt: '2026-11-20T08:00:05.000Z',
};

describe('renderReportSummaryMarkdown', () => {
  const md = renderReportSummaryMarkdown(fixture, options);

  test('has the title, range and every required section', () => {
    expect(md.startsWith('# Weekly SOC summary\n')).toBe(true);
    expect(md).toContain('Weekly SOC summary covering the 7 days from **2026-11-13T08:00:00.000Z** to **2026-11-20T08:00:00.000Z** (UTC)');
    for (const heading of ['## Alert volume', '## Status breakdown', '## SLA summary', '## Top rules', '## Top agents', '## Cases', '### Open cases by severity (now)', '## Analyst workload']) {
      expect(md).toContain(heading);
    }
  });

  test('renders the figures as GFM tables', () => {
    expect(md).toContain('Alerts in range: **120**.');
    expect(md).toContain('| Critical (12+) | 5 |');
    expect(md).toContain('| Informational | 0 |');
    expect(md).toContain('| In progress | 20 |');
    expect(md).toContain('| SLA compliance (resolved alerts) | 87.5% |');
    expect(md).toContain('| Mean time to resolve | 1.6 h |');
    expect(md).toContain('| Mean time to assign | 12 min |');
    expect(md).toContain('| SLA breached (resolved in range) | 6 |');
    expect(md).toContain('| critical | 10 | 2 |');
    expect(md).toContain('| 5710 | sshd: Attempt to login using a non-existent user | 33 |');
    expect(md).toContain('| web-01 | 001 | 70 |');
    expect(md).toContain('| db-02 | - | 50 |');
    expect(md).toContain('Cases opened in range: **7** (open 3, in progress 2, closed 2). Mean time to close: 2.8 d.');
    expect(md).toContain('| high | 3 |');
    expect(md).toContain('| 2026-11-19 | 60 |');
    expect(md).toContain('| alice | 10 | 5 | 25 | 1.0 d |');
    expect(md).toContain('_2 closed and 0 assigned alerts predate the reporting fields');
  });

  test('escapes pipes, angle brackets and backticks in values', () => {
    expect(md).toContain('| 100002 | &lt;script&gt;alert(1)&lt;/script&gt; \\| evil | 9 |');
    expect(md).toContain('| bob\\|pipe |');
    expect(md).not.toContain('<script>');
    expect(escapeMarkdown('a\nb`c\\d')).toBe('a b\\`c\\\\d');
  });

  test('empty inputs render placeholders instead of empty tables', () => {
    const empty = renderReportSummaryMarkdown(
      {
        metrics: { ...fixture.metrics, alertsPerDay: [], slaBreakdown: [], analysts: [], slaCompliancePct: null, meanTimeToResolveMinutes: null, coverage: { closedMissingReporting: 0, assignedMissingReporting: 0 } },
        extras: { ...fixture.extras, topRules: [], topAgents: [], breachedCount: null },
      },
      { ...options, schedule: { name: 'Daily', cadence: 'daily', rangeDays: 1 } }
    );
    expect(empty).toContain('Daily SOC summary covering the 1 day from');
    expect(empty).toContain('## Top rules\n\n_No alerts in range._');
    expect(empty).toContain('## Top agents\n\n_No alerts in range._');
    expect(empty).toContain('| SLA compliance (resolved alerts) | n/a |');
    expect(empty).toContain('| SLA breached (resolved in range) | n/a |');
    expect(empty).not.toContain('### Per day');
    expect(empty).not.toContain('## Analyst workload');
    expect(empty).not.toContain('predate the reporting fields');
  });
});

describe('truncateMarkdown', () => {
  test('keeps a document under the cap unchanged', () => {
    expect(truncateMarkdown('# ok\n', 100)).toEqual({ markdown: '# ok\n', truncated: false });
  });

  test('cuts at the byte cap without splitting a multi-byte character and appends the note', () => {
    const body = 'é'.repeat(200); // 400 bytes
    const cap = 100 + Buffer.byteLength(TRUNCATION_NOTE);
    const out = truncateMarkdown(body, cap);
    expect(out.truncated).toBe(true);
    expect(out.markdown.endsWith(TRUNCATION_NOTE)).toBe(true);
    expect(Buffer.byteLength(out.markdown)).toBeLessThanOrEqual(cap);
    expect(out.markdown).not.toContain('�');
    expect(out.markdown.slice(0, -TRUNCATION_NOTE.length)).toBe('é'.repeat(50));
    const odd = truncateMarkdown(body, 101 + Buffer.byteLength(TRUNCATION_NOTE));
    expect(odd.markdown.slice(0, -TRUNCATION_NOTE.length)).toBe('é'.repeat(50));
  });
});

describe('SLA enforcement block (step 3.4)', () => {
  const enforcement = {
    slaCurrentlyBreached: { asOf: '2026-11-20T08:00:00.000Z', alerts: 4, cases: 1, byBand: { critical: 3, high: 2, medium: 0, low: 0 } },
    slaBreachesInPeriod: { total: 9, alerts: 7, cases: 2 },
    slaEscalationsInPeriod: {
      total: 5,
      byEscalation: [
        { id: 'crit-unassigned', name: 'Critical | unassigned', count: 4 },
        { id: 'high-stale', name: 'High stale', count: 1 },
      ],
    },
  };

  test('renders the rows, the per-band table and the escalations by name', () => {
    const md = renderReportSummaryMarkdown({ ...fixture, metrics: { ...fixture.metrics, ...enforcement } }, options);
    expect(md).toContain('### SLA enforcement');
    expect(md).toContain('| Currently breached alerts (now) | 4 |');
    expect(md).toContain('| Currently breached cases (now) | 1 |');
    expect(md).toContain('| SLA breaches in period | 9 (7 alerts, 2 cases) |');
    expect(md).toContain('| Escalations in period | 5 |');
    expect(md).toContain('| Critical (12+) | 3 |');
    expect(md).toContain('| Low (0-3) | 0 |');
    expect(md).toContain('| Critical \\| unassigned | crit-unassigned | 4 |');
    expect(md).toContain('| High stale | high-stale | 1 |');
    expect(md.indexOf('### SLA enforcement')).toBeGreaterThan(md.indexOf('## SLA summary'));
    expect(md.indexOf('### SLA enforcement')).toBeLessThan(md.indexOf('## Top rules'));
  });

  test('no escalations in range renders a placeholder; a payload without the figures skips the block', () => {
    const md = renderReportSummaryMarkdown(
      { ...fixture, metrics: { ...fixture.metrics, ...enforcement, slaEscalationsInPeriod: { total: 0, byEscalation: [] } } },
      options
    );
    expect(md).toContain('| Escalations in period | 0 |');
    expect(md).toContain('_No escalations applied in range._');
    expect(renderReportSummaryMarkdown(fixture, options)).not.toContain('### SLA enforcement');
  });
});

describe('dispositions block (step 2.4)', () => {
  const withDispositions: ReportSummaryData = {
    ...fixture,
    metrics: {
      ...fixture.metrics,
      dispositions: { true_positive: 12, false_positive: 30, benign: 5, duplicate: 1, undetermined: 2 },
      falsePositiveByRule: [
        { rule_id: '5710', description: 'sshd: brute | force', closed: 40, false_positive: 30, rate: 0.75 },
        { rule_id: '100002', description: null, closed: 10, false_positive: 0, rate: 0 },
      ],
    },
  };

  test('renders the total, the per-disposition table and the false-positive rate by rule', () => {
    const md = renderReportSummaryMarkdown(withDispositions, options);
    expect(md).toContain('## Dispositions');
    expect(md).toContain('Alerts closed in range: **50**.');
    expect(md).toContain('| True positive | 12 |');
    expect(md).toContain('| False positive | 30 |');
    expect(md).toContain('| Undetermined | 2 |');
    expect(md).toContain('### False-positive rate by rule');
    expect(md).toContain('| 5710 | sshd: brute \\| force | 40 | 30 | 75.0% |');
    expect(md).toContain('| 100002 | - | 10 | 0 | 0.0% |');
    // Placed before the SLA summary so the outcome tables read in order.
    expect(md.indexOf('## Dispositions')).toBeLessThan(md.indexOf('## SLA summary'));
  });

  test('no closed alerts renders a placeholder; a payload without the figures skips the block', () => {
    const none = renderReportSummaryMarkdown(
      { ...fixture, metrics: { ...fixture.metrics, dispositions: { true_positive: 0, false_positive: 0, benign: 0, duplicate: 0, undetermined: 0 }, falsePositiveByRule: [] } },
      options
    );
    expect(none).toContain('Alerts closed in range: **0**.');
    expect(none).toContain('_No alerts closed in range._');
    expect(renderReportSummaryMarkdown(fixture, options)).not.toContain('## Dispositions');
  });
});

// ---------------------------------------------------------------------------
// Step 10.3: HTML / CSV / JSON exports built from the same section model
// ---------------------------------------------------------------------------

const exportOptions = { ...options, intro: 'SOC report over the selected window', generatedBy: 'analyst<1>' };

describe('buildReportSummaryDocument', () => {
  test('one section per heading of the Markdown summary, in the same order', () => {
    const doc = buildReportSummaryDocument(fixture, options);
    expect(doc.sections.map((s) => s.title)).toEqual(['Alert volume', 'Status breakdown', 'SLA summary', 'Top rules', 'Top agents', 'Cases', 'Analyst workload']);
    expect(doc.title).toBe('Weekly SOC summary');
    expect(doc.subtitle.map((r) => r.text).join('')).toBe(
      'Weekly SOC summary covering the 7 days from 2026-11-13T08:00:00.000Z to 2026-11-20T08:00:00.000Z (UTC). Generated 2026-11-20T08:00:05.000Z.'
    );
  });

  test('an intro and a generating user replace the cadence sentence (ad-hoc export)', () => {
    const doc = buildReportSummaryDocument(fixture, exportOptions);
    expect(doc.subtitle.map((r) => r.text).join('')).toBe(
      'SOC report over the selected window from 2026-11-13T08:00:00.000Z to 2026-11-20T08:00:00.000Z (UTC). Generated 2026-11-20T08:00:05.000Z by analyst<1>.'
    );
    expect(renderReportSummaryMarkdown(fixture, exportOptions)).toContain('SOC report over the selected window from **2026-11-13T08:00:00.000Z**');
  });
});

describe('renderReportSummaryHtml', () => {
  const html = renderReportSummaryHtml(fixture, exportOptions);

  test('is a self-contained page without scripts, with inline CSS and a print stylesheet', () => {
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('<meta charset="utf-8">');
    expect(html).toContain('<style>');
    expect(html).toContain('@media print');
    expect(html).toContain('page-break-before: always');
    expect(html).not.toContain('<script');
    expect(html).not.toMatch(/<link|src=|url\(/);
  });

  test('has every section as <section> with <table> figures and the band swatches', () => {
    for (const id of ['alert-volume', 'status-breakdown', 'sla-summary', 'top-rules', 'top-agents', 'cases', 'analyst-workload']) {
      expect(html).toContain(`<section class="wam-report-section" id="${id}">`);
    }
    expect(html).toContain('<h2>Alert volume</h2>');
    expect(html).toContain('<p>Alerts in range: <strong>120</strong>.</p>');
    expect(html).toContain('<th>Severity band</th><th>Alerts</th>');
    expect(html).toContain(`style="background:${SEVERITY_BAND_HEX.critical}" aria-hidden="true"></span>Critical (12+)</td><td class="wam-report-num">5</td>`);
    expect(html).toContain(`style="background:${SEVERITY_BAND_HEX.low}"`);
    expect(html).toContain('<td>In progress</td><td class="wam-report-num">20</td>');
    expect(html).toContain('<td>SLA compliance (resolved alerts)</td><td>87.5%</td>');
    expect(html).toContain('<td>5710</td><td>sshd: Attempt to login using a non-existent user</td><td class="wam-report-num">33</td>');
    expect(html).toContain('<td>db-02</td><td>-</td><td class="wam-report-num">50</td>');
    expect(html).toContain('<h3>Open cases by severity (now)</h3>');
    expect(html).toContain(`style="background:${SEVERITY_BAND_HEX.high}" aria-hidden="true"></span>high</td><td class="wam-report-num">3</td>`);
    expect(html).toContain('<td>alice</td>');
    expect(html).toContain('class="wam-report-note">2 closed and 0 assigned alerts predate the reporting fields');
  });

  test('header carries the window and the generating user; footer the plugin version', () => {
    expect(html).toContain('<h1>Weekly SOC summary</h1>');
    expect(html).toContain('from <strong>2026-11-13T08:00:00.000Z</strong> to <strong>2026-11-20T08:00:00.000Z</strong> (UTC). Generated 2026-11-20T08:00:05.000Z by analyst&lt;1&gt;.');
    const versioned = renderReportSummaryHtml(fixture, { ...exportOptions, pluginVersion: '9.9.9' });
    expect(versioned).toContain('<footer class="wam-report-footer">Wazuh Alert Manager 9.9.9 &middot; window 2026-11-13T08:00:00.000Z to 2026-11-20T08:00:00.000Z');
    expect(html).toMatch(/<footer class="wam-report-footer">Wazuh Alert Manager \d+\.\d+\.\d+/);
  });

  test('escapes every value, including the title', () => {
    const hostile = renderReportSummaryHtml(fixture, { ...exportOptions, schedule: { ...options.schedule, name: '<img src=x onerror=alert(1)>' } });
    expect(hostile).not.toContain('<script>');
    expect(hostile).not.toContain('<img');
    expect(hostile).toContain('<title>&lt;img src=x onerror=alert(1)&gt;</title>');
    expect(hostile).toContain('&lt;script&gt;alert(1)&lt;/script&gt; | evil');
    expect(hostile).toContain('<td>bob|pipe</td>');
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
  });

  test('print mode embeds exactly one nonce-stamped window.print() trigger', () => {
    const print = renderReportSummaryHtml(fixture, { ...exportOptions, print: true, nonce: 'abc"123' });
    expect(print.match(/<script/g)).toHaveLength(1);
    expect(print).toContain('<script nonce="abc&quot;123">window.addEventListener("load",function(){window.print();});</script>');
    expect(renderReportSummaryHtml(fixture, { ...exportOptions, print: false, nonce: 'abc' })).not.toContain('<script');
  });
});

describe('renderReportSummaryCsv', () => {
  const csv = renderReportSummaryCsv(fixture, exportOptions);

  test('starts with the UTF-8 BOM and a title block, then one titled block per section', () => {
    expect(csv.startsWith(CSV_BOM)).toBe(true);
    const lines = csv.slice(1).split('\r\n');
    expect(lines[0]).toBe('Weekly SOC summary');
    expect(lines).toContain('From,2026-11-13T08:00:00.000Z');
    expect(lines).toContain('To,2026-11-20T08:00:00.000Z');
    expect(lines).toContain('Generated by,analyst<1>');
    for (const title of ['# Alert volume', '# Status breakdown', '# SLA summary', '# Top rules', '# Top agents', '# Cases', '# Analyst workload']) {
      expect(lines).toContain(title);
    }
    expect(lines.indexOf('# Alert volume')).toBeLessThan(lines.indexOf('# Status breakdown'));
    // Blocks are separated by an empty record.
    expect(lines[lines.indexOf('# Status breakdown') - 1]).toBe('');
  });

  test('tables are header + rows with plain band labels; paragraphs are single cells', () => {
    const lines = csv.slice(1).split('\r\n');
    expect(lines).toContain('Severity band,Alerts');
    expect(lines).toContain('Critical (12+),5');
    expect(lines).toContain('Alerts in range: 120.');
    expect(lines).toContain('Status,Alerts');
    expect(lines).toContain('In progress,20');
    expect(lines).toContain('## Per day');
    expect(lines).toContain('2026-11-19,60');
    expect(lines).toContain('Rule,Description,Alerts');
    expect(lines).toContain('5710,sshd: Attempt to login using a non-existent user,33');
    expect(lines).toContain('db-02,,50');
    expect(lines).toContain('high,3');
    expect(lines).toContain('alice,10,5,25,1.0 d');
  });

  test('guards formula-leading and quoted cells', () => {
    const hostile = renderReportSummaryCsv(
      { ...fixture, extras: { ...fixture.extras, topRules: [{ id: '=cmd|calc', description: 'say "hi", twice', count: 1 }] } },
      exportOptions
    );
    expect(hostile).toContain('"\'=cmd|calc","say ""hi"", twice",1\r\n');
    expect(csv).toContain('<script>alert(1)</script> | evil');
  });
});

describe('renderReportSummaryJson', () => {
  test('carries the raw metrics and extras with the window, generated_at and the user', () => {
    const parsed = JSON.parse(renderReportSummaryJson(fixture, { ...exportOptions, pluginVersion: '1.2.3' }));
    expect(parsed).toEqual({
      generated_at: '2026-11-20T08:00:05.000Z',
      generated_by: 'analyst<1>',
      plugin_version: '1.2.3',
      window: { from: fixture.metrics.from, to: fixture.metrics.to },
      metrics: fixture.metrics,
      extras: fixture.extras,
    });
    expect(JSON.parse(renderReportSummaryJson(fixture, options)).generated_by).toBeNull();
  });
});

describe('export helpers', () => {
  test('renderReportSummary dispatches on the format', () => {
    expect(renderReportSummary(fixture, 'html', exportOptions)).toBe(renderReportSummaryHtml(fixture, exportOptions));
    expect(renderReportSummary(fixture, 'markdown', exportOptions)).toBe(renderReportSummaryMarkdown(fixture, exportOptions));
    expect(renderReportSummary(fixture, 'csv', exportOptions)).toBe(renderReportSummaryCsv(fixture, exportOptions));
    expect(renderReportSummary(fixture, 'json', exportOptions)).toBe(renderReportSummaryJson(fixture, exportOptions));
  });

  test('content types per format', () => {
    expect(reportExportContentType('html')).toBe('text/html; charset=utf-8');
    expect(reportExportContentType('markdown')).toBe('text/markdown; charset=utf-8');
    expect(reportExportContentType('csv')).toBe('text/csv; charset=utf-8');
    expect(reportExportContentType('json')).toBe('application/json; charset=utf-8');
  });

  test('reportExportFilename is wam-report-<date>-<from>_<to>.<ext> with ISO bounds reduced to their day', () => {
    const now = new Date('2026-11-21T10:30:00.000Z');
    expect(reportExportFilename('html', 'now-7d', 'now', now)).toBe('wam-report-2026-11-21-now-7d_now.html');
    expect(reportExportFilename('markdown', '2026-11-14T00:00:00.000Z', '2026-11-21T00:00:00.000Z', now)).toBe('wam-report-2026-11-21-2026-11-14_2026-11-21.md');
    expect(reportExportFilename('csv', 'now-30d/d', 'now/d', now)).toBe('wam-report-2026-11-21-now-30d-d_now-d.csv');
    expect(reportExportFilename('json', '../../etc', '', now)).toBe('wam-report-2026-11-21-etc_x.json');
    expect(reportExportFilename('json', 'a'.repeat(60), 'b', now)).toBe(`wam-report-2026-11-21-${'a'.repeat(24)}_b.json`);
  });
});
