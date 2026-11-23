import { ACTIVITY_READ_ALIAS, ATTACHMENTS_INDEX, CASES_INDEX, CASE_REPORT_LISTED_ALERTS, MAX_CASE_REPORT_ALERTS } from '../../common';
import {
  CaseReportData,
  caseReportFilename,
  collectCaseReportData,
  collectCaseTimeline,
  collectEnrichmentRows,
  collectMitreRows,
  escapeHtml,
  escapeMarkdownCell,
  projectTasks,
  readCaseAttachments,
  renderCaseReportHtml,
  renderCaseReportMarkdown,
} from './case_report';
import { buildAttackGraph } from './attack_graph';
import { layoutAttackGraph, renderAttackGraphSvg } from './attack_graph_svg';

const CASE_INDEX = 'wazuh-alert-manager-v2-cases-000001';
const ALERT_INDEX = 'wazuh-alert-status-v2-000001';
const ts = (h: number) => `2026-11-20T${String(h).padStart(2, '0')}:00:00.000Z`;

const ALERTS: Record<string, any> = {
  a1: {
    '@timestamp': ts(1),
    status: 'open',
    agent: { id: '001', name: 'web-01' },
    rule: { id: '5710', level: 5, description: 'sshd: attempt to login using a non-existent user', mitre: { id: ['T1110'], technique: ['Brute Force'], tactic: ['Credential Access'] } },
    data: { srcip: '203.0.113.77', srcuser: 'bob' },
    enrichment: {
      updated_at: ts(3),
      worst_verdict: 'malicious',
      items: [{ type: 'ip', value: '203.0.113.77', source: 'abuseipdb', verdict: 'malicious', score: 90, tags: ['ssh'], link: null, checked_at: ts(3) }],
    },
  },
  a2: {
    '@timestamp': ts(2),
    status: 'in_progress',
    agent: { id: '001', name: 'web-01' },
    rule: { id: '5712', level: 10, description: 'sshd: brute force trying to get access', mitre: { id: ['T1110'], technique: ['Brute Force'], tactic: ['Credential Access'] } },
    data: { srcip: '203.0.113.77', srcuser: 'bob' },
    enrichment: {
      updated_at: ts(4),
      worst_verdict: 'malicious',
      items: [{ type: 'ip', value: '203.0.113.77', source: 'abuseipdb', verdict: 'malicious', score: 95, tags: ['ssh', 'scan'], link: null, checked_at: ts(4) }],
    },
  },
  a3: {
    '@timestamp': ts(5),
    status: 'closed',
    agent: { id: '002', name: 'db-01 <internal>' },
    rule: { id: '92000', level: 12, description: 'Lateral | movement to database host', mitre: { id: ['T1021'], technique: ['Remote Services'], tactic: ['Lateral Movement'] } },
    data: { srcuser: 'bob', dstuser: 'postgres' },
  },
};

function fakeClient(overrides: { caseSource?: any; activity?: any[]; attachments?: any[] | 'missing' | Error; evidenceIds?: string[] } = {}) {
  const evidenceIds = overrides.evidenceIds ?? ['a1', 'a2', 'a3'];
  const caseSource = {
    case_uid: 'uid-c1',
    title: 'Brute force <script>alert(1)</script> | pivot',
    description: 'Analyst notes with | pipe and <b>html</b>',
    status: 'closed',
    severity: 'high',
    assigned_to: 'alice',
    created_by: 'bob',
    created_at: ts(0),
    updated_at: ts(6),
    closed_at: ts(7),
    alert_ids: evidenceIds,
    ...(overrides.caseSource || {}),
  };
  const activity = overrides.activity ?? [
    { _id: 'cm1', _source: { event_type: 'comment', case_id: 'c1', author: 'alice', text: 'Blocked the source | at the firewall', created_at: ts(3) } },
    { _id: 'au1', _source: { event_type: 'audit', case_id: 'c1', user: 'alice', action: 'status_change', from: 'open', to: 'closed', created_at: ts(7) } },
  ];
  const search = jest.fn(async (request: any) => {
    const index = request.index;
    if (index === CASES_INDEX) {
      return { body: { hits: { total: { value: 1 }, hits: [{ _id: 'c1', _index: CASE_INDEX, _source: caseSource }] } } };
    }
    if (typeof index === 'string' && index.startsWith('wazuh-alert-manager-v2-evidence')) {
      return {
        body: {
          hits: {
            total: { value: evidenceIds.length },
            hits: evidenceIds.map((id) => ({ _id: `ev-${id}`, _source: { case_id: 'c1', alert_id: id, relationship_state: 'linked', snapshot: ALERTS[id] }, sort: [1, id] })),
          },
        },
      };
    }
    if (typeof index === 'string' && index.startsWith('wazuh-alert-status-v2')) {
      const ids: string[] = request.body?.query?.ids?.values || [];
      return { body: { hits: { total: { value: ids.length }, hits: ids.filter((id) => ALERTS[id]).map((id) => ({ _id: id, _index: ALERT_INDEX, _source: ALERTS[id] })) } } };
    }
    if (index === ACTIVITY_READ_ALIAS) {
      const filters = request.body?.query?.bool?.filter || [];
      const commentsOnly = filters.some((f: any) => f.term?.event_type === 'comment');
      return { body: { hits: { hits: activity.filter((hit) => !commentsOnly || hit._source.event_type === 'comment') } } };
    }
    if (index === ATTACHMENTS_INDEX) {
      const attachments = overrides.attachments ?? 'missing';
      if (attachments === 'missing') throw { meta: { statusCode: 404, body: { error: { type: 'index_not_found_exception' } } } };
      if (attachments instanceof Error) throw attachments;
      return { body: { hits: { hits: attachments } } };
    }
    throw new Error(`unexpected index ${index}`);
  });
  return { search, get: jest.fn(async () => { throw { meta: { statusCode: 404 } }; }) };
}

describe('escaping', () => {
  test('escapeHtml neutralises every markup character', () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&</a>`)).toBe('&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(42)).toBe('42');
  });

  test('escapeMarkdownCell escapes pipes, backslashes, html and line breaks', () => {
    expect(escapeMarkdownCell('a | b')).toBe('a \\| b');
    expect(escapeMarkdownCell('c:\\x')).toBe('c:\\\\x');
    expect(escapeMarkdownCell('<img>')).toBe('&lt;img&gt;');
    expect(escapeMarkdownCell('one\r\ntwo\nthree')).toBe('one<br>two<br>three');
  });
});

describe('attack graph SVG', () => {
  const graph = buildAttackGraph(Object.entries(ALERTS).map(([id, source]) => ({ _id: id, _source: source })));

  test('lays the three entity types out in deterministic columns', () => {
    const layout = layoutAttackGraph(graph);
    expect(layout.layers.map((layer) => layer.type)).toEqual(['host', 'user', 'technique']);
    const hosts = layout.nodes.filter((node) => node.type === 'host').map((node) => node.label);
    expect(hosts).toEqual(['web-01', 'db-01 <internal>']); // 2 alerts before 1
    expect(layout.nodes.find((node) => node.id === 'user:bob')?.layer).toBe(1);
    expect(layout.edges.find((edge) => edge.source === 'host:web-01' && edge.target === 'user:bob')?.count).toBe(2);
    expect(layoutAttackGraph(graph)).toEqual(layout);
  });

  test('renders every node and merged edge, escaped, with no script or external reference', () => {
    const svg = renderAttackGraphSvg(graph);
    expect(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"')).toBe(true);
    expect(svg.endsWith('</svg>')).toBe(true);
    for (const node of graph.nodes) expect(svg).toContain(`data-node-id="${escapeHtml(node.id)}"`);
    expect(svg).toContain('db-01 &lt;internal&gt;');
    expect(svg).not.toContain('<internal>');
    expect((svg.match(/<line /g) || []).length).toBe(layoutAttackGraph(graph).edges.length);
    expect(svg).toContain('data-source="host:web-01" data-target="user:bob" data-count="2"');
    expect(svg).not.toMatch(/<script|href=|xlink:|url\(/i);
  });

  test('renders an empty placeholder for a graph without entities', () => {
    const svg = renderAttackGraphSvg(buildAttackGraph([]));
    expect(svg).toContain('wam-attack-graph-empty');
    expect(svg).not.toContain('<line');
  });

  test('keeps the top maxNodesPerLayer nodes per layer, drops their edges and draws one overflow box', () => {
    const many = Array.from({ length: 150 }, (_, i) => ({
      _id: `m${i}`,
      _source: {
        '@timestamp': ts(1),
        agent: { id: String(i), name: `host-${String(i).padStart(3, '0')}` },
        rule: { id: '1', level: 3, description: 'd', mitre: { id: ['T1110'], technique: ['Brute Force'], tactic: ['Credential Access'] } },
        data: { srcuser: i < 5 ? 'root' : `user-${i}` },
      },
    }));
    const bigGraph = buildAttackGraph(many);
    expect(bigGraph.nodes.filter((n) => n.type === 'host')).toHaveLength(150);

    const layout = layoutAttackGraph(bigGraph);
    expect(layout.nodes.filter((n) => n.type === 'host')).toHaveLength(60);
    expect(layout.nodes.filter((n) => n.type === 'user')).toHaveLength(60);
    expect(layout.dropped).toEqual([
      { type: 'host', count: 90 },
      { type: 'user', count: 146 - 60 },
    ]);
    expect(layout.overflow.map((box) => box.label)).toEqual(['+90 more hosts', `+${146 - 60} more users`]);
    // root (5 alerts) is kept, so it ranks first among users; every edge endpoint is a drawn node.
    expect(layout.nodes.find((n) => n.type === 'user' && n.row === 0)?.label).toBe('root');
    const drawn = new Set(layout.nodes.map((n) => n.id));
    for (const edge of layout.edges) {
      expect(drawn.has(edge.source)).toBe(true);
      expect(drawn.has(edge.target)).toBe(true);
    }
    // Bounded height: 60 rows + the overflow row (61 x 36px boxes, 60 x 16px gaps, 24px padding, 28px title), not 150 rows.
    expect(layout.height).toBe(24 * 2 + 28 + 61 * 36 + 60 * 16);
    expect(layout.height).toBeLessThan(layoutAttackGraph(bigGraph, { maxNodesPerLayer: 150 }).height);

    const svg = renderAttackGraphSvg(bigGraph);
    expect((svg.match(/<g class="wam-attack-graph-node /g) || []).length).toBe(121);
    expect(svg).toContain('data-dropped="90"');
    expect(svg).toContain('+90 more hosts');

    const full = layoutAttackGraph(bigGraph, { maxNodesPerLayer: 1000 });
    expect(full.dropped).toEqual([]);
    expect(full.overflow).toEqual([]);
    expect(full.nodes).toHaveLength(bigGraph.nodes.length);
  });
});

describe('aggregations', () => {
  const alerts = Object.entries(ALERTS).map(([id, source]) => ({ _id: id, _source: source }));

  test('collectEnrichmentRows coerces the newest-wins fields exactly like the first occurrence', () => {
    const rows = collectEnrichmentRows([
      { _id: 'x1', _source: { enrichment: { items: [{ type: 'ip', value: '198.51.100.9', source: 's', verdict: 'clean', score: 1, tags: ['a'], link: 'https://x', checked_at: ts(1) }] } } },
      {
        _id: 'x2',
        _source: {
          enrichment: {
            items: [
              {
                type: 'ip', value: '198.51.100.9', source: 's',
                verdict: 'owned', score: { __html: '<img src=x onerror=alert(1)>' }, tags: 'single', link: { __html: 'x' }, checked_at: ts(2),
              },
            ],
          },
        },
      },
    ]);
    expect(rows).toEqual([
      expect.objectContaining({ value: '198.51.100.9', verdict: 'unknown', score: null, tags: ['single'], link: null, checked_at: ts(2), alertCount: 2 }),
    ]);
  });

  test('a stored object carrying an __html key is escaped, never emitted as markup', () => {
    const data: CaseReportData = {
      generatedAt: '2026-11-20T12:00:00.000Z',
      case: { id: 'c1', uid: null, title: 'T', status: 'open', severity: 'low', assignee: null, createdBy: null, createdAt: null, updatedAt: null, closedAt: null, description: null, disposition: null, closureReason: null },
      tasks: null,
      timeline: { entries: [], limit: 500, truncated: false },
      alerts: { listed: [], included: 0, totalRelationships: 0, truncated: false, limit: 5000, listedLimit: CASE_REPORT_LISTED_ALERTS },
      indicators: [],
      enrichment: [{ type: 'ip', value: '198.51.100.9', source: 's', verdict: 'clean', score: { __html: '<img src=x onerror=alert(1)>' } as any, tags: [], link: null, checked_at: '', alertCount: 1 }],
      attachments: { items: [], available: true }, comments: { items: [], truncated: false },
      graph: buildAttackGraph([]), graphSvg: renderAttackGraphSvg(buildAttackGraph([])), graphDropped: [], mitre: [],
    };
    const html = renderCaseReportHtml(data);
    expect(html).not.toContain('<img');
    expect(html).toContain('[object Object]');
  });

  test('collectEnrichmentRows merges per (source, type, value), newest verdict wins, counts alerts', () => {
    const rows = collectEnrichmentRows(alerts);
    expect(rows).toEqual([expect.objectContaining({ value: '203.0.113.77', source: 'abuseipdb', verdict: 'malicious', score: 95, tags: ['ssh', 'scan'], checked_at: ts(4), alertCount: 2 })]);
  });

  test('collectMitreRows aggregates tactic x technique in kill-chain order', () => {
    const rows = collectMitreRows(alerts, buildAttackGraph(alerts));
    expect(rows).toEqual([
      { tactic: 'Credential Access', techniqueId: 'T1110', technique: 'Brute Force', alertCount: 2 },
      { tactic: 'Lateral Movement', techniqueId: 'T1021', technique: 'Remote Services', alertCount: 1 },
    ]);
    expect(collectMitreRows([{ _id: 'x', _source: { rule: { mitre: { id: 'T1', technique: 'Scalar', tactic: 'Impact' } } } }], buildAttackGraph([]))).toEqual([
      { tactic: 'Impact', techniqueId: 'T1', technique: 'Scalar', alertCount: 1 },
    ]);
  });

  test('projectTasks keeps order and omits the section when the field is absent', () => {
    expect(projectTasks(undefined)).toBeNull();
    expect(projectTasks([{ id: 't2', title: 'Second', order: 2, done: true, done_by: 'bob', done_at: ts(1) }, { id: 't1', title: 'First', order: 1 }, null])).toEqual([
      expect.objectContaining({ id: 't1', title: 'First', done: false }),
      expect.objectContaining({ id: 't2', title: 'Second', done: true, doneBy: 'bob', doneAt: ts(1) }),
    ]);
  });
});

describe('collectCaseTimeline', () => {
  test('merges alert timestamps, comments and audit events in chronological order', async () => {
    const client = fakeClient();
    const result = await collectCaseTimeline(client, 'c1', { limit: 10 });
    expect(result.entries.map((entry) => [entry.kind, entry.timestamp])).toEqual([
      ['alert', ts(1)], ['alert', ts(2)], ['comment', ts(3)], ['alert', ts(5)], ['audit', ts(7)],
    ]);
    expect(result.entries[2]).toEqual(expect.objectContaining({ actor: 'alice', summary: 'Blocked the source | at the firewall', refId: 'cm1' }));
    expect(result.entries[4].summary).toBe('status change: open \u2192 closed');
    expect(result.entries[0].summary).toContain('rule 5710');
    expect(result.truncated).toBe(false);
    const activityCall = client.search.mock.calls.find(([request]: any[]) => request.index === ACTIVITY_READ_ALIAS);
    expect(activityCall[0].body.query).toEqual({ bool: { filter: [{ term: { case_id: 'c1' } }] } });
    expect(activityCall[0].body.size).toBe(6); // two pages of ceil(10 / 2) at most
  });

  test('caps the merged list and flags truncation', async () => {
    const result = await collectCaseTimeline(fakeClient(), 'c1', { limit: 2 });
    expect(result.entries).toHaveLength(2);
    expect(result.truncated).toBe(true);
  });
});

describe('readCaseAttachments', () => {
  test('treats a missing index as "not available" and other failures as errors', async () => {
    await expect(readCaseAttachments(fakeClient({ attachments: 'missing' }), 'c1')).resolves.toEqual({ items: [], available: false });
    await expect(readCaseAttachments(fakeClient({ attachments: new Error('boom') }), 'c1')).rejects.toThrow('boom');
    const client = fakeClient({ attachments: [{ _id: 'at1', _source: { kind: 'link', name: 'PCAP', url: 'https://evidence.example/pcap', size: 2048, created_by: 'alice', created_at: ts(2) } }] });
    const result = await readCaseAttachments(client, 'c1');
    expect(result).toEqual({ available: true, items: [expect.objectContaining({ id: 'at1', kind: 'link', name: 'PCAP', size: 2048, createdBy: 'alice' })] });
    const call = client.search.mock.calls.find(([request]: any[]) => request.index === ATTACHMENTS_INDEX);
    expect(call[0].body._source).toEqual({ excludes: ['data'] });
  });
});

describe('collectCaseReportData + renderers', () => {
  const now = new Date('2026-11-20T12:00:00.000Z');

  test('reads the case once and derives every section from the resolved alerts', async () => {
    const client = fakeClient();
    const data = await collectCaseReportData(client, 'c1', now);
    expect(data.case).toEqual(expect.objectContaining({ id: 'c1', uid: 'uid-c1', status: 'closed', severity: 'high', assignee: 'alice', closedAt: ts(7), disposition: null, closureReason: null }));
    expect(data.tasks).toBeNull();
    expect(data.alerts).toEqual(expect.objectContaining({ included: 3, totalRelationships: 3, truncated: false, listedLimit: CASE_REPORT_LISTED_ALERTS }));
    expect(data.alerts.listed.map((alert) => alert.id)).toEqual(['a1', 'a2', 'a3']);
    expect(data.alerts.listed[2]).toEqual(expect.objectContaining({ level: 12, agentName: 'db-01 <internal>', availability: 'live' }));
    expect(data.indicators.find((ind) => ind.type === 'ip' && ind.value === '203.0.113.77')?.count).toBe(2);
    expect(data.enrichment).toHaveLength(1);
    expect(data.mitre).toHaveLength(2);
    expect(data.graph.nodes.length).toBeGreaterThan(0);
    expect(data.graphSvg).toContain('<svg');
    expect(data.attachments).toEqual({ items: [], available: false });
    expect(data.comments.items).toEqual([expect.objectContaining({ author: 'alice' })]);
    expect(data.timeline.entries).toHaveLength(5);
    expect(client.search.mock.calls.filter(([request]: any[]) => request.index === CASES_INDEX)).toHaveLength(1);
  });

  test('404s for an unknown case', async () => {
    const client = fakeClient();
    client.search.mockImplementation(async (request: any) => {
      if (request.index === CASES_INDEX) return { body: { hits: { total: { value: 0 }, hits: [] } } };
      throw new Error('unexpected');
    });
    await expect(collectCaseReportData(client, 'nope', now)).rejects.toMatchObject({ statusCode: 404 });
  });

  test('markdown has every section, GFM tables with escaped pipes and no raw html', async () => {
    const data = await collectCaseReportData(fakeClient(), 'c1', now);
    const md = renderCaseReportMarkdown(data);
    for (const heading of ['# Case report:', '## Summary', '### Description', '## Timeline', '## Linked alerts (3)', '## Indicators', '## Enrichment verdicts', '## MITRE ATT&CK', '## Attack graph', '## Attachments', '## Comments']) {
      expect(md).toContain(heading);
    }
    expect(md).not.toContain('## Disposition');
    expect(md).not.toContain('## Tasks');
    expect(md).toContain('Lateral \\| movement to database host');
    expect(md).toContain('Blocked the source | at the firewall'); // comments are block quotes, not cells
    expect(md).not.toContain('<script>');
    expect(md).toContain('&lt;script&gt;');
    expect(md).toContain('| Tactic | Technique id | Technique | Alerts |');
    expect(md).toContain('| Credential Access | T1110 | Brute Force | 2 |');
    expect(md).toContain('_Attachments are not available on this installation._');
  });

  test('html is self-contained, escaped, carries the print stylesheet and the inline SVG', async () => {
    const data = await collectCaseReportData(fakeClient(), 'c1', now);
    const html = renderCaseReportHtml(data);
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('@media print');
    expect(html).toContain('<svg xmlns="http://www.w3.org/2000/svg"');
    expect(html).not.toContain('<script');
    expect(html).not.toMatch(/<link\b|src=|url\(/i);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('Analyst notes with | pipe and &lt;b&gt;html&lt;/b&gt;');
    expect(html).toContain('<title>Case report: Brute force &lt;script&gt;alert(1)&lt;/script&gt; | pivot</title>');
    expect(html).toContain('wam-report-badge--closed');
    expect(html).not.toContain('<h2>Disposition</h2>');
    expect(html).not.toContain('<h2>Tasks</h2>');
    expect(html).toContain('db-01 &lt;internal&gt;');
  });

  test('print=1 adds exactly one inline window.print() trigger', async () => {
    const data = await collectCaseReportData(fakeClient(), 'c1', now);
    const html = renderCaseReportHtml(data, { print: true });
    expect((html.match(/<script>/g) || []).length).toBe(1);
    expect(html).toContain('window.print()');
  });

  test('disposition, closure reason and tasks render only when present on the case doc', async () => {
    const client = fakeClient({
      caseSource: {
        disposition: 'false_positive',
        closure_reason: 'Scanner | from the <vuln> team',
        tasks: [{ id: 't1', title: 'Confirm <scope>', owner: 'alice', done: false, order: 1 }, { id: 't2', title: 'Notify', done: true, done_by: 'bob', done_at: ts(6), order: 2 }],
      },
    });
    const data = await collectCaseReportData(client, 'c1', now);
    const md = renderCaseReportMarkdown(data);
    const html = renderCaseReportHtml(data);
    expect(md).toContain('## Disposition');
    expect(md).toContain('- Disposition: false_positive');
    expect(md).toContain('- Closure reason: Scanner | from the &lt;vuln&gt; team');
    expect(md).toContain('- [ ] Confirm &lt;scope&gt; (owner alice)');
    expect(md).toContain('- [x] Notify (done 2026-11-20T06:00:00.000Z by bob)');
    expect(html).toContain('<h2>Disposition</h2>');
    expect(html).toContain('wam-report-badge--false_positive');
    expect(html).toContain('Scanner | from the &lt;vuln&gt; team');
    expect(html).toContain('<h2>Tasks</h2>');
    expect(html).toContain('Confirm &lt;scope&gt;');
  });

  test('an empty case renders the empty states without throwing', async () => {
    const client = fakeClient({ evidenceIds: [], activity: [] });
    client.search.mockImplementation(async (request: any) => {
      if (request.index === CASES_INDEX) return { body: { hits: { total: { value: 1 }, hits: [{ _id: 'c1', _index: CASE_INDEX, _source: { title: 'Empty', status: 'open', alert_ids: [] } }] } } };
      if (String(request.index).startsWith('wazuh-alert-manager-v2-evidence')) return { body: { hits: { total: { value: 0 }, hits: [] } } };
      if (request.index === ACTIVITY_READ_ALIAS) return { body: { hits: { hits: [] } } };
      if (request.index === ATTACHMENTS_INDEX) throw { statusCode: 404 };
      throw new Error(`unexpected ${request.index}`);
    });
    const data: CaseReportData = await collectCaseReportData(client, 'c1', now);
    expect(data.alerts.included).toBe(0);
    const md = renderCaseReportMarkdown(data);
    expect(md).toContain('_No alerts are linked to this case._');
    expect(md).toContain('_No comments._');
    expect(renderCaseReportHtml(data)).toContain('wam-attack-graph-empty');
  });

  test('lists every resolved alert up to the evidence cap and flags the cut', () => {
    expect(CASE_REPORT_LISTED_ALERTS).toBe(MAX_CASE_REPORT_ALERTS);
    const fixtureAlerts = Object.entries(ALERTS).map(([id, source]) => ({ _id: id, _source: source }));
    const listed = Array.from({ length: CASE_REPORT_LISTED_ALERTS }, (_, i) => ({
      id: `a${i}`, timestamp: ts(1), status: 'open', assignee: null, ruleId: '1', ruleDescription: 'd', level: 3, severityLabel: null, agentName: 'h', agentId: '1', srcip: null, dstip: null, availability: 'live' as const,
    }));
    const data: CaseReportData = {
      generatedAt: now.toISOString(),
      case: { id: 'c1', uid: null, title: 'Big', status: 'open', severity: 'low', assignee: null, createdBy: null, createdAt: null, updatedAt: null, closedAt: null, description: null, disposition: null, closureReason: null },
      tasks: null,
      timeline: { entries: [], limit: 500, truncated: true },
      alerts: { listed, included: 5000, totalRelationships: 5000, truncated: true, limit: 5000, listedLimit: CASE_REPORT_LISTED_ALERTS },
      indicators: [], enrichment: [], attachments: { items: [], available: true }, comments: { items: [], truncated: false },
      graph: buildAttackGraph(fixtureAlerts), graphSvg: renderAttackGraphSvg(buildAttackGraph(fixtureAlerts)), graphDropped: [{ type: 'host', count: 12 }], mitre: [],
    };
    const md = renderCaseReportMarkdown(data);
    expect(md).toContain('## Linked alerts (5000+)');
    expect((md.match(/^\| 2026-11-20T01:00:00\.000Z \| a\d+ \|/gm) || []).length).toBe(MAX_CASE_REPORT_ALERTS);
    expect(md).not.toContain('not listed');
    expect(md).toContain('_The case links more than 5000 alerts');
    expect(md).toContain('_Timeline capped at 500 entries._');
    expect(md).toContain('12 more hosts not drawn');
    const html = renderCaseReportHtml(data);
    expect((html.match(/<tr><td>2026-11-20T01:00:00\.000Z<\/td><td>a\d+<\/td>/g) || []).length).toBe(MAX_CASE_REPORT_ALERTS);
    expect(html).not.toContain('not listed');
    expect(html).toContain('12 more hosts not drawn');

    // Fewer resolved records than relationships (an unresolvable alert) still gets the note.
    const partial = { ...data, alerts: { ...data.alerts, listed: listed.slice(0, 10), totalRelationships: 11, truncated: false } };
    expect(renderCaseReportMarkdown(partial)).toContain(`_1 more alert not listed (the report lists at most ${CASE_REPORT_LISTED_ALERTS})._`);
  });

  test('the print script carries the nonce and nothing else is scripted', () => {
    const client = fakeClient();
    return collectCaseReportData(client, 'c1', now).then((data) => {
      const html = renderCaseReportHtml(data, { print: true, nonce: 'abc"<>' });
      expect(html).toContain('<script nonce="abc&quot;&lt;&gt;">window.addEventListener("load",function(){window.print();});</script>');
      expect((html.match(/<script/g) || []).length).toBe(1);
      expect(renderCaseReportHtml(data, { nonce: 'n' })).not.toContain('<script');
      expect(data.graphDropped).toEqual([]);
    });
  });

  test('caseReportFilename is wam-case-<id>-<date>.<ext> with the id sanitised', () => {
    expect(caseReportFilename('c1', 'markdown', now)).toBe('wam-case-c1-2026-11-20.md');
    expect(caseReportFilename('../x y', 'html', now)).toBe('wam-case-.._x_y-2026-11-20.html');
  });
});
