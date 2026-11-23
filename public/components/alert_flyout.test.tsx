/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, waitFor, act, fireEvent } from '@testing-library/react';
import { ALERT_NAV_COLLAPSED_KEY, ALERT_NAV_GROUPS, ALERT_SECTION_ICONS, ALERT_SECTION_IDS, AlertFlyout, alertSectionCount, alertSectionLabel, flattenFields, isAlertSectionId } from './alert_flyout';
import { FINDING_TERMS, TerminologyContext } from '../terminology';

// OSD/EUI mark elements with data-test-subj, as the upstream jest setup does.
configure({ testIdAttribute: 'data-test-subj' });

// The Overview tab mounts pickers and a precedent lookup that talk to the
// API; they are not what this test exercises.
jest.mock('./precedent_callout', () => ({ PrecedentCallout: () => null }));
// 11.6: the pickers echo their current value (the Overview rows that used to
// repeat it read-only are gone; `wamAlertOverviewAssignee` / `wamAlertOverviewCase`
// now sit on the pickers' form rows).
jest.mock('./assignee_picker', () => ({ AssigneePicker: ({ value }: { value?: string | null }) => <span data-test-subj="stubAssigneePicker">{value || 'Unassigned'}</span> }));
jest.mock('./case_picker', () => ({ CasePicker: ({ value }: { value?: string | null }) => <span data-test-subj="stubCasePicker">{value || 'None'}</span> }));
// The Comments stub reports a thread total the way the real component does
// after its first fetch, so the section rail's count badge can be asserted.
jest.mock('./comments_thread', () => ({
  CommentsThread: ({ onCountChanged }: { onCountChanged?: (total: number) => void }) => {
    const ReactModule = jest.requireActual('react') as typeof import('react');
    ReactModule.useEffect(() => { onCountChanged?.(4); }, [onCountChanged]);
    return null;
  },
}));
jest.mock('./history_list', () => ({ HistoryList: () => null }));
jest.mock('./related_alerts_panel', () => ({ RelatedAlertsPanel: () => null }));
jest.mock('./ai_analysis_tab', () => ({ AiAnalysisTab: () => null }));
jest.mock('./asset_context_chips', () => ({ AssetContextChips: () => null }));

// Step 2.6: the Native case row is gated on the build's target major.
// eslint-disable-next-line no-var
var mockMajor = 4; // var: hoisted above the jest.mock factory, which runs during imports
jest.mock('../../common/build_info', () => ({
  ...(jest.requireActual('../../common/build_info') as object),
  get TARGET_WAZUH_MAJOR() {
    return mockMajor;
  },
}));

const alert: any = {
  _id: '1763632800.1234',
  _index: 'wazuh-alert-status-v2-000001',
  _source: {
    '@timestamp': '2026-11-20T10:00:00.000Z',
    status: 'open',
    agent: { id: 'a1b', name: 'web-01', ip: '192.0.2.10' },
    rule: { id: '554', level: 5, description: 'File added to the system.' },
    manager: { name: 'manager' },
    data: { srcip: '203.0.113.7', url: 'http://evil.example.com/payload.exe' },
    syscheck: { md5_after: 'd41d8cd98f00b204e9800998ecf8427e' },
  },
};

function apiServiceWith(siblings: any) {
  return {
    fetchAlertSiblingVerdicts: jest.fn(async () => siblings),
    fetchPrecedent: jest.fn(async () => ({})),
  } as any;
}

function renderFlyout(apiService: any) {
  return render(
    <AlertFlyout
      alert={alert}
      apiService={apiService}
      updating={false}
      onClose={() => {}}
      onStatusChange={() => {}}
      onAssigneeChange={() => {}}
      onCaseChange={() => {}}
      onError={() => {}}
    />
  );
}

describe('AlertFlyout indicators block', () => {
  test('renders the indicators extracted from the projected record on the Overview tab', async () => {
    const apiService = apiServiceWith({ matches: [], siblings: 0 });
    renderFlyout(apiService);
    const block = screen.getByTestId('wamAlertIndicators');
    expect(block).toBeTruthy();
    expect(screen.getByTestId('wamIndicatorGroup-ip').textContent).toContain('203.0.113.7');
    expect(screen.getByTestId('wamIndicatorGroup-domain').textContent).toContain('evil.example.com');
    expect(screen.getByTestId('wamIndicatorGroup-hash').textContent).toContain('d41d8cd98f00b204e9800998ecf8427e');
    await waitFor(() => expect(apiService.fetchAlertSiblingVerdicts).toHaveBeenCalledWith('1763632800.1234'));
  });

  test('merges sibling VirusTotal verdicts into the opened alert and survives a failed lookup', async () => {
    const apiService = apiServiceWith({
      siblings: 1,
      matches: [{ source: 'virustotal', verdict: 'malicious', detail: 'VirusTotal 7/70 engines flagged', matched_field: 'data.virustotal.source.md5', link: null, indicator: { name: 'D41D8CD98F00B204E9800998ECF8427E', type: 'md5', provider: 'VirusTotal' } }],
    });
    renderFlyout(apiService);
    await waitFor(() => expect(screen.getByTestId('wamIndicatorGroup-hash').textContent).toContain('malicious (1)'));

    const failing = { fetchAlertSiblingVerdicts: jest.fn(async () => { throw new Error('403'); }) } as any;
    const { unmount } = renderFlyout(failing);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getAllByTestId('wamAlertIndicators')).toHaveLength(2);
    unmount();
  });
});

describe('AlertFlyout Fields tab list rendering (REUSE-STUDY 0.3)', () => {
  test('flattenFields keeps every element of an object list and every value of a scalar list', () => {
    const rows = flattenFields(
      {
        rule: { groups: ['syscheck', 'pci_dss'] },
        wazuh: { threat: { enrichments: [{ indicator: { name: 'first' } }, { indicator: { name: 'second' } }] } },
        empty: [],
      },
      false
    );
    const paths = rows.map((row) => `${row.field}=${row.display}`);
    expect(paths).toEqual(
      expect.arrayContaining([
        'rule.groups=syscheck',
        'rule.groups=pci_dss',
        'wazuh.threat.enrichments[0].indicator.name=first',
        'wazuh.threat.enrichments[1].indicator.name=second',
        'empty=[]',
      ])
    );
  });

  test('the Fields tab shows every enrichment element of the raw document, not just the last one', async () => {
    const enriched = {
      ...alert,
      _raw_source: {
        wazuh: { threat: { enrichments: [{ indicator: { name: 'ioc-one', provider: 'feed-a' } }, { indicator: { name: 'ioc-two', provider: 'feed-b' } }] } },
        rule: { groups: ['g1', 'g2'] },
      },
      _source: { ...alert._source, rule: { ...alert._source.rule, groups: ['g1', 'g2'] } },
    };
    render(
      <AlertFlyout alert={enriched} apiService={apiServiceWith({ matches: [], siblings: 0 })} updating={false} onClose={() => {}} onStatusChange={() => {}} onAssigneeChange={() => {}} onCaseChange={() => {}} onError={() => {}} />
    );
    fireEvent.click(screen.getByText('Fields'));
    const text = document.querySelector('.wamDocumentFields')!.textContent || '';
    expect(text).toContain('wazuh.threat.enrichments[0].indicator.name');
    expect(text).toContain('ioc-one');
    expect(text).toContain('wazuh.threat.enrichments[1].indicator.name');
    expect(text).toContain('ioc-two');
    // Scalar lists keep one row per value under the same path.
    expect((text.match(/rule\.groups/g) || []).length).toBe(2);
  });
});

describe('AlertFlyout Enrichment tab', () => {
  const stored = {
    updated_at: '2026-11-20T09:00:00.000Z',
    worst_verdict: 'suspicious' as const,
    items: [{ type: 'ip' as const, value: '203.0.113.7', source: 'misp-1', verdict: 'suspicious' as const, score: null, tags: ['scanner'], link: 'https://misp.example.org/x', checked_at: '2026-11-20T09:00:00.000Z' }],
  };

  function renderTab(apiService: any, overrides: any = {}, terms?: any) {
    const ui = (
      <AlertFlyout
        alert={{ ...alert, _source: { ...alert._source, enrichment: stored, ...overrides } }}
        apiService={apiService}
        updating={false}
        onClose={() => {}}
        onStatusChange={() => {}}
        onAssigneeChange={() => {}}
        onCaseChange={() => {}}
        onError={() => {}}
        onEnrichmentUpdated={apiService.onEnrichmentUpdated}
      />
    );
    const result = render(terms ? <TerminologyContext.Provider value={terms}>{ui}</TerminologyContext.Provider> : ui);
    fireEvent.click(screen.getByText('Enrichment'));
    return result;
  }

  test('shows stored verdicts per source, runs a per-alert lookup that persists, and reports the new stored object', async () => {
    const response = {
      type: 'ip', value: '203.0.113.7', alertId: alert._id,
      results: [
        { sourceId: 'abuse', sourceName: 'AbuseIPDB', kind: 'abuseipdb', status: 'ok', cached: false, result: { source: 'abuse', verdict: 'malicious', score: 100, tags: [], link: 'https://www.abuseipdb.com/check/203.0.113.7', summary: 'bad', checkedAt: '2026-11-20T10:00:00.000Z' } },
        { sourceId: 'misp-1', sourceName: 'Corp MISP', kind: 'misp', status: 'error', cached: false, error: 'HTTP 502' },
      ],
      enrichment: { updated_at: '2026-11-20T10:00:00.000Z', worst_verdict: 'malicious', items: [{ type: 'ip', value: '203.0.113.7', source: 'abuse', verdict: 'malicious', score: 100, tags: [], link: null, checked_at: '2026-11-20T10:00:00.000Z' }, ...stored.items] },
    };
    const apiService = {
      ...apiServiceWith({ matches: [], siblings: 0 }),
      appUrl: jest.fn((path: string) => `/base${path}`),
      lookupAlertEnrichment: jest.fn(async () => response),
      onEnrichmentUpdated: jest.fn(),
    };
    renderTab(apiService);
    const panel = screen.getByTestId('wamEnrichmentPanel');
    expect(panel.textContent).toContain('misp-1: suspicious');
    expect(panel.textContent).toContain('1 stored verdict');
    expect(screen.queryByTestId('wamEnrichmentCtiLink')).toBeNull();

    // Rows: agent.ip, data.srcip, domain, url, hash. Click the srcip row's Lookup.
    const button = screen.getAllByTestId('wamEnrichmentLookup').find((b) => (b.closest('tr')?.textContent || '').includes('203.0.113.7'))!;
    expect(button).toBeTruthy();
    fireEvent.click(button);
    await waitFor(() => expect(apiService.lookupAlertEnrichment).toHaveBeenCalledWith(alert._id, { type: 'ip', value: '203.0.113.7', refresh: false }));
    await waitFor(() => expect(apiService.onEnrichmentUpdated).toHaveBeenCalledWith(alert._id, response.enrichment));
    await waitFor(() => expect(screen.getByTestId('wamEnrichmentPanel').textContent).toContain('AbuseIPDB: malicious 100'));
    expect(screen.getByTestId('wamEnrichmentPanel').textContent).toContain('Corp MISP: error');
  });

  test('Lookup all runs every lookupable indicator and a 5.0 build offers the CTI Explorer link', async () => {
    const apiService = {
      ...apiServiceWith({ matches: [], siblings: 0 }),
      appUrl: jest.fn((path: string) => `/base${path}`),
      lookupAlertEnrichment: jest.fn(async (_id: string, req: any) => ({ type: req.type, value: req.value, alertId: alert._id, results: [], enrichment: stored })),
      onEnrichmentUpdated: jest.fn(),
    };
    renderTab(apiService, {}, FINDING_TERMS);
    const links = screen.getAllByTestId('wamEnrichmentCtiLink');
    expect(links.length).toBeGreaterThan(0);
    expect(links[0].getAttribute('href')).toBe('/base/app/cti-explorer');

    fireEvent.click(screen.getByTestId('wamEnrichmentLookupAll'));
    // agent.ip and data.srcip are both IP indicators, plus domain, url, hash.
    await waitFor(() => expect(apiService.lookupAlertEnrichment).toHaveBeenCalledTimes(5));
    const types = apiService.lookupAlertEnrichment.mock.calls.map((c: any[]) => c[1].type).sort();
    expect(types).toEqual(['domain', 'hash', 'ip', 'ip', 'url']);
    // Every one of those answered with no results: the rows say so instead of "not looked up".
    await waitFor(() => expect(screen.getAllByTestId('wamEnrichmentNoSource').length).toBe(5));
    expect(screen.getAllByTestId('wamEnrichmentNoSource')[0].textContent).toContain('No enrichment source is enabled');
    // Nothing was stored, so the queue is not told the record changed.
    expect(apiService.onEnrichmentUpdated).not.toHaveBeenCalled();
  });

  test('the flyout runs Lookup all one at a time because every lookup also writes the record', async () => {
    let inFlight = 0;
    let peak = 0;
    const apiService = {
      ...apiServiceWith({ matches: [], siblings: 0 }),
      appUrl: jest.fn((path: string) => `/base${path}`),
      lookupAlertEnrichment: jest.fn(async (_id: string, req: any) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 5));
        inFlight -= 1;
        return { type: req.type, value: req.value, alertId: alert._id, results: [], enrichment: stored };
      }),
      onEnrichmentUpdated: jest.fn(),
    };
    renderTab(apiService);
    fireEvent.click(screen.getByTestId('wamEnrichmentLookupAll'));
    await waitFor(() => expect(apiService.lookupAlertEnrichment).toHaveBeenCalledTimes(5));
    expect(peak).toBe(1);
  });

  test('a path-only 4.x data.url row is shown but not lookupable and is left out of Lookup all', async () => {
    const apiService = {
      ...apiServiceWith({ matches: [], siblings: 0 }),
      appUrl: jest.fn((path: string) => `/base${path}`),
      lookupAlertEnrichment: jest.fn(async (_id: string, req: any) => ({ type: req.type, value: req.value, alertId: alert._id, results: [], enrichment: stored })),
      onEnrichmentUpdated: jest.fn(),
    };
    renderTab(apiService, { data: { srcip: '203.0.113.7', url: '/wp-login.php' } });
    const panel = screen.getByTestId('wamEnrichmentPanel');
    expect(panel.textContent).toContain('/wp-login.php');
    const row = screen.getByText('/wp-login.php').closest('tr')!;
    expect(row.querySelector('[data-test-subj="wamEnrichmentNotLookupable"]')).toBeTruthy();
    expect(row.querySelector('[data-test-subj="wamEnrichmentLookup"]')).toBeNull();
    // agent.ip, data.srcip, hash: the path-only url is not counted.
    expect(screen.getByTestId('wamEnrichmentLookupAll').textContent).toContain('(3)');
    fireEvent.click(screen.getByTestId('wamEnrichmentLookupAll'));
    await waitFor(() => expect(apiService.lookupAlertEnrichment).toHaveBeenCalledTimes(3));
    expect(apiService.lookupAlertEnrichment.mock.calls.some((c: any[]) => c[1].type === 'url')).toBe(false);
  });
});

describe('AlertFlyout native case row (step 2.6)', () => {
  const nativeCase = { id: 'c-1', status: 'active', severity: 'medium', priority: 'p3', tlp: 'green', title: 'Native title', tags: ['t1'], updated_at: null };
  const withNative: any = { ...alert, _source: { ...alert._source, source_family: 'wazuh5_findings', native_case: nativeCase } };

  afterEach(() => {
    mockMajor = 4;
  });

  test('shows the read-only chip with the Cases link on a 5.0 build', () => {
    mockMajor = 5;
    const apiService = { ...apiServiceWith([]), appUrl: (path: string) => `/base${path}` };
    render(<AlertFlyout alert={withNative} apiService={apiService} updating={false} onClose={() => {}} onStatusChange={() => {}} onAssigneeChange={() => {}} onCaseChange={() => {}} onError={() => {}} />);
    const chip = screen.getByTestId('wamAlertNativeCase');
    expect(chip.textContent).toContain('Native case c-1');
    expect(screen.getByTestId('wamAlertNativeCaseTitle').textContent).toBe('Native title');
    expect(screen.getByTestId('wamAlertNativeCaseLink').getAttribute('href')).toBe('/base/app/case-management#/overview/?tab=caseManagement&tabView=cases');
  });

  test('renders no native-case element on a 4.x build, even if a record carries one', () => {
    mockMajor = 4;
    const apiService = { ...apiServiceWith([]), appUrl: (path: string) => `/base${path}` };
    render(<AlertFlyout alert={withNative} apiService={apiService} updating={false} onClose={() => {}} onStatusChange={() => {}} onAssigneeChange={() => {}} onCaseChange={() => {}} onError={() => {}} />);
    expect(screen.queryByTestId('wamAlertNativeCase')).toBeNull();
    expect(screen.queryByText('Native case')).toBeNull();
  });
});

describe('AlertFlyout header and overview layout (step 8.2)', () => {
  function renderWith(overrides: any = {}, props: any = {}) {
    const apiService = { ...apiServiceWith({ matches: [], siblings: 0 }), appUrl: (path: string) => `/base${path}` };
    const onOpenCase = jest.fn();
    render(
      <AlertFlyout
        alert={{ ...alert, _source: { ...alert._source, ...overrides } }}
        apiService={apiService}
        updating={false}
        onClose={() => {}}
        onStatusChange={() => {}}
        onAssigneeChange={() => {}}
        onCaseChange={() => {}}
        onError={() => {}}
        onOpenCase={onOpenCase}
        {...props}
      />
    );
    return { apiService, onOpenCase };
  }

  test('header is the rule title, one metadata row and a right-aligned action group', () => {
    renderWith({ assigned_to: 'analyst', case_id: 'case-9' });
    expect(screen.getByTestId('wamAlertFlyoutTitle').textContent).toBe('File added to the system.');
    const meta = screen.getByTestId('wamAlertFlyoutMeta');
    expect(meta.textContent).toContain('Open');
    expect(screen.getByTestId('wamAlertFlyoutSeverity').textContent).toBe('Medium 5');
    expect(screen.getByTestId('wamAlertFlyoutAgent').textContent).toBe('web-01 (192.0.2.10)');
    expect(screen.getByTestId('wamAlertFlyoutTimestamp').textContent).not.toBe('');
    const actions = screen.getByTestId('wamAlertFlyoutActions');
    // 11.6: the action group sits on the title row (right-aligned), not on
    // the meta row, so a wide asset chip row never wraps it onto a third line.
    expect(actions.closest('.wamAlertFlyoutTitleRow')).not.toBeNull();
    expect(meta.contains(actions)).toBe(false);
    expect(actions.querySelector('[data-test-subj="wamAlertFlyoutOpenCase"]')).toBeTruthy();
    expect(actions.querySelector('[data-test-subj="wamAlertFlyoutExpand"]')).toBeTruthy();
    // The header ends with its own Close action (EuiFlyout's floating X is
    // hidden), exactly like the case flyout.
    const close = actions.querySelector('[data-test-subj="wamAlertFlyoutClose"]') as HTMLButtonElement;
    expect(close).toBeTruthy();
    expect(close.getAttribute('aria-label')).toBe('Close details');
    expect(close.textContent).toContain('Close');
    expect(document.querySelector('.euiFlyout__closeButton')).toBeNull();
    // Every header action is an EuiButtonEmpty size s, like the case flyout.
    const buttons = Array.from(actions.querySelectorAll('button'));
    expect(buttons.length).toBe(3);
    buttons.forEach((button) => {
      expect(button.className).toContain('euiButtonEmpty');
      expect(button.className).toContain('euiButtonEmpty--small');
    });
  });

  test('the title falls back to the unit label when the rule has no description', () => {
    renderWith({ rule: { id: '1', level: 3 } });
    expect(screen.getByTestId('wamAlertFlyoutTitle').textContent).toBe('Alert details');
  });

  test('Expand toggles the flyout to full width and back and Open case hands the case id over', () => {
    const { onOpenCase } = renderWith({ case_id: 'case-9' });
    const expand = screen.getByTestId('wamAlertFlyoutExpand');
    expect(expand.getAttribute('aria-label')).toBe('Expand to full screen');
    fireEvent.click(expand);
    expect(screen.getByTestId('wamAlertFlyoutExpand').textContent).toContain('Collapse');
    expect(screen.getByTestId('wamAlertFlyoutExpand').getAttribute('aria-label')).toBe('Collapse');
    fireEvent.click(screen.getByTestId('wamAlertFlyoutExpand'));
    expect(screen.getByTestId('wamAlertFlyoutExpand').textContent).toContain('Expand');
    fireEvent.click(screen.getByTestId('wamAlertFlyoutOpenCase'));
    expect(onOpenCase).toHaveBeenCalledWith('case-9');
  });

  test('the Overview is the controls row followed by one grouped meta grid (Detection, Triage, Record) with rule, level, agent, timestamp, manager, enrichment and id rows', () => {
    renderWith({
      assigned_to: 'analyst',
      case_id: 'case-9',
      enrichment: { updated_at: '2026-11-20T09:00:00.000Z', worst_verdict: 'malicious', items: [{ type: 'ip', value: '203.0.113.7', source: 's', verdict: 'malicious', score: 90, tags: [], link: null, checked_at: '2026-11-20T09:00:00.000Z' }] },
    });
    const meta = screen.getByTestId('wamAlertMeta');
    expect(meta.className).toContain('wamMetaList');
    expect(meta.className).toContain('wamMetaGrid');
    // Valid content model: a <div> grid of role=group blocks, each with ONE
    // <dl> whose direct children wrap exactly one <dt> + <dd> pair.
    expect(meta.tagName).toBe('DIV');
    const detectionGroup = screen.getByTestId('wamAlertMetaDetection');
    expect(detectionGroup.getAttribute('role')).toBe('group');
    expect(detectionGroup.getAttribute('aria-labelledby')).toBe(detectionGroup.querySelector('.wamMetaGrid__groupTitle span')!.id);
    const detectionList = detectionGroup.querySelector(':scope > dl.wamMetaGrid__rows')!;
    expect(detectionList).not.toBeNull();
    expect(Array.from(detectionList.children).every((row) => row.tagName === 'DIV' && row.className === 'wamMetaGrid__row' && row.children.length === 2 && row.children[0].tagName === 'DT' && row.children[1].tagName === 'DD')).toBe(true);
    // 11.6: the editable row (status, assignee, case) comes first, the facts after it.
    const grid = screen.getByTestId('wamAlertFormGrid');
    expect(grid.compareDocumentPosition(meta) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const groups = Array.from(meta.querySelectorAll('.wamMetaGrid__groupTitle')).map((node) => node.textContent);
    expect(groups).toEqual(['Detection', 'Triage', 'Record']);
    const labelsOf = (subject: string) => Array.from(screen.getByTestId(subject).querySelectorAll('.wamMetaGrid__label')).map((node) => node.textContent);
    expect(labelsOf('wamAlertMetaDetection')).toEqual(['Rule', 'Level', 'Agent', 'Timestamp', 'Manager']);
    expect(labelsOf('wamAlertMetaTriage')).toEqual(['Enrichment verdict']);
    expect(labelsOf('wamAlertMetaRecord')).toEqual(['Alert ID']);
    // The read-only Status / Assigned to / Case rows are gone: the controls show them.
    const titles = Array.from(meta.querySelectorAll('.wamMetaGrid__label')).map((node) => node.textContent);
    expect(titles).not.toContain('Status');
    expect(titles).not.toContain('Assigned to');
    expect(titles).not.toContain('Case');
    expect(meta.querySelector('[data-test-subj="wamAlertOverviewDisposition"]')).toBeNull();
    // The two pickers carry the Overview subjects their rows used to have.
    const assignee = screen.getByTestId('wamAlertOverviewAssignee');
    expect(grid.contains(assignee)).toBe(true);
    expect(assignee.className).toContain('euiFormRow');
    expect(assignee.textContent).toContain('analyst');
    const caseRow = screen.getByTestId('wamAlertOverviewCase');
    expect(grid.contains(caseRow)).toBe(true);
    expect(caseRow.textContent).toContain('case-9');
    expect(screen.getByTestId('wamAlertOverviewEnrichment').textContent).toContain('malicious');
    expect(screen.getByTestId('wamAlertOverviewEnrichment').textContent).toContain('1 stored verdict');
    expect(screen.getByTestId('wamAlertOverviewEnrichment').tagName).toBe('DD');
    // Nothing in the Overview is larger than EuiText size s except the Indicators panel title.
    const overview = screen.getByTestId('wamAlertOverview');
    const texts = Array.from(overview.querySelectorAll('.euiText')).map((node) => node.className);
    texts.forEach((className) => expect(className).toMatch(/euiText--(small|extraSmall)/));
    // The only titles are inside the (unchanged) Indicators panel: its xs heading
    // and the xxs indicator group headings.
    const indicators = screen.getByTestId('wamAlertIndicators');
    Array.from(overview.querySelectorAll('.euiTitle')).forEach((node) => expect(indicators.contains(node)).toBe(true));
    expect(indicators.querySelector('.euiTitle')!.className).toContain('euiTitle--xsmall');
  });

  test('a closed alert shows its disposition once in the header (the subject the Playwright specs read) and again under its own Overview subject', () => {
    renderWith({ status: 'closed', disposition: 'false_positive', closure_reason: 'Known scanner' });
    expect(screen.getAllByTestId('wamAlertFlyoutDisposition')).toHaveLength(1);
    expect(screen.getByTestId('wamAlertFlyoutDisposition').textContent).toBe('False positive');
    // 11.6: the disposition badge and the reason share the Triage "Closure reason" row.
    const closureRow = screen.getByTestId('wamAlertClosureRow');
    expect(screen.getByTestId('wamAlertMetaTriage').contains(closureRow)).toBe(true);
    expect(closureRow.querySelector('[data-test-subj="wamAlertOverviewDisposition"]')!.textContent).toBe('False positive');
    expect(screen.getByTestId('wamAlertClosureReason').textContent).toBe('Known scanner');
  });

  test('without an assignee, case or lookups the rows say so instead of going blank', () => {
    renderWith();
    expect(screen.getByTestId('wamAlertOverviewAssignee').textContent).toContain('Unassigned');
    expect(screen.getByTestId('wamAlertOverviewCase').textContent).toContain('None');
    expect(screen.getByTestId('wamAlertOverviewEnrichment').textContent).toBe('Not looked up');
    expect(screen.queryByTestId('wamAlertClosureRow')).toBeNull();
    expect(screen.queryByTestId('wamAlertFlyoutOpenCase')).toBeNull();
    expect(screen.queryByTestId('wamAlertFlyoutSeverity')).toBeTruthy();
  });

  test('a 5.0 finding shows its severity label in the header and a Severity row instead of Level', () => {
    renderWith({ rule: { id: 'r-1', level: null, description: 'Finding' }, severity_label: 'High' });
    expect(screen.getByTestId('wamAlertFlyoutSeverity').textContent).toBe('High');
    const titles = Array.from(screen.getByTestId('wamAlertMeta').querySelectorAll('.wamMetaGrid__label')).map((node) => node.textContent);
    expect(titles).toContain('Severity');
    expect(titles).not.toContain('Level');
  });

  test('the SLA due chip sits in the header once and in the Overview under its own subject', () => {
    renderWith({ reporting: { sla_due_at: '2099-01-01T00:00:00.000Z' } });
    expect(screen.getAllByTestId('wamAlertFlyoutDue')).toHaveLength(1);
    expect(screen.getByTestId('wamAlertDueLine')).toBeTruthy();
    expect(screen.getByTestId('wamAlertOverviewDue')).toBeTruthy();
  });

  test('status, assignee and case controls sit on one compressed form row with labels', () => {
    renderWith();
    const grid = screen.getByTestId('wamAlertFormGrid');
    const labels = Array.from(grid.querySelectorAll('label')).map((node) => node.textContent);
    expect(labels).toEqual(expect.arrayContaining(['Status', 'Assigned to', 'Case']));
    // The segmented status control is the compressed size so its height matches the pickers.
    expect(grid.querySelector('.euiButtonGroup--compressed')).toBeTruthy();
  });

  test('every tab body shares the wamAlertFlyoutTab wrapper and the Fields table is compressed', () => {
    renderWith();
    expect(screen.getByTestId('wamAlertOverview').className).toContain('wamAlertFlyoutTab');
    expect(screen.getByTestId('wamAlertIndicators').className).toContain('euiPanel');
    fireEvent.click(screen.getByText('Fields'));
    const table = document.querySelector('.wamDocumentFields table')!;
    expect(table.className).toContain('euiTable--compressed');
    const headers = Array.from(table.querySelectorAll('th')).map((th) => th.textContent?.trim());
    expect(headers).toEqual(['Field', 'Value', 'Source', 'Filter']);
    expect(document.querySelector('.wamDocumentFields')!.closest('.wamAlertFlyoutTab')).toBeTruthy();
  });
});

describe('AlertFlyout section rail (step 11.1)', () => {
  function renderWith(sourceOverrides: any = {}, terms?: any) {
    const apiService = apiServiceWith({ matches: [], siblings: 0 });
    const record = { ...alert, _source: { ...alert._source, ...sourceOverrides } };
    const ui = (
      <AlertFlyout
        alert={record}
        apiService={apiService}
        updating={false}
        onClose={() => {}}
        onStatusChange={() => {}}
        onAssigneeChange={() => {}}
        onCaseChange={() => {}}
        onError={() => {}}
      />
    );
    render(terms ? <TerminologyContext.Provider value={terms}>{ui}</TerminologyContext.Provider> : ui);
    return apiService;
  }

  afterEach(() => {
    try { window.localStorage.removeItem(ALERT_NAV_COLLAPSED_KEY); } catch (e) { /* jsdom */ }
  });

  test('the section set is the old tab ids (details renamed to fields), grouped Overview | Investigation | Work | Detail with icons', () => {
    expect([...ALERT_SECTION_IDS]).toEqual(['overview', 'related', 'enrichment', 'ai', 'comments', 'history', 'fields', 'raw']);
    const grouped = ALERT_NAV_GROUPS.flatMap((group) => group.items);
    expect(grouped).toEqual([...ALERT_SECTION_IDS]);
    expect(new Set(grouped).size).toBe(ALERT_SECTION_IDS.length);
    expect(ALERT_NAV_GROUPS.map((group) => group.id)).toEqual(['overview', 'investigation', 'work', 'detail']);
    for (const id of ALERT_SECTION_IDS) expect(typeof ALERT_SECTION_ICONS[id]).toBe('string');
    expect(ALERT_SECTION_ICONS.comments).toBe('editorComment');
    expect(alertSectionLabel('related')).toBe('Related alerts');
    expect(alertSectionLabel('related', 'findings')).toBe('Related findings');
    expect(alertSectionLabel('fields')).toBe('Fields');
    expect(alertSectionLabel('raw')).toBe('Raw JSON');
    expect(isAlertSectionId('fields')).toBe(true);
    expect(isAlertSectionId('details')).toBe(false);
    expect(alertSectionCount('comments', { comments: 0 })).toBeNull();
    expect(alertSectionCount('comments', { comments: 2 })).toBe('2');
    expect(alertSectionCount('related', { related: null })).toBeNull();
    expect(alertSectionCount('enrichment', { enrichment: 3 })).toBe('3');
    expect(alertSectionCount('overview', { comments: 2, related: 2, enrichment: 2 })).toBeNull();
    expect(ALERT_NAV_COLLAPSED_KEY).toBe('wam.alertNav.collapsed');
  });

  test('replaces the tabs with the rail: one subject per section, only the active section mounted, selection by id', () => {
    renderWith();
    expect(document.querySelector('.wamAlertFlyoutTabs')).toBeNull();
    expect(document.querySelector('[role="tablist"]')).toBeNull();
    const nav = screen.getByTestId('wamAlertNav');
    expect(nav.className).toBe('wamAlertNav');
    expect(nav.closest('.wamAlertNavColumn')).not.toBeNull();
    expect(nav.closest('.wamAlertNavColumn')!.className).not.toContain('wamAlertNavColumn--collapsed');
    const subjects = Array.from(nav.querySelectorAll('[data-test-subj^="wamAlertNav-"]')).map((node) => node.getAttribute('data-test-subj'));
    expect(subjects).toEqual(ALERT_SECTION_IDS.map((id) => `wamAlertNav-${id}`));
    expect(nav.querySelector('nav')!.getAttribute('aria-label')).toBe('Alert sections');
    expect(screen.getByTestId('wamAlertNav-overview').className).toContain('isSelected');
    expect(screen.getByTestId('wamAlertSection-overview').querySelector('[data-test-subj="wamAlertOverview"]')).not.toBeNull();
    expect(screen.queryByTestId('wamAlertSection-raw')).toBeNull();

    fireEvent.click(screen.getByTestId('wamAlertNav-raw'));
    expect(screen.getByTestId('wamAlertNav-raw').className).toContain('isSelected');
    expect(screen.getByTestId('wamAlertNav-overview').className).not.toContain('isSelected');
    expect(screen.queryByTestId('wamAlertSection-overview')).toBeNull();
    expect(screen.getByTestId('wamAlertSection-raw').textContent).toContain('"srcip": "203.0.113.7"');

    fireEvent.click(screen.getByTestId('wamAlertNav-fields'));
    expect(screen.getByTestId('wamAlertSection-fields').querySelector('.wamDocumentFields')).not.toBeNull();
    expect(screen.getByTestId('wamAlertSection-fields').closest('.wamAlertContent')).not.toBeNull();
  });

  test('labels follow the terminology and the toggle collapses the column', () => {
    renderWith({}, FINDING_TERMS);
    expect(screen.getByTestId('wamAlertNav-related').textContent).toContain('Related findings');
    expect(screen.getByTestId('wamAlertNav').querySelector('nav')!.getAttribute('aria-label')).toBe('Finding sections');
    const toggle = screen.getByTestId('wamAlertNavToggle');
    expect(toggle.getAttribute('aria-label')).toBe('Collapse navigation');
    fireEvent.click(toggle);
    expect(screen.getByTestId('wamAlertNav').getAttribute('data-collapsed')).toBe('true');
    expect(screen.getByTestId('wamAlertNav').closest('.wamAlertNavColumn')!.className).toContain('wamAlertNavColumn--collapsed');
    expect(screen.getByTestId('wamAlertNavToggle').getAttribute('aria-label')).toBe('Expand navigation');
    expect(window.localStorage.getItem(ALERT_NAV_COLLAPSED_KEY)).toBe('true');
    // The rail keeps the subjects and still switches sections.
    fireEvent.click(screen.getByTestId('wamAlertNav-history'));
    expect(screen.getByTestId('wamAlertSection-history')).not.toBeNull();
  });

  test('a saved preference opens the flyout collapsed', () => {
    window.localStorage.setItem(ALERT_NAV_COLLAPSED_KEY, 'true');
    renderWith();
    expect(screen.getByTestId('wamAlertNav').className).toBe('wamAlertNav wamAlertNav--collapsed');
    expect(screen.getByTestId('wamAlertNav').closest('.wamAlertNavColumn')!.className).toContain('wamAlertNavColumn--collapsed');
    expect(screen.getByTestId('wamAlertNav-enrichment').tagName).toBe('BUTTON');
    expect(screen.getByTestId('wamAlertNav-enrichment').getAttribute('aria-label')).toBe('Enrichment');
  });

  test('counts: stored enrichment verdicts up front, the comments total once the thread has loaded', async () => {
    renderWith({ enrichment: { worst_verdict: 'malicious', items: [{ source_id: 'a' }, { source_id: 'b' }] } });
    expect(screen.getByTestId('wamAlertNavCount-enrichment').textContent).toBe('2');
    expect(screen.queryByTestId('wamAlertNavCount-comments')).toBeNull();
    expect(screen.queryByTestId('wamAlertNavCount-related')).toBeNull();
    fireEvent.click(screen.getByTestId('wamAlertNav-comments'));
    await waitFor(() => expect(screen.getByTestId('wamAlertNavCount-comments').textContent).toBe('4'));
    expect(screen.getByTestId('wamAlertSection-comments')).not.toBeNull();
    // Switching away keeps the known count on the rail.
    fireEvent.click(screen.getByTestId('wamAlertNav-overview'));
    expect(screen.getByTestId('wamAlertNavCount-comments').textContent).toBe('4');
  });
});
