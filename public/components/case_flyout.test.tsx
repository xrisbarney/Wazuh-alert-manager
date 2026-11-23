/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import { CaseFlyout, contextAgentSubject } from './case_flyout';
import { CASE_SECTION_IDS } from './case_flyout_nav';

// OSD/EUI mark elements with data-test-subj, as the upstream jest setup does.
configure({ testIdAttribute: 'data-test-subj' });

// The sections mount pickers, graphs and threads that talk to the API; the
// nav, header and Overview layout are what this test exercises. The tab
// stubs expose the count callbacks the nav badges are fed by.
// The stub echoes its value: since 11.6 the Overview's `wamCaseOverviewAssignee`
// sits on the picker's form row instead of a read-only row.
jest.mock('./assignee_picker', () => ({ AssigneePicker: ({ value }: { value?: string | null }) => <div data-test-subj="stubAssigneePicker">{value || 'Unassigned'}</div> }));
jest.mock('./attack_path_view', () => ({ AttackPathView: () => null }));
jest.mock('./alert_multi_picker', () => ({ AlertMultiPicker: () => null }));
jest.mock('./ai_analysis_tab', () => ({ AiAnalysisTab: () => null }));
// The chip row is stubbed: the flyout fetches each agent's context itself
// (step 11.4) and hands it to the row through `source`, so the stub only
// echoes that state; the summary helpers and count badges are real.
jest.mock('./asset_context_chips', () => {
  const actual = jest.requireActual('./asset_context_chips');
  const { createElement } = require('react');
  return {
    ...actual,
    AssetContextChips: ({ agentId, agentName, testSubj, source }: any) =>
      createElement('div', { 'data-test-subj': testSubj || 'stubAssetContext', 'data-agent': agentId || agentName, 'data-source': source?.status || 'own' }),
  };
});

// One canned context per agent id: 001 has vulnerabilities only (4.x: SCA not
// indexed), 002 has both families, anything else carries no readable family.
function assetContextFor({ agentId, agentName }: { agentId?: string | null; agentName?: string | null }) {
  const sca = agentId === '002' ? { status: 'ok', total: 10, failed: 4, passed: 6 } : { status: 'not_available', reason: 'not indexed' };
  return {
    agentId,
    agentName,
    line: 4,
    fetchedAt: '2026-11-20T10:00:00.000Z',
    cached: false,
    families: {
      system: { status: 'ok', os: { name: 'Ubuntu', version: '22.04' } },
      networks: { status: 'ok', ips: ['10.0.0.5'], total: 1 },
      ports: { status: 'ok', open: 2, listening: 1 },
      vulnerabilities: { status: 'ok', total: 3, critical: 1, high: 2, medium: 0, low: 0, topCves: [] },
      sca,
    },
    links: { vulnerabilityDetection: '/app/vulnerability-detection' },
  };
}
jest.mock('./sla_escalated', () => ({ SlaEscalated: () => null }));
jest.mock('./case_timeline_tab', () => ({ CaseTimelineTab: () => <div data-test-subj="stubTimeline" /> }));
jest.mock('./enrichment_panel', () => ({
  EnrichmentLookupControls: () => null,
  EnrichmentVerdictBadges: () => null,
  ctiExplorerUrlFor: () => null,
  isLookupableIndicator: () => false,
  lookupKey: (type: string, value: string) => `${type}:${value}`,
  useEnrichmentLookups: () => ({ results: {}, errors: {}, pending: {}, runningAll: false, run: () => {}, runAll: () => {} }),
}));
jest.mock('./comments_thread', () => {
  const { createElement, useEffect } = require('react');
  return {
    CommentsThread: ({ onCountChanged }: any) => {
      useEffect(() => {
        onCountChanged?.(5);
      }, []);
      return createElement('div', { 'data-test-subj': 'stubComments' });
    },
  };
});
jest.mock('./attachments_tab', () => {
  const { createElement, useEffect } = require('react');
  return {
    AttachmentsTab: ({ onCountChanged }: any) => {
      useEffect(() => {
        onCountChanged?.(2);
      }, []);
      return createElement('div', { 'data-test-subj': 'stubAttachments' });
    },
  };
});
jest.mock('./case_tasks_tab', () => ({
  ...(jest.requireActual('./case_tasks_tab') as object),
  CaseTasksTab: () => <div data-test-subj="stubTasks" />,
}));

const caseDoc: any = {
  id: 'case-1',
  case_uid: 'uid-1',
  title: 'Suspicious logins on web-01',
  description: 'Several failed logins followed by a success.',
  severity: 'high',
  status: 'in_progress',
  assigned_to: 'analyst',
  alert_ids: ['a1', 'a2', 'a3'],
  evidence_count: 3,
  created_by: 'admin',
  created_at: '2026-11-20T10:00:00.000Z',
  updated_by: 'analyst',
  updated_at: '2026-11-20T11:00:00.000Z',
  sla_due_at: '2099-01-01T00:00:00.000Z',
  task_counts: { open: 2, done: 1 },
  history: [
    { timestamp: '2026-11-20T10:00:00.000Z', user: 'admin', action: 'case_created' },
    { timestamp: '2026-11-20T10:30:00.000Z', user: 'analyst', action: 'status_change', from: 'open', to: 'in_progress' },
  ],
};

function alertRow(id: string, agent: { id: string; name: string } = { id: '001', name: 'web-01' }): any {
  return {
    _id: id,
    _source: { '@timestamp': '2026-11-20T09:00:00.000Z', status: 'open', agent, rule: { id: '5710', level: 5, description: 'sshd: attempt' } },
  };
}

function apiServiceWith(overrides: Record<string, any> = {}) {
  return {
    fetchCase: jest.fn(async () => ({
      case: caseDoc,
      alerts: ['a1', 'a2', 'a3'].map((id) => alertRow(id)),
      evidence: { evidence: ['a1', 'a2', 'a3'].map((id) => ({ alert_id: id, relationship_state: 'live' })), total: 3, nextCursor: null },
    })),
    fetchSystemCapabilities: jest.fn(async () => ({ canManageLifecycle: false })),
    updateCase: jest.fn(async (_id: string, payload: any) => ({ ...caseDoc, ...payload })),
    lookupEnrichment: jest.fn(async () => ({})),
    fetchAssetContext: jest.fn(async (input: any) => assetContextFor(input)),
    ...overrides,
  } as any;
}

function renderFlyout(apiService: any, props: Partial<React.ComponentProps<typeof CaseFlyout>> = {}) {
  return render(
    <CaseFlyout
      caseId="case-1"
      apiService={apiService}
      onClose={() => {}}
      onError={() => {}}
      onChanged={() => {}}
      {...props}
    />
  );
}

async function openCase(apiService = apiServiceWith()) {
  renderFlyout(apiService);
  await waitFor(() => expect(screen.getByTestId('wamCaseNav')).toBeTruthy());
  return apiService;
}

describe('CaseFlyout section navigation (step 8.1)', () => {
  test('renders the ten sections as a side nav with Overview active and the Overview content beside it', async () => {
    await openCase();
    for (const id of CASE_SECTION_IDS) {
      expect(screen.getByTestId(`wamCaseNav-${id}`)).toBeTruthy();
    }
    expect(screen.getByTestId('wamCaseNav-overview').className).toContain('isSelected');
    expect(screen.getByTestId('wamCaseSection-overview')).toBeTruthy();
    expect(screen.getByTestId('wamCaseMeta')).toBeTruthy();
    expect(screen.getByTestId('wamCaseNav-alerts').textContent).toContain('Linked alerts');
  });

  test('badges the evidence total and the task counts from the loaded case document', async () => {
    await openCase();
    expect(screen.getByTestId('wamCaseNavCount-alerts').textContent).toBe('3');
    expect(screen.getByTestId('wamCaseNavCount-tasks').textContent).toBe('1/3');
    // Attachments and comments are unknown until their section fetched them.
    expect(screen.queryByTestId('wamCaseNavCount-attachments')).toBeNull();
    expect(screen.queryByTestId('wamCaseNavCount-comments')).toBeNull();
  });

  test('selecting a section swaps the content and keeps the section id as the test subject', async () => {
    await openCase();
    fireEvent.click(screen.getByTestId('wamCaseNav-tasks'));
    expect(screen.getByTestId('wamCaseSection-tasks')).toBeTruthy();
    expect(screen.getByTestId('stubTasks')).toBeTruthy();
    expect(screen.queryByTestId('wamCaseSection-overview')).toBeNull();
    expect(screen.getByTestId('wamCaseNav-tasks').className).toContain('isSelected');
    expect(screen.getByTestId('wamCaseNav-overview').className).not.toContain('isSelected');

    fireEvent.click(screen.getByTestId('wamCaseNav-history'));
    expect(screen.getByTestId('wamCaseSection-history')).toBeTruthy();
    expect(screen.getAllByTestId('wamHistoryRow')).toHaveLength(2);
    expect(screen.getByTestId('wamHistory').textContent).toContain('changed status');
  });

  test('counts reported by the Comments and Attachments sections appear once those sections were opened', async () => {
    await openCase();
    fireEvent.click(screen.getByTestId('wamCaseNav-comments'));
    await waitFor(() => expect(screen.getByTestId('wamCaseNavCount-comments').textContent).toBe('5'));
    fireEvent.click(screen.getByTestId('wamCaseNav-attachments'));
    await waitFor(() => expect(screen.getByTestId('wamCaseNavCount-attachments').textContent).toBe('2'));
    // Leaving the section keeps the count: it is case data the flyout now holds.
    fireEvent.click(screen.getByTestId('wamCaseNav-overview'));
    expect(screen.getByTestId('wamCaseNavCount-comments').textContent).toBe('5');
  });
});

describe('CaseFlyout header and Overview (step 8.1)', () => {
  test('shows one metadata row with status, severity, assignee, times, due date and the task chip plus the action group', async () => {
    await openCase();
    const meta = screen.getByTestId('wamCaseFlyoutMeta');
    expect(meta.textContent).toContain('In progress');
    expect(meta.textContent).toContain('High');
    expect(screen.getByTestId('wamCaseFlyoutAssignee').textContent).toBe('Assigned to analyst');
    expect(screen.getByTestId('wamCaseFlyoutTimes').textContent).toContain('Created ');
    expect(screen.getByTestId('wamCaseFlyoutTimes').textContent).toContain('updated ');
    expect(screen.getByTestId('wamCaseFlyoutDue')).toBeTruthy();
    expect(screen.getByTestId('wamCaseFlyoutTasksChip').textContent).toBe('1/3 tasks');
    const actions = screen.getByTestId('wamCaseFlyoutActions');
    expect(actions.querySelector('[data-test-subj="wamCaseReportButton"]')).toBeTruthy();
    expect(actions.querySelector('[data-test-subj="wamCaseFlyoutExpand"]')).toBeTruthy();
    expect(actions.querySelector('[data-test-subj="wamCaseFlyoutClose"]')).toBeTruthy();
    // The built-in EUI flyout X is hidden so the header carries exactly one close control.
    expect(
      document.querySelectorAll(
        '[data-test-subj="wamCaseFlyoutClose"], [data-test-subj="euiFlyoutCloseButton"], .euiFlyout__closeButton'
      ).length
    ).toBe(1);
    expect(screen.getByTestId('wamCaseFlyoutTitle').textContent).toBe('Suspicious logins on web-01');
  });

  test('Close in the action group calls onClose; Expand toggles to Collapse', async () => {
    const onClose = jest.fn();
    renderFlyout(apiServiceWith(), { onClose });
    await waitFor(() => expect(screen.getByTestId('wamCaseNav')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamCaseFlyoutClose'));
    expect(onClose).toHaveBeenCalledTimes(1);
    // The EUI test build does not carry the flyout's className into the DOM,
    // so the toggle is asserted through the button's own state.
    expect(screen.getByTestId('wamCaseFlyoutExpand').getAttribute('aria-label')).toBe('Expand to full screen');
    fireEvent.click(screen.getByTestId('wamCaseFlyoutExpand'));
    expect(screen.getByTestId('wamCaseFlyoutExpand').getAttribute('aria-label')).toBe('Collapse');
    expect(screen.getByTestId('wamCaseFlyoutExpand').textContent).toContain('Collapse');
    fireEvent.click(screen.getByTestId('wamCaseFlyoutExpand'));
    expect(screen.getByTestId('wamCaseFlyoutExpand').textContent).toContain('Expand');
  });

  test('Overview is the edit form followed by the Record / Progress meta grid and edits through a Save that is disabled until something changed', async () => {
    const apiService = await openCase();
    const meta = screen.getByTestId('wamCaseMeta');
    // 11.6: a grouped meta grid after the form; Status / Severity / Assigned to
    // are only shown once, as the controls above it.
    // Valid content model: a <div> grid of role=group blocks, each with ONE
    // <dl> whose direct children wrap exactly one <dt> + <dd> pair.
    expect(meta.tagName).toBe('DIV');
    const recordGroup = screen.getByTestId('wamCaseMetaRecord');
    expect(recordGroup.getAttribute('role')).toBe('group');
    expect(recordGroup.getAttribute('aria-labelledby')).toBe(recordGroup.querySelector('.wamMetaGrid__groupTitle span')!.id);
    const recordList = recordGroup.querySelector(':scope > dl.wamMetaGrid__rows')!;
    expect(recordList).not.toBeNull();
    expect(Array.from(recordList.children).every((row) => row.tagName === 'DIV' && row.className === 'wamMetaGrid__row' && row.children.length === 2 && row.children[0].tagName === 'DT' && row.children[1].tagName === 'DD')).toBe(true);
    expect(meta.className).toContain('wamMetaGrid');
    expect(meta.className).toContain('wamMetaList');
    const titleField = screen.getByTestId('wamCaseEditTitle');
    expect(titleField.compareDocumentPosition(meta) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByTestId('wamCaseEditSave').compareDocumentPosition(meta) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const groups = Array.from(meta.querySelectorAll('.wamMetaGrid__groupTitle')).map((node) => node.textContent);
    expect(groups).toEqual(['Record', 'Progress']);
    const titles = Array.from(meta.querySelectorAll('.wamMetaGrid__label')).map((node) => node.textContent);
    expect(titles).toEqual(['Created', 'Last updated', 'SLA due', 'Tasks']);
    expect(Array.from(screen.getByTestId('wamCaseMetaProgress').querySelectorAll('.wamMetaGrid__label')).map((node) => node.textContent)).toEqual(['SLA due', 'Tasks']);
    const assignee = screen.getByTestId('wamCaseOverviewAssignee');
    expect(assignee.className).toContain('euiFormRow');
    expect(assignee.closest('.wamCaseFormGrid')).not.toBeNull();
    expect(assignee.textContent).toContain('analyst');
    expect(screen.getByTestId('wamCaseOverviewTasks').textContent).toBe('1 of 3 done');
    expect(screen.getByTestId('wamCaseOverviewDue')).toBeTruthy();
    // Nothing in the Overview is larger than EuiText size s (no titles at all).
    const overview = screen.getByTestId('wamCaseOverview');
    Array.from(overview.querySelectorAll('.euiText')).forEach((node) => expect(node.className).toMatch(/euiText--(small|extraSmall)/));
    expect(overview.querySelectorAll('.euiTitle').length).toBe(0);
    expect((screen.getByTestId('wamCaseEditDescription') as HTMLTextAreaElement).rows).toBe(3);

    const save = screen.getByTestId('wamCaseEditSave') as HTMLButtonElement;
    const cancel = screen.getByTestId('wamCaseEditCancel') as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(cancel.disabled).toBe(true);

    fireEvent.change(screen.getByTestId('wamCaseEditTitle'), { target: { value: 'Renamed case' } });
    expect(save.disabled).toBe(false);
    expect(cancel.disabled).toBe(false);

    fireEvent.click(cancel);
    expect((screen.getByTestId('wamCaseEditTitle') as HTMLInputElement).value).toBe('Suspicious logins on web-01');
    expect(save.disabled).toBe(true);

    fireEvent.change(screen.getByTestId('wamCaseEditDescription'), { target: { value: 'Updated description' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('wamCaseEditSave'));
    });
    expect(apiService.updateCase).toHaveBeenCalledWith('case-1', { title: 'Suspicious logins on web-01', description: 'Updated description' });
    await waitFor(() => expect((screen.getByTestId('wamCaseEditSave') as HTMLButtonElement).disabled).toBe(true));
  });

  test('a closed case shows the closed time, the disposition and the closure reason in the Overview list and the header badge', async () => {
    const closed = { ...caseDoc, status: 'closed', closed_at: '2026-11-21T09:00:00.000Z', disposition: 'false_positive', closure_reason: 'Scanner noise', sla_due_at: null };
    await openCase(apiServiceWith({ fetchCase: jest.fn(async () => ({ case: closed, alerts: [], evidence: { evidence: [], total: 0, nextCursor: null } })) }));
    expect(screen.getByTestId('wamCaseFlyoutDisposition').textContent).toBe('False positive');
    expect(screen.getByTestId('wamCaseClosedRow')).toBeTruthy();
    expect(screen.getByTestId('wamCaseOverviewDisposition').textContent).toBe('False positive');
    expect(screen.getByTestId('wamCaseClosureReason').textContent).toBe('Scanner noise');
    expect(screen.queryByTestId('wamCaseOverviewDue')).toBeNull();
    expect(screen.queryByTestId('wamCaseFlyoutDue')).toBeNull();
    expect(screen.getByTestId('wamCaseNavCount-alerts').textContent).toBe('0');
  });
});

describe('CaseFlyout Assets section (step 11.4)', () => {
  function withAgents(agents: Array<{ id: string; name: string }>) {
    const ids = agents.map((_, i) => `a${i + 1}`);
    return apiServiceWith({
      fetchCase: jest.fn(async () => ({
        case: { ...caseDoc, alert_ids: ids, evidence_count: ids.length },
        alerts: ids.map((id, i) => alertRow(id, agents[i])),
        evidence: { evidence: ids.map((id) => ({ alert_id: id, relationship_state: 'live' })), total: ids.length, nextCursor: null },
      })),
    });
  }

  test('a single-agent case: the header shows one summary line whose counts fill in without visiting the section; the only row is expanded and reads the same fetch', async () => {
    const apiService = await openCase();
    // The header carries the summary line only: no chip rows, no "+N more agents".
    expect(screen.queryByTestId('wamCaseAssetContext')).toBeNull();
    expect(screen.queryByTestId('wamCaseAssetContextMore')).toBeNull();
    const summary = screen.getByTestId('wamCaseAssetSummary');
    expect(summary.tagName).toBe('BUTTON');
    // The visible text is the accessible name (no aria-label hides the counts from a screen reader).
    expect(summary.getAttribute('aria-label')).toBeNull();
    expect(summary.getAttribute('title')).toBe('Open the Assets section');
    expect(screen.getByTestId('wamCaseAssetSummaryAgents').textContent).toBe('1 agent');
    expect(screen.getByTestId('wamCaseNavCount-assets').textContent).toBe('1');
    expect(screen.getByTestId('wamCaseNav-assets').textContent).toContain('Assets');
    // The flyout fetched the default-open row itself while Overview is active: the header counts appear.
    await waitFor(() => expect(screen.getByTestId('wamCaseAssetSummaryCounts-vuln').textContent).toBe('1 critical / 2 high'));
    expect(screen.queryByTestId('wamCaseAssetSummaryCounts-sca')).toBeNull();
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1);
    expect(apiService.fetchAssetContext).toHaveBeenCalledWith({ agentId: '001', agentName: 'web-01' });

    fireEvent.click(summary);
    expect(screen.getByTestId('wamCaseSection-assets')).toBeTruthy();
    expect(screen.getByTestId('wamCaseNav-assets').className).toContain('isSelected');
    expect(screen.getAllByTestId(/^wamCaseAssetRow-/)).toHaveLength(1);
    expect(screen.getByTestId('wamCaseAssetRowName-001').textContent).toBe('web-01');
    expect(screen.getByTestId('wamCaseAssetRowId-001').textContent).toBe('001');
    expect(screen.getByTestId('wamCaseAssetRowToggle-001').getAttribute('aria-expanded')).toBe('true');
    // Auto-expanded: the row shows the cached context (no second fetch) and its title carries the counts.
    const chips = screen.getByTestId('wamCaseAssetContext');
    expect(chips.getAttribute('data-agent')).toBe('001');
    expect(chips.getAttribute('data-source')).toBe('ready');
    expect(screen.getByTestId('wamCaseAssetRowCounts-001-vuln').textContent).toBe('1 critical / 2 high');
    expect(screen.queryByTestId('wamCaseAssetRowCounts-001-sca')).toBeNull();
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1);

    // Leaving and re-entering the section keeps the header counts and costs no refetch.
    fireEvent.click(screen.getByTestId('wamCaseNav-overview'));
    expect(screen.getByTestId('wamCaseAssetSummaryCounts-vuln').textContent).toBe('1 critical / 2 high');
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    expect(screen.getByTestId('wamCaseAssetContext').getAttribute('data-source')).toBe('ready');
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1);
  });

  test('a two-agent case: the header counts agents, every agent gets a collapsed row and a row fetches only when expanded', async () => {
    const apiService = await openCase(withAgents([{ id: '001', name: 'web-01' }, { id: '002', name: 'db-01' }, { id: '001', name: 'web-01' }]));
    expect(screen.getByTestId('wamCaseAssetSummaryAgents').textContent).toBe('2 agents');
    expect(screen.getByTestId('wamCaseNavCount-assets').textContent).toBe('2');
    expect(apiService.fetchAssetContext).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    const rows = screen.getAllByTestId(/^wamCaseAssetRow-/).map((row) => row.getAttribute('data-test-subj'));
    expect(rows).toEqual(['wamCaseAssetRow-001', 'wamCaseAssetRow-002']);
    expect(screen.getByTestId('wamCaseAssetRowToggle-001').getAttribute('aria-expanded')).toBe('false');
    expect(screen.getByTestId('wamCaseAssetRowToggle-002').getAttribute('aria-expanded')).toBe('false');
    // Nothing fetched yet: no chip row is mounted and the header has no counts.
    expect(screen.queryByTestId('wamCaseAssetContext')).toBeNull();
    expect(screen.queryByTestId('wamCaseAssetSummaryCounts')).toBeNull();
    expect(apiService.fetchAssetContext).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('wamCaseAssetRowToggle-002'));
    expect(screen.getByTestId('wamCaseAssetRowToggle-002').getAttribute('aria-expanded')).toBe('true');
    expect(screen.getAllByTestId('wamCaseAssetContext')).toHaveLength(1);
    expect(screen.getByTestId('wamCaseAssetContext').getAttribute('data-agent')).toBe('002');
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1);
    expect(apiService.fetchAssetContext).toHaveBeenCalledWith({ agentId: '002', agentName: 'db-01' });
    await waitFor(() => expect(screen.getByTestId('wamCaseAssetRowCounts-002-sca').textContent).toBe('4 SCA failed'));
    expect(screen.getByTestId('wamCaseAssetContext').getAttribute('data-source')).toBe('ready');
    expect(screen.queryByTestId('wamCaseAssetRowCounts-001')).toBeNull();
    // The header aggregates the loaded rows only.
    expect(screen.getByTestId('wamCaseAssetSummaryCounts-vuln').textContent).toBe('1 critical / 2 high');
    expect(screen.getByTestId('wamCaseAssetSummaryCounts-sca').textContent).toBe('4 SCA failed');

    // Collapsing keeps the fetched row mounted (no refetch on the next expand); expanding the other row mounts a second.
    fireEvent.click(screen.getByTestId('wamCaseAssetRowToggle-002'));
    expect(screen.getByTestId('wamCaseAssetRowToggle-002').getAttribute('aria-expanded')).toBe('false');
    expect(screen.getAllByTestId('wamCaseAssetContext')).toHaveLength(1);
    fireEvent.click(screen.getByTestId('wamCaseAssetRowToggle-001'));
    expect(screen.getAllByTestId('wamCaseAssetContext')).toHaveLength(2);
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(screen.getByTestId('wamCaseAssetSummaryCounts-vuln').textContent).toBe('2 critical / 4 high'));

    // Leaving and re-entering the section re-renders both rows from the cache: no further read.
    fireEvent.click(screen.getByTestId('wamCaseNav-overview'));
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    expect(screen.getAllByTestId('wamCaseAssetContext').map((el) => el.getAttribute('data-source'))).toEqual(['ready', 'ready']);
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(2);
  });

  test('a failed context read marks the row unavailable, leaves the header without counts and is not retried on re-entry', async () => {
    const apiService = await openCase(apiServiceWith({ fetchAssetContext: jest.fn(async () => { throw new Error('boom'); }) }));
    await waitFor(() => expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    await waitFor(() => expect(screen.getByTestId('wamCaseAssetContext').getAttribute('data-source')).toBe('failed'));
    expect(screen.queryByTestId('wamCaseAssetSummaryCounts')).toBeNull();
    expect(screen.queryByTestId('wamCaseAssetRowCounts-001')).toBeNull();
    fireEvent.click(screen.getByTestId('wamCaseNav-overview'));
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1);
  });

  test('paging the Linked alerts list grows the agent set over every loaded page and keeps the first row open and fetched', async () => {
    const ids = Array.from({ length: 25 }, (_, i) => `a${i + 1}`);
    const apiService = apiServiceWith({
      fetchCase: jest.fn(async () => ({
        case: { ...caseDoc, alert_ids: ids, evidence_count: 30 },
        alerts: ids.map((id) => alertRow(id)),
        evidence: { evidence: ids.map((id) => ({ alert_id: id, relationship_state: 'live' })), total: 30, nextCursor: 'cursor-2' },
      })),
      fetchCaseEvidence: jest.fn(async () => ({
        alerts: ['b1', 'b2'].map((id) => alertRow(id, { id: '002', name: 'db-01' })),
        evidence: ['b1', 'b2'].map((id) => ({ alert_id: id, relationship_state: 'live' })),
        total: 30,
        nextCursor: null,
      })),
    });
    await openCase(apiService);
    expect(screen.getByTestId('wamCaseAssetSummaryAgents').textContent).toBe('1 agent');
    await waitFor(() => expect(screen.getByTestId('wamCaseAssetSummaryCounts-vuln').textContent).toBe('1 critical / 2 high'));

    fireEvent.click(screen.getByTestId('wamCaseNav-alerts'));
    fireEvent.click(screen.getByTestId('wamCaseEvidenceNext'));
    await waitFor(() => expect(screen.getByTestId('wamCaseAssetSummaryAgents').textContent).toBe('2 agents'));
    expect(apiService.fetchCaseEvidence).toHaveBeenCalledWith('case-1', 'cursor-2', 25);
    expect(screen.getByTestId('wamCaseNavCount-assets').textContent).toBe('2');
    // The page-1 agent survives (the list is the union of the loaded pages), its row stays open and its counts stay in the header.
    expect(screen.getByTestId('wamCaseAssetSummaryCounts-vuln').textContent).toBe('1 critical / 2 high');
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    expect(screen.getAllByTestId(/^wamCaseAssetRow-/).map((row) => row.getAttribute('data-test-subj'))).toEqual(['wamCaseAssetRow-001', 'wamCaseAssetRow-002']);
    expect(screen.getByTestId('wamCaseAssetRowToggle-001').getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByTestId('wamCaseAssetRowToggle-002').getAttribute('aria-expanded')).toBe('false');
    expect(screen.getByTestId('wamCaseAssetContext').getAttribute('data-source')).toBe('ready');
    expect(apiService.fetchAssetContext).toHaveBeenCalledTimes(1);

    // Paging back to page 1 does not drop the page-2 agent.
    fireEvent.click(screen.getByTestId('wamCaseNav-alerts'));
    fireEvent.click(screen.getByTestId('wamCaseEvidencePrev'));
    expect(screen.getByTestId('wamCaseAssetSummaryAgents').textContent).toBe('2 agents');
  });

  test('row subjects stay distinct for an id-keyed agent and a name-only agent that share a label', async () => {
    expect(contextAgentSubject({ key: 'id:001', id: '001', name: 'web-01' })).toBe('001');
    expect(contextAgentSubject({ key: 'name:001', id: null, name: '001' })).toBe('name-001');
    expect(contextAgentSubject({ key: 'name:web 01', id: null, name: 'web 01' })).toBe('name-web_01');

    const rows: any[] = [alertRow('a1', { id: '001', name: 'web-01' }), { _id: 'a2', _source: { '@timestamp': '2026-11-20T09:00:00.000Z', status: 'open', agent: { name: '001' }, rule: { id: '1', level: 3 } } }];
    await openCase(apiServiceWith({
      fetchCase: jest.fn(async () => ({
        case: { ...caseDoc, alert_ids: ['a1', 'a2'], evidence_count: 2 },
        alerts: rows,
        evidence: { evidence: [{ alert_id: 'a1', relationship_state: 'live' }, { alert_id: 'a2', relationship_state: 'live' }], total: 2, nextCursor: null },
      })),
    }));
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    const subjects = screen.getAllByTestId(/^wamCaseAssetRow-/).map((row) => row.getAttribute('data-test-subj'));
    expect(subjects).toEqual(['wamCaseAssetRow-001', 'wamCaseAssetRow-name-001']);
    // Each toggle controls its own panel (the accordion ids are derived from the same unique subject).
    const controls = screen.getAllByTestId(/^wamCaseAssetRowToggle-/).map((toggle) => toggle.getAttribute('aria-controls'));
    expect(controls).toEqual(['wamCaseAssetRow-001', 'wamCaseAssetRow-name-001']);
  });

  test('a case without agents has no summary line and the section says so', async () => {
    await openCase(withAgents([]));
    expect(screen.queryByTestId('wamCaseAssetSummary')).toBeNull();
    expect(screen.queryByTestId('wamCaseNavCount-assets')).toBeNull();
    fireEvent.click(screen.getByTestId('wamCaseNav-assets'));
    expect(screen.getByTestId('wamCaseAssetsEmpty')).toBeTruthy();
  });
});

describe('CaseFlyout Indicators section (step 10.5)', () => {
  const indicatorRows = [
    { type: 'ip', value: '10.0.2.15', fields: ['data.srcip'], tags: ['private'], count: 14, alert_ids: ['a1', 'a2'], first_seen: '2026-11-21T10:00:28.000Z', last_seen: '2026-11-21T11:57:26.000Z', verdictHints: [], enrichment: [] },
    { type: 'hash', value: '2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376', fields: ['syscheck.sha256_after'], tags: [], count: 1, alert_ids: ['a3'], first_seen: '2026-11-21T10:00:28.000Z', last_seen: '2026-11-21T10:00:28.000Z', verdictHints: [], enrichment: [] },
  ];

  function withIndicators() {
    return apiServiceWith({
      fetchCaseIndicators: jest.fn(async () => ({ indicators: indicatorRows, includedAlerts: 3, truncated: false, limit: 500 })),
    });
  }

  test('(b) a successful load clears "(refreshing...)" and re-enables Refresh; Refresh loads again and settles the same way', async () => {
    const api = await openCase(withIndicators());
    fireEvent.click(screen.getByTestId('wamCaseNav-indicators'));
    const section = screen.getByTestId('wamCaseIndicators');
    await waitFor(() => expect(section.querySelectorAll('.wamIndicatorTable tbody tr').length).toBe(2));
    expect(api.fetchCaseIndicators).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(section.textContent).not.toContain('(refreshing...)'));
    expect(section.textContent).toContain('2 indicator(s) across 3 linked alerts');
    const refresh = screen.getByTestId('wamCaseIndicatorsRefresh') as HTMLButtonElement;
    expect(refresh.disabled).toBe(false);

    fireEvent.click(refresh);
    await waitFor(() => expect(api.fetchCaseIndicators).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(section.textContent).not.toContain('(refreshing...)'));
    expect((screen.getByTestId('wamCaseIndicatorsRefresh') as HTMLButtonElement).disabled).toBe(false);
    // Leaving and re-entering the section does not refetch a settled load.
    fireEvent.click(screen.getByTestId('wamCaseNav-overview'));
    fireEvent.click(screen.getByTestId('wamCaseNav-indicators'));
    expect(api.fetchCaseIndicators).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('wamCaseIndicators').querySelectorAll('.wamIndicatorTable tbody tr').length).toBe(2);
  });

  test('(b) a failed load also settles: the error callout shows, the label clears and Refresh is enabled', async () => {
    const onError = jest.fn();
    const api = apiServiceWith({
      fetchCaseIndicators: jest.fn(async () => {
        throw Object.assign(new Error('nope'), { body: { statusCode: 403 } });
      }),
    });
    renderFlyout(api, { onError });
    await waitFor(() => expect(screen.getByTestId('wamCaseNav')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamCaseNav-indicators'));
    await waitFor(() => expect(screen.getByTestId('wamCaseIndicatorsError').textContent).toContain('You do not have access to this case'));
    expect(screen.getByTestId('wamCaseIndicators').textContent).not.toContain('(refreshing...)');
    expect((screen.getByTestId('wamCaseIndicatorsRefresh') as HTMLButtonElement).disabled).toBe(false);
    expect(onError).toHaveBeenCalledWith('Failed to load case indicators');
  });

  test('(a) the table is compressed auto layout with no fixed widths, a growing value cell, badge cells and a right-aligned actions cell', async () => {
    await openCase(withIndicators());
    fireEvent.click(screen.getByTestId('wamCaseNav-indicators'));
    const section = screen.getByTestId('wamCaseIndicators');
    await waitFor(() => expect(section.querySelectorAll('.wamIndicatorTable tbody tr').length).toBe(2));
    const table = section.querySelector('table')!;
    expect(table.className).toContain('euiTable--auto');
    expect(table.className).toContain('euiTable--compressed');
    const headers = Array.from(table.querySelectorAll('th')).map((th) => th.textContent!.trim());
    expect(headers).toEqual(['Type', 'Value', 'Alerts', 'First seen', 'Last seen', 'Native verdicts', 'Lookups', 'Actions']);
    for (const th of Array.from(table.querySelectorAll('th'))) {
      expect((th as HTMLElement).style.width).toBe('');
    }
    const hashRow = Array.from(table.querySelectorAll('tbody tr')).find((row) => row.textContent!.includes('2ce9f77d'))!;
    expect(hashRow.querySelector('.wamIndicatorTable__value [data-test-subj="wamIndicatorValueCell"] code')!.textContent).toBe('2ce9f77d55364b99a68c5a8600b4040ac99401ae2dbcfc61ee596d3bc7bdb376');
    expect(hashRow.querySelectorAll('.wamIndicatorTable__narrow').length).toBe(4);
    expect(hashRow.querySelectorAll('.wamIndicatorTable__badges').length).toBe(2);
    expect(hashRow.querySelector('.wamIndicatorTable__actions')!.className).toContain('euiTableCellContent--alignRight');
  });

  test('(a) below 1100px of content width the First seen / Last seen columns fold into one Seen column', async () => {
    const original = HTMLElement.prototype.getBoundingClientRect;
    HTMLElement.prototype.getBoundingClientRect = function () {
      return { width: 900, height: 0, top: 0, left: 0, right: 900, bottom: 0, x: 0, y: 0, toJSON: () => ({}) } as DOMRect;
    };
    try {
      await openCase(withIndicators());
      fireEvent.click(screen.getByTestId('wamCaseNav-indicators'));
      const section = screen.getByTestId('wamCaseIndicators');
      await waitFor(() => expect(section.querySelectorAll('.wamIndicatorTable tbody tr').length).toBe(2));
      const headers = Array.from(section.querySelectorAll('th')).map((th) => th.textContent!.trim());
      expect(headers).toEqual(['Type', 'Value', 'Alerts', 'Seen', 'Native verdicts', 'Lookups', 'Actions']);
      expect(section.querySelectorAll('[data-test-subj="wamIndicatorSeen"]').length).toBe(2);
    } finally {
      HTMLElement.prototype.getBoundingClientRect = original;
    }
  });
});

describe('CaseFlyout Attack graph reloads (step 10.4)', () => {
  function caseResponse(ids: string[], holdOn?: string) {
    // A held relationship carries `relationship_state: 'held'`, as the server writes it.
    const rel = (id: string) => (id === holdOn ? { alert_id: id, relationship_state: 'held', hold_reason: 'keep' } : { alert_id: id, relationship_state: 'linked' });
    return {
      case: { ...caseDoc, alert_ids: ids, evidence_count: ids.length },
      alerts: ids.map((id) => alertRow(id)),
      evidence: { evidence: ids.map(rel), total: ids.length, nextCursor: null },
    };
  }

  function withGraph(reloaded: any) {
    const fetchCase = jest.fn()
      .mockResolvedValueOnce(caseResponse(['a1', 'a2', 'a3'], 'a1'))
      .mockResolvedValue(reloaded);
    return apiServiceWith({
      fetchCase,
      fetchAttackPath: jest.fn(async () => ({ hops: [], nodes: [], edges: [] })),
      releaseEvidenceHold: jest.fn(async () => ({})),
      // The hold buttons render only for lifecycle managers.
      fetchSystemCapabilities: jest.fn(async () => ({ canManageLifecycle: true })),
    });
  }

  // Open the graph once, then release the hold on a1 from the Linked alerts
  // section (the flyout reloads the case) and come back to the graph.
  async function openGraphReleaseHoldReturn(apiService: any) {
    renderFlyout(apiService);
    await waitFor(() => expect(screen.getByTestId('wamCaseNav')).toBeTruthy());
    fireEvent.click(screen.getByTestId('wamCaseNav-attack-path'));
    await waitFor(() => expect(apiService.fetchAttackPath).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByTestId('wamCaseNav-alerts'));
    const release = await screen.findByLabelText('Release evidence hold');
    await act(async () => {
      fireEvent.click(release);
    });
    await waitFor(() => expect(apiService.fetchCase).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByLabelText('Release evidence hold')).toBeNull());
    fireEvent.click(screen.getByTestId('wamCaseNav-attack-path'));
  }

  test('a reload that leaves the linked-evidence set unchanged does not refetch the graph', async () => {
    const apiService = withGraph(caseResponse(['a1', 'a2', 'a3']));
    await openGraphReleaseHoldReturn(apiService);
    await waitFor(() => expect(screen.getByTestId('wamCaseNav-attack-path').className).toContain('isSelected'));
    expect(apiService.fetchAttackPath).toHaveBeenCalledTimes(1);
  });

  test('a reload whose evidence set changed refetches the graph on the next visit', async () => {
    const apiService = withGraph(caseResponse(['a1', 'a2']));
    await openGraphReleaseHoldReturn(apiService);
    await waitFor(() => expect(apiService.fetchAttackPath).toHaveBeenCalledTimes(2));
  });
});
