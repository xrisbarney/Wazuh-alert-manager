/**
 * @jest-environment jsdom
 */
import React from 'react';
import { configure, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { RulesView } from './rules_view';

configure({ testIdAttribute: 'data-test-subj' });

const FIRED_AT = new Date(Date.now() - 5 * 60_000).toISOString();

const baseRule = (overrides: any) => ({
  schemaVersion: 2,
  revision: 2,
  if_seq_no: 10,
  if_primary_term: 1,
  priority: 100,
  sortOrder: 0,
  processingMode: 'continue',
  match: { ruleGroups: ['sshd'], agentNames: ['lab'] },
  trigger: { type: 'per_alert', entityExpression: { version: 1, groups: [] }, routing: 'separate_by_group' },
  actions: { setStatus: 'in_progress', createCase: false },
  preconditions: { statuses: ['open'], assignment: 'any' },
  safety: { acknowledgeMatchAll: false },
  created_by: 'admin',
  ...overrides,
});

const FIRED = baseRule({ id: 'r1', name: 'Fired rule', enabled: true, matchCount: 44, lastFired: FIRED_AT, counters: { matchedAlerts: 44, triggeredEntities: 3 } });
const DRAFT = baseRule({ id: 'r2', name: 'Draft rule', enabled: false, revision: 1 });

function apiServiceWith(rules: any[], isPluginAdmin = true) {
  return {
    fetchRules: jest.fn(async () => ({ rules })),
    fetchRule: jest.fn(async (id: string) => rules.find((rule) => rule.id === id)),
    fetchUsers: jest.fn(async () => ['admin', 'bob']),
    fetchTaskLists: jest.fn(async () => ({ taskLists: [], limit: 200 })),
    fetchNotificationSettings: jest.fn(async () => ({ channels: [] })),
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    fetchAutomationQueue: jest.fn(async () => ({ lag: 0, oldestEvent: null, oldestAgeSeconds: null, retries: 0, dlq: 0, states: {}, paused: false, admissionOpen: true, deferred: 0, maxBacklog: 1000, maxDeferred: 5000, fencing: { generation: 1, holderId: 'w1' } })),
    fetchAutomationSettings: jest.fn(async () => ({ paused: false, maxBacklog: 1000, maxDeferred: 5000 })),
    fetchAutomationDlq: jest.fn(async () => ({ items: [], nextCursor: null })),
    fetchRuleRevisions: jest.fn(async () => ({ revisions: [], total: 0, page: 1, size: 100 })),
    updateRule: jest.fn(async (id: string, payload: any) => ({ ...rules.find((rule) => rule.id === id), ...payload, revision: 3, if_seq_no: 11 })),
    createRule: jest.fn(),
    previewRule: jest.fn(),
  } as any;
}

/** The "Enable after save" EuiSwitch control (checkbox input or switch button, depending on the EUI build). */
function enableSwitch(): HTMLInputElement | HTMLButtonElement {
  const label = screen.getByText('Enable after save');
  const host = label.closest('.euiSwitch') || label.parentElement!;
  return host.querySelector('input[type="checkbox"], button[role="switch"]') as HTMLInputElement | HTMLButtonElement;
}
const isChecked = (control: HTMLInputElement | HTMLButtonElement) => (control as HTMLInputElement).type === 'checkbox' ? (control as HTMLInputElement).checked : control.getAttribute('aria-checked') === 'true';

async function renderView(rules: any[]) {
  const apiService = apiServiceWith(rules);
  const onToast = jest.fn();
  render(<RulesView apiService={apiService} onToast={onToast} />);
  await waitFor(() => expect(screen.getByText('Fired rule')).toBeTruthy());
  await waitFor(() => expect(apiService.fetchSystemCapabilities).toHaveBeenCalled());
  return { apiService, onToast };
}

describe('RulesView execution state and enabled-rule edits (step 12.3)', () => {
  test('the list and the runtime card read matchCount / lastFired the runtime wrote', async () => {
    await renderView([FIRED, DRAFT]);
    const firedRow = screen.getByText('Fired rule').closest('tr')!;
    expect(within(firedRow).getByText(/44 matched/).textContent).toMatch(/ago · 44 matched/);
    const draftRow = screen.getByText('Draft rule').closest('tr')!;
    expect(within(draftRow).getByText('Never')).toBeTruthy();
    expect(screen.getByTestId('wamAutomationRuleCounters').textContent).toContain('Rules fired: Fired rule (44 matched,');
  });

  test('an enabled rule can be edited and saved without a preview; the revision bump is announced', async () => {
    const { apiService, onToast } = await renderView([FIRED, DRAFT]);
    await waitFor(() => expect((screen.getByLabelText('Edit Fired rule') as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByLabelText('Edit Fired rule'));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Edit Fired rule' })).toBeTruthy());
    const nameInput = screen.getByPlaceholderText('Authentication failures per host') as HTMLInputElement;
    expect(nameInput.value).toBe('Fired rule');
    fireEvent.change(nameInput, { target: { value: 'Fired rule v2' } });
    fireEvent.click(screen.getByRole('tab', { name: '6. Preview' }));
    const control = enableSwitch();
    expect(isChecked(control)).toBe(true);
    expect(control.disabled).toBe(false);
    const save = screen.getByRole('button', { name: 'Save changes' }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(apiService.updateRule).toHaveBeenCalledTimes(1));
    expect(apiService.updateRule.mock.calls[0][0]).toBe('r1');
    expect(apiService.updateRule.mock.calls[0][1]).toEqual(expect.objectContaining({ name: 'Fired rule v2', enabled: true }));
    expect(apiService.updateRule.mock.calls[0][2]).toEqual({ revision: 2, if_seq_no: 10, if_primary_term: 1 });
    expect(apiService.previewRule).not.toHaveBeenCalled();
    expect(onToast).toHaveBeenCalledWith('Rule updated', 'success', 'Revision 3 is live; the rule stays enabled.');
  });

  test('a disabled draft still needs a current preview before it can be enabled', async () => {
    const { apiService } = await renderView([FIRED, DRAFT]);
    await waitFor(() => expect((screen.getByLabelText('Edit Draft rule') as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByLabelText('Edit Draft rule'));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Edit Draft rule' })).toBeTruthy());
    fireEvent.click(screen.getByRole('tab', { name: '6. Preview' }));
    expect(screen.getByText('Activation gate not satisfied')).toBeTruthy();
    expect(enableSwitch().disabled).toBe(true);
    expect(screen.getByRole('button', { name: 'Save draft' })).toBeTruthy();
    expect(apiService.updateRule).not.toHaveBeenCalled();
  });
});

describe('RulesView enabled-rule editor guards (step 12.3 review fixes)', () => {
  /** The Basics-stage "Enabled" EuiSwitch control. */
  const basicsSwitch = (): HTMLInputElement | HTMLButtonElement => {
    const label = screen.getAllByText('Enabled').find((node) => node.closest('.euiSwitch'))!;
    const host = label.closest('.euiSwitch')!;
    return host.querySelector('input[type="checkbox"], button[role="switch"]') as HTMLInputElement | HTMLButtonElement;
  };
  const openFired = async (rules: any[]) => {
    const view = await renderView(rules);
    await waitFor(() => expect((screen.getByLabelText('Edit Fired rule') as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByLabelText('Edit Fired rule'));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Edit Fired rule' })).toBeTruthy());
    return view;
  };

  test('the Basics switch of an enabled rule can be turned off and back on without a preview', async () => {
    const { onToast, apiService } = await openFired([FIRED, DRAFT]);
    expect(screen.getByText(/This rule is enabled; switch it off to disable it on save/)).toBeTruthy();
    expect(isChecked(basicsSwitch())).toBe(true);
    fireEvent.click(basicsSwitch());
    await waitFor(() => expect(isChecked(basicsSwitch())).toBe(false));
    fireEvent.click(basicsSwitch());
    await waitFor(() => expect(isChecked(basicsSwitch())).toBe(true));
    expect(onToast).not.toHaveBeenCalledWith('Preview the current definition before enabling', 'primary');
    // Still on the Basics stage (the name field is rendered there), not bounced to the preview stage.
    expect(screen.getByPlaceholderText('Authentication failures per host')).toBeTruthy();
    expect(apiService.previewRule).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('tab', { name: '6. Preview' }));
    expect((screen.getByRole('button', { name: 'Save changes' }) as HTMLButtonElement).disabled).toBe(false);
  });

  test('an entity-group 409 keeps the edits and shows the server reason instead of reloading the rule', async () => {
    const message = 'Disable and save the rule before changing entity groups, then save, preview, and enable the new definition.';
    const { apiService, onToast } = await openFired([FIRED, DRAFT]);
    apiService.updateRule.mockRejectedValueOnce({ body: { statusCode: 409, message } });
    const nameInput = screen.getByPlaceholderText('Authentication failures per host') as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Fired rule v2' } });
    fireEvent.click(screen.getByRole('tab', { name: '6. Preview' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('Failed to save rule', 'danger', message));
    expect(onToast).not.toHaveBeenCalledWith('Rule changed on the server', 'primary', expect.anything());
    expect(apiService.fetchRule).not.toHaveBeenCalled();
    // The editor is still open with the user's edit.
    fireEvent.click(screen.getByRole('tab', { name: '1. Basics' }));
    expect((screen.getByPlaceholderText('Authentication failures per host') as HTMLInputElement).value).toBe('Fired rule v2');
  });

  test('a stale-revision 409 still reloads the server copy', async () => {
    const { apiService, onToast } = await openFired([FIRED, DRAFT]);
    apiService.updateRule.mockRejectedValueOnce({ body: { statusCode: 409, message: 'Rule revision is stale.' } });
    fireEvent.click(screen.getByRole('tab', { name: '6. Preview' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(onToast).toHaveBeenCalledWith('Rule changed on the server', 'primary', expect.any(String)));
    expect(apiService.fetchRule).toHaveBeenCalledWith('r1');
  });
});
