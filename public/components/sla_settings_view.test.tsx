/**
 * @jest-environment jsdom
 */

// These assertions describe the Wazuh 4.x behaviour of this module (native
// alert indices, numeric rule levels, the 4.x channel/source set). The build
// target is a build-time constant and CI runs this suite once per matrix
// entry, including the 5.0 one, so pin it rather than assert whichever
// target happens to be checked in.
jest.mock('../../common/build_info', () => ({ ...(jest.requireActual('../../common/build_info') as object), TARGET_WAZUH_MAJOR: 4, TARGET_WAZUH_VERSION: '4.14.10' }));

import React from 'react';
import { configure, fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  SlaSettingsView,
  describeEscalationActions,
  describeEscalationStatus,
  draftToEscalation,
  draftToTargets,
  EMPTY_ESCALATION_DRAFT,
  minutesHelper,
  parseChannelIds,
  sameTargets,
  suggestEscalationId,
} from './sla_settings_view';
import { slaTargetsText } from './sla_targets_text';

configure({ testIdAttribute: 'data-test-subj' });

const defaults = {
  targets: {
    critical: { resolveMinutes: 60, assignMinutes: 15 },
    high: { resolveMinutes: 240, assignMinutes: 60 },
    medium: { resolveMinutes: 1440, assignMinutes: 360 },
    low: { resolveMinutes: 4320, assignMinutes: 1080 },
  },
  escalations: [],
};

function apiServiceWith(isPluginAdmin: boolean, policy: any = defaults, failLoad = false, storedInvalid = false, scanner: any = undefined) {
  let stored = policy;
  return {
    fetchSystemCapabilities: jest.fn(async () => ({ isPluginAdmin })),
    ...(scanner !== undefined ? { fetchSlaEscalationStatus: jest.fn(async () => scanner) } : {}),
    fetchSlaPolicy: jest.fn(async () => {
      if (failLoad) {
        failLoad = false;
        throw new Error('meta index unavailable');
      }
      return { policy: stored, defaults, updated_by: stored === defaults ? undefined : 'admin', storedInvalid: storedInvalid && stored === defaults };
    }),
    saveSlaPolicy: jest.fn(async (next: any) => {
      stored = next;
      return { policy: next, defaults, updated_by: 'admin', updated_at: '2026-11-21T10:00:00.000Z' };
    }),
  } as any;
}

describe('SlaSettingsView', () => {
  test('locks the tab for non-administrators but still shows the current targets', async () => {
    render(<SlaSettingsView apiService={apiServiceWith(false)} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByText(/administered by Wazuh administrators/)).toBeTruthy());
    expect(screen.queryByTestId('wamSlaSave')).toBeNull();
    expect(screen.getByTestId('wamSlaReadOnlySummary').textContent).toMatch(/default policy.*Critical 1h/);
  });

  test('shows the default-policy callout and saves edited targets with the stored escalations', async () => {
    const api = apiServiceWith(true);
    const onToast = jest.fn();
    render(<SlaSettingsView apiService={api} onToast={onToast} />);
    await waitFor(() => expect(screen.getByTestId('wamSlaDefaultPolicy')).toBeTruthy());
    expect((screen.getByTestId('wamSla-critical-resolveMinutes') as HTMLInputElement).value).toBe('60');
    expect((screen.getByTestId('wamSlaSave') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByTestId('wamSla-critical-resolveMinutes'), { target: { value: '30' } });
    expect(screen.getByTestId('wamSlaDirty')).toBeTruthy();
    expect(screen.queryByTestId('wamSlaDefaultPolicy')).toBeNull();
    fireEvent.click(screen.getByTestId('wamSlaSave'));
    await waitFor(() => expect(api.saveSlaPolicy).toHaveBeenCalled());
    expect(api.saveSlaPolicy.mock.calls[0][0]).toEqual({
      targets: { ...defaults.targets, critical: { resolveMinutes: 30, assignMinutes: 15 } },
      escalations: [],
    });
    expect(onToast).toHaveBeenCalledWith('SLA policy saved', 'success', expect.any(String));
    await waitFor(() => expect(screen.getByText(/Last saved by admin/)).toBeTruthy());
    expect(screen.queryByTestId('wamSlaDirty')).toBeNull();
  });

  test('an invalid minutes value disables Save and shows the range helper', async () => {
    render(<SlaSettingsView apiService={apiServiceWith(true)} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamSla-low-assignMinutes')).toBeTruthy());
    fireEvent.change(screen.getByTestId('wamSla-low-assignMinutes'), { target: { value: '0' } });
    expect((screen.getByTestId('wamSlaSave') as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText(/1-525600 whole minutes/).length).toBeGreaterThan(0);
  });

  test('Reset to defaults fills the form with the defaults of a customised policy', async () => {
    const custom = { ...defaults, targets: { ...defaults.targets, high: { resolveMinutes: 120, assignMinutes: 20 } } };
    const api = apiServiceWith(true, custom);
    render(<SlaSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect((screen.getByTestId('wamSla-high-resolveMinutes') as HTMLInputElement).value).toBe('120'));
    expect(screen.queryByTestId('wamSlaDefaultPolicy')).toBeNull();
    fireEvent.click(screen.getByTestId('wamSlaResetDefaults'));
    expect((screen.getByTestId('wamSla-high-resolveMinutes') as HTMLInputElement).value).toBe('240');
    expect(screen.getByTestId('wamSlaDirty')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamSlaDiscard'));
    expect((screen.getByTestId('wamSla-high-resolveMinutes') as HTMLInputElement).value).toBe('120');
  });

  test('an unreadable stored policy shows the repair callout instead of the default-policy note', async () => {
    const api = apiServiceWith(true, defaults, false, true);
    render(<SlaSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamSlaStoredInvalid')).toBeTruthy());
    expect(screen.queryByTestId('wamSlaDefaultPolicy')).toBeNull();
    expect(screen.getByTestId('wamSlaTargets-critical')).toBeTruthy();
  });

  test('a load error offers Retry', async () => {
    const api = apiServiceWith(true, defaults, true);
    render(<SlaSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamSlaLoadError')).toBeTruthy());
    expect(screen.getByText(/meta index unavailable/)).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamSlaRetry'));
    await waitFor(() => expect(screen.getByTestId('wamSlaTargets')).toBeTruthy());
    expect(api.fetchSlaPolicy).toHaveBeenCalledTimes(2);
  });

  test('helpers', () => {
    expect(minutesHelper('240')).toEqual({ text: '4h', invalid: false });
    expect(minutesHelper('4320')).toEqual({ text: '3d', invalid: false });
    expect(minutesHelper('5')).toEqual({ text: '5 min', invalid: false });
    expect(minutesHelper('1.5').invalid).toBe(true);
    expect(minutesHelper('').invalid).toBe(true);
    expect(draftToTargets({ ...toDraft(defaults), low: { resolveMinutes: 'x', assignMinutes: '1' } } as any)).toBeNull();
    expect(draftToTargets(toDraft(defaults) as any)).toEqual(defaults.targets);
    expect(sameTargets(defaults.targets, defaults.targets)).toBe(true);
    expect(sameTargets(defaults.targets, { ...defaults.targets, low: { resolveMinutes: 1, assignMinutes: 1 } })).toBe(false);
  });
});

const storedEscalation = {
  id: 'first-response',
  name: 'First response',
  target: 'alert',
  thresholdPercent: 50,
  condition: 'unassigned',
  actions: { assignTo: 'bob', notify: ['chan-1'] },
  enabled: true,
};

describe('SlaSettingsView escalations editor (step 3.3)', () => {
  test('adds an escalation (id suggested from the name), saves it with the targets, and shows the scanner status', async () => {
    const api = apiServiceWith(true, defaults, false, false, {
      enabled: true,
      tickSeconds: 60,
      status: { last_tick_at: '2026-11-21T12:00:00.000Z', holder: 'h', breached_alerts: 2, breached_cases: 0, escalated: 1, errors: [], capped: false },
    });
    render(<SlaSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamSlaEscalationsEmpty')).toBeTruthy());
    expect(screen.queryByTestId('wamSlaEscalationsPlaceholder')).toBeNull();
    await waitFor(() => expect(screen.getByTestId('wamSlaEscalationStatus').textContent).toMatch(/2 alert\(s\) and 0 case\(s\) newly breached, 1 escalated/));

    fireEvent.click(screen.getByTestId('wamSlaEscalationAdd'));
    expect(screen.getByTestId('wamSlaEscalationForm')).toBeTruthy();
    fireEvent.change(screen.getByTestId('wamSlaEscalation-name'), { target: { value: 'Second Look!' } });
    expect((screen.getByTestId('wamSlaEscalation-id') as HTMLInputElement).value).toBe('second-look');
    // Raise severity is a case-only control.
    expect((screen.getByTestId('wamSlaEscalation-raiseSeverity') as HTMLInputElement).disabled).toBe(true);
    fireEvent.change(screen.getByTestId('wamSlaEscalation-target'), { target: { value: 'case' } });
    expect((screen.getByTestId('wamSlaEscalation-raiseSeverity') as HTMLInputElement).disabled).toBe(false);
    fireEvent.change(screen.getByTestId('wamSlaEscalation-thresholdPercent'), { target: { value: '75' } });
    fireEvent.change(screen.getByTestId('wamSlaEscalation-condition'), { target: { value: 'any' } });

    // No action yet: the editor refuses.
    fireEvent.click(screen.getByTestId('wamSlaEscalationApply'));
    expect(screen.getByTestId('wamSlaEscalationError').textContent).toMatch(/At least one action/);

    fireEvent.change(screen.getByTestId('wamSlaEscalation-assignTo'), { target: { value: 'bob' } });
    fireEvent.change(screen.getByTestId('wamSlaEscalation-comment'), { target: { value: 'Escalated {{escalation}}' } });
    fireEvent.change(screen.getByTestId('wamSlaEscalation-notify'), { target: { value: 'chan-1, chan-2\nchan-1' } });
    fireEvent.click(screen.getByTestId('wamSlaEscalationApply'));
    expect(screen.queryByTestId('wamSlaEscalationForm')).toBeNull();
    expect(screen.getByTestId('wamSlaEscalation-second-look')).toBeTruthy();
    expect(screen.getByTestId('wamSlaDirty')).toBeTruthy();

    fireEvent.click(screen.getByTestId('wamSlaSave'));
    await waitFor(() => expect(api.saveSlaPolicy).toHaveBeenCalled());
    expect(api.saveSlaPolicy.mock.calls[0][0]).toEqual({
      targets: defaults.targets,
      escalations: [
        {
          id: 'second-look',
          name: 'Second Look!',
          target: 'case',
          thresholdPercent: 75,
          condition: 'any',
          actions: { assignTo: 'bob', comment: 'Escalated {{escalation}}', notify: ['chan-1', 'chan-2'] },
          enabled: true,
        },
      ],
    });
    await waitFor(() => expect(screen.queryByTestId('wamSlaDirty')).toBeNull());
  });

  test('edits, toggles, deletes and discards stored escalations', async () => {
    const api = apiServiceWith(true, { ...defaults, escalations: [storedEscalation] });
    render(<SlaSettingsView apiService={api} onToast={jest.fn()} />);
    await waitFor(() => expect(screen.getByTestId('wamSlaEscalation-first-response')).toBeTruthy());
    expect(screen.getByTestId('wamSlaEscalation-first-response').textContent).toMatch(/assign to bob · notify 1/);
    expect(screen.queryByTestId('wamSlaDirty')).toBeNull();

    fireEvent.click(screen.getByTestId('wamSlaEscalationEdit-first-response'));
    expect((screen.getByTestId('wamSlaEscalation-id') as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByTestId('wamSlaEscalation-notify') as HTMLTextAreaElement).value).toBe('chan-1');
    fireEvent.change(screen.getByTestId('wamSlaEscalation-name'), { target: { value: 'Renamed' } });
    fireEvent.click(screen.getByTestId('wamSlaEscalationApply'));
    expect(screen.getByTestId('wamSlaEscalation-first-response').textContent).toMatch(/Renamed/);
    expect(screen.getByTestId('wamSlaDirty')).toBeTruthy();

    fireEvent.click(screen.getByTestId('wamSlaEscalationToggle-first-response'));
    fireEvent.click(screen.getByTestId('wamSlaSave'));
    await waitFor(() => expect(api.saveSlaPolicy).toHaveBeenCalled());
    expect(api.saveSlaPolicy.mock.calls[0][0].escalations).toEqual([{ ...storedEscalation, name: 'Renamed', enabled: false }]);

    fireEvent.click(screen.getByTestId('wamSlaEscalationDelete-first-response'));
    expect(screen.queryByTestId('wamSlaEscalation-first-response')).toBeNull();
    expect(screen.getByTestId('wamSlaDirty')).toBeTruthy();
    fireEvent.click(screen.getByTestId('wamSlaDiscard'));
    expect(screen.getByTestId('wamSlaEscalation-first-response')).toBeTruthy();
    expect(screen.queryByTestId('wamSlaDirty')).toBeNull();
  });

  test('editor helpers mirror the server validation', () => {
    const draft = { ...EMPTY_ESCALATION_DRAFT, id: 'x', name: 'X', assignTo: 'bob' };
    expect(draftToEscalation(draft, []).escalation).toEqual({
      id: 'x', name: 'X', target: 'alert', thresholdPercent: 50, condition: 'unassigned', actions: { assignTo: 'bob' }, enabled: true,
    });
    expect(draftToEscalation({ ...draft, id: 'Bad Id' }, []).error).toMatch(/Id must be/);
    expect(draftToEscalation(draft, ['x']).error).toMatch(/already used/);
    expect(draftToEscalation({ ...draft, name: ' ' }, []).error).toMatch(/Name is required/);
    expect(draftToEscalation({ ...draft, thresholdPercent: '0' }, []).error).toMatch(/Threshold/);
    expect(draftToEscalation({ ...draft, thresholdPercent: '101' }, []).error).toMatch(/Threshold/);
    expect(draftToEscalation({ ...draft, raiseSeverity: true }, []).error).toMatch(/cases only/);
    expect(draftToEscalation({ ...draft, target: 'case', raiseSeverity: true, assignTo: '' }, []).escalation?.actions).toEqual({ raiseSeverity: true });
    expect(draftToEscalation({ ...draft, assignTo: '' }, []).error).toMatch(/At least one action/);
    expect(draftToEscalation({ ...draft, notify: Array.from({ length: 21 }, (_, i) => `c${i}`).join(',') }, []).error).toMatch(/At most 20/);
    expect(parseChannelIds(' a, b\nb \n\n c ')).toEqual(['a', 'b', 'c']);
    expect(suggestEscalationId('  First Response!! ')).toBe('first-response');
    expect(describeEscalationActions({ assignTo: 'bob', raiseSeverity: true, comment: 'x', notify: ['a', 'b'] })).toBe('assign to bob · raise severity · comment · notify 2');
    expect(describeEscalationStatus(null)).toMatch(/unavailable/);
    expect(describeEscalationStatus({ enabled: false, tickSeconds: 60, status: null })).toMatch(/disabled/);
    expect(describeEscalationStatus({ enabled: null, tickSeconds: 60, status: null })).toMatch(/not running on this dashboard \(plugin not initialised\)/);
    expect(describeEscalationStatus({ enabled: true, tickSeconds: 30, status: null })).toBe('Scanner enabled (every 30s); no tick recorded yet.');
    expect(
      describeEscalationStatus({
        enabled: true,
        tickSeconds: 60,
        status: { last_tick_at: '2026-11-21T12:00:00.000Z', holder: 'h', breached_alerts: 1, breached_cases: 2, escalated: 3, errors: [{ at: 'x', message: 'm' }], capped: true },
      })
    ).toMatch(/1 alert\(s\) and 2 case\(s\) newly breached, 3 escalated \(capped, continuing next tick\); 1 recent error\(s\)\./);
  });
});

function toDraft(policy: typeof defaults) {
  const out: any = {};
  for (const band of ['critical', 'high', 'medium', 'low'] as const) {
    out[band] = { resolveMinutes: String(policy.targets[band].resolveMinutes), assignMinutes: String(policy.targets[band].assignMinutes) };
  }
  return out;
}

describe('slaTargetsText (Reports view)', () => {
  test('cites the stored policy and flags the defaults', () => {
    expect(slaTargetsText({ policy: defaults, defaults }, null)).toBe(
      'Targets: Critical (level 12+) 1h · High (level 7-11) 4h · Medium (level 4-6) 1d · Low (level 0-3) 3d (default policy)'
    );
    const custom = { ...defaults, targets: { ...defaults.targets, critical: { resolveMinutes: 30, assignMinutes: 5 } } };
    expect(slaTargetsText({ policy: custom, defaults, updated_by: 'admin' }, null)).toMatch(/Critical \(level 12\+\) 30m .* \(policy saved by admin\)/);
  });

  test('falls back to the tiers of the metrics response, then to a loading note', () => {
    const metrics: any = { slaPolicy: [{ minLevel: 12, label: 'Critical', targetMinutes: 90 }, { minLevel: 0, label: 'Low', targetMinutes: 60 }] };
    expect(slaTargetsText(null, metrics)).toMatch(/Critical \(level 12\+\) 1h 30m .* High \(level 7-11\) — .* Low \(level 0-3\) 1h$/);
    expect(slaTargetsText(null, null)).toBe('Targets: loading the SLA policy');
  });
});
