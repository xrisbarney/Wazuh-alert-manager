import { META_INDEX, SLA_POLICY_CACHE_TTL_MS, SLA_POLICY_DOC_ID } from '../../../common';
import {
  DEFAULT_SLA_POLICY,
  getSlaPolicy,
  invalidateSlaPolicyCache,
  loadSlaPolicy,
  normaliseSlaPolicy,
  primeSlaPolicyCache,
  saveSlaPolicy,
  slaTierForBand,
  slaTierForLevel,
} from './policy';
import { buildReportingUpdate, policyToTiers, slaForLevel, REPORTING_SLA_POLICY } from '../reporting_fields';
import { effectiveLevel } from '../../../common/severity';

function clientWith(stored: any | null) {
  const writes: any[] = [];
  return {
    writes,
    get: jest.fn(async (req: any) => {
      if (req.index === META_INDEX && req.id === SLA_POLICY_DOC_ID && stored !== null) return { body: { _source: stored } };
      throw Object.assign(new Error('not found'), { meta: { statusCode: 404 } });
    }),
    index: jest.fn(async (req: any) => {
      writes.push(req);
      stored = req.body;
      return { body: { result: 'created' } };
    }),
  };
}

const custom = () => ({
  targets: {
    critical: { resolveMinutes: 30, assignMinutes: 5 },
    high: { resolveMinutes: 120, assignMinutes: 20 },
    medium: { resolveMinutes: 600, assignMinutes: 60 },
    low: { resolveMinutes: 2880, assignMinutes: 240 },
  },
  escalations: [],
});

beforeEach(() => {
  invalidateSlaPolicyCache();
  jest.restoreAllMocks();
});

describe('DEFAULT_SLA_POLICY', () => {
  test('resolve targets equal REPORTING_SLA_POLICY and assign targets are 25% floored at 15', () => {
    expect(DEFAULT_SLA_POLICY.targets).toEqual({
      critical: { resolveMinutes: 60, assignMinutes: 15 },
      high: { resolveMinutes: 240, assignMinutes: 60 },
      medium: { resolveMinutes: 1440, assignMinutes: 360 },
      low: { resolveMinutes: 4320, assignMinutes: 1080 },
    });
    expect(DEFAULT_SLA_POLICY.escalations).toEqual([]);
    expect(policyToTiers(DEFAULT_SLA_POLICY)).toEqual(REPORTING_SLA_POLICY);
  });
});

describe('normaliseSlaPolicy', () => {
  test('fills missing targets from the defaults and drops unknown keys', () => {
    const out = normaliseSlaPolicy({ targets: { critical: { resolveMinutes: 45 } }, extra: true } as any);
    expect(out.targets.critical).toEqual({ resolveMinutes: 45, assignMinutes: 15 });
    expect(out.targets.low).toEqual(DEFAULT_SLA_POLICY.targets.low);
    expect(out.escalations).toEqual([]);
    expect((out as any).extra).toBeUndefined();
  });

  test('rejects out-of-range or fractional minutes with a 400', () => {
    for (const value of [0, 525601, 1.5, 'abc', -1]) {
      expect(() => normaliseSlaPolicy({ targets: { high: { resolveMinutes: value } } } as any)).toThrow(
        expect.objectContaining({ statusCode: 400 })
      );
    }
  });

  test('validates escalations: ids, threshold, condition, actions, uniqueness and the cap', () => {
    const base = { id: 'esc-1', name: 'Page on-call', target: 'alert', thresholdPercent: 50, condition: 'unassigned', actions: { assignTo: 'oncall' } };
    const ok = normaliseSlaPolicy({ escalations: [{ ...base, actions: { assignTo: ' oncall ', notify: ['slack', 'slack', ''] } }] });
    expect(ok.escalations).toEqual([
      { ...base, actions: { assignTo: 'oncall', notify: ['slack'] }, enabled: true },
    ]);
    const bad = (patch: any) => expect(() => normaliseSlaPolicy({ escalations: [{ ...base, ...patch }] })).toThrow(expect.objectContaining({ statusCode: 400 }));
    bad({ id: 'Bad Id' });
    bad({ thresholdPercent: 0 });
    bad({ thresholdPercent: 101 });
    bad({ condition: 'never' });
    bad({ target: 'rule' });
    bad({ actions: {} });
    bad({ actions: { raiseSeverity: true } }); // alerts cannot raise severity
    bad({ name: '' });
    expect(normaliseSlaPolicy({ escalations: [{ ...base, target: 'case', actions: { raiseSeverity: true } }] }).escalations[0].actions).toEqual({ raiseSeverity: true });
    expect(() => normaliseSlaPolicy({ escalations: [base, { ...base, name: 'dup' }] })).toThrow(/more than once/);
    const many = Array.from({ length: 21 }, (_, i) => ({ ...base, id: `e${i}` }));
    expect(() => normaliseSlaPolicy({ escalations: many })).toThrow(/At most 20/);
  });
});

describe('loadSlaPolicy / saveSlaPolicy', () => {
  test('load answers the defaults when nothing is stored', async () => {
    const loaded = await loadSlaPolicy(clientWith(null));
    expect(loaded.targets).toEqual(DEFAULT_SLA_POLICY.targets);
    expect(loaded.updated_by).toBeUndefined();
  });

  test('save is a full replace through the meta index and the next load reads it back', async () => {
    const client = clientWith(null);
    const saved = await saveSlaPolicy(client, { targets: custom().targets, escalations: [] }, { updatedBy: 'admin' });
    expect(saved.targets).toEqual(custom().targets);
    expect(saved.updated_by).toBe('admin');
    expect(client.writes[0]).toMatchObject({ index: META_INDEX, id: SLA_POLICY_DOC_ID, refresh: 'wait_for' });
    expect(client.writes[0].body.source).toBe('workbench');
    const loaded = await loadSlaPolicy(client);
    expect(loaded.targets.critical.resolveMinutes).toBe(30);
    // A later save without escalations clears them (full replace, not merge).
    await saveSlaPolicy(client, { targets: custom().targets, escalations: [{ id: 'a', name: 'A', target: 'alert', thresholdPercent: 80, condition: 'any', actions: { comment: 'late' } }] }, { updatedBy: 'admin' });
    expect((await loadSlaPolicy(client)).escalations).toHaveLength(1);
    await saveSlaPolicy(client, { targets: custom().targets }, { updatedBy: 'admin' });
    expect((await loadSlaPolicy(client)).escalations).toEqual([]);
  });

  test('save rejects an invalid patch before writing', async () => {
    const client = clientWith(null);
    await expect(saveSlaPolicy(client, { targets: { low: { resolveMinutes: 0 } } } as any, { updatedBy: 'admin' })).rejects.toMatchObject({ statusCode: 400 });
    expect(client.index).not.toHaveBeenCalled();
  });
});

describe('getSlaPolicy cache', () => {
  test('reads once, serves from cache inside the TTL and re-reads after it', async () => {
    let now = 1_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const client = clientWith(custom());
    const first = await getSlaPolicy(client);
    expect(first.targets.critical.resolveMinutes).toBe(30);
    expect(client.get).toHaveBeenCalledTimes(1);
    now += SLA_POLICY_CACHE_TTL_MS - 1;
    await getSlaPolicy(client);
    expect(client.get).toHaveBeenCalledTimes(1);
    now += 2;
    await getSlaPolicy(client);
    expect(client.get).toHaveBeenCalledTimes(2);
  });

  test('invalidateSlaPolicyCache forces a re-read and saveSlaPolicy refreshes the cache', async () => {
    const client = clientWith(custom());
    await getSlaPolicy(client);
    expect(client.get).toHaveBeenCalledTimes(1);
    invalidateSlaPolicyCache();
    await getSlaPolicy(client);
    expect(client.get).toHaveBeenCalledTimes(2);
    await saveSlaPolicy(client, { targets: { ...custom().targets, critical: { resolveMinutes: 10, assignMinutes: 2 } } }, { updatedBy: 'admin' });
    const after = await getSlaPolicy(client);
    expect(after.targets.critical.resolveMinutes).toBe(10);
  });

  test('concurrent callers share one read', async () => {
    const client = clientWith(custom());
    const [a, b] = await Promise.all([getSlaPolicy(client), getSlaPolicy(client)]);
    expect(a).toBe(b);
    expect(client.get).toHaveBeenCalledTimes(1);
  });

  test('never throws: a read failure answers the defaults, then the last cached policy', async () => {
    const logger = { warn: jest.fn() };
    const broken = { get: jest.fn(async () => { throw new Error('cluster down'); }) };
    const fallback = await getSlaPolicy(broken, logger);
    expect(fallback.targets).toEqual(DEFAULT_SLA_POLICY.targets);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringMatching(/using the default policy: cluster down/));
    primeSlaPolicyCache(custom(), 0);
    const cached = await getSlaPolicy(broken, logger);
    expect(cached.targets.critical.resolveMinutes).toBe(30);
    expect(logger.warn).toHaveBeenLastCalledWith(expect.stringMatching(/using the last cached policy/));
    // A client without get (some test doubles) also degrades to the defaults once nothing is cached.
    invalidateSlaPolicyCache();
    expect((await getSlaPolicy({})).targets).toEqual(DEFAULT_SLA_POLICY.targets);
  });

  test('a read in flight during a save does not overwrite the primed post-save cache', async () => {
    const client = clientWith(custom());
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const preSave = custom(); // what the gated read answers: the document before the save (critical=30)
    client.get.mockImplementationOnce(async () => {
      await gate;
      return { body: { _source: preSave } };
    });
    const pending = getSlaPolicy(client);
    await saveSlaPolicy(client, { targets: { ...custom().targets, critical: { resolveMinutes: 20, assignMinutes: 5 } } }, { updatedBy: 'admin' });
    release();
    const stale = await pending;
    // The waiting caller gets the newer (saved) policy, and the cache keeps it.
    expect(stale.targets.critical.resolveMinutes).toBe(20);
    const after = await getSlaPolicy(client);
    expect(after.targets.critical.resolveMinutes).toBe(20);
  });

  test('a stored document that fails validation falls back instead of throwing', async () => {
    const client = clientWith({ targets: { critical: { resolveMinutes: 'oops' } } });
    const policy = await getSlaPolicy(client, { warn: jest.fn() });
    expect(policy.targets).toEqual(DEFAULT_SLA_POLICY.targets);
  });
});

describe('slaTierForLevel / slaTierForBand', () => {
  const policy = custom();

  test('covers every numeric band boundary', () => {
    expect(slaTierForLevel(policy, 0)).toMatchObject({ band: 'low', label: 'Low', resolveMinutes: 2880, assignMinutes: 240 });
    expect(slaTierForLevel(policy, 3).band).toBe('low');
    expect(slaTierForLevel(policy, 4).band).toBe('medium');
    expect(slaTierForLevel(policy, 6).band).toBe('medium');
    expect(slaTierForLevel(policy, 7).band).toBe('high');
    expect(slaTierForLevel(policy, 11).band).toBe('high');
    expect(slaTierForLevel(policy, 12)).toMatchObject({ band: 'critical', label: 'Critical', resolveMinutes: 30, assignMinutes: 5 });
    expect(slaTierForLevel(policy, 16).band).toBe('critical');
    expect(slaTierForLevel(policy, null).band).toBe('low');
  });

  test('5.0 label-only records map through effectiveLevel exactly like 4.x bands', () => {
    const cases: Array<[string, string]> = [
      ['informational', 'low'], ['low', 'low'], ['medium', 'medium'], ['high', 'high'], ['critical', 'critical'],
      ['Major', 'high'], ['severe', 'critical'],
    ];
    for (const [label, band] of cases) {
      const level = effectiveLevel({ rule: { level: null }, severity_label: label });
      expect(slaTierForLevel(policy, level).band).toBe(band);
    }
    expect(slaTierForBand(policy, 'informational').band).toBe('low');
    expect(slaTierForBand(policy, null).band).toBe('low');
    expect(slaTierForBand(policy, 'high').resolveMinutes).toBe(120);
  });
});

describe('reporting_fields with a custom policy', () => {
  const source = (overrides: any = {}) => ({ '@timestamp': '2026-08-28T10:00:00.000Z', status: 'open', assigned_to: null, rule: { level: 8 }, ...overrides });

  test('slaForLevel and buildReportingUpdate honour the configured targets', () => {
    expect(slaForLevel(8, custom())).toEqual({ minLevel: 7, label: 'High', targetMinutes: 120 });
    expect(slaForLevel(8)).toEqual({ minLevel: 7, label: 'High', targetMinutes: 240 });
    // 180 minutes: met under the default 240 target, breached under the custom 120 one.
    const at = '2026-08-28T13:00:00.000Z';
    expect(buildReportingUpdate(source(), { status: 'closed' }, at)?.sla_met).toBe(true);
    expect(buildReportingUpdate(source(), { status: 'closed' }, at, custom())?.sla_met).toBe(false);
    expect(buildReportingUpdate(source(), { status: 'closed' }, at, custom())?.sla_tier).toBe('High');
    // 5.0 label-only record under the custom policy.
    const finding = source({ rule: { level: null }, severity_label: 'critical' });
    expect(buildReportingUpdate(finding, { status: 'closed' }, '2026-08-28T10:45:00.000Z', custom())?.sla_met).toBe(false);
    expect(buildReportingUpdate(finding, { status: 'closed' }, '2026-08-28T10:45:00.000Z')?.sla_met).toBe(true);
  });
});
