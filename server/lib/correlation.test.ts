import {
  alertMatchesRule,
  coverageRequirements,
  entityField,
  entityValueFromAlert,
  evaluateAlertMatch,
  usesAllMatchMode,
} from './correlation';
import labAudit80792 from '../../lab/agent/samples/80792.json';

const rule = (match: any, trigger: any = { type: 'per_alert' }): any => ({
  id: 'rule',
  name: 'rule',
  enabled: true,
  match,
  trigger,
  actions: { createCase: false },
});

const source = {
  agent: { name: 'agent-a' },
  rule: { id: '100', groups: ['auth', 'login'], level: 8 },
};

describe('correlation Any/All shared semantics', () => {
  test('uses Any within sections and AND between sections for document matching', () => {
    expect(
      alertMatchesRule(
        rule({ ruleIds: ['99', '100'], ruleGroups: ['other', 'auth'], agentNames: ['agent-a'], minLevel: 7 }),
        source
      )
    ).toBe(true);
    expect(alertMatchesRule(rule({ ruleIds: ['100'], agentNames: ['agent-b'] }), source)).toBe(false);
  });

  test('rejects every populated All section on a per-alert trigger', () => {
    expect(evaluateAlertMatch(rule({ ruleIds: ['100'], ruleIdsMode: 'all' }), source)).toEqual({
      supported: false,
      matched: false,
      reason: 'all_mode_requires_burst',
    });
    expect(evaluateAlertMatch(rule({ agentNames: ['agent-a', 'agent-b'], agentNamesMode: 'all' }), source)).toEqual({
      supported: false,
      matched: false,
      reason: 'all_mode_requires_burst',
    });
  });

  test('ignores All mode on an empty section', () => {
    const candidate = rule({ ruleIds: [], ruleIdsMode: 'all' });
    expect(usesAllMatchMode(candidate.match)).toBe(false);
    expect(evaluateAlertMatch(candidate, source)).toEqual({ supported: true, matched: true });
  });

  test('uses Any as the burst candidate pre-filter and exposes exact All coverage', () => {
    const candidate = rule(
      {
        ruleIds: ['99', '100'],
        ruleIdsMode: 'all',
        ruleGroups: ['auth', 'malware'],
        ruleGroupsMode: 'all',
        agentNames: ['agent-a', 'agent-b'],
        agentNamesMode: 'all',
      },
      { type: 'burst', entity: 'srcip', threshold: 3, windowMinutes: 10 }
    );

    expect(evaluateAlertMatch(candidate, source)).toEqual({ supported: true, matched: true });
    expect(coverageRequirements(candidate.match)).toEqual({
      ids: ['99', '100'],
      groups: ['auth', 'malware'],
      agents: ['agent-a', 'agent-b'],
    });
  });

  test('does not create coverage requirements for Any sections', () => {
    expect(
      coverageRequirements({
        ruleIds: ['100'],
        ruleIdsMode: 'any',
        ruleGroups: ['auth'],
        agentNames: ['agent-a'],
      })
    ).toEqual({ ids: [], groups: [], agents: [] });
  });
});

describe('minAssetCriticality match scope (step 6.4a)', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { buildMatchFilters } = require('./correlation');
  const stamped = (criticality: string | null) => ({ ...source, asset: { criticality, tags: [], groups: [] } });

  test('evaluates like minLevel: at or above the floor matches, unstamped never matches', () => {
    const r = rule({ minAssetCriticality: 'high' });
    expect(evaluateAlertMatch(r, stamped('critical'))).toEqual({ supported: true, matched: true });
    expect(evaluateAlertMatch(r, stamped('high'))).toEqual({ supported: true, matched: true });
    expect(evaluateAlertMatch(r, stamped('medium'))).toEqual({ supported: true, matched: false });
    expect(evaluateAlertMatch(r, stamped(null))).toEqual({ supported: true, matched: false });
    expect(evaluateAlertMatch(r, source)).toEqual({ supported: true, matched: false });
    expect(alertMatchesRule(rule({ minAssetCriticality: 'low', minLevel: 7 }), stamped('low'))).toBe(true);
    expect(alertMatchesRule(rule({ minAssetCriticality: 'low', minLevel: 9 }), stamped('low'))).toBe(false);
  });

  test('the preview filter uses the same floor as a terms clause on asset.criticality', () => {
    expect(buildMatchFilters({ minAssetCriticality: 'medium' })).toEqual([
      { terms: { 'asset.criticality': ['medium', 'high', 'critical'] } },
    ]);
    expect(buildMatchFilters({})).toEqual([]);
  });
});

describe('process entity on auditd alerts (step 9.4)', () => {
  test('entityValueFromAlert falls back to data.audit.exe when data.process is absent', () => {
    expect(labAudit80792._source.data).not.toHaveProperty('process');
    expect(entityValueFromAlert('process', labAudit80792._source)).toBe('/usr/bin/curl');
    expect(entityValueFromAlert('process', { data: { process: { name: 'sshd' }, audit: { exe: '/usr/sbin/sshd' } } })).toBe('sshd');
    expect(entityValueFromAlert('process', { data: {} })).toBeNull();
    // Aggregations keep grouping on the decoder process name.
    expect(entityField('process')).toBe('data.process.name');
  });
});
