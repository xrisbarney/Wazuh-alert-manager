import {
  eventTitle,
  getNotificationDashboardUrl,
  mustacheEscape,
  notificationLink,
  projectAlertForNotification,
  projectCase,
  projectCaseEvent,
  renderSubject,
  renderText,
  setNotificationRuntime,
} from './render';

const alertSource = {
  '@timestamp': '2026-11-21T10:00:00.000Z',
  status: 'open',
  assigned_to: 'alice',
  updated_at: '2026-11-21T10:05:00.000Z',
  rule: { id: '5710', description: 'sshd: Attempt to login using a non-existent user', level: 10, groups: ['sshd'], mitre: { id: ['T1110'] } },
  agent: { id: '001', name: 'web-01', ip: '10.0.0.5' },
  manager: { name: 'wazuh-manager' },
  disposition: null,
  reporting: { sla_due_at: '2026-11-21T14:00:00.000Z', sla_tier: 'High' },
  case_id: 'case-1',
  data: { srcip: '203.0.113.9', srcuser: 'root' },
  full_log: 'Nov 21 10:00:00 web-01 sshd[1]: Invalid user root from 203.0.113.9',
  history: [{ action: 'x' }],
  _raw_source: { secret: 'never' },
};

const caseDoc = {
  id: 'case-1',
  case_uid: 'CASE-0001',
  title: 'Brute force on web-01',
  description: 'long analyst notes with internal detail',
  severity: 'high',
  status: 'open',
  assigned_to: 'alice',
  alert_ids: ['a', 'b'],
  evidence_count: 3,
  created_by: 'bob',
  created_at: '2026-11-21T09:00:00.000Z',
  updated_at: '2026-11-21T10:00:00.000Z',
  closed_at: null,
  disposition: null,
  sla_due_at: '2026-11-21T13:00:00.000Z',
  history: [{ action: 'created' }],
  ai_analysis: { summary: 'internal' },
  tasks: [{ title: 'x' }],
};

describe('render projections', () => {
  beforeEach(() => setNotificationRuntime(null));

  test('projectAlertForNotification copies the allowlist only (no data, full_log, history or raw source)', () => {
    const out = projectAlertForNotification(alertSource, { id: 'alert-1' });
    expect(Object.keys(out).sort()).toEqual(
      ['agent', 'assigned_to', 'case_id', 'disposition', 'id', 'link', 'rule', 'severity', 'sla_due_at', 'status', 'timestamp', 'title', 'updated_at'].sort()
    );
    expect(out).toMatchObject({
      id: 'alert-1',
      title: 'sshd: Attempt to login using a non-existent user',
      status: 'open',
      severity: { band: 'high', level: 10 },
      assigned_to: 'alice',
      timestamp: '2026-11-21T10:00:00.000Z',
      rule: { id: '5710', description: 'sshd: Attempt to login using a non-existent user' },
      agent: { id: '001', name: 'web-01' },
      disposition: null,
      sla_due_at: '2026-11-21T14:00:00.000Z',
      case_id: 'case-1',
      link: '/app/wazuh-alert-manager?tab=alerts&alert=alert-1',
    });
    expect(Object.keys(out.agent)).toEqual(['id', 'name']);
    expect(Object.keys(out.rule)).toEqual(['id', 'description']);
    expect(JSON.stringify(out)).not.toMatch(/203\.0\.113\.9|full_log|never|srcuser/);
    // 5.0 label severity and a missing record both project safely.
    expect(projectAlertForNotification({ severity_label: 'critical', rule: { level: null } }).severity).toEqual({ band: 'critical', level: null, label: 'critical' });
    expect(projectAlertForNotification(null).id).toBeNull();
  });

  test('projectCase copies the allowlist only and counts evidence', () => {
    const out = projectCase(caseDoc)!;
    expect(Object.keys(out).sort()).toEqual(
      ['alert_count', 'assigned_to', 'case_uid', 'closed_at', 'created_at', 'created_by', 'disposition', 'id', 'link', 'severity', 'sla_due_at', 'status', 'title', 'updated_at'].sort()
    );
    expect(out.alert_count).toBe(3);
    expect(out.link).toBe('/app/wazuh-alert-manager?tab=cases&case=case-1');
    expect(JSON.stringify(out)).not.toMatch(/analyst notes|internal/);
    expect(projectCase({ ...caseDoc, evidence_count: undefined }).alert_count).toBe(2);
    expect(projectCase(null)).toBeNull();
  });

  test('projectCaseEvent bounds the extra fields and re-projects an embedded alert', () => {
    const payload = projectCaseEvent(
      'sla.escalated',
      caseDoc,
      { actor: 'system:sla', from: null, to: 'alice', escalation: { id: 'esc-1', name: 'Page on-call' }, alert: projectAlertForNotification(alertSource, { id: 'alert-1' }), message: 'x'.repeat(5000), unknown: 'dropped' } as any,
      { now: new Date('2026-11-21T12:00:00.000Z') }
    );
    expect(Object.keys(payload).sort()).toEqual(['actor', 'alert', 'case', 'escalation', 'event', 'from', 'message', 'occurred_at', 'source', 'to'].sort());
    expect(payload).toMatchObject({ event: 'sla.escalated', occurred_at: '2026-11-21T12:00:00.000Z', source: 'wazuh-alert-manager', actor: 'system:sla', from: null, to: 'alice', escalation: { id: 'esc-1', name: 'Page on-call' } });
    expect(payload.message!.length).toBe(2000);
    expect(payload.alert).toMatchObject({ id: 'alert-1', title: 'sshd: Attempt to login using a non-existent user', severity: { band: 'high', level: 10 }, agent: { id: '001', name: 'web-01' } });
    expect(projectCaseEvent('case.created', null).case).toBeNull();
  });

  test('deep links are app-relative by default and absolute once the dashboard URL is configured', () => {
    expect(getNotificationDashboardUrl()).toBeNull();
    expect(notificationLink({ caseId: 'c/1' })).toBe('/app/wazuh-alert-manager?tab=cases&case=c%2F1');
    setNotificationRuntime({ notifications: { dashboardUrl: 'https://soc.example.com/' } } as any);
    expect(getNotificationDashboardUrl()).toBe('https://soc.example.com');
    expect(notificationLink({ alertId: 'a1' })).toBe('https://soc.example.com/app/wazuh-alert-manager?tab=alerts&alert=a1');
    expect(projectCase(caseDoc)!.link).toBe('https://soc.example.com/app/wazuh-alert-manager?tab=cases&case=case-1');
    expect(notificationLink({})).toBe('https://soc.example.com/app/wazuh-alert-manager');
    setNotificationRuntime({ notifications: { dashboardUrl: '  ' } } as any);
    expect(getNotificationDashboardUrl()).toBeNull();
  });

  test('renderSubject and renderText are plain text with the key fields and the deep link', () => {
    const payload = projectCaseEvent('case.assigned', caseDoc, { actor: 'bob', from: null, to: 'alice' }, { now: new Date('2026-11-21T12:00:00.000Z') });
    expect(renderSubject('case.assigned', payload)).toBe('[Wazuh Alert Manager] Case assigned: Brute force on web-01');
    const text = renderText('case.assigned', payload, 'https://soc.example.com');
    expect(text.split('\n')[0]).toBe('[Wazuh Alert Manager] Case assigned: Brute force on web-01');
    expect(text).toContain('Case: CASE-0001 Brute force on web-01');
    expect(text).toContain('Severity: high');
    expect(text).toContain('Assigned to: alice');
    expect(text).toContain('Alerts: 3');
    expect(text).toContain('Change: - -> alice');
    expect(text).toContain('By: bob');
    expect(text).toContain('At: 2026-11-21T12:00:00.000Z');
    expect(text.trim().split('\n').pop()).toBe('Open: https://soc.example.com/app/wazuh-alert-manager?tab=cases&case=case-1');
    expect(text).not.toMatch(/<[a-z]+>|analyst notes/);

    const alertPayload = projectCaseEvent('sla.breached', null, { actor: 'system:sla', alert: projectAlertForNotification(alertSource, { id: 'alert-1' }) });
    expect(renderSubject('sla.breached', alertPayload)).toBe('[Wazuh Alert Manager] SLA breached: sshd: Attempt to login using a non-existent user');
    const alertText = renderText('sla.breached', alertPayload, null);
    expect(alertText).toContain('Rule: 5710');
    expect(alertText).toContain('Severity: high (level 10)');
    expect(alertText).toContain('Agent: web-01 (001)');
    expect(alertText).toContain('Open: /app/wazuh-alert-manager?tab=alerts&alert=alert-1');

    const long = projectCaseEvent('case.created', { ...caseDoc, title: 'T'.repeat(300) });
    expect(renderSubject('case.created', long).length).toBe(200);
    expect(renderSubject('test', projectCaseEvent('test', null))).toBe('[Wazuh Alert Manager] Test notification');
    expect(eventTitle('report.scheduled')).toBe('Scheduled report');
  });

  test('mustacheEscape leaves plain text alone and neutralises mustache tags', () => {
    expect(mustacheEscape('plain {json: 1} text')).toBe('plain {json: 1} text');
    expect(mustacheEscape('')).toBe('');
    const escaped = mustacheEscape('a {{ctx.monitor}} b <% c');
    expect(escaped.startsWith('{{=<% %>=}}')).toBe(true);
    expect(escaped).toBe('{{=<% %>=}}a {{ctx.monitor}} b <<%! %>% c');
    // With `<% %>` as the delimiters the only tags left are the delimiter switch and empty comments.
    const tags = escaped.slice('{{=<% %>=}}'.length).match(/<%[\s\S]*?%>/g) || [];
    expect(tags).toEqual(['<%! %>']);
  });
});

describe('rule.action payload (step 1.4)', () => {
  test('projectCaseEvent bounds the applied actions and renderText names them with the case link', () => {
    const payload = projectCaseEvent(
      'rule.action',
      null,
      {
        actor: 'correlation-rule',
        rule: { id: 'rule-1', name: 'Brute force' },
        actions: { status: 'in_progress', assignee: 'x'.repeat(300), caseId: 'case-9' },
        alert: projectAlertForNotification({ rule: { id: '5710', description: 'sshd: brute force', level: 10 }, status: 'in_progress' }, { id: 'a1' }),
      },
      { now: new Date('2026-11-21T10:00:05.000Z'), dashboardUrl: 'https://soc.example.com' }
    );
    expect(payload.actions).toEqual({ status: 'in_progress', assignee: 'x'.repeat(256), caseId: 'case-9' });
    const text = renderText('rule.action', payload, 'https://soc.example.com');
    expect(text).toContain('Rule: Brute force (rule-1)');
    expect(text).toContain('Actions: status set to in_progress; assigned to ' + 'x'.repeat(256) + '; case case-9 https://soc.example.com/app/wazuh-alert-manager?tab=cases&case=case-9');
    expect(text).toContain('Open: https://soc.example.com/app/wazuh-alert-manager?tab=alerts&alert=a1');

    const bare = projectCaseEvent('rule.action', null, { rule: { id: 'rule-1', name: 'Notify only' }, actions: {} });
    expect(bare.actions).toEqual({});
    expect(renderText('rule.action', bare, null)).toContain('Actions: notification only');
    expect(projectCaseEvent('rule.action', null, { rule: { id: 'rule-1', name: 'n' } }).actions).toBeUndefined();
  });
});
