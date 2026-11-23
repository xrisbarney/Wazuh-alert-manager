import { configSchema } from './config';

describe('plugin config schema', () => {
  test('sla.escalation defaults to enabled with a 60-s tick', () => {
    const config = configSchema.validate({});
    expect(config.sla.escalation).toEqual({ enabled: true, tickSeconds: 60, breachNotifyGraceMinutes: 1440 });
    expect(config.reports.scheduler).toEqual({ enabled: true, tickSeconds: 60 });
  });

  test('sla.escalation.tickSeconds is bounded to 15-3600 and enabled must be a boolean', () => {
    expect(configSchema.validate({ sla: { escalation: { tickSeconds: 15 } } }).sla.escalation.tickSeconds).toBe(15);
    expect(configSchema.validate({ sla: { escalation: { tickSeconds: 3600, enabled: false } } }).sla.escalation).toEqual({ enabled: false, tickSeconds: 3600, breachNotifyGraceMinutes: 1440 });
    expect(() => configSchema.validate({ sla: { escalation: { tickSeconds: 14 } } })).toThrow(/tickSeconds/);
    expect(() => configSchema.validate({ sla: { escalation: { tickSeconds: 3601 } } })).toThrow(/tickSeconds/);
    expect(() => configSchema.validate({ sla: { escalation: { enabled: 'yes' } } })).toThrow(/enabled/);
  });

  test('sla.escalation.breachNotifyGraceMinutes is bounded to 0-43200 (0 = notify every breach)', () => {
    expect(configSchema.validate({ sla: { escalation: { breachNotifyGraceMinutes: 0 } } }).sla.escalation.breachNotifyGraceMinutes).toBe(0);
    expect(configSchema.validate({ sla: { escalation: { breachNotifyGraceMinutes: 43200 } } }).sla.escalation.breachNotifyGraceMinutes).toBe(43200);
    expect(() => configSchema.validate({ sla: { escalation: { breachNotifyGraceMinutes: -1 } } })).toThrow(/breachNotifyGraceMinutes/);
    expect(() => configSchema.validate({ sla: { escalation: { breachNotifyGraceMinutes: 43201 } } })).toThrow(/breachNotifyGraceMinutes/);
  });

  test('notifications.dashboardUrl must be an absolute http(s) URL when set', () => {
    expect(configSchema.validate({}).notifications.dashboardUrl).toBeUndefined();
    expect(configSchema.validate({ notifications: { dashboardUrl: 'https://soc.example.com/dash' } }).notifications.dashboardUrl).toBe('https://soc.example.com/dash');
    expect(configSchema.validate({ notifications: { dashboardUrl: 'http://10.0.0.5:5601' } }).notifications.dashboardUrl).toBe('http://10.0.0.5:5601');
    expect(() => configSchema.validate({ notifications: { dashboardUrl: 'soc.example.com' } })).toThrow(/dashboardUrl/);
    expect(() => configSchema.validate({ notifications: { dashboardUrl: 'ftp://soc.example.com' } })).toThrow(/dashboardUrl/);
  });
});
