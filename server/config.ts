import { schema, TypeOf } from '@osd/config-schema';
import { SLA_BREACH_NOTIFY_GRACE_MINUTES } from '../common/constants';

export const SOURCE_MODES = ['auto', 'wazuh4_alerts', 'wazuh5_findings'] as const;
export type SourceMode = typeof SOURCE_MODES[number];

export const configSchema = schema.object({
  enabled: schema.boolean({ defaultValue: true }),
  sync: schema.object({
    enabled: schema.boolean({ defaultValue: true }),
    intervalSeconds: schema.number({ defaultValue: 60, min: 15 }),
    // Which native Wazuh source family this build may read. `auto` selects
    // the only family compatible with the build target (Wazuh 4.x builds
    // read `wazuh-alerts-*`; Wazuh 5.0 builds read `wazuh-findings-v5-*`).
    // An explicit value must still be eligible for the build; it never
    // unlocks a family the build was not compiled for.
    sourceMode: schema.oneOf(
      [schema.literal('auto'), schema.literal('wazuh4_alerts'), schema.literal('wazuh5_findings')],
      { defaultValue: 'auto' }
    ),
    // Optional allowlisted override of the family's default pattern. When
    // unset, the selected source profile's default applies. Values outside
    // the selected family are rejected and sync stops safely.
    sourceIndexPattern: schema.maybe(schema.string()),
    initialLookbackMinutes: schema.number({ defaultValue: 10, min: 1 }),
    batchSize: schema.number({ defaultValue: 10000, min: 100, max: 10000 }),
    // 4.x: numeric rule.level floor applied at the source.
    minRuleLevel: schema.maybe(schema.number()),
    // 5.0: label floor applied at the source (wazuh.rule.level). Findings at
    // this band or above are projected; ignored by 4.x builds.
    minSeverityLabel: schema.maybe(
      schema.oneOf([
        schema.literal('informational'),
        schema.literal('low'),
        schema.literal('medium'),
        schema.literal('high'),
        schema.literal('critical'),
      ])
    ),
    overlapSeconds: schema.number({ defaultValue: 120, min: 0, max: 3600 }),
  }),
  lifecycle: schema.object({
    enabled: schema.boolean({ defaultValue: true }),
    rolloverAge: schema.string({ defaultValue: '7d' }),
    rolloverPrimarySize: schema.string({ defaultValue: '20gb' }),
    operationalRetentionDays: schema.number({ defaultValue: 90, min: 7 }),
    activityRetentionDays: schema.number({ defaultValue: 365, min: 30 }),
    caseRetentionDays: schema.number({ defaultValue: 365, min: 30 }),
    evidenceRetentionDays: schema.number({ defaultValue: 730, min: 30 }),
  }),
  migration: schema.object({
    enabled: schema.boolean({ defaultValue: true }),
    batchSize: schema.number({ defaultValue: 1000, min: 100, max: 5000 }),
    shadowWriteDays: schema.number({ defaultValue: 14, min: 0, max: 90 }),
  }),
  sla: schema.object({
    // Escalation scanner (step 3.3): lease-based, one replica ticks; stamps
    // breach markers and applies the policy's escalations.
    escalation: schema.object({
      enabled: schema.boolean({ defaultValue: true }),
      tickSeconds: schema.number({ defaultValue: 60, min: 15, max: 3600 }),
      // A record whose due date passed more than this many minutes before the
      // tick that stamps it is stamped but not notified (`sla.breached`), so
      // an overdue backlog never floods the channels. 0 = notify every stamp.
      breachNotifyGraceMinutes: schema.number({ defaultValue: SLA_BREACH_NOTIFY_GRACE_MINUTES, min: 0, max: 30 * 24 * 60 }),
    }),
  }),
  notifications: schema.object({
    // Phase 1: public base URL of the dashboard (e.g. https://soc.example.com)
    // used for deep links in notification payloads; when unset the links are
    // app-relative (`/app/wazuh-alert-manager?...`). http(s) only; include
    // `server.basePath` when one is set (`/app/wazuh-alert-manager` is
    // appended to the value as given).
    dashboardUrl: schema.maybe(schema.uri({ scheme: ['http', 'https'] })),
    // Outbox dispatcher (step 1.2): lease-based, one replica delivers the
    // queued notifications every tickSeconds through the bound channels.
    dispatcher: schema.object({
      enabled: schema.boolean({ defaultValue: true }),
      tickSeconds: schema.number({ defaultValue: 5, min: 1, max: 300 }),
    }),
  }),
  reports: schema.object({
    // Scheduled summaries (step 5.4): the lease-based scheduler that renders
    // each `report_schedules` entry at its UTC slot. One replica runs it.
    scheduler: schema.object({
      enabled: schema.boolean({ defaultValue: true }),
      tickSeconds: schema.number({ defaultValue: 60, min: 15, max: 3600 }),
    }),
  }),
});

export type AlertManagerConfigType = TypeOf<typeof configSchema>;
