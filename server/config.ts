import { schema, TypeOf } from '@osd/config-schema';

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
});

export type AlertManagerConfigType = TypeOf<typeof configSchema>;
