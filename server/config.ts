import { schema, TypeOf } from '@osd/config-schema';

export const configSchema = schema.object({
  enabled: schema.boolean({ defaultValue: true }),
  sync: schema.object({
    enabled: schema.boolean({ defaultValue: true }),
    intervalSeconds: schema.number({ defaultValue: 60, min: 15 }),
    sourceIndexPattern: schema.string({ defaultValue: 'wazuh-alerts-*' }),
    initialLookbackMinutes: schema.number({ defaultValue: 10, min: 1 }),
    batchSize: schema.number({ defaultValue: 10000, min: 100, max: 10000 }),
    minRuleLevel: schema.maybe(schema.number()),
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
