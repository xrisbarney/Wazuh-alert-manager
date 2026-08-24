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
  }),
});

export type AlertManagerConfigType = TypeOf<typeof configSchema>;
