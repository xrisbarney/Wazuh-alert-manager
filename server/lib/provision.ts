import { Logger } from '../../../../src/core/server';
import {
  ALERTS_INITIAL_INDEX,
  ALERTS_READ_ALIAS,
  ALERTS_WRITE_ALIAS,
  ACTIVITY_INITIAL_INDEX,
  ACTIVITY_READ_ALIAS,
  ACTIVITY_WRITE_ALIAS,
  CASES_INITIAL_INDEX,
  CASES_READ_ALIAS,
  CASES_WRITE_ALIAS,
  EVIDENCE_INITIAL_INDEX,
  EVIDENCE_READ_ALIAS,
  EVIDENCE_WRITE_ALIAS,
  META_INDEX,
  RULES_INDEX,
  MIGRATION_INDEX,
  SYNC_DLQ_INDEX,
  AUTOMATION_QUEUE_INDEX,
  AUTOMATION_DLQ_INDEX,
  AUTOMATION_EXECUTIONS_INDEX,
} from '../../common';
import {
  alertStatusMapping,
  activityMapping,
  casesMapping,
  evidenceMapping,
  metaMapping,
  rulesMapping,
  migrationMapping,
  syncDlqMapping,
  automationQueueMapping,
  automationDlqMapping,
  automationExecutionMapping,
} from './mappings';
import { assertManagedWriteTarget } from './index_namespace';

// Bump whenever a mapping in ./mappings.ts gains a field or dynamic_template.
// A fresh install creates indices with the current mapping and records this
// version; an upgraded install has an older (or absent) version and runs
// ensureMappingAdditions() once to PUT the new fields onto its existing indices.
const MAPPING_VERSION = 11;
const MAPPING_VERSION_DOC_ID = 'mapping_version';

const MANAGED_INDICES: Array<[string, any]> = [
  [META_INDEX, metaMapping],
  [RULES_INDEX, rulesMapping],
  [MIGRATION_INDEX, migrationMapping],
  [SYNC_DLQ_INDEX, syncDlqMapping],
  [AUTOMATION_QUEUE_INDEX, automationQueueMapping],
  [AUTOMATION_DLQ_INDEX, automationDlqMapping],
  [AUTOMATION_EXECUTIONS_INDEX, automationExecutionMapping],
];

// PUT mapping through read aliases so every retained rollover generation gets
// additive fields, not only the current writer.
const ADDITIVE_MAPPING_TARGETS: Array<[string, any]> = [
  [ALERTS_READ_ALIAS, alertStatusMapping],
  [ACTIVITY_READ_ALIAS, activityMapping],
  [EVIDENCE_READ_ALIAS, evidenceMapping],
  [CASES_READ_ALIAS, casesMapping],
  ...MANAGED_INDICES,
];

export function isResourceAlreadyExists(error: any): boolean {
  const type = error?.body?.error?.type || error?.meta?.body?.error?.type || error?.meta?.body?.error?.root_cause?.[0]?.type;
  return type === 'resource_already_exists_exception';
}

function verifyProperties(expected: any, actual: any, path = ''): void {
  for (const [name, definition] of Object.entries<any>(expected || {})) {
    const field = actual?.[name];
    const fieldPath = path ? `${path}.${name}` : name;
    if (!field) throw new Error(`required mapping field ${fieldPath} is missing`);
    if (definition.type && field.type !== definition.type) {
      throw new Error(`required mapping field ${fieldPath} must have type ${definition.type}`);
    }
    if (definition.enabled === false && field.enabled !== false) {
      throw new Error(`required mapping field ${fieldPath} must be disabled`);
    }
    if (definition.properties) verifyProperties(definition.properties, field.properties, fieldPath);
    if (definition.fields) verifyProperties(definition.fields, field.fields, `${fieldPath}.fields`);
  }
}

async function verifyMapping(client: any, index: string, expected: any): Promise<void> {
  const result: any = await client.indices.getMapping({ index });
  const mappings = Object.values<any>(result?.body || {}).map((entry: any) => entry?.mappings);
  if (!mappings.length) throw new Error(`required mapping for ${index} is unavailable`);
  for (const mapping of mappings) {
    if (expected.dynamic !== undefined && String(mapping?.dynamic) !== String(expected.dynamic)) {
      throw new Error(`required mapping for ${index} must set dynamic to ${expected.dynamic}`);
    }
    verifyProperties(expected.properties, mapping?.properties);
  }
}

async function ensureIndex(client: any, index: string, mappings: any, logger: Logger) {
  assertManagedWriteTarget(index);
  const exists = await client.indices.exists({ index });
  if (exists.body) {
    return;
  }
  try {
    await client.indices.create({ index, body: { mappings } });
    logger.info(`Created index ${index}`);
  } catch (e: any) {
    // Another dashboard node may have created it concurrently.
    if (!isResourceAlreadyExists(e)) {
      logger.error(`Failed to create index ${index}: ${e.message}`);
      throw e;
    }
  }
}

function rolloverGeneration(index: string, initialIndex: string): string | null {
  const initial = initialIndex.match(/^(.*?)(\d+)$/);
  if (!initial || !index.startsWith(initial[1])) return null;
  const suffix = index.slice(initial[1].length);
  if (!/^\d+$/.test(suffix) || suffix.length < initial[2].length) return null;
  return suffix.replace(/^0+(?=\d)/, '');
}

function isAlertCarryReadMember(
  index: string,
  initialIndex: string,
  readAlias: string,
  writeAlias: string
): boolean {
  return initialIndex === ALERTS_INITIAL_INDEX &&
    readAlias === ALERTS_READ_ALIAS &&
    writeAlias === ALERTS_WRITE_ALIAS &&
    /^wazuh-alert-status-v2-carry-\d{17}$/.test(index);
}

function settingIsTrue(settings: any, name: string): boolean {
  const shortName = name.replace(/^index\./, '');
  const value = settings?.[name] ?? settings?.index?.[shortName] ??
    shortName.split('.').reduce((current: any, part: string) => current?.[part], settings?.index);
  return value === true || value === 'true';
}

function latestRolloverGeneration(
  members: string[],
  initialIndex: string,
  writeAlias: string
): string {
  const generations = members.map((member) => ({
    member,
    generation: rolloverGeneration(member, initialIndex),
  }));
  if (!generations.length) {
    throw new Error(`Cannot repair ${writeAlias}: no safe rollover generation is available.`);
  }
  if (generations.some(({ generation }) => generation === null)) {
    throw new Error(`Cannot repair ${writeAlias}: rollover membership is ambiguous.`);
  }
  if (new Set(generations.map(({ generation }) => generation)).size !== generations.length) {
    throw new Error(`Cannot repair ${writeAlias}: rollover membership is ambiguous.`);
  }
  generations.sort((a, b) => {
    const left = a.generation!;
    const right = b.generation!;
    return left.length - right.length || left.localeCompare(right);
  });
  const latest = generations[generations.length - 1];
  return latest.member;
}

async function assertWritableGeneration(client: any, index: string, writeAlias: string): Promise<void> {
  assertManagedWriteTarget(index);
  const settingsResult: any = await client.indices.getSettings({ index });
  const settings = settingsResult?.body?.[index]?.settings;
  if (!settings) {
    throw new Error(`Cannot repair ${writeAlias}: no settings are available for ${index}.`);
  }
  if (
    settingIsTrue(settings, 'index.blocks.write') ||
    settingIsTrue(settings, 'index.blocks.read_only') ||
    settingIsTrue(settings, 'index.blocks.read_only_allow_delete')
  ) {
    throw new Error(`Cannot repair ${writeAlias}: latest generation ${index} is write-blocked or retired.`);
  }
}

export async function ensureRolloverFamily(
  client: any,
  index: string,
  readAlias: string,
  writeAlias: string,
  mappings: any,
  logger: Logger
) {
  assertManagedWriteTarget(index);
  assertManagedWriteTarget(readAlias);
  assertManagedWriteTarget(writeAlias);
  let readExists = Boolean((await client.indices.existsAlias({ name: readAlias })).body);
  let writeExists = Boolean((await client.indices.existsAlias({ name: writeAlias })).body);

  if (!readExists && !writeExists && !(await client.indices.exists({ index })).body) {
    try {
      await client.indices.create({
        index,
        body: {
          aliases: {
            [readAlias]: {},
            [writeAlias]: { is_write_index: true },
          },
          mappings,
        },
      });
      logger.info(`Created rollover family ${index} (${readAlias}, ${writeAlias})`);
      return;
    } catch (e: any) {
      if (!isResourceAlreadyExists(e)) throw e;
      // A concurrent node may have created the complete family. Re-read its
      // topology rather than applying aliases from the stale existence checks.
      readExists = Boolean((await client.indices.existsAlias({ name: readAlias })).body);
      writeExists = Boolean((await client.indices.existsAlias({ name: writeAlias })).body);
    }
  }

  const [readResult, writeResult]: any[] = await Promise.all([
    readExists ? client.indices.getAlias({ name: readAlias }) : Promise.resolve({ body: {} }),
    writeExists ? client.indices.getAlias({ name: writeAlias }) : Promise.resolve({ body: {} }),
  ]);
  const readMembers = readResult?.body || {};
  const writeMembers = writeResult?.body || {};
  const writeMemberNames = Object.keys(writeMembers);
  if (writeMemberNames.some((member) => rolloverGeneration(member, index) === null)) {
    throw new Error(`Cannot repair ${writeAlias}: rollover membership is ambiguous.`);
  }
  const members = Array.from(new Set([
    ...Object.keys(readMembers).filter((member) => {
      if (rolloverGeneration(member, index) !== null) return true;
      if (isAlertCarryReadMember(member, index, readAlias, writeAlias)) return false;
      throw new Error(`Cannot repair ${writeAlias}: rollover membership is ambiguous.`);
    }),
    ...writeMemberNames,
  ]));
  if (!members.length && !readExists && !writeExists) members.push(index);

  const explicitWriters = writeMemberNames.filter(
    (member) => writeMembers[member]?.aliases?.[writeAlias]?.is_write_index === true
  );
  if (explicitWriters.length > 1) {
    throw new Error(`Cannot repair ${writeAlias}: multiple explicit write generations are configured.`);
  }

  const latest = latestRolloverGeneration(members, index, writeAlias);
  await assertWritableGeneration(client, latest, writeAlias);

  // Make the highest generation the sole explicit writer in one cluster-state
  // update. Read history is deliberately never removed.
  const actions: any[] = [];
  for (const member of Object.keys(writeMembers)) {
    if (member !== latest) actions.push({ remove: { index: member, alias: writeAlias } });
  }
  if (!readMembers[latest]) actions.push({ add: { index: latest, alias: readAlias } });
  if (writeMembers[latest]?.aliases?.[writeAlias]?.is_write_index !== true) {
    actions.push({ add: { index: latest, alias: writeAlias, is_write_index: true } });
  }
  if (actions.length) await client.indices.updateAliases({ body: { actions } });
}

async function getStoredMappingVersion(client: any): Promise<number> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: MAPPING_VERSION_DOC_ID });
    return res?.body?._source?.version ?? 0;
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 404) return 0;
    throw e;
  }
}

/**
 * Applies additive mapping changes (new fields, new dynamic_templates) to
 * indices that ALREADY EXIST. Index creation only ever runs on a brand-new
 * install, so without this an upgraded deployment would never receive a field
 * added in a later release. PUT _mapping is additive - it accepts new fields
 * and dynamic_templates and is a no-op for identical existing ones; it only
 * rejects an incompatible change to an existing field's type. Startup fails in
 * that case rather than running against a schema that cannot honor contracts.
 */
export async function ensureMappingAdditions(client: any, logger: Logger) {
  const stored = await getStoredMappingVersion(client);
  if (stored < MAPPING_VERSION) {
    logger.info(`wazuh-alert-manager: applying mapping additions (stored v${stored} -> v${MAPPING_VERSION})`);
  }
  for (const [index, mapping] of ADDITIVE_MAPPING_TARGETS) {
    try {
      const exists = await client.indices.exists({ index });
      if (!exists.body) {
        throw new Error(`required managed index or alias ${index} does not exist`);
      }
      if (stored < MAPPING_VERSION) {
        const body: any = {};
        if (mapping.dynamic !== undefined) body.dynamic = mapping.dynamic;
        if (mapping.dynamic_templates) body.dynamic_templates = mapping.dynamic_templates;
        if (mapping.properties) body.properties = mapping.properties;
        await client.indices.putMapping({ index, body });
        logger.info(`wazuh-alert-manager: applied mapping additions to ${index}`);
      }
      await verifyMapping(client, index, mapping);
    } catch (e: any) {
      logger.error(
        `wazuh-alert-manager: required mapping verification failed for ${index}: ${e.message}`
      );
      throw e;
    }
  }
  if (stored < MAPPING_VERSION) {
    await client.index({
      index: META_INDEX,
      id: MAPPING_VERSION_DOC_ID,
      body: { version: MAPPING_VERSION, updated_at: new Date().toISOString() },
    });
  }
}

/**
 * Creates the indices this plugin owns if they don't already exist, then
 * applies any additive mapping changes to indices that predate this release.
 * Safe to call on every server start.
 */
export async function ensureIndices(client: any, logger: Logger) {
  await ensureRolloverFamily(
    client,
    ALERTS_INITIAL_INDEX,
    ALERTS_READ_ALIAS,
    ALERTS_WRITE_ALIAS,
    alertStatusMapping,
    logger
  );
  await ensureRolloverFamily(
    client,
    ACTIVITY_INITIAL_INDEX,
    ACTIVITY_READ_ALIAS,
    ACTIVITY_WRITE_ALIAS,
    activityMapping,
    logger
  );
  await ensureRolloverFamily(
    client,
    EVIDENCE_INITIAL_INDEX,
    EVIDENCE_READ_ALIAS,
    EVIDENCE_WRITE_ALIAS,
    evidenceMapping,
    logger
  );
  await ensureRolloverFamily(
    client,
    CASES_INITIAL_INDEX,
    CASES_READ_ALIAS,
    CASES_WRITE_ALIAS,
    casesMapping,
    logger
  );
  await Promise.all(MANAGED_INDICES.map(([index, mapping]) => ensureIndex(client, index, mapping, logger)));
  await ensureMappingAdditions(client, logger);
}
