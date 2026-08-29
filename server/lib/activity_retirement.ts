import { ACTIVITY_READ_ALIAS, ACTIVITY_WRITE_ALIAS, META_INDEX } from '../../common';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from './index_namespace';

async function members(client: any, alias: string): Promise<Record<string, any>> {
  const res: any = await client.indices.getAlias({ name: alias });
  return res?.body || {};
}

function validate(index: string) {
  if (!isManagedPhysicalIndex(index, 'wazuh-alert-manager-v2-activity-')) {
    throw new Error('Only a physical plugin activity generation can be retired or purged.');
  }
}

export async function retireActivityIndex(client: any, index: string, actor: string, retentionDays = 365) {
  validate(index);
  const [read, write] = await Promise.all([
    members(client, ACTIVITY_READ_ALIAS),
    members(client, ACTIVITY_WRITE_ALIAS),
  ]);
  if (!read[index]) throw new Error(`${index} is not attached to the activity read alias.`);
  if (write[index]?.aliases?.[ACTIVITY_WRITE_ALIAS]?.is_write_index === true) {
    throw new Error('Detach the activity write alias before retiring this generation.');
  }
  const indexSettings: any = await client.indices.getSettings({ index });
  const createdAt = Number(indexSettings?.body?.[index]?.settings?.index?.creation_date || 0);
  const ageDays = createdAt ? (Date.now() - createdAt) / 86400000 : 0;
  if (!createdAt || ageDays < retentionDays) {
    throw new Error(`Activity retention requires ${retentionDays} days; this generation is ${Math.floor(ageDays)} days old.`);
  }
  const count: any = await client.count({ index, body: { query: { match_all: {} } } });
  const record = {
    status: 'completed',
    retiring_index: index,
    retained_documents: count.body.count || 0,
    actor,
    completed_at: new Date().toISOString(),
    source_retained: true,
  };
  let detached = false;
  await client.indices.putSettings({ index, body: { 'index.blocks.write': true } });
  try {
    await client.indices.updateAliases({
      body: { actions: [
        { remove: { index, alias: ACTIVITY_READ_ALIAS } },
        { remove: { index, alias: ACTIVITY_WRITE_ALIAS } },
      ] },
    });
    detached = true;
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: `activity-retirement:${index}`,
      body: record,
      refresh: 'wait_for',
    });
  } catch (error) {
    if (detached) {
      try {
        await client.indices.updateAliases({
          body: { actions: [{ add: { index, alias: ACTIVITY_READ_ALIAS } }] },
        });
      } catch (rollbackError: any) {
        throw new Error(
          `Activity retirement metadata failed and the read alias could not be restored: ${rollbackError.message}`
        );
      }
    }
    await client.indices.putSettings({ index, body: { 'index.blocks.write': false } });
    throw error;
  }
  return record;
}

export async function purgeRetiredActivityIndex(client: any, index: string, actor: string) {
  validate(index);
  const [read, write, record, settings]: any[] = await Promise.all([
    members(client, ACTIVITY_READ_ALIAS),
    members(client, ACTIVITY_WRITE_ALIAS),
    client.get({ index: META_INDEX, id: `activity-retirement:${index}` }),
    client.indices.getSettings({ index }),
  ]);
  if (read[index] || write[index]) throw new Error('The activity index is still attached to a live alias.');
  if (record?.body?._source?.status !== 'completed') throw new Error('No completed retirement record exists.');
  if (settings?.body?.[index]?.settings?.index?.blocks?.write !== 'true') {
    throw new Error('The retired activity index is not write-blocked.');
  }
  const [freshRead, freshWrite]: any[] = await Promise.all([
    members(client, ACTIVITY_READ_ALIAS),
    members(client, ACTIVITY_WRITE_ALIAS),
  ]);
  if (freshRead[index] || freshWrite[index]) throw new Error('The activity index became attached to a live alias.');
  await client.indices.delete({ index: assertManagedWriteTarget(index) });
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: `activity-retirement:${index}`,
    body: { ...record.body._source, status: 'purged', purged_at: new Date().toISOString(), purged_by: actor },
    refresh: 'wait_for',
  });
  return { index, purged: true };
}
