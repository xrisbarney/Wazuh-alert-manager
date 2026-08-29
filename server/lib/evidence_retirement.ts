import { EVIDENCE_READ_ALIAS, EVIDENCE_WRITE_ALIAS, META_INDEX } from '../../common';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from './index_namespace';

const PREFIX = 'evidence-retirement:';
const PAGE_SIZE = 500;

function validate(index: string) {
  if (!isManagedPhysicalIndex(index, 'wazuh-alert-manager-v2-evidence-')) {
    throw new Error('Only a physical plugin evidence generation can be retired or purged.');
  }
}

async function aliases(client: any, name: string): Promise<Record<string, any>> {
  const result: any = await client.indices.getAlias({ name });
  return result?.body || {};
}

export async function retireEvidenceIndex(client: any, index: string, actor: string) {
  validate(index);
  const [read, write] = await Promise.all([
    aliases(client, EVIDENCE_READ_ALIAS), aliases(client, EVIDENCE_WRITE_ALIAS),
  ]);
  if (!read[index]) throw new Error(`${index} is not attached to the evidence read alias.`);
  if (write[index]?.aliases?.[EVIDENCE_WRITE_ALIAS]?.is_write_index === true) {
    throw new Error('Cannot retire the current evidence write generation; roll it over first.');
  }

  let copied = 0;
  let alreadyCurrent = 0;
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index, scroll: '2m', size: PAGE_SIZE,
      body: { query: { match_all: {} }, sort: ['_doc'], _source: true },
    });
    for (;;) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      const body: any[] = [];
      for (const hit of hits) body.push(
        { create: { _index: assertManagedWriteTarget(EVIDENCE_WRITE_ALIAS), _id: hit._id } },
        hit._source || {}
      );
      const bulk: any = await client.bulk({ body, refresh: false });
      const items = bulk?.body?.items || [];
      if (items.length !== hits.length) throw new Error('Evidence carry-forward returned an incomplete bulk response.');
      for (const item of items) {
        const op = item?.create;
        if (Number(op?.status) === 409) alreadyCurrent += 1;
        else if (op?.error || Number(op?.status) < 200 || Number(op?.status) >= 300) {
          throw new Error(op?.error?.reason || 'Evidence carry-forward failed.');
        } else copied += 1;
      }
      if (hits.length < PAGE_SIZE) break;
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } finally {
    if (scrollId) {
      try { await client.clearScroll({ scrollId }); } catch (e) { /* expired */ }
    }
  }
  await client.indices.refresh({ index: EVIDENCE_WRITE_ALIAS });

  let detached = false;
  await client.indices.putSettings({ index, body: { 'index.blocks.write': true } });
  try {
    await client.indices.updateAliases({ body: { actions: [
      { remove: { index, alias: EVIDENCE_READ_ALIAS } },
      { remove: { index, alias: EVIDENCE_WRITE_ALIAS } },
    ] } });
    detached = true;
    const record = {
      status: 'completed', retiring_index: index, copied, already_current: alreadyCurrent,
      source_retained: true, completed_at: new Date().toISOString(), actor,
    };
    await client.index({
      index: assertManagedWriteTarget(META_INDEX), id: `${PREFIX}${index}`,
      body: record, refresh: 'wait_for',
    });
    return record;
  } catch (error) {
    if (detached) {
      try {
        await client.indices.updateAliases({ body: { actions: [
          { add: { index, alias: EVIDENCE_READ_ALIAS } },
        ] } });
      } catch (rollbackError: any) {
        throw new Error(`Evidence retirement failed and the read alias could not be restored: ${rollbackError.message}`);
      }
    }
    await client.indices.putSettings({ index, body: { 'index.blocks.write': false } });
    throw error;
  }
}

export async function purgeRetiredEvidenceIndex(client: any, index: string, actor: string) {
  validate(index);
  const [read, write, record, settings]: any[] = await Promise.all([
    aliases(client, EVIDENCE_READ_ALIAS), aliases(client, EVIDENCE_WRITE_ALIAS),
    client.get({ index: META_INDEX, id: `${PREFIX}${index}` }),
    client.indices.getSettings({ index }),
  ]);
  if (read[index] || write[index]) throw new Error('The evidence index is still attached to a live alias.');
  if (record?.body?._source?.status !== 'completed') throw new Error('No completed evidence retirement record exists.');
  if (settings?.body?.[index]?.settings?.index?.blocks?.write !== 'true') {
    throw new Error('The retired evidence index is not write-blocked.');
  }
  const [freshRead, freshWrite] = await Promise.all([
    aliases(client, EVIDENCE_READ_ALIAS), aliases(client, EVIDENCE_WRITE_ALIAS),
  ]);
  if (freshRead[index] || freshWrite[index]) throw new Error('The evidence index became attached to a live alias.');
  await client.indices.delete({ index: assertManagedWriteTarget(index) });
  await client.index({
    index: assertManagedWriteTarget(META_INDEX), id: `${PREFIX}${index}`,
    body: { ...record.body._source, status: 'purged', purged_at: new Date().toISOString(), purged_by: actor },
    refresh: 'wait_for',
  });
  return { index, purged: true };
}
