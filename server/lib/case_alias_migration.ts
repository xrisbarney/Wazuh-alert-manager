import { Logger } from '../../../../src/core/server';
import { CASES_V2_SINGLETON_INDEX, CASES_WRITE_ALIAS, META_INDEX } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';

const MIGRATION_DOC_ID = 'cases_alias_migration';
const PAGE_SIZE = 500;

async function exists(client: any, index: string): Promise<boolean> {
  try {
    const res: any = await client.indices.exists({ index });
    return Boolean(res.body);
  } catch (e) {
    return false;
  }
}

async function isComplete(client: any): Promise<boolean> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: MIGRATION_DOC_ID });
    return res?.body?._source?.completed === true;
  } catch (e: any) {
    if ((e?.meta?.statusCode || e?.statusCode) === 404) return false;
    throw e;
  }
}

// Insert-only: preserves the existing _id and never overwrites a case that
// already landed in the alias family. Idempotent, so replay is safe.
function insertOnly(index: string, id: string, doc: any): any[] {
  return [
    { update: { _index: assertManagedWriteTarget(index), _id: id } },
    { upsert: doc, script: { lang: 'painless', source: "ctx.op = 'none'" } },
  ];
}

/**
 * Non-destructive migration of the pre-alias v2 cases singleton into the
 * rollover-backed cases family. The singleton is read-only and retained
 * afterwards. Idempotent and resumable: a restart replays the scroll through
 * non-overwriting writes, and a meta completion marker skips the scan once done.
 */
export async function migrateCaseAliases(client: any, logger: Logger): Promise<number> {
  if (await isComplete(client)) return 0;
  if (!(await exists(client, CASES_V2_SINGLETON_INDEX))) {
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: MIGRATION_DOC_ID,
      body: { completed: true, migrated: 0, updated_at: new Date().toISOString() },
      refresh: 'wait_for',
    });
    return 0;
  }

  let migrated = 0;
  let scrollId: string | undefined;
  try {
    let page: any = await client.search({
      index: CASES_V2_SINGLETON_INDEX,
      scroll: '2m',
      size: PAGE_SIZE,
      body: { query: { match_all: {} }, sort: ['_doc'], _source: true },
    });
    for (;;) {
      scrollId = page?.body?._scroll_id || scrollId;
      const hits = page?.body?.hits?.hits || [];
      if (!hits.length) break;
      const bulk: any[] = [];
      for (const hit of hits) {
        bulk.push(...insertOnly(CASES_WRITE_ALIAS, hit._id, hit._source || {}));
      }
      if (bulk.length) {
        const result: any = await client.bulk({ body: bulk });
        const items = result?.body?.items || [];
        const failed = items.some((item: any) => {
          const op: any = Object.values(item || {})[0];
          const status = Number(op?.status);
          return !op || op.error || !Number.isInteger(status) || status < 200 || status >= 300;
        });
        if (result?.body?.errors || items.length !== bulk.length / 2 || failed) {
          throw new Error('One or more cases failed to migrate to the cases alias family');
        }
        migrated += hits.length;
      }
      page = await client.scroll({ scrollId, scroll: '2m' });
    }
  } catch (e: any) {
    logger.error(`wazuh-alert-manager cases alias migration failed safely: ${e.message}`);
    throw e;
  } finally {
    if (scrollId) {
      try {
        await client.clearScroll({ scrollId });
      } catch (e) {
        // Expired scroll contexts are harmless.
      }
    }
  }

  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: MIGRATION_DOC_ID,
    body: { completed: true, migrated, completed_at: new Date().toISOString() },
    refresh: 'wait_for',
  });
  logger.info(`wazuh-alert-manager cases alias migration: migrated ${migrated} cases; singleton retained`);
  return migrated;
}
