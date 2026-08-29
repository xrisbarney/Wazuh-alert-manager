import { CASES_WRITE_ALIAS } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';

const MAX_BACKFILL_PASSES = 5;
const MISSING_CASE_UID_QUERY = { bool: { must_not: [{ exists: { field: 'case_uid' } }] } };

export async function backfillCaseUids(client: any): Promise<void> {
  const index = assertManagedWriteTarget(CASES_WRITE_ALIAS);

  for (let pass = 1; pass <= MAX_BACKFILL_PASSES; pass++) {
    const result: any = await client.updateByQuery({
      index,
      conflicts: 'proceed',
      refresh: true,
      body: {
        query: MISSING_CASE_UID_QUERY,
        script: {
          lang: 'painless',
          source: 'ctx._source.case_uid = ctx._id',
        },
      },
    });
    const body = result?.body || {};
    const failures = Array.isArray(body.failures) ? body.failures : [];
    if (body.timed_out || failures.length) {
      throw new Error(
        `Case UID backfill failed on pass ${pass} (timed out ${Boolean(body.timed_out)}, failures ${failures.length})`
      );
    }

    const verification: any = await client.count({
      index,
      body: { query: MISSING_CASE_UID_QUERY },
    });
    const remaining = Number(verification?.body?.count);
    if (!Number.isSafeInteger(remaining) || remaining < 0) {
      throw new Error('Case UID backfill verification returned an invalid count');
    }
    if (remaining === 0) return;
  }

  throw new Error(`Case UID backfill exhausted ${MAX_BACKFILL_PASSES} passes`);
}
