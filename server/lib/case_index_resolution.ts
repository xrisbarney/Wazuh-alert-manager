import { CASES_READ_ALIAS } from '../../common';
import { assertManagedWriteTarget, isManagedPhysicalIndex } from './index_namespace';

export interface ResolvedCaseDocument {
  id: string;
  index: string;
  source: any;
  seqNo?: number;
  primaryTerm?: number;
}

function safeCaseIndex(index: string): string {
  if (!isManagedPhysicalIndex(index, 'wazuh-alert-manager-v2-cases-')) {
    throw new Error(`Case resolved to an unmanaged index: ${index}`);
  }
  return assertManagedWriteTarget(index);
}

/**
 * Resolve case ids through the multi-index read alias and retain each hit's
 * physical index. OpenSearch rejects GET/MGET against a multi-index alias and
 * an update sent to the write alias cannot mutate a document in an older
 * generation, so every point read/mutation must use this resolver.
 */
export async function resolveCases(client: any, ids: string[]): Promise<Map<string, ResolvedCaseDocument>> {
  const unique = Array.from(new Set(ids.filter(Boolean)));
  const resolved = new Map<string, ResolvedCaseDocument>();
  if (!unique.length) return resolved;

  for (let offset = 0; offset < unique.length; offset += 1000) {
    const chunk = unique.slice(offset, offset + 1000);
    const response: any = await client.search({
      index: CASES_READ_ALIAS,
      body: {
        size: 10000,
        track_total_hits: true,
        query: { ids: { values: chunk } },
        _source: true,
      },
    });
    const hits = response?.body?.hits?.hits || [];
    const rawTotal = response?.body?.hits?.total;
    const total = typeof rawTotal === 'number' ? rawTotal : rawTotal?.value ?? hits.length;
    if (total > hits.length) {
      throw new Error(`Case resolution returned ${hits.length} of ${total} physical document(s).`);
    }
    for (const hit of hits) {
      const id = String(hit._id || '');
      if (!id) continue;
      const candidate = {
        id,
        index: safeCaseIndex(String(hit._index || '')),
        source: hit._source || {},
        seqNo: hit._seq_no,
        primaryTerm: hit._primary_term,
      };
      const existing = resolved.get(id);
      // Numeric generations are zero-padded. Prefer the newest physical hit
      // during the brief carry-before-detach window if a case exists twice.
      if (!existing || candidate.index.localeCompare(existing.index) > 0) resolved.set(id, candidate);
    }
  }
  return resolved;
}

export async function resolveCase(client: any, id: string): Promise<ResolvedCaseDocument> {
  const found = (await resolveCases(client, [id])).get(id);
  if (!found) {
    const error: any = new Error(`Case ${id} was not found.`);
    error.statusCode = 404;
    throw error;
  }
  return found;
}
