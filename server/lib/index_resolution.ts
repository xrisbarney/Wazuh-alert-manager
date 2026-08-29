import { ALERTS_READ_ALIAS } from '../../common';
import { isManagedPhysicalIndex } from './index_namespace';

export interface ManagedDocumentLocation {
  id: string;
  index: string;
  source?: any;
}

/** Resolve mutable documents behind a multi-index read alias. */
export async function resolveManagedDocuments(
  client: any,
  alias: string,
  ids: string[],
  physicalPrefix: string,
  includeSource = false
): Promise<Map<string, ManagedDocumentLocation>> {
  const unique = Array.from(new Set(ids.filter(Boolean)));
  const out = new Map<string, ManagedDocumentLocation>();
  if (!unique.length) return out;

  // Keep each ids query below practical clause/result limits. Two hits per ID
  // allows a temporary old/new duplicate during a controlled carry-forward;
  // the sort below deterministically selects the newest state.
  for (let offset = 0; offset < unique.length; offset += 750) {
    const chunk = unique.slice(offset, offset + 750);
    const res: any = await client.search({
      index: alias,
      body: {
        size: chunk.length * 2,
        query: { ids: { values: chunk } },
        _source: includeSource,
        sort: [
          { state_version: { order: 'desc', unmapped_type: 'long' } },
          { ingested_at: { order: 'desc', unmapped_type: 'date' } },
        ],
      },
    });
    for (const hit of res?.body?.hits?.hits || []) {
      if (!isManagedPhysicalIndex(hit._index, physicalPrefix)) {
        throw new Error(`Alias ${alias} resolved outside its managed family: ${hit._index}`);
      }
      if (!out.has(hit._id)) out.set(hit._id, { id: hit._id, index: hit._index, source: hit._source });
    }
  }
  return out;
}

export const resolveAlerts = (client: any, ids: string[], includeSource = false) =>
  resolveManagedDocuments(client, ALERTS_READ_ALIAS, ids, 'wazuh-alert-status-v2-', includeSource);

export async function alertIndexOrThrow(client: any, id: string): Promise<string> {
  const found = await resolveAlerts(client, [id]);
  const location = found.get(id);
  if (!location) throw new Error(`Alert ${id} was not found in managed storage`);
  return location.index;
}

export interface ResolvedCaseAlert {
  id: string;
  index?: string;
  source: any;
  availability: 'live' | 'archived' | 'snapshot' | 'unavailable';
}

/** Resolve case relationships without accepting an index from the caller. */
export async function resolveCaseAlerts(
  client: any,
  evidence: any[]
): Promise<Map<string, ResolvedCaseAlert>> {
  const ids = Array.from(new Set(evidence.map((item) => item?.alert_id).filter(Boolean)));
  const live = await resolveAlerts(client, ids, true);
  const resolved = new Map<string, ResolvedCaseAlert>();
  for (const item of evidence) {
    const id = item?.alert_id;
    if (!id || resolved.has(id)) continue;
    const liveAlert = live.get(id);
    if (liveAlert) {
      resolved.set(id, { id, index: liveAlert.index, source: liveAlert.source, availability: 'live' });
      continue;
    }
    const archiveIndex = item?.archive_index;
    const archiveId = item?.archive_id || id;
    if (archiveIndex) {
      if (!isManagedPhysicalIndex(archiveIndex, 'wazuh-alert-status-v2-')) {
        throw new Error(`Refusing to read untrusted archive location: ${archiveIndex}`);
      }
      try {
        const archived: any = await client.get({ index: archiveIndex, id: archiveId });
        if (archived?.body?._source) {
          resolved.set(id, { id, source: archived.body._source, availability: 'archived' });
          continue;
        }
      } catch (e: any) {
        // A retained archive can be offline or unavailable to the current user;
        // the relationship snapshot remains a valid bounded fallback.
      }
    }
    resolved.set(id, {
      id,
      source: item?.snapshot || null,
      availability: item?.snapshot ? 'snapshot' : 'unavailable',
    });
  }
  return resolved;
}
