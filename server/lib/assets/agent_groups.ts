import { ASSET_GROUP_CACHE_TTL_MS } from '../../../common/constants';
import { getWazuhApiClient, WazuhApiClient, WazuhCoreSource } from '../wazuh_api';
import { boundedGroups } from './matcher';

/**
 * 4.x agent groups for the sync job (step 6.4a).
 *
 * Wazuh 4.x alerts do not carry the agent's groups; they only exist behind
 * the server API (`GET /agents?agents_list=...&select=id,group`). The sync
 * job asks this cache for the agents in a batch; it fetches only ids it has
 * not seen within ASSET_GROUP_CACHE_TTL_MS and caches an empty list for
 * agents the API does not return (agent 000 has no group). When `wazuhCore`
 * is absent or a call fails, every agent resolves to [] and nothing is
 * cached, so a transient API error is retried on the next batch.
 *
 * Only the background sync job may use this (internal API credential).
 */

export interface AgentGroupLookup {
  /** Groups for each requested agent id, [] when unknown. */
  lookup(agentIds: Iterable<string>): Promise<Map<string, string[]>>;
}

const MAX_IDS_PER_REQUEST = 100;
/** Upper bound on the wall-clock time one lookup() may spend on API calls. */
const DEFAULT_LOOKUP_DEADLINE_MS = 30_000;

interface CacheEntry {
  groups: string[];
  expiresAt: number;
}

export class AgentGroupCache implements AgentGroupLookup {
  private readonly cache = new Map<string, CacheEntry>();
  private client: WazuhApiClient | null = null;
  private clientResolvedAt = 0;

  constructor(
    private readonly source: WazuhCoreSource,
    private readonly options: {
      ttlMs?: number;
      /** Per-lookup wall-clock budget for the chunked API calls (default 30 s). */
      lookupDeadlineMs?: number;
      now?: () => number;
      logger?: { debug(message: string): void };
    } = {}
  ) {}

  private now(): number {
    return this.options.now ? this.options.now() : Date.now();
  }

  private ttl(): number {
    return this.options.ttlMs ?? ASSET_GROUP_CACHE_TTL_MS;
  }

  /** Resolve the API client once per TTL so a later-loaded wazuhCore is picked up. */
  private async apiClient(): Promise<WazuhApiClient> {
    if (!this.client || this.now() - this.clientResolvedAt > this.ttl()) {
      this.client = await getWazuhApiClient(this.source);
      this.clientResolvedAt = this.now();
    }
    return this.client;
  }

  get size(): number {
    return this.cache.size;
  }

  async lookup(agentIds: Iterable<string>): Promise<Map<string, string[]>> {
    const result = new Map<string, string[]>();
    const missing: string[] = [];
    const now = this.now();
    for (const raw of agentIds) {
      const id = typeof raw === 'string' ? raw.trim() : '';
      if (!id || result.has(id)) continue;
      const hit = this.cache.get(id);
      if (hit && hit.expiresAt > now) {
        result.set(id, hit.groups);
      } else {
        result.set(id, []);
        missing.push(id);
      }
    }
    if (!missing.length) return result;

    const client = await this.apiClient();
    if (!client.available) {
      const reason = 'reason' in client ? client.reason : 'unavailable';
      this.options.logger?.debug(`wazuh-alert-manager assets: agent groups unavailable (${reason})`);
      return result;
    }
    // The sync job holds a lease while this runs: stop issuing further chunks
    // once the budget is spent so a slow Wazuh API cannot hold a tick past the
    // lease TTL. Agents not reached stay uncached and are retried next batch.
    const deadline = this.now() + (this.options.lookupDeadlineMs ?? DEFAULT_LOOKUP_DEADLINE_MS);
    for (let offset = 0; offset < missing.length; offset += MAX_IDS_PER_REQUEST) {
      if (offset > 0 && this.now() >= deadline) {
        this.options.logger?.debug(
          `wazuh-alert-manager assets: agent group lookup deadline reached, ${missing.length - offset} agent(s) left unresolved this batch`
        );
        break;
      }
      const ids = missing.slice(offset, offset + MAX_IDS_PER_REQUEST);
      const response = await client.request<any>('GET', '/agents', {
        agents_list: ids.join(','),
        select: 'id,group',
        limit: ids.length,
      });
      if (!response.ok) {
        const reason = 'reason' in response ? response.reason : 'unknown error';
        this.options.logger?.debug(`wazuh-alert-manager assets: agent group lookup failed: ${reason}`);
        continue;
      }
      const items: any[] = Array.isArray(response.data?.data?.affected_items) ? response.data.data.affected_items : [];
      const seen = new Map<string, string[]>();
      for (const item of items) {
        if (!item || typeof item !== 'object' || typeof item.id !== 'string') continue;
        seen.set(item.id, boundedGroups(item.group));
      }
      const expiresAt = this.now() + this.ttl();
      for (const id of ids) {
        const groups = seen.get(id) || [];
        this.cache.set(id, { groups, expiresAt });
        result.set(id, groups);
      }
    }
    return result;
  }
}

/** A lookup that always answers [] (no wazuhCore, or 5.0 where groups are on the record). */
export const NO_AGENT_GROUPS: AgentGroupLookup = {
  async lookup(agentIds: Iterable<string>) {
    const out = new Map<string, string[]>();
    for (const id of agentIds) if (id) out.set(id, []);
    return out;
  },
};
