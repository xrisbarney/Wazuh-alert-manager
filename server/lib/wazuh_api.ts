/**
 * Optional Wazuh server API access through the `wazuhCore` dashboard plugin.
 *
 * The plugin declares `wazuhCore` as an *optional* dependency: when it is
 * present it exposes a Server API client on its setup/start contract
 * (`plugins.wazuhCore.api.client.asInternalUser`) and on the route-handler
 * context (`context.wazuh_core.api.client.asInternalUser`), authenticated with
 * the stored `wazuh-wui` credential. When it is absent, misconfigured or
 * unreachable every caller must degrade gracefully, so this module never throws:
 * each failure is reported as `{ available: false, reason }` or
 * `{ ok: false, reason }`.
 *
 * Only the background sync job may use this (agent groups on 4.x, optional
 * MITRE table cache). Routes run as the logged-in user and must not call the
 * Wazuh server API with the internal credential on an analyst's behalf.
 *
 * Everything here is typed structurally; nothing is imported from the Wazuh
 * plugins so the build does not depend on them.
 */

export type WazuhApiMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

/** Query parameters accepted by the Wazuh server API (`?select=...`, `?limit=...`). */
export type WazuhApiParams = Record<string, string | number | boolean | undefined>;

/** The subset of `ServerAPIClient.asInternalUser` this module relies on. */
export interface WazuhCoreInternalUserClient {
  request: (
    method: string,
    path: string,
    data: { params?: WazuhApiParams; body?: unknown; headers?: Record<string, string> },
    options: { apiHostID: string; forceRefresh?: boolean }
  ) => Promise<{ status?: number; data?: unknown } | undefined>;
}

/** The subset of `ManageHosts` this module relies on. */
export interface WazuhCoreManageHosts {
  /** Without an id returns every configured host; with an id returns one or throws. */
  get: (hostID?: string, options?: { excludePassword?: boolean }) => Promise<unknown>;
}

/** What `wazuhCore` exposes on its setup/start contract and on the route context. */
export interface WazuhCoreContract {
  api?: { client?: { asInternalUser?: Partial<WazuhCoreInternalUserClient> } };
  manageHosts?: Partial<WazuhCoreManageHosts>;
}

/**
 * Any of the places the contract can be reached from: the plugin setup/start
 * dependencies (`plugins.wazuhCore`), a route-handler context
 * (`context.wazuh_core`) or the contract itself.
 */
export type WazuhCoreSource =
  | { wazuhCore?: WazuhCoreContract | null }
  | { wazuh_core?: WazuhCoreContract | null }
  | WazuhCoreContract
  | null
  | undefined;

export interface WazuhApiClientOptions {
  /** Explicit API host id; otherwise the first configured host is used. */
  apiHostID?: string;
}

export type WazuhApiResult<T = unknown> =
  | { ok: true; status: number; data: T }
  | { ok: false; status?: number; reason: string };

export interface WazuhApiRequester {
  <T = unknown>(method: WazuhApiMethod, path: string, params?: WazuhApiParams): Promise<WazuhApiResult<T>>;
}

export type WazuhApiClient =
  | { available: true; apiHostID: string; request: WazuhApiRequester }
  | { available: false; reason: string; request: WazuhApiRequester };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function errorMessage(error: unknown): string {
  if (isRecord(error) && typeof error.message === 'string' && error.message) return error.message;
  return String(error);
}

/** HTTP status carried by an axios-style error, if any. */
function errorStatus(error: unknown): number | undefined {
  if (!isRecord(error) || !isRecord(error.response)) return undefined;
  return typeof error.response.status === 'number' ? error.response.status : undefined;
}

function unavailable(reason: string): WazuhApiClient {
  return {
    available: false,
    reason,
    request: async () => ({ ok: false, reason }),
  };
}

/** Locate the wazuhCore contract on whichever object the caller passed. */
export function resolveWazuhCoreContract(source: WazuhCoreSource): WazuhCoreContract | null {
  if (!isRecord(source)) return null;
  const candidates: unknown[] = [source.wazuhCore, source.wazuh_core, source];
  for (const candidate of candidates) {
    if (isRecord(candidate) && isRecord(candidate.api)) return candidate as WazuhCoreContract;
  }
  return null;
}

/**
 * Pick the API host the way the Wazuh plugin does when nothing selects one:
 * the first entry of the configured `hosts` list.
 */
async function resolveApiHostID(contract: WazuhCoreContract, explicit?: string): Promise<string> {
  if (explicit && explicit.trim()) return explicit.trim();
  const manageHosts = contract.manageHosts;
  if (!manageHosts || typeof manageHosts.get !== 'function') {
    throw new Error('wazuhCore does not expose manageHosts; pass an explicit apiHostID');
  }
  const hosts = await manageHosts.get(undefined, { excludePassword: true });
  const list = Array.isArray(hosts) ? hosts : hosts ? [hosts] : [];
  const first = list.find((host) => isRecord(host) && typeof host.id === 'string' && host.id);
  if (!first) throw new Error('no Wazuh API host is configured');
  return (first as { id: string }).id;
}

/**
 * Build a client for the Wazuh server API as the dashboard's internal API
 * user. Never throws: when `wazuhCore` is missing, lacks an internal-user
 * client, or has no usable API host, the result is `{ available: false }` and
 * its `request` resolves to `{ ok: false }` with the same reason.
 */
export async function getWazuhApiClient(
  source: WazuhCoreSource,
  options: WazuhApiClientOptions = {}
): Promise<WazuhApiClient> {
  const contract = resolveWazuhCoreContract(source);
  if (!contract) return unavailable('wazuhCore plugin is not available');

  const internal = contract.api && contract.api.client && contract.api.client.asInternalUser;
  if (!internal || typeof internal.request !== 'function') {
    return unavailable('wazuhCore does not expose an internal-user API client');
  }
  const requestFn = internal.request;

  let apiHostID: string;
  try {
    apiHostID = await resolveApiHostID(contract, options.apiHostID);
  } catch (e) {
    return unavailable(`Wazuh API host could not be resolved: ${errorMessage(e)}`);
  }

  const request: WazuhApiRequester = async <T = unknown>(
    method: WazuhApiMethod,
    path: string,
    params?: WazuhApiParams
  ): Promise<WazuhApiResult<T>> => {
    if (!path || !path.startsWith('/')) {
      return { ok: false, reason: `Wazuh API path must start with "/": ${path || '<empty>'}` };
    }
    try {
      const response = await requestFn(method, path, { params: params || {} }, { apiHostID });
      const status = response && typeof response.status === 'number' ? response.status : 200;
      if (status >= 400) {
        return { ok: false, status, reason: `Wazuh API ${method} ${path} returned HTTP ${status}` };
      }
      return { ok: true, status, data: (response ? response.data : undefined) as T };
    } catch (e) {
      const status = errorStatus(e);
      const suffix = status ? ` (HTTP ${status})` : '';
      return { ok: false, status, reason: `Wazuh API ${method} ${path} failed${suffix}: ${errorMessage(e)}` };
    }
  };

  return { available: true, apiHostID, request };
}
