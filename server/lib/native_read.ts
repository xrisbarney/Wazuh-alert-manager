import { MANAGED_INDEX_PREFIXES } from '../../common';

/**
 * Native Wazuh index families the plugin may READ outside the alert/finding
 * source family (which `assertSafeSourcePattern` governs). Every entry is a
 * name prefix; a request pattern must start with one of them. Extend this
 * list deliberately - each addition is a new native store the plugin reads.
 */
export const READ_ONLY_NATIVE_PATTERNS: string[] = ['wazuh-states-', 'wazuh-threatintel-enrichments'];

export interface NativeSearchRequest {
  /** Index name or trailing-wildcard pattern, e.g. `wazuh-states-inventory-system*`. */
  indexPattern: string;
  /** OpenSearch search/count body (query, size, sort, _source, aggs). */
  body: Record<string, unknown>;
  /** Short label naming the feature performing the read, for diagnostics. */
  purpose: string;
}

export interface NativeHit<T = Record<string, unknown>> {
  _id: string;
  _index: string;
  _source: T;
  sort?: unknown[];
}

export type NativeSearchResult<T = Record<string, unknown>> =
  | { status: 'ok'; hits: Array<NativeHit<T>>; total: number; aggregations?: Record<string, unknown> }
  | { status: 'no_access' }
  | { status: 'not_available' };

export type NativeCountResult =
  | { status: 'ok'; total: number }
  | { status: 'no_access' }
  | { status: 'not_available' };

function namesPluginStorage(index: string): boolean {
  return MANAGED_INDEX_PREFIXES.some((prefix) => index.startsWith(prefix));
}

/**
 * Fail closed before any native read reaches OpenSearch: the pattern must be
 * a single explicit name or trailing-wildcard pattern inside
 * `READ_ONLY_NATIVE_PATTERNS`. Multi-target strings, exclusions, `_all`, bare
 * wildcards, path characters and anything touching plugin storage are refused.
 */
export function assertNativeReadPattern(pattern: string): string {
  const normalized = String(pattern || '').trim();
  if (!normalized || normalized === '*' || normalized === '_all') {
    throw new Error('A native read pattern must be explicit; * and _all are not allowed.');
  }
  if (!/^[a-z0-9][a-z0-9._-]*\*?$/.test(normalized)) {
    throw new Error(`Unsafe native read pattern: ${normalized}`);
  }
  if (namesPluginStorage(normalized)) {
    throw new Error(`Native read pattern overlaps plugin storage: ${normalized}`);
  }
  if (!READ_ONLY_NATIVE_PATTERNS.some((prefix) => normalized.startsWith(prefix))) {
    throw new Error(
      `Native read pattern is outside the read-only allowlist: ${normalized}. Expected one of ${READ_ONLY_NATIVE_PATTERNS.join(
        ', '
      )}.`
    );
  }
  return normalized;
}

function statusCodeOf(error: any): number | undefined {
  const code = error?.meta?.statusCode ?? error?.statusCode;
  return typeof code === 'number' ? code : undefined;
}

function errorTypeOf(error: any): string | undefined {
  return error?.meta?.body?.error?.type || error?.body?.error?.type;
}

export function isNoAccessError(error: any): boolean {
  return statusCodeOf(error) === 403 || errorTypeOf(error) === 'security_exception';
}

export function isNotAvailableError(error: any): boolean {
  return statusCodeOf(error) === 404 || errorTypeOf(error) === 'index_not_found_exception';
}

function totalOf(hits: any): number {
  const total = hits?.total;
  if (typeof total === 'number') return total;
  if (total && typeof total.value === 'number') return total.value;
  return 0;
}

/**
 * Read-only search over a native Wazuh index outside the alert family. Only
 * ever issues `search`; a missing role grant comes back as `no_access`, a
 * missing index (e.g. a 4.x cluster asked for a 5.0-only family) as
 * `not_available`, and every other failure is rethrown so callers see real
 * outages. A wildcard that matches no index is an `ok` result with no hits.
 */
export async function searchNative<T = Record<string, unknown>>(
  client: any,
  request: NativeSearchRequest
): Promise<NativeSearchResult<T>> {
  const index = assertNativeReadPattern(request.indexPattern);
  try {
    const result: any = await client.search({ index, body: request.body || {} });
    const hits = result?.body?.hits || {};
    const aggregations = result?.body?.aggregations;
    return {
      status: 'ok',
      hits: (hits.hits || []) as Array<NativeHit<T>>,
      total: totalOf(hits),
      ...(aggregations ? { aggregations } : {}),
    };
  } catch (e: any) {
    if (isNoAccessError(e)) return { status: 'no_access' };
    if (isNotAvailableError(e)) return { status: 'not_available' };
    throw e;
  }
}

/** Read-only count with the same allowlist and error mapping as `searchNative`. */
export async function countNative(client: any, request: NativeSearchRequest): Promise<NativeCountResult> {
  const index = assertNativeReadPattern(request.indexPattern);
  try {
    const result: any = await client.count({ index, body: request.body || {} });
    const count = Number(result?.body?.count);
    return { status: 'ok', total: Number.isFinite(count) ? count : 0 };
  } catch (e: any) {
    if (isNoAccessError(e)) return { status: 'no_access' };
    if (isNotAvailableError(e)) return { status: 'not_available' };
    throw e;
  }
}
