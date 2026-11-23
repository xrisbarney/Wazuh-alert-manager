import { TARGET_WAZUH_MAJOR, TARGET_WAZUH_VERSION } from '../../common';
import type {
  AssetContextFamilyStatus,
  AssetContextResponse,
  AssetContextTopCve,
} from '../../common';
import { NativeCountResult, NativeSearchResult, searchNative } from './native_read';

/**
 * Asset context chips (step 6.4b): a handful of read-only summaries from the
 * native `wazuh-states-*` families for one agent, read through
 * `native_read.ts` as the signed-in user. Nothing here writes, nothing here
 * builds inventory tables; the Wazuh apps keep that job and the response
 * carries deep links to them.
 *
 * Both Wazuh lines share the WCS data fields (`host.os.*`, `network.ip`,
 * `interface.state`, `vulnerability.*`, `check.*`); they differ in the index
 * names (4.14 `wazuh-states-<family>-<cluster.name>`, 5.0 bare names, so every
 * pattern is a trailing wildcard) and in the identity field (4.14 root
 * `agent.id`, 5.0 `wazuh.agent.id`). `FIELD_MAPS` holds one map per line,
 * selected by the build target; the other line's identity field is tried as a
 * fallback when the primary finds nothing, so a build pointed at the wrong
 * line still answers. SCA has no state index on 4.x and is reported
 * `not_available` there without a query.
 *
 * Every family runs in parallel under one overall budget; a slow family comes
 * back as `error` (`timeout`) without delaying the others, and a thrown
 * client error maps to `error` with its message so the flyout never fails on
 * it. Results are cached in memory per user + agent for `CACHE_TTL_MS`;
 * a response in which any family is `error` is not cached, so a transient
 * blip is retried on the next flyout open instead of pinned for a minute.
 */

export const ASSET_CONTEXT_BUDGET_MS = 5000;
export const ASSET_CONTEXT_CACHE_TTL_MS = 60 * 1000;
export const ASSET_CONTEXT_MAX_IPS = 8;
export const ASSET_CONTEXT_TOP_CVES = 3;
/** Cache entries are bounded; the oldest is evicted past this size. */
export const ASSET_CONTEXT_CACHE_MAX_ENTRIES = 500;

export const IT_HYGIENE_APP_PATH = '/app/it-hygiene';
export const VULNERABILITY_DETECTION_APP_PATH = '/app/vulnerability-detection';
/** Wazuh 4.x Configuration Assessment app (app id `configuration-assessment`, verified on 4.14): the only place SCA results are visible on 4.x. */
export const CONFIGURATION_ASSESSMENT_APP_PATH = '/app/configuration-assessment';
export const SCA_NOT_INDEXED_REASON = 'SCA results are not indexed on Wazuh 4.x (the SCA module reads them from the manager API); open Configuration Assessment for this agent';

export type WazuhLine = 4 | 5;

export interface AssetContextFieldMap {
  line: WazuhLine;
  /** Identity fields, primary first; the rest are tried when the primary finds nothing. */
  identityFields: string[];
  /** Agent-name fields (same order), used only when no agent id is known. */
  nameFields: string[];
  patterns: {
    system: string;
    networks: string;
    ports: string;
    vulnerabilities: string;
    /** null = the family does not exist on this line. */
    sca: string | null;
  };
  fields: {
    osName: string;
    osVersion: string;
    osPlatform: string;
    hostname: string;
    ip: string;
    portState: string;
    vulnSeverity: string;
    vulnUnderEvaluation: string;
    vulnId: string;
    vulnScore: string;
    scaResult: string;
    modifiedAt: string;
  };
}

const SHARED_FIELDS: AssetContextFieldMap['fields'] = {
  osName: 'host.os.name',
  osVersion: 'host.os.version',
  osPlatform: 'host.os.platform',
  hostname: 'host.hostname',
  ip: 'network.ip',
  portState: 'interface.state',
  vulnSeverity: 'vulnerability.severity',
  vulnUnderEvaluation: 'vulnerability.under_evaluation',
  vulnId: 'vulnerability.id',
  vulnScore: 'vulnerability.score.base',
  scaResult: 'check.result',
  modifiedAt: 'state.modified_at',
};

export const FIELD_MAPS: Record<WazuhLine, AssetContextFieldMap> = {
  4: {
    line: 4,
    identityFields: ['agent.id', 'wazuh.agent.id'],
    nameFields: ['agent.name', 'wazuh.agent.name'],
    patterns: {
      system: 'wazuh-states-inventory-system*',
      networks: 'wazuh-states-inventory-networks*',
      ports: 'wazuh-states-inventory-ports*',
      vulnerabilities: 'wazuh-states-vulnerabilities*',
      sca: null,
    },
    fields: SHARED_FIELDS,
  },
  5: {
    line: 5,
    identityFields: ['wazuh.agent.id', 'agent.id'],
    nameFields: ['wazuh.agent.name', 'agent.name'],
    patterns: {
      system: 'wazuh-states-inventory-system*',
      networks: 'wazuh-states-inventory-networks*',
      ports: 'wazuh-states-inventory-ports*',
      vulnerabilities: 'wazuh-states-vulnerabilities*',
      sca: 'wazuh-states-sca*',
    },
    fields: SHARED_FIELDS,
  },
};

export function fieldMapForLine(major: unknown = TARGET_WAZUH_MAJOR): AssetContextFieldMap {
  return Number(major) === 5 ? FIELD_MAPS[5] : FIELD_MAPS[4];
}

export interface AssetContextTarget {
  agentId: string | null;
  agentName: string | null;
}

export interface AssetContextBuildTarget {
  major: unknown;
  version: unknown;
}

/**
 * The IT Hygiene app only exists from Wazuh 4.13 (REUSE-STUDY 1.3); a 4.12
 * build must not emit a link that lands on a missing app. 5.0 and any
 * unparseable version keep the link.
 */
export function itHygieneAvailable(target: AssetContextBuildTarget): boolean {
  if (Number(target.major) !== 4) return true;
  const m = /^(\d+)\.(\d+)/.exec(String(target.version ?? ''));
  if (!m) return true;
  return Number(m[1]) > 4 || Number(m[2]) >= 13;
}

const BUILD_TARGET: AssetContextBuildTarget = { major: TARGET_WAZUH_MAJOR, version: TARGET_WAZUH_VERSION };

/**
 * App-relative deep links (the browser prepends `server.basePath`). `itHygiene` is
 * null where the app does not exist; `configurationAssessment` is emitted on the
 * 4.x line only (the app id was verified on 4.14; the 5.0 dashboard indexes SCA
 * results instead, so the chip carries counts there and no link is needed).
 */
export function assetContextLinks(agentId: string | null, target: AssetContextBuildTarget = BUILD_TARGET): AssetContextResponse['links'] {
  const suffix = agentId ? `&agentId=${encodeURIComponent(agentId)}` : '';
  return {
    itHygiene: itHygieneAvailable(target) ? `${IT_HYGIENE_APP_PATH}#/overview/?tab=it-hygiene&tabView=dashboard${suffix}` : null,
    vulnerabilityDetection: `${VULNERABILITY_DETECTION_APP_PATH}#/overview/?tab=vuls&tabView=dashboard${suffix}`,
    configurationAssessment: Number(target.major) === 4 ? `${CONFIGURATION_ASSESSMENT_APP_PATH}#/overview/?tab=sca&tabView=inventory${suffix}` : null,
  };
}

/** Identity clauses in fallback order: `[field, value]` pairs the queries try one after the other. */
export function identityCandidates(map: AssetContextFieldMap, target: AssetContextTarget): Array<[string, string]> {
  if (target.agentId) return map.identityFields.map((field) => [field, target.agentId as string]);
  if (target.agentName) return map.nameFields.map((field) => [field, target.agentName as string]);
  return [];
}

type FamilyOutcome<T> = { status: AssetContextFamilyStatus; reason?: string } & Partial<T>;

function statusOf(result: NativeSearchResult<any> | NativeCountResult): AssetContextFamilyStatus {
  return result.status;
}

/**
 * Run `query(field, value)` for each identity candidate in turn; a result
 * that is `ok` with hits/total wins, as does any non-`ok` status (no point
 * retrying a 403/404 with another field). An `ok` with nothing falls through
 * to the next candidate and is returned last.
 */
async function withIdentityFallback<R extends NativeSearchResult<any> | NativeCountResult>(
  candidates: Array<[string, string]>,
  query: (field: string, value: string) => Promise<R>
): Promise<R> {
  let last: R | null = null;
  for (const [field, value] of candidates) {
    const result = await query(field, value);
    if (result.status !== 'ok') return result;
    if (result.total > 0) return result;
    last = result;
  }
  if (!last) throw new Error('No agent identity to query asset context for.');
  return last;
}

function str(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
}

function get(source: any, path: string): unknown {
  let cur = source;
  for (const part of path.split('.')) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[part];
  }
  return cur;
}

function termFilter(field: string, value: string) {
  return { term: { [field]: value } };
}

async function readSystem(client: any, map: AssetContextFieldMap, candidates: Array<[string, string]>) {
  const f = map.fields;
  const result = await withIdentityFallback(candidates, (field, value) =>
    searchNative<any>(client, {
      indexPattern: map.patterns.system,
      purpose: 'Asset context (system inventory)',
      body: {
        size: 1,
        _source: [f.osName, f.osVersion, f.osPlatform, f.hostname, f.modifiedAt],
        query: { bool: { filter: [termFilter(field, value)] } },
      },
    })
  );
  if (result.status !== 'ok') return { status: statusOf(result) };
  const source = result.hits[0]?._source || {};
  const name = str(get(source, f.osName));
  const version = str(get(source, f.osVersion));
  return {
    status: 'ok' as const,
    os: name || version ? { name, version, platform: str(get(source, f.osPlatform)) } : null,
    hostname: str(get(source, f.hostname)),
  };
}

async function readNetworks(client: any, map: AssetContextFieldMap, candidates: Array<[string, string]>) {
  const f = map.fields;
  const result = await withIdentityFallback(candidates, (field, value) =>
    searchNative<any>(client, {
      indexPattern: map.patterns.networks,
      purpose: 'Asset context (network addresses)',
      body: {
        size: 0,
        query: { bool: { filter: [termFilter(field, value)] } },
        aggs: { ips: { terms: { field: f.ip, size: ASSET_CONTEXT_MAX_IPS } } },
      },
    })
  );
  if (result.status !== 'ok') return { status: statusOf(result) };
  const buckets: any[] = (result.aggregations as any)?.ips?.buckets || [];
  const ips = buckets.map((b) => str(b?.key_as_string ?? b?.key)).filter((v): v is string => !!v);
  return { status: 'ok' as const, ips, total: result.total };
}

async function readPorts(client: any, map: AssetContextFieldMap, candidates: Array<[string, string]>) {
  const f = map.fields;
  const result = await withIdentityFallback(candidates, (field, value) =>
    searchNative<any>(client, {
      indexPattern: map.patterns.ports,
      purpose: 'Asset context (open ports)',
      body: {
        size: 0,
        track_total_hits: true,
        query: { bool: { filter: [termFilter(field, value)] } },
        aggs: { listening: { filter: { term: { [f.portState]: 'listening' } } } },
      },
    })
  );
  if (result.status !== 'ok') return { status: statusOf(result) };
  const listening = Number((result.aggregations as any)?.listening?.doc_count);
  return { status: 'ok' as const, open: result.total, listening: Number.isFinite(listening) ? listening : 0 };
}

function severityCount(buckets: any[], wanted: string): number {
  const bucket = buckets.find((b) => String(b?.key || '').toLowerCase() === wanted);
  const count = Number(bucket?.doc_count);
  return Number.isFinite(count) ? count : 0;
}

async function readVulnerabilities(client: any, map: AssetContextFieldMap, candidates: Array<[string, string]>) {
  const f = map.fields;
  const result = await withIdentityFallback(candidates, (field, value) =>
    searchNative<any>(client, {
      indexPattern: map.patterns.vulnerabilities,
      purpose: 'Asset context (vulnerabilities)',
      body: {
        size: ASSET_CONTEXT_TOP_CVES,
        track_total_hits: true,
        _source: [f.vulnId, f.vulnSeverity, f.vulnScore],
        sort: [{ [f.vulnScore]: { order: 'desc', missing: '_last', unmapped_type: 'float' } }],
        query: {
          bool: {
            filter: [termFilter(field, value)],
            // Under-evaluation entries are CVEs the scanner has not scored yet; the Wazuh app hides them too.
            must_not: [{ term: { [f.vulnUnderEvaluation]: true } }],
          },
        },
        aggs: { severity: { terms: { field: f.vulnSeverity, size: 10 } } },
      },
    })
  );
  if (result.status !== 'ok') return { status: statusOf(result) };
  const buckets: any[] = (result.aggregations as any)?.severity?.buckets || [];
  const topCves: AssetContextTopCve[] = result.hits
    .map((hit) => {
      const id = str(get(hit._source, f.vulnId));
      if (!id) return null;
      const score = Number(get(hit._source, f.vulnScore));
      return { id, severity: str(get(hit._source, f.vulnSeverity)), score: Number.isFinite(score) ? score : null };
    })
    .filter((v): v is AssetContextTopCve => !!v);
  return {
    status: 'ok' as const,
    total: result.total,
    critical: severityCount(buckets, 'critical'),
    high: severityCount(buckets, 'high'),
    medium: severityCount(buckets, 'medium'),
    low: severityCount(buckets, 'low'),
    topCves,
  };
}

async function readSca(client: any, map: AssetContextFieldMap, candidates: Array<[string, string]>) {
  const pattern = map.patterns.sca;
  if (!pattern) return { status: 'not_available' as const, reason: SCA_NOT_INDEXED_REASON };
  const f = map.fields;
  const result = await withIdentityFallback(candidates, (field, value) =>
    searchNative<any>(client, {
      indexPattern: pattern,
      purpose: 'Asset context (SCA)',
      body: {
        size: 0,
        track_total_hits: true,
        query: { bool: { filter: [termFilter(field, value)] } },
        aggs: { result: { terms: { field: f.scaResult, size: 10 } } },
      },
    })
  );
  if (result.status !== 'ok') return { status: statusOf(result) };
  const buckets: any[] = (result.aggregations as any)?.result?.buckets || [];
  return {
    status: 'ok' as const,
    total: result.total,
    failed: severityCount(buckets, 'failed'),
    passed: severityCount(buckets, 'passed'),
  };
}

type FamilyName = keyof AssetContextResponse['families'];

function errorOutcome(reason: string): { status: 'error'; reason: string } {
  return { status: 'error', reason };
}

/**
 * Run every family under one deadline. `allSettled` keeps a thrown client
 * error local to its family; the shared timer turns anything still pending
 * at the budget into `error: timeout` without waiting for it.
 */
export async function readAssetContextFamilies(
  client: any,
  target: AssetContextTarget,
  options: { map?: AssetContextFieldMap; budgetMs?: number } = {}
): Promise<AssetContextResponse['families']> {
  const map = options.map || fieldMapForLine();
  const budgetMs = options.budgetMs ?? ASSET_CONTEXT_BUDGET_MS;
  const candidates = identityCandidates(map, target);
  if (!candidates.length) throw new Error('An agent id or agent name is required.');

  let timer: NodeJS.Timeout | null = null;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), budgetMs);
  });
  const race = <T>(p: Promise<T>): Promise<T> => Promise.race([p, deadline]);

  const readers: Record<FamilyName, () => Promise<any>> = {
    system: () => readSystem(client, map, candidates),
    networks: () => readNetworks(client, map, candidates),
    ports: () => readPorts(client, map, candidates),
    vulnerabilities: () => readVulnerabilities(client, map, candidates),
    sca: () => readSca(client, map, candidates),
  };
  const names = Object.keys(readers) as FamilyName[];
  try {
    const settled = await Promise.allSettled(names.map((name) => race(readers[name]())));
    const families: Record<string, FamilyOutcome<any>> = {};
    names.forEach((name, i) => {
      const outcome = settled[i];
      families[name] =
        outcome.status === 'fulfilled'
          ? outcome.value
          : errorOutcome(outcome.reason?.message === 'timeout' ? 'timeout' : String(outcome.reason?.message || outcome.reason || 'error'));
    });
    return families as AssetContextResponse['families'];
  } finally {
    if (timer) clearTimeout(timer);
    // Nothing else awaits the deadline once we leave; keep a rejected timer from surfacing as unhandled.
    deadline.catch(() => undefined);
  }
}

interface CacheEntry {
  expiresAt: number;
  value: AssetContextResponse;
}

const cache = new Map<string, CacheEntry>();

export function cacheKey(user: string, map: AssetContextFieldMap, target: AssetContextTarget): string {
  return [user, map.line, target.agentId ? `id:${target.agentId}` : `name:${target.agentName}`].join('|');
}

/** Test hook: drop every cached entry. */
export function clearAssetContextCache(): void {
  cache.clear();
}

function remember(key: string, value: AssetContextResponse, now: number): void {
  if (cache.size >= ASSET_CONTEXT_CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, { value, expiresAt: now + ASSET_CONTEXT_CACHE_TTL_MS });
}

export function hasErrorFamily(families: AssetContextResponse['families']): boolean {
  return Object.values(families).some((f) => f.status === 'error');
}

/**
 * The route's entry point: cached per user + line + agent for 60 s. The cache
 * is keyed by user because a `no_access` answer for one analyst must never be
 * served to an administrator (and the other way round). `cache: false`
 * bypasses the cache entirely: the route passes it when the user could not be
 * named by the security plugin, so anonymous fallbacks never share a slot.
 * A response with an `error` family (timeout, connection error) is never
 * stored, so the next call retries.
 */
export async function getAssetContext(
  client: any,
  user: string,
  target: AssetContextTarget,
  options: { map?: AssetContextFieldMap; budgetMs?: number; now?: () => number; cache?: boolean } = {}
): Promise<AssetContextResponse> {
  const map = options.map || fieldMapForLine();
  const now = options.now || Date.now;
  const useCache = options.cache !== false;
  const key = cacheKey(user, map, target);
  const hit = useCache ? cache.get(key) : undefined;
  const at = now();
  if (hit && hit.expiresAt > at) return { ...hit.value, cached: true };
  if (hit) cache.delete(key);

  const families = await readAssetContextFamilies(client, target, { map, budgetMs: options.budgetMs });
  const value: AssetContextResponse = {
    agentId: target.agentId,
    agentName: target.agentName,
    line: map.line,
    fetchedAt: new Date(at).toISOString(),
    cached: false,
    families,
    links: assetContextLinks(target.agentId),
  };
  if (useCache && !hasErrorFamily(families)) remember(key, value, at);
  return value;
}
