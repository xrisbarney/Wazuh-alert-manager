import { META_INDEX, TARGET_WAZUH_MAJOR, TARGET_WAZUH_VERSION, TARGET_OSD_VERSION } from '../../common';
import { AlertManagerConfigType, SourceMode } from '../config';
import { assertManagedWriteTarget, assertSafeSourcePattern } from './index_namespace';
import { SourceFamily, WazuhSourceProfile, sourceProfile } from './source_profile';

export const SOURCE_STATE_DOC_ID = 'source_state';

export type SourceStatus =
  /** Pattern resolves to native storage with the expected shape; sync may run. */
  | 'ready'
  /** Eligible family and valid pattern, but nothing matches yet (fresh install). */
  | 'waiting'
  /** Configuration or build cannot be honoured safely; sync stays stopped. */
  | 'blocked';

export interface BuildTarget {
  wazuhMajor: number;
  wazuhVersion: string;
  osdVersion: string;
}

export interface SourceResolution {
  status: SourceStatus;
  family: SourceFamily | null;
  profile: WazuhSourceProfile | null;
  pattern: string | null;
  mode: SourceMode;
  eligible: SourceFamily[];
  reason: string;
  checkedAt: string;
  build: BuildTarget;
  probe?: { indices: number; dataStreams: number; aliases: number; timestampMapped: boolean | null };
}

export const CURRENT_BUILD: BuildTarget = {
  wazuhMajor: TARGET_WAZUH_MAJOR,
  wazuhVersion: TARGET_WAZUH_VERSION,
  osdVersion: TARGET_OSD_VERSION,
};

/** Families a build is allowed to read. A build never reads outside this set. */
export function eligibleFamilies(build: BuildTarget = CURRENT_BUILD): SourceFamily[] {
  if (build.wazuhMajor === 4) return ['wazuh4_alerts'];
  if (build.wazuhMajor === 5) return ['wazuh5_findings'];
  return [];
}

function selectFamily(mode: SourceMode, eligible: SourceFamily[]): { family: SourceFamily | null; reason: string } {
  if (!eligible.length) {
    return { family: null, reason: 'This build has no eligible Wazuh source family.' };
  }
  if (mode === 'auto') {
    return { family: eligible[0], reason: `auto selected ${eligible[0]} for a Wazuh ${eligible[0] === 'wazuh4_alerts' ? '4.x' : '5.0'} build.` };
  }
  if (!eligible.includes(mode)) {
    return {
      family: null,
      reason: `sourceMode ${mode} is not eligible for this build (eligible: ${eligible.join(', ')}).`,
    };
  }
  return { family: mode, reason: `sourceMode ${mode} configured explicitly.` };
}

interface ProbeResult {
  indices: number;
  dataStreams: number;
  aliases: number;
  timestampMapped: boolean | null;
  error?: string;
}

/**
 * Read-only look at what the pattern resolves to. Uses `_resolve/index` so
 * data streams and plain indices are distinguished, then `field_caps` to
 * confirm the family's timestamp field exists. Clients without these calls
 * (unit-test doubles, exotic transports) are treated as resolvable so the
 * sync path itself remains the final arbiter.
 */
async function probePattern(client: any, pattern: string, profile: WazuhSourceProfile): Promise<ProbeResult> {
  const result: ProbeResult = { indices: 0, dataStreams: 0, aliases: 0, timestampMapped: null };
  if (typeof client?.transport?.request !== 'function') {
    return { ...result, indices: 1 };
  }
  try {
    const res: any = await client.transport.request({
      method: 'GET',
      path: `/_resolve/index/${encodeURIComponent(pattern)}`,
      querystring: { expand_wildcards: 'open' },
    });
    const body = res?.body || {};
    if (!Array.isArray(body.indices) && !Array.isArray(body.data_streams) && !Array.isArray(body.aliases)) {
      // Not a `_resolve/index` response shape (a proxying client or test
      // double). Treat as resolvable; the sync search remains the arbiter.
      return { ...result, indices: 1 };
    }
    result.indices = body.indices.length;
    result.dataStreams = Array.isArray(body.data_streams) ? body.data_streams.length : 0;
    result.aliases = Array.isArray(body.aliases) ? body.aliases.length : 0;
  } catch (e: any) {
    const status = e?.meta?.statusCode || e?.statusCode;
    if (status === 404) return result;
    return { ...result, error: `resolve failed: ${e?.message || e}` };
  }
  if (result.indices + result.dataStreams + result.aliases === 0) return result;
  if (typeof client.fieldCaps === 'function') {
    try {
      const caps: any = await client.fieldCaps({ index: pattern, fields: profile.timestampField });
      const fields = caps?.body?.fields || {};
      result.timestampMapped = Boolean(fields[profile.timestampField]);
    } catch (e: any) {
      result.timestampMapped = null;
    }
  }
  return result;
}

/**
 * Decide, every tick, which native source this build may read and whether
 * it is actually there. Never guesses: an ineligible mode, an off-family
 * pattern, or an unexpected shape blocks sync and says why.
 */
export async function resolveSource(
  client: any,
  config: AlertManagerConfigType,
  build: BuildTarget = CURRENT_BUILD
): Promise<SourceResolution> {
  const checkedAt = new Date().toISOString();
  const mode: SourceMode = (config.sync as any).sourceMode || 'auto';
  const eligible = eligibleFamilies(build);
  const base = { mode, eligible, checkedAt, build };
  const selected = selectFamily(mode, eligible);
  if (!selected.family) {
    return { ...base, status: 'blocked', family: null, profile: null, pattern: null, reason: selected.reason };
  }
  const profile = sourceProfile(selected.family);
  const configured = config.sync.sourceIndexPattern;
  let pattern: string;
  try {
    pattern = assertSafeSourcePattern(configured || profile.defaultPattern, profile);
  } catch (e: any) {
    return {
      ...base,
      status: 'blocked',
      family: selected.family,
      profile,
      pattern: null,
      reason: `sourceIndexPattern rejected for ${selected.family}: ${e.message}`,
    };
  }
  const probe = await probePattern(client, pattern, profile);
  const probeSummary = {
    indices: probe.indices,
    dataStreams: probe.dataStreams,
    aliases: probe.aliases,
    timestampMapped: probe.timestampMapped,
  };
  if (probe.error) {
    return { ...base, status: 'blocked', family: selected.family, profile, pattern, reason: probe.error, probe: probeSummary };
  }
  if (probe.indices + probe.dataStreams + probe.aliases === 0) {
    return {
      ...base,
      status: 'waiting',
      family: selected.family,
      profile,
      pattern,
      reason: `${pattern} matches no index or data stream yet; sync will start when Wazuh creates it.`,
      probe: probeSummary,
    };
  }
  if (selected.family === 'wazuh5_findings' && probe.dataStreams === 0 && probe.indices > 0 && !configured) {
    // The default 5.0 pattern must resolve to data streams. Plain indices
    // under that name would be a different, unexpected layout.
    return {
      ...base,
      status: 'blocked',
      family: selected.family,
      profile,
      pattern,
      reason: `${pattern} resolved to plain indices, not data streams; refusing to guess the 5.0 layout.`,
      probe: probeSummary,
    };
  }
  if (probe.timestampMapped === false) {
    return {
      ...base,
      status: 'blocked',
      family: selected.family,
      profile,
      pattern,
      reason: `${pattern} has no mapped ${profile.timestampField} field; this is not a ${profile.label} source.`,
      probe: probeSummary,
    };
  }
  return {
    ...base,
    status: 'ready',
    family: selected.family,
    profile,
    pattern,
    reason: selected.reason,
    probe: probeSummary,
  };
}

/** Sync cursor document for a family. 4.x keeps the historical id so v2 can roll back. */
export function syncStateDocId(family: SourceFamily): string {
  return family === 'wazuh4_alerts' ? 'sync_state' : `sync_state:${family}`;
}

let lastPersistedSignature: string | null = null;
let lastPersistedAt = 0;
const PERSIST_HEARTBEAT_MS = 5 * 60 * 1000;

export function _resetSourceStateCache() {
  lastPersistedSignature = null;
  lastPersistedAt = 0;
}

/**
 * Record the resolution in the meta index for Storage Health. Written when
 * anything meaningful changes and at least every few minutes as a heartbeat.
 */
export async function persistSourceState(client: any, resolution: SourceResolution): Promise<void> {
  const signature = JSON.stringify([
    resolution.status, resolution.family, resolution.pattern, resolution.mode, resolution.reason, resolution.probe,
  ]);
  const now = Date.now();
  if (signature === lastPersistedSignature && now - lastPersistedAt < PERSIST_HEARTBEAT_MS) return;
  await client.index({
    index: assertManagedWriteTarget(META_INDEX),
    id: SOURCE_STATE_DOC_ID,
    body: {
      document_type: 'source_state',
      status: resolution.status,
      family: resolution.family,
      pattern: resolution.pattern,
      mode: resolution.mode,
      eligible: resolution.eligible,
      reason: resolution.reason,
      probe: resolution.probe || null,
      build: resolution.build,
      sync_state_doc_id: resolution.family ? syncStateDocId(resolution.family) : null,
      checked_at: resolution.checkedAt,
    },
  });
  lastPersistedSignature = signature;
  lastPersistedAt = now;
}
