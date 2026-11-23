import {
  SLA_BANDS,
  SLA_ESCALATION_CONDITIONS,
  SLA_ESCALATION_MAX_NOTIFY,
  SLA_ESCALATION_TARGETS,
  SLA_MAX_ESCALATIONS,
  SLA_MINUTES_MAX,
  SLA_MINUTES_MIN,
  SLA_POLICY_CACHE_TTL_MS,
  SLA_POLICY_DOC_ID,
} from '../../../common/constants';
import type { SlaBand, SlaEscalation, SlaPolicy, SlaTarget } from '../../../common/types';
import { SeverityBand, bandFromLevel } from '../../../common/severity';
import { defineSettingsDoc, typedError, SettingsEnvelope } from '../plugin_settings';
import { DEFAULT_SLA_TARGETS, REPORTING_SLA_POLICY, SLA_BAND_LABELS } from '../reporting_fields';

/**
 * SLA policy settings document (`sla_policy` in META_INDEX, step 3.1).
 *
 * `targets` holds, per numeric severity band, the resolve and first-assign
 * targets in minutes. The defaults are the resolve targets of
 * `REPORTING_SLA_POLICY` (Critical 60 / High 240 / Medium 1440 / Low 4320)
 * with an assign target of 25% of the resolve target, floored at 15 minutes.
 * `escalations[]` is validated here and consumed by the scanner of step 3.3;
 * `notify` channel ids are stored only until phase 1 delivers them.
 *
 * There are no secrets in this document. Readers go through `getSlaPolicy`,
 * which caches the validated policy per process for SLA_POLICY_CACHE_TTL_MS
 * (60 s) and never throws: a missing document is the default policy, and a
 * read or validation failure degrades to the last cached value, else the
 * defaults, so a close/assign/report never fails because of the policy.
 * `PUT /sla/policy` calls `invalidateSlaPolicyCache()` after the write;
 * other dashboard replicas pick the change up within the TTL.
 */

export interface SlaTier {
  band: SlaBand;
  /** Display label, the same string stored in `reporting.sla_tier`. */
  label: string;
  resolveMinutes: number;
  assignMinutes: number;
}

const ESCALATION_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_NAME = 120;
const MAX_ASSIGNEE = 256;
const MAX_COMMENT = 2000;
const MAX_CHANNEL_ID = 128;
const TARGETS = new Set<string>(SLA_ESCALATION_TARGETS);
const CONDITIONS = new Set<string>(SLA_ESCALATION_CONDITIONS);

function buildDefaultPolicy(): SlaPolicy {
  // The one table of built-in targets lives in reporting_fields.ts so the
  // due-date helpers and this policy can never disagree.
  const targets = {} as Record<SlaBand, SlaTarget>;
  for (const band of SLA_BANDS) {
    const tier = REPORTING_SLA_POLICY.find((t) => t.label === SLA_BAND_LABELS[band]);
    const defaults = DEFAULT_SLA_TARGETS[band];
    targets[band] = { resolveMinutes: tier ? tier.targetMinutes : defaults.resolveMinutes, assignMinutes: defaults.assignMinutes };
  }
  return { targets, escalations: [] };
}

/** The built-in policy; `Object.freeze`d shallowly, so always clone before editing. */
export const DEFAULT_SLA_POLICY: SlaPolicy = Object.freeze(buildDefaultPolicy()) as SlaPolicy;

function clonePolicy(policy: SlaPolicy): SlaPolicy {
  return JSON.parse(JSON.stringify(policy));
}

function bad(message: string): never {
  throw typedError(message, 400);
}

function minutes(raw: unknown, label: string): number {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : NaN;
  if (!Number.isFinite(n) || !Number.isInteger(n)) bad(`${label} must be a whole number of minutes.`);
  if (n < SLA_MINUTES_MIN || n > SLA_MINUTES_MAX) {
    bad(`${label} must be between ${SLA_MINUTES_MIN} and ${SLA_MINUTES_MAX} minutes.`);
  }
  return n;
}

function normaliseTargets(raw: unknown): Record<SlaBand, SlaTarget> {
  const input: any = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const out = {} as Record<SlaBand, SlaTarget>;
  for (const band of SLA_BANDS) {
    const entry: any = input[band] && typeof input[band] === 'object' && !Array.isArray(input[band]) ? input[band] : {};
    const defaults = DEFAULT_SLA_POLICY.targets[band];
    const resolveMinutes = entry.resolveMinutes === undefined ? defaults.resolveMinutes : minutes(entry.resolveMinutes, `targets.${band}.resolveMinutes`);
    const assignMinutes = entry.assignMinutes === undefined ? defaults.assignMinutes : minutes(entry.assignMinutes, `targets.${band}.assignMinutes`);
    out[band] = { resolveMinutes, assignMinutes };
  }
  return out;
}

function cleanString(raw: unknown, label: string, max: number, required: boolean): string | undefined {
  if (raw === undefined || raw === null) {
    if (required) bad(`${label} is required.`);
    return undefined;
  }
  if (typeof raw !== 'string') bad(`${label} must be a string.`);
  const value = raw.trim();
  if (!value) {
    if (required) bad(`${label} is required.`);
    return undefined;
  }
  if (value.length > max) bad(`${label} must be at most ${max} characters.`);
  return value;
}

function normaliseEscalation(raw: any, index: number): SlaEscalation {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad(`escalations[${index}] must be an object.`);
  const id = typeof raw.id === 'string' ? raw.id : '';
  if (!ESCALATION_ID.test(id)) bad(`escalations[${index}]: id must be 1-64 lower-case letters, digits, "-" or "_".`);
  const label = `Escalation "${id}"`;
  const name = cleanString(raw.name, `${label}: name`, MAX_NAME, true)!;
  const target = typeof raw.target === 'string' ? raw.target : '';
  if (!TARGETS.has(target)) bad(`${label}: target must be one of ${SLA_ESCALATION_TARGETS.join(', ')}.`);
  const thresholdPercent = typeof raw.thresholdPercent === 'number' ? raw.thresholdPercent : NaN;
  if (!Number.isInteger(thresholdPercent) || thresholdPercent < 1 || thresholdPercent > 100) {
    bad(`${label}: thresholdPercent must be a whole number between 1 and 100.`);
  }
  const condition = typeof raw.condition === 'string' ? raw.condition : '';
  if (!CONDITIONS.has(condition)) bad(`${label}: condition must be one of ${SLA_ESCALATION_CONDITIONS.join(', ')}.`);
  const rawActions: any = raw.actions && typeof raw.actions === 'object' && !Array.isArray(raw.actions) ? raw.actions : {};
  const actions: SlaEscalation['actions'] = {};
  const assignTo = cleanString(rawActions.assignTo, `${label}: actions.assignTo`, MAX_ASSIGNEE, false);
  if (assignTo) actions.assignTo = assignTo;
  if (rawActions.raiseSeverity !== undefined && rawActions.raiseSeverity !== null) {
    if (typeof rawActions.raiseSeverity !== 'boolean') bad(`${label}: actions.raiseSeverity must be a boolean.`);
    if (rawActions.raiseSeverity && target !== 'case') bad(`${label}: actions.raiseSeverity applies to cases only.`);
    if (rawActions.raiseSeverity) actions.raiseSeverity = true;
  }
  const comment = cleanString(rawActions.comment, `${label}: actions.comment`, MAX_COMMENT, false);
  if (comment) actions.comment = comment;
  if (rawActions.notify !== undefined && rawActions.notify !== null) {
    if (!Array.isArray(rawActions.notify)) bad(`${label}: actions.notify must be a list of channel ids.`);
    const notify: string[] = [];
    for (const item of rawActions.notify) {
      const channel = cleanString(item, `${label}: actions.notify`, MAX_CHANNEL_ID, false);
      if (channel && !notify.includes(channel)) notify.push(channel);
    }
    if (notify.length > SLA_ESCALATION_MAX_NOTIFY) bad(`${label}: at most ${SLA_ESCALATION_MAX_NOTIFY} notify channels.`);
    if (notify.length) actions.notify = notify;
  }
  if (!actions.assignTo && !actions.raiseSeverity && !actions.comment && !actions.notify) {
    bad(`${label}: at least one action (assignTo, raiseSeverity, comment, notify) is required.`);
  }
  if (raw.enabled !== undefined && typeof raw.enabled !== 'boolean') bad(`${label}: enabled must be a boolean.`);
  return {
    id,
    name,
    target: target as SlaEscalation['target'],
    thresholdPercent,
    condition: condition as SlaEscalation['condition'],
    actions,
    enabled: raw.enabled !== false,
  };
}

function normaliseEscalations(raw: unknown): SlaEscalation[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) bad('escalations must be a list.');
  if (raw.length > SLA_MAX_ESCALATIONS) bad(`At most ${SLA_MAX_ESCALATIONS} escalations can be configured.`);
  const seen = new Set<string>();
  return raw.map((entry, index) => {
    const escalation = normaliseEscalation(entry, index);
    if (seen.has(escalation.id)) bad(`Escalation id "${escalation.id}" is used more than once.`);
    seen.add(escalation.id);
    return escalation;
  });
}

/** Validate and normalise a policy; missing targets fall back to the defaults. Throws a 400 TypedError. */
export function normaliseSlaPolicy(doc: Partial<SlaPolicy> | Record<string, unknown> | null | undefined): SlaPolicy {
  const input: any = doc && typeof doc === 'object' ? doc : {};
  return { targets: normaliseTargets(input.targets), escalations: normaliseEscalations(input.escalations) };
}

export const slaPolicySettings = defineSettingsDoc<SlaPolicy>({
  docId: SLA_POLICY_DOC_ID,
  defaults: clonePolicy(DEFAULT_SLA_POLICY),
  validate: normaliseSlaPolicy,
});

export interface LoadedSlaPolicy extends SlaPolicy, SettingsEnvelope {}

/** The stored policy, validated with defaults merged in. Throws on a storage failure. */
export async function loadSlaPolicy(client: any): Promise<LoadedSlaPolicy> {
  const doc = await slaPolicySettings.read(client);
  const policy = normaliseSlaPolicy(doc);
  return { ...policy, updated_at: doc.updated_at, updated_by: doc.updated_by };
}

/**
 * Replace the targets and escalations (a full replace: both lists come from
 * the patch, missing target fields fall back to the defaults) and refresh the
 * local cache with the saved document.
 */
export async function saveSlaPolicy(
  client: any,
  patch: Partial<SlaPolicy> | Record<string, unknown>,
  options: { updatedBy: string }
): Promise<LoadedSlaPolicy> {
  const input: any = patch && typeof patch === 'object' ? patch : {};
  const next = normaliseSlaPolicy({ targets: input.targets, escalations: input.escalations ?? [] });
  const saved = await slaPolicySettings.write(client, next, { actor: options.updatedBy });
  const policy = normaliseSlaPolicy(saved);
  invalidateSlaPolicyCache();
  primeSlaPolicyCache(policy);
  return { ...policy, updated_at: saved.updated_at, updated_by: saved.updated_by };
}

interface PolicyCache {
  policy: SlaPolicy;
  expiresAt: number;
}

let cache: PolicyCache | null = null;
let inFlight: Promise<SlaPolicy> | null = null;
/**
 * Bumped by every invalidate/prime. An in-flight read captures it when it
 * starts and only installs its result when nothing changed meanwhile, so a
 * read that overlaps `saveSlaPolicy` cannot overwrite the primed post-save
 * cache with the pre-save document.
 */
let generation = 0;

export interface SlaPolicyLogger {
  warn?(message: string): void;
  debug?(message: string): void;
}

/**
 * The cached policy (60-s TTL per process). Never throws: a read failure
 * logs (when a logger is given) and answers the last cached policy, else the
 * defaults. Concurrent callers share one in-flight read.
 */
export async function getSlaPolicy(client: any, logger?: SlaPolicyLogger): Promise<SlaPolicy> {
  const now = Date.now();
  if (cache && cache.expiresAt > now) return cache.policy;
  if (inFlight) return inFlight;
  const startedAt = generation;
  inFlight = (async () => {
    try {
      const loaded = await loadSlaPolicy(client);
      const policy: SlaPolicy = { targets: loaded.targets, escalations: loaded.escalations };
      if (generation !== startedAt) {
        // A save (or explicit invalidate) happened while this read was in
        // flight: whatever is cached now is newer than what was read.
        return cache ? cache.policy : policy;
      }
      cache = { policy, expiresAt: Date.now() + SLA_POLICY_CACHE_TTL_MS };
      return policy;
    } catch (e: any) {
      const message = `wazuh-alert-manager sla: could not read ${SLA_POLICY_DOC_ID}, using ${cache ? 'the last cached' : 'the default'} policy: ${e?.message || String(e)}`;
      if (logger?.warn) logger.warn(message);
      else logger?.debug?.(message);
      return cache ? cache.policy : clonePolicy(DEFAULT_SLA_POLICY);
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

/** Drop the process-local cache so the next `getSlaPolicy` re-reads the document. */
export function invalidateSlaPolicyCache(): void {
  cache = null;
  generation += 1;
}

/** Seed the cache (after a save, or in tests) without a read. */
export function primeSlaPolicyCache(policy: SlaPolicy, ttlMs: number = SLA_POLICY_CACHE_TTL_MS): void {
  cache = { policy: clonePolicy(policy), expiresAt: Date.now() + ttlMs };
  generation += 1;
}

/** Map any severity band onto an SLA band: `informational` has no numeric range and is treated as `low`. */
export function slaBandOf(band: SeverityBand | SlaBand | null | undefined): SlaBand {
  return band === 'critical' || band === 'high' || band === 'medium' ? band : 'low';
}

/** The tier of a severity band under a policy. */
export function slaTierForBand(policy: SlaPolicy, band: SeverityBand | SlaBand | null | undefined): SlaTier {
  const slaBand = slaBandOf(band);
  const target = policy.targets[slaBand] || DEFAULT_SLA_POLICY.targets[slaBand];
  return { band: slaBand, label: SLA_BAND_LABELS[slaBand], resolveMinutes: target.resolveMinutes, assignMinutes: target.assignMinutes };
}

/**
 * The tier of a numeric level (4.x `rule.level`, or a 5.0 record's
 * `effectiveLevel`) under a policy, through `bandFromLevel` of
 * common/severity.ts so the band boundaries are the plugin's one model.
 */
export function slaTierForLevel(policy: SlaPolicy, level: number | null | undefined): SlaTier {
  return slaTierForBand(policy, bandFromLevel(level));
}
