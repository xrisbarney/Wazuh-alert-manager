import { META_INDEX } from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { encryptSecret, decryptSecret } from './crypto';
import { getEncryptionKey, ENCRYPTION_KEY_ENV_VAR } from './secrets_config';

/**
 * Typed settings documents in the meta index.
 *
 * A settings doc is a single document in META_INDEX (`dynamic: false`, so the
 * fields are stored in `_source` and only ever read back by id). Every doc
 * carries the same envelope as the existing sync/lifecycle/AI settings docs:
 * `updated_at`, `updated_by` and `source: 'workbench'`.
 *
 * Secret fields (API keys, HMAC secrets, ...) follow the precedent set by
 * routes/ai.ts for `ai_settings.apiKey`:
 *
 * - At rest they are AES-256-GCM ciphertext produced by crypto.ts with the key
 *   from the WAZUH_ALERT_MANAGER_ENCRYPTION_KEY environment variable
 *   (secrets_config.ts). An absent secret is stored as ''.
 * - `read()` never returns a secret. Each secret field is removed and a
 *   sibling boolean `<field>Configured` says whether one is stored, e.g.
 *   `{ apiKey: 'xxx' }` reads as `{ apiKeyConfigured: true }` and
 *   `{ sources: [{ apiKey: 'xxx' }, { apiKey: '' }] }` reads as
 *   `{ sources: [{ apiKeyConfigured: true }, { apiKeyConfigured: false }] }`.
 * - `readWithSecrets()` is for server-side callers only (dispatchers,
 *   lookups) and returns the decrypted plaintext.
 * - `write()` merges a patch onto the current document. A secret is replaced
 *   only when the patch carries a non-empty string for it; omitting the field,
 *   sending '' or sending the mask object `{ hasSecret: true }` keeps the
 *   stored ciphertext, and sending `null` clears it. Array elements keep their
 *   secret by matching `id` when both sides have one, otherwise by position.
 *
 * Secret paths are dotted and use `[]` to step into an array:
 * `'apiKey'`, `'webhook.secret'`, `'sources[].apiKey'`.
 */

export const SECRET_MASK = { hasSecret: true } as const;
export type SecretMask = typeof SECRET_MASK;

/** Suffix appended to a secret field's name for its `read()` presence flag. */
export const SECRET_CONFIGURED_SUFFIX = 'Configured';

export interface SettingsEnvelope {
  updated_at?: string;
  updated_by?: string;
  source?: string;
}

export interface TypedError extends Error {
  statusCode: number;
}

export interface SettingsDocDefinition<T extends object> {
  /** Document id inside META_INDEX, e.g. 'enrichment_settings'. */
  docId: string;
  /** Shape returned when nothing is stored yet; also fills missing top-level keys. */
  defaults: T;
  /** Dotted secret paths (`[]` steps into arrays): 'apiKey', 'sources[].apiKey'. */
  secretFields?: ReadonlyArray<Extract<keyof T, string> | string>;
  /**
   * Normalises/validates the merged document on write. It receives the
   * document WITHOUT its secret fields (they are re-attached afterwards) and
   * may throw a `TypedError` (statusCode 400) to reject the patch.
   */
  validate?: (value: T) => T;
}

export interface WriteOptions {
  /** Trusted identity name recorded as `updated_by`. */
  actor: string;
}

/**
 * The masked read shape: `T` with every secret field absent and a
 * `<field>Configured` boolean beside it, plus the envelope. The sibling flags
 * cannot be expressed per dotted path in the type system, so they are typed
 * loosely; consumers that want them typed can declare them optional on `T`.
 */
export type MaskedSettings<T> = T & SettingsEnvelope & { [configuredFlag: string]: unknown };

export interface SettingsDoc<T extends object> {
  docId: string;
  secretFields: string[];
  /** Secrets removed, `<field>Configured` flags added. Safe to send to the browser. */
  read(client: any): Promise<MaskedSettings<T>>;
  /** Decrypted secrets in place. Server-side only; never return this from a route. */
  readWithSecrets(client: any): Promise<T & SettingsEnvelope>;
  /** Merge `patch` onto the stored document, encrypt new secrets, persist, return the masked result. */
  write(client: any, patch: Partial<T> | Record<string, unknown>, options: WriteOptions): Promise<MaskedSettings<T>>;
}

export function typedError(message: string, statusCode: number): TypedError {
  const error = new Error(message) as TypedError;
  error.statusCode = statusCode;
  return error;
}

export function isSecretMask(value: unknown): value is SecretMask {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (value as any).hasSecret === true &&
    Object.keys(value as object).length === 1
  );
}

export function missingEncryptionKeyError(): TypedError {
  return typedError(
    `Set the ${ENCRYPTION_KEY_ENV_VAR} environment variable (32+ characters) for the wazuh-dashboard ` +
      'service and restart it before storing a secret. This key is used to encrypt secrets at rest.',
    400
  );
}

interface PathSegment {
  key: string;
  array: boolean;
}

export function parseSecretPath(path: string): PathSegment[] {
  if (!path || typeof path !== 'string') {
    throw new Error(`Invalid secret path: ${String(path)}`);
  }
  const segments = path.split('.').map((part) => {
    const match = /^([^\[\]\.]+)(\[\])?$/.exec(part);
    if (!match) throw new Error(`Invalid secret path segment "${part}" in "${path}"`);
    return { key: match[1], array: Boolean(match[2]) };
  });
  if (segments[segments.length - 1].array) {
    throw new Error(`Secret path "${path}" must end with a field name, not "[]".`);
  }
  return segments;
}

function isPlainObject(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value);
}

/** Plain objects merge recursively; arrays and scalars from `patch` replace. */
export function deepMerge<T>(base: T, patch: unknown): T {
  if (!isPlainObject(base) || !isPlainObject(patch)) {
    return (patch === undefined ? base : patch) as T;
  }
  const out: Record<string, any> = { ...base };
  for (const key of Object.keys(patch)) {
    const value = patch[key];
    if (value === undefined) continue;
    out[key] = isPlainObject(out[key]) && isPlainObject(value) ? deepMerge(out[key], value) : value;
  }
  return out as T;
}

interface SecretSite {
  /** Object that directly holds the secret field. */
  parent: Record<string, any>;
  /** Field name of the secret inside `parent`. */
  key: string;
  /** Array trail used to find the same site in another document. */
  trail: Array<{ key: string; index: number; id?: string }>;
}

/**
 * Every concrete location of `segments` inside `root`, expanding `[]` over
 * array elements. Parents that are absent or not objects are skipped.
 */
function collectSites(root: unknown, segments: PathSegment[]): SecretSite[] {
  const sites: SecretSite[] = [];
  const visit = (node: unknown, depth: number, trail: SecretSite['trail']) => {
    if (!isPlainObject(node)) return;
    const segment = segments[depth];
    if (depth === segments.length - 1) {
      sites.push({ parent: node, key: segment.key, trail });
      return;
    }
    const child = node[segment.key];
    if (segment.array) {
      if (!Array.isArray(child)) return;
      child.forEach((element, index) => {
        const id = isPlainObject(element) && typeof element.id === 'string' ? element.id : undefined;
        visit(element, depth + 1, [...trail, { key: segment.key, index, id }]);
      });
      return;
    }
    visit(child, depth + 1, trail);
  };
  visit(root, 0, []);
  return sites;
}

/** Follow a site's trail into another document and return its stored value. */
function counterpartValue(root: unknown, segments: PathSegment[], site: SecretSite): unknown {
  let node: any = root;
  let trailIndex = 0;
  for (let depth = 0; depth < segments.length; depth += 1) {
    if (!isPlainObject(node)) return undefined;
    const segment = segments[depth];
    if (depth === segments.length - 1) return node[segment.key];
    const child = node[segment.key];
    if (segment.array) {
      if (!Array.isArray(child)) return undefined;
      const step = site.trail[trailIndex++];
      if (!step) return undefined;
      // Match by id when the patched element carries one, else by position.
      node = step.id !== undefined ? child.find((e: any) => isPlainObject(e) && e.id === step.id) : child[step.index];
      continue;
    }
    node = child;
  }
  return undefined;
}

function configuredFlag(key: string): string {
  return `${key}${SECRET_CONFIGURED_SUFFIX}`;
}

function clone<T>(value: T): T {
  return value === undefined ? value : JSON.parse(JSON.stringify(value));
}

async function loadSource(client: any, docId: string): Promise<Record<string, any> | null> {
  try {
    const res: any = await client.get({ index: META_INDEX, id: docId });
    // Clone so in-place secret decryption never mutates a cached client response.
    return clone(res?.body?._source ?? null);
  } catch (e: any) {
    if (e?.meta?.statusCode === 404 || e?.statusCode === 404) return null;
    throw e;
  }
}

export function defineSettingsDoc<T extends object>(definition: SettingsDocDefinition<T>): SettingsDoc<T> {
  const { docId, defaults, validate } = definition;
  const secretPaths = (definition.secretFields ?? []).map((path) => ({
    path: String(path),
    segments: parseSecretPath(String(path)),
  }));

  const stored = async (client: any): Promise<Record<string, any>> => {
    const source = await loadSource(client, docId);
    return deepMerge(clone(defaults) as Record<string, any>, source ?? {});
  };

  const mask = (doc: Record<string, any>): MaskedSettings<T> => {
    const out = clone(doc);
    for (const { segments } of secretPaths) {
      for (const site of collectSites(out, segments)) {
        const value = site.parent[site.key];
        delete site.parent[site.key];
        site.parent[configuredFlag(site.key)] = typeof value === 'string' && value.length > 0;
      }
    }
    return out as MaskedSettings<T>;
  };

  const read = async (client: any): Promise<MaskedSettings<T>> => mask(await stored(client));

  const readWithSecrets = async (client: any): Promise<T & SettingsEnvelope> => {
    const doc = await stored(client);
    const encryptionKey = getEncryptionKey();
    for (const { path, segments } of secretPaths) {
      for (const site of collectSites(doc, segments)) {
        const value = site.parent[site.key];
        if (typeof value !== 'string' || value.length === 0) {
          site.parent[site.key] = '';
          continue;
        }
        if (!encryptionKey) {
          throw typedError(
            `Cannot decrypt the stored secret "${path}" of ${docId}: the ${ENCRYPTION_KEY_ENV_VAR} ` +
              'environment variable is not set for the wazuh-dashboard service.',
            500
          );
        }
        try {
          site.parent[site.key] = decryptSecret(value, encryptionKey);
        } catch (e) {
          throw typedError(
            `Cannot decrypt the stored secret "${path}" of ${docId}. The ${ENCRYPTION_KEY_ENV_VAR} ` +
              'value has changed since it was saved; re-enter the secret in Settings.',
            500
          );
        }
      }
    }
    return doc as T & SettingsEnvelope;
  };

  const write = async (
    client: any,
    patch: Partial<T> | Record<string, unknown>,
    options: WriteOptions
  ): Promise<MaskedSettings<T>> => {
    if (!options || typeof options.actor !== 'string' || !options.actor) {
      throw new Error(`Settings write to ${docId} requires an actor.`);
    }
    const existing = await stored(client);
    const incoming: Record<string, any> = clone(isPlainObject(patch) ? patch : {});

    // Pass 1: encrypt new plaintext secrets inside the patch, and normalise
    // "keep" markers so the merge below cannot mistake them for values. The
    // `<field>Configured` flags a client sends back from read() are output
    // only and are dropped so they never land in the stored document.
    const KEEP = '\u0000keep';
    const encryptionKey = getEncryptionKey();
    for (const { path, segments } of secretPaths) {
      for (const site of collectSites(incoming, segments)) {
        delete site.parent[configuredFlag(site.key)];
        const value = site.parent[site.key];
        if (value === null) {
          site.parent[site.key] = '';
        } else if (value === undefined || value === '' || isSecretMask(value)) {
          site.parent[site.key] = KEEP;
        } else if (typeof value === 'string') {
          if (!encryptionKey) throw missingEncryptionKeyError();
          site.parent[site.key] = encryptSecret(value, encryptionKey);
        } else {
          throw typedError(`Secret "${path}" of ${docId} must be a string.`, 400);
        }
      }
    }

    // Pass 2: merge, then resolve KEEP markers (and array elements that omitted
    // their secret entirely) against the stored document.
    const merged: Record<string, any> = deepMerge(clone(existing), incoming);
    const carried: Array<{ site: SecretSite; value: string }> = [];
    for (const { segments } of secretPaths) {
      for (const site of collectSites(merged, segments)) {
        delete site.parent[configuredFlag(site.key)];
        const value = site.parent[site.key];
        const keep = value === KEEP || value === undefined;
        if (!keep) continue;
        const previous = counterpartValue(existing, segments, site);
        site.parent[site.key] = typeof previous === 'string' ? previous : '';
      }
    }

    // Validation sees the document without secrets; they are re-attached after.
    for (const { segments } of secretPaths) {
      for (const site of collectSites(merged, segments)) {
        carried.push({ site, value: site.parent[site.key] });
        delete site.parent[site.key];
      }
    }
    delete merged.updated_at;
    delete merged.updated_by;
    delete merged.source;
    const validated: Record<string, any> = clone(validate ? validate(merged as T) : merged);
    // Re-attach secrets by their site (array elements matched by id, else position).
    for (const { segments } of secretPaths) {
      for (const site of collectSites(validated, segments)) {
        const match = carried.find((c) => sameSite(c.site, site));
        site.parent[site.key] = match ? match.value : '';
      }
    }

    const body = {
      ...validated,
      updated_at: new Date().toISOString(),
      updated_by: options.actor,
      source: 'workbench',
    };
    await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: docId,
      body,
      refresh: 'wait_for',
    });
    return mask(body);
  };

  return { docId, secretFields: secretPaths.map((s) => s.path), read, readWithSecrets, write };
}

function sameSite(a: SecretSite, b: SecretSite): boolean {
  if (a.key !== b.key || a.trail.length !== b.trail.length) return false;
  return a.trail.every((step, i) => {
    const other = b.trail[i];
    if (step.key !== other.key) return false;
    return step.id !== undefined && other.id !== undefined ? step.id === other.id : step.index === other.index;
  });
}
