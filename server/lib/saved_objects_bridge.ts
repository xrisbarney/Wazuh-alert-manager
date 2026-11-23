import type { Logger } from '../../../../src/core/server';
import {
  ALERTS_READ_ALIAS,
  CASES_READ_ALIAS,
  META_INDEX,
  SavedObjectsBridgeStatus,
  WAM_ALERTS_INDEX_PATTERN_ID,
  WAM_CASES_INDEX_PATTERN_ID,
  WAM_OPEN_ALERTS_COLUMNS,
  WAM_OPEN_ALERTS_QUERY,
  WAM_OPEN_ALERTS_SEARCH_ID,
  WAM_OPEN_CASES_COLUMNS,
  WAM_OPEN_CASES_QUERY,
  WAM_OPEN_CASES_SEARCH_ID,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { MAPPING_VERSION } from './provision';

/**
 * Discover/Reporting bridge (step 5.6).
 *
 * At plugin start the server upserts two index patterns (`wam-alerts` over
 * the alert read alias, `wam-cases` over the case read alias) and two saved
 * searches (open alerts, open cases) with FIXED saved-object ids through
 * `core.savedObjects.createInternalRepository()`, so Discover and the
 * OpenSearch Reporting plugin can work on the plugin's own indices without
 * any analyst creating patterns by hand.
 *
 * Why the raw repository and not `IndexPatternsService.createAndSave`: the
 * server-side index-pattern service resolves fields through the browser API
 * client and throws (REUSE-STUDY 5.1b). Reporting only needs a `fields`
 * attribute to exist; `'[]'` is sufficient and Discover refreshes the field
 * list itself.
 *
 * Boundaries:
 * - The internal repository writes to the global tenant (`.kibana`). Under
 *   the security plugin's multi-tenancy, users in a private tenant will not
 *   see the objects; this is documented, not worked around.
 * - A default index pattern is never set.
 * - The version record lives in the plugin's meta index (doc
 *   `saved_objects_bridge`), not in the saved objects: the `search` type's
 *   mapping is strict, so an unknown attribute would be refused. Objects are
 *   rewritten only when the recorded version differs from
 *   SAVED_OBJECTS_BRIDGE_VERSION or an object is missing; nothing is touched
 *   otherwise, so analysts' own edits survive restarts between releases.
 * - "Record absent" (404, meta index missing) means a fresh install and
 *   re-upserts everything. "Record unreadable" (any other error: cluster red,
 *   timeout, 503) must NOT clobber possibly-edited objects: only missing
 *   objects are created, the rest are left alone, and the run reports
 *   `error` so the next start retries.
 * - Any failure is logged at warn, reported through `getSavedObjectsBridgeStatus()`
 *   (surfaced by GET /system/version) and never fails plugin start.
 */
export const SAVED_OBJECTS_BRIDGE_DOC_ID = 'saved_objects_bridge';
/**
 * Bump when the provisioned objects change without a mapping change (e.g. the
 * saved-search columns). Revision 2: columns corrected to fields that exist
 * on the projections (`rule.level`/`severity_label`, `assigned_to`).
 */
export const SAVED_OBJECTS_BRIDGE_REVISION = 2;
/** Version recorded in the meta doc: a mapping bump or a bridge revision bump rewrites the objects. */
export const SAVED_OBJECTS_BRIDGE_VERSION = MAPPING_VERSION * 1000 + SAVED_OBJECTS_BRIDGE_REVISION;
export const INDEX_REF_NAME = 'kibanaSavedObjectMeta.searchSourceJSON.index';

export interface BridgeSavedObject {
  type: 'index-pattern' | 'search';
  id: string;
  attributes: Record<string, unknown>;
  references: Array<{ name: string; type: string; id: string }>;
}

/** The subset of ISavedObjectsRepository the bridge uses (keeps tests free of core types). */
export interface SavedObjectsRepositoryLike {
  get(type: string, id: string): Promise<{ id: string; type: string; attributes?: unknown }>;
  create(
    type: string,
    attributes: Record<string, unknown>,
    options?: { id?: string; overwrite?: boolean; references?: Array<{ name: string; type: string; id: string }> }
  ): Promise<unknown>;
}

export interface SavedObjectsBridgeDocument {
  document_type: 'saved_objects_bridge';
  version: number;
  updated_at: string;
  objects: Record<string, 'created' | 'updated' | 'unchanged'>;
}

function searchSourceJson(query: string): string {
  return JSON.stringify({
    query: { query, language: 'kuery' },
    filter: [],
    highlightAll: true,
    version: true,
    indexRefName: INDEX_REF_NAME,
  });
}

/** The four objects, in dependency order (patterns before the searches that reference them). */
export function bridgeSavedObjects(): BridgeSavedObject[] {
  return [
    {
      type: 'index-pattern',
      id: WAM_ALERTS_INDEX_PATTERN_ID,
      attributes: { title: ALERTS_READ_ALIAS, timeFieldName: '@timestamp', fields: '[]' },
      references: [],
    },
    {
      type: 'index-pattern',
      id: WAM_CASES_INDEX_PATTERN_ID,
      attributes: { title: CASES_READ_ALIAS, timeFieldName: 'created_at', fields: '[]' },
      references: [],
    },
    {
      type: 'search',
      id: WAM_OPEN_ALERTS_SEARCH_ID,
      attributes: {
        title: 'WAM open alerts',
        description: 'Wazuh Alert Manager: alerts that are open or in progress (provisioned by the plugin).',
        columns: [...WAM_OPEN_ALERTS_COLUMNS],
        sort: [['@timestamp', 'desc']],
        hits: 0,
        version: 1,
        kibanaSavedObjectMeta: { searchSourceJSON: searchSourceJson(WAM_OPEN_ALERTS_QUERY) },
      },
      references: [{ name: INDEX_REF_NAME, type: 'index-pattern', id: WAM_ALERTS_INDEX_PATTERN_ID }],
    },
    {
      type: 'search',
      id: WAM_OPEN_CASES_SEARCH_ID,
      attributes: {
        title: 'WAM open cases',
        description: 'Wazuh Alert Manager: cases that are open or in progress (provisioned by the plugin).',
        columns: [...WAM_OPEN_CASES_COLUMNS],
        sort: [['created_at', 'desc']],
        hits: 0,
        version: 1,
        kibanaSavedObjectMeta: { searchSourceJSON: searchSourceJson(WAM_OPEN_CASES_QUERY) },
      },
      references: [{ name: INDEX_REF_NAME, type: 'index-pattern', id: WAM_CASES_INDEX_PATTERN_ID }],
    },
  ];
}

function isNotFound(error: any): boolean {
  const status = error?.output?.statusCode ?? error?.statusCode ?? error?.meta?.statusCode;
  return status === 404;
}

function errorMessage(error: any): string {
  return String(error?.output?.payload?.message || error?.message || error || 'unknown error');
}

const INITIAL_STATUS: SavedObjectsBridgeStatus = {
  indexPatterns: 'skipped',
  message: 'The Discover/Reporting bridge has not run on this replica yet.',
  version: null,
  checkedAt: null,
  objects: {},
};

let currentStatus: SavedObjectsBridgeStatus = INITIAL_STATUS;

/** Last outcome on this replica (each dashboard replica runs the bridge itself; the result is idempotent). */
export function getSavedObjectsBridgeStatus(): SavedObjectsBridgeStatus {
  return currentStatus;
}

export function setSavedObjectsBridgeStatus(status: SavedObjectsBridgeStatus): void {
  currentStatus = status;
}

export function resetSavedObjectsBridgeStatus(): void {
  currentStatus = INITIAL_STATUS;
}

const GENERIC_MESSAGE: Record<SavedObjectsBridgeStatus['indexPatterns'], string> = {
  ok: 'Index patterns wam-alerts and wam-cases and the two saved searches are provisioned in the global tenant.',
  skipped: 'The Discover/Reporting bridge did not provision index patterns on this replica.',
  error: 'The Discover/Reporting bridge could not provision all index patterns on this replica; a plugin administrator can see the details here or in the dashboard logs.',
};

/**
 * The status as shown to a caller who is not a plugin administrator: the
 * detailed `message` embeds raw OpenSearch/Boom text from the internal
 * repository and the meta index (internal-user permission errors, index
 * names), so only the state, version and timestamp are exposed.
 */
export function redactSavedObjectsBridgeStatus(status: SavedObjectsBridgeStatus): SavedObjectsBridgeStatus {
  return {
    indexPatterns: status.indexPatterns,
    message: GENERIC_MESSAGE[status.indexPatterns] || GENERIC_MESSAGE.error,
    version: status.version,
    checkedAt: status.checkedAt,
    objects: {},
  };
}

async function readBridgeDocument(client: any): Promise<SavedObjectsBridgeDocument | null> {
  try {
    const res = await client.get({ index: META_INDEX, id: SAVED_OBJECTS_BRIDGE_DOC_ID });
    const source = res?.body?._source;
    return source && source.document_type === 'saved_objects_bridge' ? (source as SavedObjectsBridgeDocument) : null;
  } catch (e: any) {
    if (isNotFound(e)) return null;
    throw e;
  }
}

export interface EnsureSavedObjectsBridgeOptions {
  version?: number;
  now?: () => Date;
}

/**
 * Upsert the bridge objects. Resolves (never rejects) with the status; the
 * caller decides whether to publish it through `setSavedObjectsBridgeStatus`.
 */
export async function ensureSavedObjectsBridge(
  client: any,
  repository: SavedObjectsRepositoryLike,
  logger: Logger,
  options: EnsureSavedObjectsBridgeOptions = {}
): Promise<SavedObjectsBridgeStatus> {
  const version = options.version ?? SAVED_OBJECTS_BRIDGE_VERSION;
  const now = options.now || (() => new Date());
  const checkedAt = now().toISOString();
  const objects: SavedObjectsBridgeStatus['objects'] = {};
  const errors: string[] = [];

  let stored: SavedObjectsBridgeDocument | null = null;
  // Set when the version record exists but could not be read (not a 404):
  // the recorded version is then unknown, and existing objects may carry
  // analyst edits, so they are left alone rather than overwritten.
  let recordUnreadable: string | null = null;
  try {
    stored = await readBridgeDocument(client);
  } catch (e: any) {
    recordUnreadable = errorMessage(e);
    logger.warn(`wazuhAlertManager: saved-objects bridge version record unreadable, existing objects left untouched: ${recordUnreadable}`);
  }
  const versionCurrent = stored?.version === version;

  for (const object of bridgeSavedObjects()) {
    try {
      let exists = true;
      try {
        await repository.get(object.type, object.id);
      } catch (e: any) {
        if (!isNotFound(e)) throw e;
        exists = false;
      }
      if (exists && (versionCurrent || recordUnreadable)) {
        objects[object.id] = 'unchanged';
        continue;
      }
      await repository.create(object.type, object.attributes, {
        id: object.id,
        overwrite: true,
        references: object.references,
      });
      objects[object.id] = exists ? 'updated' : 'created';
    } catch (e: any) {
      objects[object.id] = 'error';
      const message = `${object.type}/${object.id}: ${errorMessage(e)}`;
      errors.push(message);
      logger.warn(`wazuhAlertManager: saved-objects bridge could not upsert ${message}`);
    }
  }

  const changed = Object.values(objects).some((outcome) => outcome === 'created' || outcome === 'updated');
  if (recordUnreadable) {
    // The version is not advanced: nothing was verified against it, and the
    // meta index is the thing that just failed. The next start retries.
    errors.push(`version record ${META_INDEX}/${SAVED_OBJECTS_BRIDGE_DOC_ID} unreadable: ${recordUnreadable}`);
  } else if (!errors.length && (changed || !versionCurrent)) {
    try {
      const document: SavedObjectsBridgeDocument = {
        document_type: 'saved_objects_bridge',
        version,
        updated_at: checkedAt,
        objects: objects as SavedObjectsBridgeDocument['objects'],
      };
      await client.index({
        index: assertManagedWriteTarget(META_INDEX),
        id: SAVED_OBJECTS_BRIDGE_DOC_ID,
        body: document,
        refresh: false,
      });
    } catch (e: any) {
      const message = `version record ${META_INDEX}/${SAVED_OBJECTS_BRIDGE_DOC_ID}: ${errorMessage(e)}`;
      errors.push(message);
      logger.warn(`wazuhAlertManager: saved-objects bridge could not write its ${message}`);
    }
  }

  if (errors.length) {
    return {
      indexPatterns: 'error',
      message:
        `Discover/Reporting bridge failed (${errors.length} problem(s)): ${errors.join('; ')}. ` +
        'Index patterns wam-alerts/wam-cases may be missing or outdated in Discover; the plugin keeps running and retries on the next start.',
      version: stored?.version ?? null,
      checkedAt,
      objects,
    };
  }

  const created = Object.values(objects).filter((o) => o === 'created').length;
  const updated = Object.values(objects).filter((o) => o === 'updated').length;
  const summary = changed
    ? `created ${created}, updated ${updated}, unchanged ${Object.values(objects).length - created - updated}`
    : 'all current';
  const result: SavedObjectsBridgeStatus = {
    indexPatterns: 'ok',
    message: `Index patterns wam-alerts and wam-cases and saved searches wam-open-alerts and wam-open-cases are provisioned in the global tenant (bridge version ${version}: ${summary}).`,
    version,
    checkedAt,
    objects,
  };
  if (changed) logger.info(`wazuhAlertManager: ${result.message}`);
  return result;
}

export interface SavedObjectsCoreLike {
  savedObjects?: { createInternalRepository?: (includedHiddenTypes?: string[]) => SavedObjectsRepositoryLike };
}

/**
 * Plugin-start entry point: obtains the internal repository, runs the upsert
 * and publishes the outcome. Never throws.
 */
export async function runSavedObjectsBridge(core: SavedObjectsCoreLike, client: any, logger: Logger): Promise<SavedObjectsBridgeStatus> {
  let status: SavedObjectsBridgeStatus;
  const factory = core?.savedObjects?.createInternalRepository;
  if (typeof factory !== 'function') {
    status = {
      indexPatterns: 'skipped',
      message: 'The dashboard core did not expose an internal saved-objects repository; index patterns were not provisioned.',
      version: null,
      checkedAt: new Date().toISOString(),
      objects: {},
    };
    logger.warn(`wazuhAlertManager: ${status.message}`);
  } else {
    try {
      const repository = factory.call(core.savedObjects);
      status = await ensureSavedObjectsBridge(client, repository, logger);
    } catch (e: any) {
      status = {
        indexPatterns: 'error',
        message: `Discover/Reporting bridge failed: ${errorMessage(e)}. The plugin keeps running.`,
        version: null,
        checkedAt: new Date().toISOString(),
        objects: {},
      };
      logger.warn(`wazuhAlertManager: ${status.message}`);
    }
  }
  setSavedObjectsBridgeStatus(status);
  return status;
}
