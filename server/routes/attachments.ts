import { createHash, randomUUID } from 'crypto';
import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  ATTACHMENTS_INDEX,
  ATTACHMENT_ALLOWED_CONTENT_TYPES,
  ATTACHMENT_KINDS,
  ATTACHMENT_MAX_FILE_BYTES,
  ATTACHMENT_MAX_NAME_LENGTH,
  ATTACHMENT_MAX_PER_CASE,
  ATTACHMENT_MAX_URL_LENGTH,
  ATTACHMENT_REQUEST_MAX_BYTES,
  CaseAttachment,
  CaseAttachmentListResponse,
} from '../../common';
import { assertManagedWriteTarget } from '../lib/index_namespace';
import { ATTACHMENT_ADDED_ACTION, ATTACHMENT_REMOVED_ACTION, appendActivity } from '../lib/activity';
import { getCurrentUsername } from '../lib/opensearch';
import { trustedIdentity } from '../lib/identity';
import { isPluginAdmin } from '../lib/authorization';
import { resolveCase } from '../lib/case_index_resolution';
import { downloadResponse } from '../lib/http_download';

/**
 * Case attachments (step 5.3): links and small files in the fixed
 * plugin-owned index `wazuh-alert-manager-v2-attachments`. Every document
 * carries `case_id`, every route checks it against the path, file bytes live
 * in `data` (base64, mapped `enabled: false`) and only ever leave the server
 * through the download route with attachment headers.
 */

/** Base64 length that can hold ATTACHMENT_MAX_FILE_BYTES (padding included), plus a little slack for whitespace. */
const MAX_BASE64_LENGTH = Math.ceil(ATTACHMENT_MAX_FILE_BYTES / 3) * 4 + 1024;
const BASE64_ALPHABET = /^[A-Za-z0-9+/]*={0,2}$/;
const ALLOWED_CONTENT_TYPES = new Set<string>(ATTACHMENT_ALLOWED_CONTENT_TYPES);

function httpError(statusCode: number, message: string): Error {
  const error: any = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function isNotFound(error: any): boolean {
  return (error?.statusCode || error?.meta?.statusCode) === 404;
}

/**
 * Validate a link attachment. Unlike `validateEgressUrl` (which guards what
 * the server itself fetches) an attachment link is only ever opened by the
 * analyst's browser, so a private host (an internal ticket, a wiki page) is
 * legitimate: http/https only, no embedded credentials, bounded length.
 * Returns the normalised URL string.
 */
export function validateAttachmentUrl(value: unknown): string {
  const raw = String(value ?? '').trim();
  if (!raw) throw httpError(400, 'A link attachment needs a URL.');
  if (raw.length > ATTACHMENT_MAX_URL_LENGTH) {
    throw httpError(400, `The URL must be at most ${ATTACHMENT_MAX_URL_LENGTH} characters.`);
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch (e) {
    throw httpError(400, 'The URL must be a valid http or https URL.');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw httpError(400, 'The URL must use http or https.');
  }
  if (parsed.username || parsed.password) {
    throw httpError(400, 'The URL must not contain embedded credentials.');
  }
  if (!parsed.hostname) {
    throw httpError(400, 'The URL must name a host.');
  }
  const normalised = parsed.toString();
  if (normalised.length > ATTACHMENT_MAX_URL_LENGTH) {
    throw httpError(400, `The URL must be at most ${ATTACHMENT_MAX_URL_LENGTH} characters.`);
  }
  return normalised;
}

/** Lower-cased media type without parameters; throws 400 unless allowlisted. */
export function validateAttachmentContentType(value: unknown): string {
  const type = String(value ?? '').split(';')[0].trim().toLowerCase();
  if (!type) throw httpError(400, 'A file attachment needs a content type.');
  if (!ALLOWED_CONTENT_TYPES.has(type)) {
    throw httpError(400, `Content type ${type} is not allowed. Allowed: ${ATTACHMENT_ALLOWED_CONTENT_TYPES.join(', ')}.`);
  }
  return type;
}

/**
 * Decode a base64 file body. The cap is enforced on the decoded bytes; a
 * cheap length check first keeps a huge payload from being decoded at all.
 */
export function decodeAttachmentData(value: unknown): Buffer {
  const text = String(value ?? '').replace(/\s+/g, '');
  if (!text) throw httpError(400, 'A file attachment needs file data.');
  if (text.length > MAX_BASE64_LENGTH || !BASE64_ALPHABET.test(text) || text.length % 4 !== 0) {
    if (text.length > MAX_BASE64_LENGTH) {
      throw httpError(413, `The file exceeds the ${ATTACHMENT_MAX_FILE_BYTES / (1024 * 1024)} MiB limit.`);
    }
    throw httpError(400, 'The file data must be valid base64.');
  }
  const bytes = Buffer.from(text, 'base64');
  if (bytes.length === 0) throw httpError(400, 'The file is empty.');
  if (bytes.length > ATTACHMENT_MAX_FILE_BYTES) {
    throw httpError(413, `The file exceeds the ${ATTACHMENT_MAX_FILE_BYTES / (1024 * 1024)} MiB limit.`);
  }
  return bytes;
}

function normaliseName(value: unknown): string {
  const name = String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!name) throw httpError(400, 'An attachment needs a name.');
  if (name.length > ATTACHMENT_MAX_NAME_LENGTH) {
    throw httpError(400, `The name must be at most ${ATTACHMENT_MAX_NAME_LENGTH} characters.`);
  }
  return name;
}

/** The public shape: the stored document without `data`. */
export function toAttachment(id: string, source: any): CaseAttachment {
  return {
    id,
    case_id: String(source?.case_id ?? ''),
    kind: source?.kind === 'link' ? 'link' : 'file',
    name: String(source?.name ?? ''),
    url: typeof source?.url === 'string' ? source.url : null,
    content_type: typeof source?.content_type === 'string' ? source.content_type : null,
    size: Number.isFinite(Number(source?.size)) ? Number(source.size) : 0,
    sha256: typeof source?.sha256 === 'string' ? source.sha256 : null,
    created_by: String(source?.created_by ?? ''),
    created_at: String(source?.created_at ?? ''),
  };
}

/**
 * Count a case's attachments. A missing index is tolerated (0) only when the
 * caller says so (a read-only path); on the write path it is a 503, because
 * writing into an absent index would auto-create it with a dynamic mapping
 * (the base64 `data` as analysed text) and break the next provisioning run's
 * `putMapping`.
 */
export async function countCaseAttachments(
  client: any,
  caseId: string,
  options: { tolerateMissing?: boolean } = {}
): Promise<number> {
  try {
    const res: any = await client.count({
      index: ATTACHMENTS_INDEX,
      body: { query: { bool: { filter: [{ term: { case_id: caseId } }] } } },
    });
    return Number(res?.body?.count ?? 0);
  } catch (error: any) {
    if (isNotFound(error)) {
      if (options.tolerateMissing) return 0;
      throw httpError(503, 'The attachments store is not provisioned.');
    }
    throw error;
  }
}

export async function listCaseAttachments(client: any, caseId: string): Promise<CaseAttachmentListResponse> {
  try {
    const res: any = await client.search({
      index: ATTACHMENTS_INDEX,
      body: {
        size: ATTACHMENT_MAX_PER_CASE * 2,
        track_total_hits: true,
        sort: [{ created_at: { order: 'asc' } }, { _doc: { order: 'asc' } }],
        query: { bool: { filter: [{ term: { case_id: caseId } }] } },
        _source: { excludes: ['data'] },
      },
    });
    const hits: any[] = res?.body?.hits?.hits || [];
    const rawTotal = res?.body?.hits?.total;
    const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal?.value ?? hits.length);
    return {
      attachments: hits.map((hit) => toAttachment(String(hit._id), hit._source)),
      total,
      limit: ATTACHMENT_MAX_PER_CASE,
    };
  } catch (error: any) {
    if (isNotFound(error)) return { attachments: [], total: 0, limit: ATTACHMENT_MAX_PER_CASE };
    throw error;
  }
}

/**
 * Fetch one attachment and insist that it belongs to the case in the path
 * (404 otherwise). The base64 `data` (up to ~2.7 MB) is read only when the
 * caller needs it (download); delete and ownership checks leave it out.
 */
async function getCaseAttachment(client: any, caseId: string, attachmentId: string, includeData = false): Promise<any> {
  let res: any;
  try {
    res = await client.get({
      index: ATTACHMENTS_INDEX,
      id: attachmentId,
      ...(includeData ? {} : { _source_excludes: 'data' }),
    });
  } catch (error: any) {
    if (isNotFound(error)) throw httpError(404, 'Attachment not found.');
    throw error;
  }
  const source = res?.body?._source;
  if (!res?.body?.found || !source || source.case_id !== caseId) {
    throw httpError(404, 'Attachment not found.');
  }
  return source;
}

export interface CreateAttachmentInput {
  kind: 'link' | 'file';
  name: string;
  url?: string;
  contentType?: string;
  dataBase64?: string;
}

/**
 * Validate and store one attachment. The per-case cap is counted before the
 * write; because two analysts can race past that check, the count is repeated
 * after the write and, when the case is now over the cap and this document is
 * among the newest extras, it is removed again and the caller gets a 409.
 */
export async function createCaseAttachment(
  client: any,
  caseId: string,
  input: CreateAttachmentInput,
  user: string,
  now: Date = new Date()
): Promise<CaseAttachment> {
  const kind = input.kind;
  if (!ATTACHMENT_KINDS.includes(kind)) throw httpError(400, 'kind must be "link" or "file".');
  const name = normaliseName(input.name);
  const createdAt = now.toISOString();
  const doc: Record<string, any> = {
    case_id: caseId,
    kind,
    name,
    url: null,
    content_type: null,
    size: 0,
    sha256: null,
    data: null,
    created_by: user,
    created_at: createdAt,
  };
  if (kind === 'link') {
    doc.url = validateAttachmentUrl(input.url);
  } else {
    doc.content_type = validateAttachmentContentType(input.contentType);
    const bytes = decodeAttachmentData(input.dataBase64);
    doc.size = bytes.length;
    doc.sha256 = createHash('sha256').update(bytes).digest('hex');
    doc.data = bytes.toString('base64');
  }

  const before = await countCaseAttachments(client, caseId);
  if (before >= ATTACHMENT_MAX_PER_CASE) {
    throw httpError(409, `This case already has ${ATTACHMENT_MAX_PER_CASE} attachments; remove one first.`);
  }

  const id = randomUUID();
  const index = assertManagedWriteTarget(ATTACHMENTS_INDEX);
  await client.index({ index, id, op_type: 'create', body: doc, refresh: 'wait_for' });

  const after = await countCaseAttachments(client, caseId);
  if (after > ATTACHMENT_MAX_PER_CASE) {
    const extras = after - ATTACHMENT_MAX_PER_CASE;
    const newest: any = await client.search({
      index: ATTACHMENTS_INDEX,
      body: {
        size: extras,
        track_total_hits: false,
        sort: [{ created_at: { order: 'desc' } }, { _doc: { order: 'desc' } }],
        query: { bool: { filter: [{ term: { case_id: caseId } }] } },
        _source: false,
      },
    });
    const extraIds = new Set<string>((newest?.body?.hits?.hits || []).map((hit: any) => String(hit._id)));
    if (extraIds.has(id)) {
      await client.delete({ index, id, refresh: 'wait_for' });
      throw httpError(409, `This case already has ${ATTACHMENT_MAX_PER_CASE} attachments; remove one first.`);
    }
  }

  const { data, ...rest } = doc;
  return toAttachment(id, rest);
}

const caseParams = schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) });
const attachmentParams = schema.object({
  id: schema.string({ minLength: 1, maxLength: 256 }),
  attachmentId: schema.string({ minLength: 1, maxLength: 256 }),
});

export const createAttachmentBodySchema = schema.object({
  kind: schema.oneOf(ATTACHMENT_KINDS.map((kind) => schema.literal(kind)) as any),
  name: schema.string({ minLength: 1, maxLength: ATTACHMENT_MAX_NAME_LENGTH }),
  url: schema.maybe(schema.string({ maxLength: ATTACHMENT_MAX_URL_LENGTH })),
  contentType: schema.maybe(schema.string({ maxLength: 200 })),
  dataBase64: schema.maybe(schema.string({ maxLength: MAX_BASE64_LENGTH })),
});

function failure(response: any, error: any) {
  const statusCode = error?.statusCode || error?.meta?.statusCode || 500;
  const body = { message: error?.message || 'Operation failed' };
  if (statusCode === 404) return response.notFound({ body });
  if (statusCode === 403) return response.forbidden({ body });
  if (statusCode === 400) return response.badRequest({ body });
  return response.customError({ statusCode, body });
}

export function defineAttachmentRoutes(router: IRouter) {
  router.get(
    {
      path: `${API_ROOT}/cases/{id}/attachments`,
      validate: { params: caseParams },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        await resolveCase(client, id);
        return response.ok({ body: await listCaseAttachments(client, id) });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/cases/{id}/attachments`,
      validate: { params: caseParams, body: createAttachmentBodySchema },
      options: { body: { maxBytes: ATTACHMENT_REQUEST_MAX_BYTES } },
    },
    async (context, request, response) => {
      const { id } = request.params as any;
      const body = request.body as CreateAttachmentInput;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        await resolveCase(client, id);
        const user = await getCurrentUsername(context, request);
        const attachment = await createCaseAttachment(client, id, body, user);
        await appendActivity(client, {
          targetType: 'case',
          targetId: id,
          user,
          action: ATTACHMENT_ADDED_ACTION,
          to: `${attachment.kind}:${attachment.name}`,
        });
        return response.ok({ body: { attachment } });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.delete(
    {
      path: `${API_ROOT}/cases/{id}/attachments/{attachmentId}`,
      validate: { params: attachmentParams },
    },
    async (context, request, response) => {
      const { id, attachmentId } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const source = await getCaseAttachment(client, id, attachmentId);
        const identity = await trustedIdentity(context, request);
        if (identity.source === 'anonymous') {
          throw httpError(403, 'A trusted identity is required to remove an attachment.');
        }
        if (source.created_by !== identity.name && !isPluginAdmin(identity)) {
          throw httpError(403, 'Only the attachment author or a plugin administrator can remove it.');
        }
        await client.delete({ index: assertManagedWriteTarget(ATTACHMENTS_INDEX), id: attachmentId, refresh: 'wait_for' });
        await appendActivity(client, {
          targetType: 'case',
          targetId: id,
          user: identity.name,
          action: ATTACHMENT_REMOVED_ACTION,
          from: `${source.kind}:${source.name}`,
        });
        return response.ok({ body: { deleted: true } });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );

  router.get(
    {
      path: `${API_ROOT}/cases/{id}/attachments/{attachmentId}/download`,
      validate: { params: attachmentParams },
    },
    async (context, request, response) => {
      const { id, attachmentId } = request.params as any;
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const source = await getCaseAttachment(client, id, attachmentId, true);
        if (source.kind !== 'file' || typeof source.data !== 'string') {
          throw httpError(404, 'Attachment not found.');
        }
        // Re-validate the stored type: the allowlist is the only thing that
        // decides what media type the browser is told, never the file name.
        const contentType = validateAttachmentContentType(source.content_type);
        const bytes = Buffer.from(source.data, 'base64');
        // The sanitised ASCII `filename` keeps its extension; the analyst's
        // original name travels alongside as RFC 5987 `filename*`.
        return downloadResponse(response, {
          filename: String(source.name || ''),
          fallback: 'attachment',
          originalFilename: String(source.name || ''),
          contentType,
          headers: {
            'x-content-type-options': 'nosniff',
            'content-security-policy': "default-src 'none'",
          },
          body: bytes,
        });
      } catch (e: any) {
        return failure(response, e);
      }
    }
  );
}
