import { createHash } from 'crypto';
import { API_ROOT, ATTACHMENTS_INDEX, ATTACHMENT_MAX_FILE_BYTES, ATTACHMENT_MAX_PER_CASE } from '../../common';
import {
  countCaseAttachments,
  createAttachmentBodySchema,
  createCaseAttachment,
  decodeAttachmentData,
  defineAttachmentRoutes,
  listCaseAttachments,
  validateAttachmentContentType,
  validateAttachmentUrl,
} from './attachments';

jest.mock('../lib/opensearch', () => ({ getCurrentUsername: jest.fn(async () => 'analyst') }));
jest.mock('../lib/identity', () => ({ trustedIdentity: jest.fn() }));
jest.mock('../lib/case_index_resolution', () => ({ resolveCase: jest.fn() }));

const trustedIdentity: jest.Mock = require('../lib/identity').trustedIdentity;
const resolveCase: jest.Mock = require('../lib/case_index_resolution').resolveCase;

const ANALYST = { name: 'analyst', roles: [], securityRoles: ['readall'], backendRoles: [], source: 'security_plugin' };
const ADMIN = { name: 'admin', roles: [], securityRoles: ['all_access'], backendRoles: [], source: 'security_plugin' };
const ANONYMOUS = { name: 'dashboard_user', roles: [], securityRoles: [], backendRoles: [], source: 'anonymous' };

function routes() {
  const router: any = { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() };
  defineAttachmentRoutes(router);
  const find = (method: 'get' | 'post' | 'delete', path: string) => {
    const registration = router[method].mock.calls.find(([config]: any[]) => config.path === `${API_ROOT}${path}`);
    expect(registration).toBeDefined();
    return registration!;
  };
  return {
    list: find('get', '/cases/{id}/attachments'),
    create: find('post', '/cases/{id}/attachments'),
    remove: find('delete', '/cases/{id}/attachments/{attachmentId}'),
    download: find('get', '/cases/{id}/attachments/{attachmentId}/download'),
  };
}

function response() {
  return {
    ok: jest.fn((v: any) => ({ kind: 'ok', ...v })),
    notFound: jest.fn((v: any) => ({ kind: 'notFound', ...v })),
    forbidden: jest.fn((v: any) => ({ kind: 'forbidden', ...v })),
    badRequest: jest.fn((v: any) => ({ kind: 'badRequest', ...v })),
    customError: jest.fn((v: any) => ({ kind: 'customError', ...v })),
  };
}

function contextWith(client: any) {
  return { core: { opensearch: { client: { asCurrentUser: client } } } } as any;
}

function notFoundError() {
  const error: any = new Error('not found');
  error.meta = { statusCode: 404 };
  return error;
}

function fakeClient(options: { counts?: number[]; docs?: Record<string, any> } = {}): any {
  const counts = [...(options.counts || [0, 1])];
  const docs = options.docs || {};
  return {
    count: jest.fn(async () => ({ body: { count: counts.length > 1 ? counts.shift() : counts[0] } })),
    index: jest.fn(async () => ({ body: { result: 'created' } })),
    delete: jest.fn(async () => ({ body: { result: 'deleted' } })),
    search: jest.fn(async () => ({ body: { hits: { total: { value: 0 }, hits: [] } } })),
    get: jest.fn(async ({ id }: any) => {
      if (!docs[id]) throw notFoundError();
      return { body: { _id: id, found: true, _source: docs[id] } };
    }),
  };
}

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

describe('attachment validators', () => {
  test('links accept http and https, private hosts included, and refuse everything else', () => {
    expect(validateAttachmentUrl('https://tickets.example.org/T-1')).toBe('https://tickets.example.org/T-1');
    expect(validateAttachmentUrl(' http://10.0.0.5:8080/wiki/page ')).toBe('http://10.0.0.5:8080/wiki/page');
    expect(validateAttachmentUrl('http://localhost/x')).toBe('http://localhost/x');
    expect(() => validateAttachmentUrl('ftp://files.example.org/a')).toThrow(/http or https/);
    expect(() => validateAttachmentUrl('javascript:alert(1)')).toThrow(/http or https/);
    expect(() => validateAttachmentUrl('https://user:pw@example.org/')).toThrow(/credentials/);
    expect(() => validateAttachmentUrl('not a url')).toThrow(/valid http/);
    expect(() => validateAttachmentUrl('')).toThrow(/needs a URL/);
    expect(() => validateAttachmentUrl(`https://example.org/${'a'.repeat(2048)}`)).toThrow(/2048/);
  });

  test('content types are normalised and allowlisted', () => {
    expect(validateAttachmentContentType('Image/PNG')).toBe('image/png');
    expect(validateAttachmentContentType('text/plain; charset=utf-8')).toBe('text/plain');
    expect(validateAttachmentContentType('application/vnd.tcpdump.pcap')).toBe('application/vnd.tcpdump.pcap');
    expect(() => validateAttachmentContentType('text/html')).toThrow(/not allowed/);
    expect(() => validateAttachmentContentType('application/x-msdownload')).toThrow(/not allowed/);
    expect(() => validateAttachmentContentType('')).toThrow(/needs a content type/);
  });

  test('file data is checked on the decoded size, not the base64 length', () => {
    expect(decodeAttachmentData(PNG.toString('base64')).equals(PNG)).toBe(true);
    const exactly = Buffer.alloc(ATTACHMENT_MAX_FILE_BYTES, 7);
    expect(decodeAttachmentData(exactly.toString('base64')).length).toBe(ATTACHMENT_MAX_FILE_BYTES);
    const over = Buffer.alloc(ATTACHMENT_MAX_FILE_BYTES + 1, 7);
    expect(() => decodeAttachmentData(over.toString('base64'))).toThrow(/2 MiB/);
    expect(() => decodeAttachmentData('')).toThrow(/needs file data/);
    expect(() => decodeAttachmentData('@@@@')).toThrow(/valid base64/);
    expect(() => decodeAttachmentData('AAAA'.repeat(800000))).toThrow(/2 MiB/);
  });

  test('the request body schema forbids unknown keys and bad kinds', () => {
    expect(createAttachmentBodySchema.validate({ kind: 'link', name: 'Ticket', url: 'https://x.example' })).toEqual({
      kind: 'link', name: 'Ticket', url: 'https://x.example',
    });
    expect(() => createAttachmentBodySchema.validate({ kind: 'note', name: 'x' })).toThrow();
    expect(() => createAttachmentBodySchema.validate({ kind: 'link', name: '' })).toThrow();
    expect(() => createAttachmentBodySchema.validate({ kind: 'file', name: 'a', extra: true })).toThrow();
  });
});

describe('createCaseAttachment', () => {
  test('stores a link with no file fields and audits nothing itself', async () => {
    const client = fakeClient();
    const created = await createCaseAttachment(client, 'case-1', { kind: 'link', name: 'Ticket', url: 'https://t.example/1' }, 'analyst', new Date('2026-11-20T10:00:00Z'));
    expect(created).toMatchObject({ case_id: 'case-1', kind: 'link', name: 'Ticket', url: 'https://t.example/1', size: 0, sha256: null, content_type: null, created_by: 'analyst', created_at: '2026-11-20T10:00:00.000Z' });
    expect((created as any).data).toBeUndefined();
    const write = client.index.mock.calls[0][0];
    expect(write.index).toBe(ATTACHMENTS_INDEX);
    expect(write.op_type).toBe('create');
    expect(write.refresh).toBe('wait_for');
    expect(write.body).toMatchObject({ case_id: 'case-1', kind: 'link', url: 'https://t.example/1', data: null });
  });

  test('stores a file with decoded size, sha256 and base64 body', async () => {
    const client = fakeClient();
    const created = await createCaseAttachment(client, 'case-1', { kind: 'file', name: 'shot.png', contentType: 'image/png', dataBase64: PNG.toString('base64') }, 'analyst');
    expect(created).toMatchObject({ kind: 'file', size: PNG.length, content_type: 'image/png', sha256: createHash('sha256').update(PNG).digest('hex'), url: null });
    expect(client.index.mock.calls[0][0].body.data).toBe(PNG.toString('base64'));
  });

  test('a link needs a URL and a file needs an allowlisted type and data', async () => {
    const client = fakeClient();
    await expect(createCaseAttachment(client, 'c', { kind: 'link', name: 'x' }, 'a')).rejects.toMatchObject({ statusCode: 400 });
    await expect(createCaseAttachment(client, 'c', { kind: 'file', name: 'x', contentType: 'text/html', dataBase64: 'AAAA' }, 'a')).rejects.toMatchObject({ statusCode: 400 });
    await expect(createCaseAttachment(client, 'c', { kind: 'file', name: 'x', contentType: 'text/plain' }, 'a')).rejects.toMatchObject({ statusCode: 400 });
    await expect(createCaseAttachment(client, 'c', { kind: 'file', name: 'x', contentType: 'text/plain', dataBase64: Buffer.alloc(ATTACHMENT_MAX_FILE_BYTES + 1).toString('base64') }, 'a')).rejects.toMatchObject({ statusCode: 413 });
    expect(client.index).not.toHaveBeenCalled();
  });

  test('a missing attachments index is a 503 on the write path and never auto-created', async () => {
    const client = fakeClient();
    client.count = jest.fn(async () => { throw notFoundError(); });
    await expect(createCaseAttachment(client, 'c', { kind: 'link', name: 'x', url: 'https://x.example' }, 'a')).rejects.toMatchObject({ statusCode: 503 });
    expect(client.index).not.toHaveBeenCalled();
    await expect(countCaseAttachments(client, 'c')).rejects.toMatchObject({ statusCode: 503 });
    await expect(countCaseAttachments(client, 'c', { tolerateMissing: true })).resolves.toBe(0);
  });

  test('refuses the 21st attachment before writing', async () => {
    const client = fakeClient({ counts: [ATTACHMENT_MAX_PER_CASE] });
    await expect(createCaseAttachment(client, 'c', { kind: 'link', name: 'x', url: 'https://x.example' }, 'a')).rejects.toMatchObject({ statusCode: 409 });
    expect(client.index).not.toHaveBeenCalled();
  });

  test('a race past the cap removes this write again when it is among the newest extras', async () => {
    const client = fakeClient({ counts: [ATTACHMENT_MAX_PER_CASE - 1, ATTACHMENT_MAX_PER_CASE + 1] });
    client.search = jest.fn(async () => ({ body: { hits: { hits: [{ _id: client.index.mock.calls[0][0].id }] } } }));
    await expect(createCaseAttachment(client, 'c', { kind: 'link', name: 'x', url: 'https://x.example' }, 'a')).rejects.toMatchObject({ statusCode: 409 });
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: ATTACHMENTS_INDEX, id: client.index.mock.calls[0][0].id }));
  });

  test('a race past the cap keeps this write when an even newer one is the extra', async () => {
    const client = fakeClient({ counts: [ATTACHMENT_MAX_PER_CASE - 1, ATTACHMENT_MAX_PER_CASE + 1] });
    client.search = jest.fn(async () => ({ body: { hits: { hits: [{ _id: 'someone-elses' }] } } }));
    await expect(createCaseAttachment(client, 'c', { kind: 'link', name: 'x', url: 'https://x.example' }, 'a')).resolves.toMatchObject({ kind: 'link' });
    expect(client.delete).not.toHaveBeenCalled();
  });
});

describe('attachment routes', () => {
  beforeEach(() => {
    resolveCase.mockReset();
    resolveCase.mockResolvedValue({ id: 'case-1', index: 'wazuh-alert-manager-v2-cases-000001', source: {} });
    trustedIdentity.mockReset();
    trustedIdentity.mockResolvedValue(ANALYST);
  });

  test('every route validates its params; create validates the body and lifts the payload cap', () => {
    const r = routes();
    expect(r.list[0].validate.params).toBeDefined();
    expect(r.create[0].validate.params).toBeDefined();
    expect(r.create[0].validate.body).toBe(createAttachmentBodySchema);
    expect(r.create[0].options).toEqual({ body: { maxBytes: 3 * 1024 * 1024 } });
    expect(r.remove[0].validate.params).toBeDefined();
    expect(r.download[0].validate.params).toBeDefined();
  });

  test('list is scoped to the case, excludes data and tolerates a missing index', async () => {
    const client = fakeClient();
    client.search = jest.fn(async () => ({ body: { hits: { total: { value: 1 }, hits: [
      { _id: 'a1', _source: { case_id: 'case-1', kind: 'file', name: 'x.txt', content_type: 'text/plain', size: 3, sha256: 'ab', created_by: 'analyst', created_at: '2026-11-20T00:00:00Z', data: 'should-not-leak' } },
    ] } } }));
    const res = response();
    const out: any = await routes().list[1](contextWith(client), { params: { id: 'case-1' } }, res);
    expect(out.kind).toBe('ok');
    expect(out.body.attachments[0]).toEqual({ id: 'a1', case_id: 'case-1', kind: 'file', name: 'x.txt', url: null, content_type: 'text/plain', size: 3, sha256: 'ab', created_by: 'analyst', created_at: '2026-11-20T00:00:00Z' });
    expect(out.body).toMatchObject({ total: 1, limit: ATTACHMENT_MAX_PER_CASE });
    const search = client.search.mock.calls[0][0];
    expect(search.index).toBe(ATTACHMENTS_INDEX);
    expect(search.body.query).toEqual({ bool: { filter: [{ term: { case_id: 'case-1' } }] } });
    expect(search.body._source).toEqual({ excludes: ['data'] });

    client.search = jest.fn(async () => { throw notFoundError(); });
    await expect(listCaseAttachments(client, 'case-1')).resolves.toEqual({ attachments: [], total: 0, limit: ATTACHMENT_MAX_PER_CASE });

    resolveCase.mockRejectedValue(Object.assign(new Error('Case nope was not found.'), { statusCode: 404 }));
    const missing: any = await routes().list[1](contextWith(client), { params: { id: 'nope' } }, response());
    expect(missing.kind).toBe('notFound');
  });

  test('create writes the attachment and an attachment_added audit event on the case', async () => {
    const client = fakeClient();
    const res = response();
    const out: any = await routes().create[1](contextWith(client), { params: { id: 'case-1' }, body: { kind: 'link', name: 'Ticket', url: 'https://t.example/1' } }, res);
    expect(out.kind).toBe('ok');
    expect(out.body.attachment).toMatchObject({ kind: 'link', name: 'Ticket', created_by: 'analyst' });
    expect(client.index).toHaveBeenCalledTimes(2);
    expect(client.index.mock.calls[1][0]).toMatchObject({
      index: 'wazuh-alert-manager-v2-activity-write',
      body: expect.objectContaining({ event_type: 'audit', target_type: 'case', target_id: 'case-1', case_id: 'case-1', user: 'analyst', action: 'attachment_added', to: 'link:Ticket' }),
    });
  });

  test('create maps validation failures to 400, the cap to 409 and an unknown case to 404', async () => {
    const client = fakeClient();
    const bad: any = await routes().create[1](contextWith(client), { params: { id: 'case-1' }, body: { kind: 'file', name: 'x', contentType: 'text/html', dataBase64: 'AAAA' } }, response());
    expect(bad.kind).toBe('badRequest');
    const full: any = await routes().create[1](contextWith(fakeClient({ counts: [ATTACHMENT_MAX_PER_CASE] })), { params: { id: 'case-1' }, body: { kind: 'link', name: 'x', url: 'https://x.example' } }, response());
    expect(full).toMatchObject({ kind: 'customError', statusCode: 409 });
    resolveCase.mockRejectedValue(Object.assign(new Error('Case nope was not found.'), { statusCode: 404 }));
    const missing: any = await routes().create[1](contextWith(client), { params: { id: 'nope' }, body: { kind: 'link', name: 'x', url: 'https://x.example' } }, response());
    expect(missing.kind).toBe('notFound');
    expect(client.index).not.toHaveBeenCalled();
  });

  const fileDoc = { case_id: 'case-1', kind: 'file', name: 'evil name/../..\\report (1).pdf', content_type: 'application/pdf', size: PNG.length, sha256: 'x', data: PNG.toString('base64'), created_by: 'analyst', created_at: '2026-11-20T00:00:00Z' };

  test('download sends the stored bytes as an attachment with nosniff and a sanitised name', async () => {
    const client = fakeClient({ docs: { a1: fileDoc } });
    const out: any = await routes().download[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a1' } }, response());
    expect(out.kind).toBe('ok');
    expect(out.headers['content-type']).toBe('application/pdf');
    expect(out.headers['content-disposition']).toBe('attachment; filename="evil_name_.._.._report_1_.pdf"; filename*=UTF-8\'\'evil%20name....report%20(1).pdf');
    expect(client.get.mock.calls[0][0]).toEqual({ index: ATTACHMENTS_INDEX, id: 'a1' });
    expect(out.headers['x-content-type-options']).toBe('nosniff');
    expect(out.headers['cache-control']).toBe('no-store');
    expect(Buffer.isBuffer(out.body)).toBe(true);
    expect(out.body.equals(PNG)).toBe(true);
  });

  test('download keeps the extension and carries a non-ASCII name as filename*', async () => {
    const client = fakeClient({ docs: { a2: { ...fileDoc, name: 'отчёт.pdf' }, a3: { ...fileDoc, name: '報告.png', content_type: 'image/png' } } });
    const r = routes();
    const pdf: any = await r.download[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a2' } }, response());
    expect(pdf.headers['content-disposition']).toBe("attachment; filename=\"attachment.pdf\"; filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf");
    const png: any = await r.download[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a3' } }, response());
    expect(png.headers['content-disposition']).toBe("attachment; filename=\"attachment.png\"; filename*=UTF-8''%E5%A0%B1%E5%91%8A.png");
  });

  test('download and delete are 404 when the attachment belongs to another case, is missing or is a link', async () => {
    const client = fakeClient({ docs: { a1: fileDoc, l1: { ...fileDoc, kind: 'link', url: 'https://x.example', data: null } } });
    const r = routes();
    expect((await r.download[1](contextWith(client), { params: { id: 'case-2', attachmentId: 'a1' } }, response())).kind).toBe('notFound');
    expect((await r.download[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'missing' } }, response())).kind).toBe('notFound');
    expect((await r.download[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'l1' } }, response())).kind).toBe('notFound');
    expect((await r.remove[1](contextWith(client), { params: { id: 'case-2', attachmentId: 'a1' } }, response())).kind).toBe('notFound');
    expect(client.delete).not.toHaveBeenCalled();
  });

  test('delete is allowed for the author and an admin, refused for others and for anonymous identities', async () => {
    const r = routes();
    const docs = { a1: { ...fileDoc } };

    let client = fakeClient({ docs });
    trustedIdentity.mockResolvedValue({ ...ANALYST, name: 'someone-else' });
    expect((await r.remove[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a1' } }, response())).kind).toBe('forbidden');
    trustedIdentity.mockResolvedValue(ANONYMOUS);
    expect((await r.remove[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a1' } }, response())).kind).toBe('forbidden');
    expect(client.delete).not.toHaveBeenCalled();

    client = fakeClient({ docs });
    trustedIdentity.mockResolvedValue(ANALYST);
    const own: any = await r.remove[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a1' } }, response());
    expect(own).toMatchObject({ kind: 'ok', body: { deleted: true } });
    expect(client.get.mock.calls[0][0]).toEqual({ index: ATTACHMENTS_INDEX, id: 'a1', _source_excludes: 'data' });
    expect(client.delete).toHaveBeenCalledWith(expect.objectContaining({ index: ATTACHMENTS_INDEX, id: 'a1', refresh: 'wait_for' }));
    expect(client.index).toHaveBeenCalledWith(expect.objectContaining({
      index: 'wazuh-alert-manager-v2-activity-write',
      body: expect.objectContaining({ target_type: 'case', target_id: 'case-1', user: 'analyst', action: 'attachment_removed', from: `file:${fileDoc.name}` }),
    }));

    client = fakeClient({ docs });
    trustedIdentity.mockResolvedValue(ADMIN);
    expect((await r.remove[1](contextWith(client), { params: { id: 'case-1', attachmentId: 'a1' } }, response())).kind).toBe('ok');
    expect(client.index.mock.calls[0][0].body.user).toBe('admin');
  });
});
