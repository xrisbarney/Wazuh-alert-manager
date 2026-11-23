import { csvEscape, downloadResponse, encodeFilenameStar, sanitizeFilename, toCsvLine, CSV_LINE_BREAK } from './http_download';

describe('sanitizeFilename', () => {
  test('keeps simple names and extensions', () => {
    expect(sanitizeFilename('alerts-2026-11-20.csv')).toBe('alerts-2026-11-20.csv');
  });

  test('strips path separators, quotes, control characters and header breakers', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('etc_passwd');
    expect(sanitizeFilename('C:\\temp\\report".csv')).toBe('C_temp_report_.csv');
    expect(sanitizeFilename('name\r\nSet-Cookie: x=y;.md')).toBe('name_Set-Cookie_x_y_.md');
    expect(sanitizeFilename('spaces and ünicode.html')).toBe('spaces_and_nicode.html');
  });

  test('never returns an empty or dot-only name', () => {
    expect(sanitizeFilename('')).toBe('download');
    expect(sanitizeFilename('...')).toBe('download');
    expect(sanitizeFilename(undefined as any, 'export.csv')).toBe('export.csv');
  });

  test('bounds the length', () => {
    expect(sanitizeFilename('a'.repeat(500) + '.csv').length).toBeLessThanOrEqual(150);
    expect(sanitizeFilename('a'.repeat(500) + '.csv')).toMatch(/\.csv$/);
  });

  test('keeps the extension when the stem is entirely non-ASCII', () => {
    expect(sanitizeFilename('отчёт.pdf')).toBe('download.pdf');
    expect(sanitizeFilename('報告.png', 'attachment')).toBe('attachment.png');
    expect(sanitizeFilename('.pdf', 'export.csv')).toBe('export.pdf');
    expect(sanitizeFilename('отчёт', 'attachment')).toBe('attachment');
  });
});

describe('encodeFilenameStar', () => {
  test('percent-encodes UTF-8 and drops header breakers, quotes and path separators', () => {
    expect(encodeFilenameStar('отчёт.pdf')).toBe("UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf");
    expect(encodeFilenameStar('a"b\r\nc/d\\e.txt')).toBe("UTF-8''abcde.txt");
    expect(encodeFilenameStar('')).toBeNull();
    expect(encodeFilenameStar('...')).toBeNull();
  });
});

describe('downloadResponse', () => {
  test('adds filename* only when an original name is given', () => {
    const response: any = { ok: jest.fn((v: any) => v) };
    const result: any = downloadResponse(response, {
      filename: 'отчёт.pdf',
      fallback: 'attachment',
      originalFilename: 'отчёт.pdf',
      contentType: 'application/pdf',
      body: Buffer.from('x'),
    });
    expect(result.headers['content-disposition']).toBe("attachment; filename=\"attachment.pdf\"; filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf");
  });

  test('returns response.ok with attachment headers and the verbatim body', () => {
    const response: any = { ok: jest.fn((v: any) => v) };
    const result: any = downloadResponse(response, {
      filename: 'cases export.csv',
      contentType: 'text/csv; charset=utf-8',
      body: 'a,b\r\n',
    });
    expect(response.ok).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      headers: {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': 'attachment; filename="cases_export.csv"',
        'cache-control': 'no-store',
      },
      body: 'a,b\r\n',
    });
  });

  test('passes a Buffer body through untouched', () => {
    const response: any = { ok: jest.fn((v: any) => v) };
    const body = Buffer.from('<html></html>');
    const result: any = downloadResponse(response, { filename: 'r.html', contentType: 'text/html', body });
    expect(result.body).toBe(body);
    expect(result.headers['content-disposition']).toBe('attachment; filename="r.html"');
  });
});

describe('csvEscape', () => {
  test('leaves plain cells alone and stringifies scalars', () => {
    expect(csvEscape('hello')).toBe('hello');
    expect(csvEscape(42)).toBe('42');
    expect(csvEscape(-7)).toBe('-7');
    expect(csvEscape(true)).toBe('true');
    expect(csvEscape(null)).toBe('');
    expect(csvEscape(undefined)).toBe('');
  });

  test('quotes cells containing commas, quotes or line breaks and doubles quotes', () => {
    expect(csvEscape('a,b')).toBe('"a,b"');
    expect(csvEscape('say "hi"')).toBe('"say ""hi"""');
    expect(csvEscape('line1\nline2')).toBe('"line1\nline2"');
    expect(csvEscape('line1\r\nline2')).toBe('"line1\r\nline2"');
  });

  test('neutralises formula leaders to prevent CSV injection', () => {
    expect(csvEscape('=1+1')).toBe('"\'=1+1"');
    expect(csvEscape('+cmd')).toBe('"\'+cmd"');
    expect(csvEscape('-cmd')).toBe('"\'-cmd"');
    expect(csvEscape('@SUM(A1)')).toBe('"\'@SUM(A1)"');
    expect(csvEscape('\tcalc')).toBe('"\'\tcalc"');
    expect(csvEscape('=HYPERLINK("http://x","y")')).toBe('"\'=HYPERLINK(""http://x"",""y"")"');
  });

  test('guards array and object cells whose text starts with a formula leader', () => {
    expect(csvEscape(['=cmd', 'x'])).toBe('"\'=cmd; x"');
    expect(csvEscape([['=cmd|calc!A0']])).toBe('"\'=cmd|calc!A0"');
    expect(toCsvLine([['=HYPERLINK("http://x")']])).toBe('"\'=HYPERLINK(""http://x"")"' + CSV_LINE_BREAK);
    expect(csvEscape(['safe', '=cmd'])).toBe('safe; =cmd');
    expect(csvEscape(-7)).toBe('-7');
    expect(csvEscape(BigInt(-7))).toBe('-7');
  });

  test('serialises dates, arrays and objects', () => {
    expect(csvEscape(new Date('2026-11-20T10:00:00.000Z'))).toBe('2026-11-20T10:00:00.000Z');
    expect(csvEscape(['a', 'b'])).toBe('a; b');
    expect(csvEscape({ k: 'v' })).toBe('"{""k"":""v""}"');
  });
});

describe('toCsvLine', () => {
  test('joins escaped cells with commas and terminates with CRLF', () => {
    expect(toCsvLine(['id', 'rule, level', '=evil', 3])).toBe('id,"rule, level","\'=evil",3' + CSV_LINE_BREAK);
    expect(toCsvLine([])).toBe(CSV_LINE_BREAK);
  });
});

describe('csvExportStream', () => {
  const { csvExportStream } = require('./http_download');
  const columns = [
    { header: 'id', value: (r: any) => r.id },
    { header: 'name', value: (r: any) => r.name },
  ];
  const rows = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => ({ id: `${prefix}-${i}`, name: `n${i}` }));

  const readAll = async (stream: any): Promise<string> => {
    let text = '';
    for await (const chunk of stream) text += chunk.toString();
    return text;
  };

  test('emits the header and first page, then reports a mid-stream page failure and rejects the consumer', async () => {
    const failure = new Error('search exploded');
    const onError = jest.fn();
    const fetchPage = jest.fn(async () => { throw failure; });
    const stream = csvExportStream({
      columns,
      firstPage: { records: rows('p1', 2), searchAfter: [1, 'p1-1'] },
      fetchPage,
      pageSize: 2,
      maxRows: 10,
      onError,
    });
    let text = '';
    let caught: unknown = null;
    try {
      for await (const chunk of stream) text += chunk.toString();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(failure);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledWith(failure);
    expect(fetchPage).toHaveBeenCalledWith([1, 'p1-1']);
    expect(text).toBe(`id,name${CSV_LINE_BREAK}p1-0,n0${CSV_LINE_BREAK}p1-1,n1${CSV_LINE_BREAK}`);
  });

  test('stops at maxRows mid-page and calls onTruncated with the rows written', async () => {
    const onTruncated = jest.fn();
    const fetchPage = jest.fn(async () => ({ records: rows('p2', 2), searchAfter: [2, 'p2-1'] }));
    const stream = csvExportStream({
      columns,
      firstPage: { records: rows('p1', 2), searchAfter: [1, 'p1-1'] },
      fetchPage,
      pageSize: 2,
      maxRows: 3,
      onTruncated,
    });
    const text = await readAll(stream);
    const lines = text.split(CSV_LINE_BREAK).filter(Boolean);
    expect(lines).toEqual(['id,name', 'p1-0,n0', 'p1-1,n1', 'p2-0,n0']);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(onTruncated).toHaveBeenCalledTimes(1);
    expect(onTruncated).toHaveBeenCalledWith(3);
  });

  test('ends without onTruncated when the last page is short', async () => {
    const onTruncated = jest.fn();
    const stream = csvExportStream({
      columns,
      firstPage: { records: rows('p1', 1), searchAfter: [1, 'p1-0'] },
      fetchPage: jest.fn(),
      pageSize: 2,
      maxRows: 10,
      onTruncated,
    });
    const text = await readAll(stream);
    expect(text).toBe(`id,name${CSV_LINE_BREAK}p1-0,n0${CSV_LINE_BREAK}`);
    expect(onTruncated).not.toHaveBeenCalled();
  });
});
