import { Readable } from 'stream';
import { OpenSearchDashboardsResponseFactory } from '../../../../src/core/server';

/**
 * Helpers for routes that hand the browser a file (CSV, Markdown, HTML
 * exports) instead of JSON.
 */

export interface DownloadOptions {
  /** Suggested file name; sanitised before it reaches the header. */
  filename: string;
  /** Name used when `filename` sanitises to nothing (its extension is kept); default `download`. */
  fallback?: string;
  /**
   * When set, the header also carries an RFC 5987 `filename*=UTF-8''...`
   * form of this (CR/LF/quote-free, percent-encoded) name so a non-ASCII
   * name such as `отчёт.pdf` survives the ASCII sanitising of `filename`.
   */
  originalFilename?: string;
  /** Full media type, e.g. 'text/csv; charset=utf-8'. */
  contentType: string;
  /** A string/Buffer is sent as-is; a Readable is piped to the client as it produces chunks. */
  body: string | Buffer | Readable;
  /** Extra response headers (e.g. `x-wam-truncated`); never override the attachment headers. */
  headers?: Record<string, string>;
}

export const DOWNLOAD_FILENAME_MAX_LENGTH = 150;

const FILENAME_EXTENSION = /^(.*)\.([A-Za-z0-9]{1,10})$/;

function sanitizeFilenamePart(part: string): string {
  return part
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^[._-]+/, '')
    .replace(/_+/g, '_');
}

/**
 * Reduce an arbitrary name to something safe inside `Content-Disposition`:
 * only ASCII letters, digits, `.`, `-` and `_` survive (runs of anything else
 * collapse to `_`), path separators cannot appear, no leading dots or
 * dashes, bounded length, never empty. The extension is sanitised on its own
 * so a name whose stem is entirely non-ASCII (`отчёт.pdf`) keeps its type
 * (`download.pdf`, or `<fallback stem>.pdf`) instead of collapsing to `pdf`.
 */
export function sanitizeFilename(name: string, fallback = 'download'): string {
  const raw = String(name ?? '');
  const match = raw.match(FILENAME_EXTENSION);
  if (match) {
    const extension = match[2];
    const fallbackStem = (fallback.match(FILENAME_EXTENSION) || [])[1] || fallback;
    const stemLimit = Math.max(1, DOWNLOAD_FILENAME_MAX_LENGTH - extension.length - 1);
    let stem = sanitizeFilenamePart(match[1]);
    if (stem.length > stemLimit) stem = stem.slice(0, stemLimit);
    if (!stem || /^[._-]+$/.test(stem)) stem = sanitizeFilenamePart(fallbackStem) || 'download';
    return `${stem}.${extension}`;
  }
  const collapsed = sanitizeFilenamePart(raw);
  const bounded = collapsed.length > DOWNLOAD_FILENAME_MAX_LENGTH ? collapsed.slice(0, DOWNLOAD_FILENAME_MAX_LENGTH) : collapsed;
  const trimmed = bounded.replace(/[._-]+$/, '');
  return trimmed || fallback;
}

/**
 * RFC 5987 `filename*` value: control characters, quotes, backslashes and
 * path separators removed, bounded, then percent-encoded as UTF-8. Returns
 * null when nothing usable is left.
 */
export function encodeFilenameStar(name: string): string | null {
  const cleaned = String(name ?? '')
    .replace(/[\u0000-\u001f\u007f"\\/]+/g, '')
    .trim()
    .slice(0, DOWNLOAD_FILENAME_MAX_LENGTH);
  if (!cleaned || /^\.+$/.test(cleaned)) return null;
  return `UTF-8''${encodeURIComponent(cleaned)}`;
}

/**
 * `response.ok` with attachment headers. The body is sent verbatim; the
 * caller chooses the media type (and `charset`) that matches it. `no-store`
 * keeps exports out of shared caches.
 */
export function downloadResponse(response: OpenSearchDashboardsResponseFactory, options: DownloadOptions) {
  const filename = sanitizeFilename(options.filename, options.fallback);
  const star = options.originalFilename !== undefined ? encodeFilenameStar(options.originalFilename) : null;
  const disposition = star ? `attachment; filename="${filename}"; filename*=${star}` : `attachment; filename="${filename}"`;
  return response.ok({
    headers: {
      ...(options.headers || {}),
      'content-type': options.contentType,
      'content-disposition': disposition,
      'cache-control': 'no-store',
    },
    body: options.body,
  });
}

/** RFC 4180 record terminator. */
export const CSV_LINE_BREAK = '\r\n';

/**
 * Characters that make a spreadsheet interpret a cell as a formula when the
 * file is opened (OWASP "CSV injection"). Such cells are prefixed with a
 * single quote so they render as text.
 */
const FORMULA_LEADERS = /^[=+\-@\t\r]/;

function stringifyCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? '' : value.toISOString();
  if (Array.isArray(value)) return value.map((v) => stringifyCell(v)).join('; ');
  try {
    return JSON.stringify(value);
  } catch (e) {
    return String(value);
  }
}

/**
 * Escape one cell per RFC 4180: double quotes are doubled and the cell is
 * quoted when it contains a quote, comma, CR or LF. Any non-numeric cell
 * whose text starts with a formula leader (`=`, `+`, `-`, `@`, tab, CR) gets
 * a leading `'` and is always quoted so the guard survives every CSV reader.
 * Arrays and objects are guarded on their joined/serialised text, so a tag
 * list whose first entry is `=cmd` is neutralised too; numbers, bigints and
 * booleans are the only values trusted as-is (so `-7` stays a number).
 */
export function csvEscape(value: unknown): string {
  let text = stringifyCell(value);
  let mustQuote = /["\r\n,]/.test(text);
  const trustedScalar = typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean';
  if (!trustedScalar && FORMULA_LEADERS.test(text)) {
    text = `'${text}`;
    mustQuote = true;
  }
  if (!mustQuote) return text;
  return `"${text.replace(/"/g, '""')}"`;
}

/** One CSV record: escaped cells joined by commas, terminated with CRLF. */
export function toCsvLine(values: ReadonlyArray<unknown>): string {
  return values.map((value) => csvEscape(value)).join(',') + CSV_LINE_BREAK;
}

/** Hard cap on rows in one CSV export (PLAN.md 5.1). */
export const CSV_EXPORT_MAX_ROWS = 10000;
/** Rows fetched per `search_after` page while exporting. */
export const CSV_EXPORT_PAGE_SIZE = 1000;

/** One exported column: header text plus how to read the cell from a hit. */
export interface CsvColumn<T = any> {
  header: string;
  value: (record: T) => unknown;
}

export interface CsvExportPage<T = any> {
  /** Records of this page, in sort order. */
  records: T[];
  /** `sort` values of the last record, handed back as `search_after` for the next page. */
  searchAfter?: unknown[] | null;
}

export interface CsvExportStreamOptions<T = any> {
  columns: ReadonlyArray<CsvColumn<T>>;
  /** Already-fetched first page (lets the caller surface search errors before headers are sent). */
  firstPage: CsvExportPage<T>;
  /** Fetches the page after `searchAfter`; called until a page is short or the cap is reached. */
  fetchPage: (searchAfter: unknown[]) => Promise<CsvExportPage<T>>;
  pageSize?: number;
  maxRows?: number;
  /** Called once when rows beyond the cap were dropped. */
  onTruncated?: (written: number) => void;
  /** Called when a later page fails; the stream ends with that error. */
  onError?: (error: unknown) => void;
}

/**
 * Lazily page a sorted search into CSV lines: header first, then one line per
 * record. Pages after the first are fetched only as the consumer drains the
 * stream, so a 10,000-row export never sits in memory at once. Rows beyond
 * `maxRows` are dropped (the caller signals that through `x-wam-truncated`,
 * which it decides from the first page's total). Every cell goes through
 * `csvEscape` (formula guard).
 */
export function csvExportStream<T>(options: CsvExportStreamOptions<T>): Readable {
  const pageSize = options.pageSize ?? CSV_EXPORT_PAGE_SIZE;
  const maxRows = options.maxRows ?? CSV_EXPORT_MAX_ROWS;
  const columns = options.columns;
  async function* lines() {
    yield toCsvLine(columns.map((column) => column.header));
    let written = 0;
    let page = options.firstPage;
    try {
      for (;;) {
        for (const record of page.records) {
          if (written >= maxRows) {
            options.onTruncated?.(written);
            return;
          }
          yield toCsvLine(columns.map((column) => column.value(record)));
          written += 1;
        }
        if (page.records.length < pageSize || !page.searchAfter || !page.searchAfter.length) return;
        if (written >= maxRows) {
          // The cap landed exactly on a page boundary; the first page's total
          // already told the caller whether anything was dropped.
          return;
        }
        page = await options.fetchPage(page.searchAfter);
      }
    } catch (error) {
      options.onError?.(error);
      throw error;
    }
  }
  return Readable.from(lines(), { objectMode: false });
}

/** `search_after` cursor of a hit, as OpenSearch returns it (`hit.sort`). */
export function searchAfterOf(hits: ReadonlyArray<{ sort?: unknown[] }>): unknown[] | null {
  const last = hits.length ? hits[hits.length - 1] : null;
  return last && Array.isArray(last.sort) && last.sort.length ? last.sort : null;
}

/** `wam-<kind>-<YYYY-MM-DD>.csv`, the attachment name of every CSV export. */
export function csvExportFilename(kind: string, now: Date = new Date()): string {
  return `wam-${kind}-${now.toISOString().slice(0, 10)}.csv`;
}
