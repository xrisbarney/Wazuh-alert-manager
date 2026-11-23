import { TARGET_OSD_VERSION, TARGET_WAZUH_MAJOR } from './build_info';

/**
 * Discover/Reporting bridge (step 5.6): the fixed saved-object ids the server
 * provisions through the internal saved-objects repository, the default
 * columns of the two saved searches, and the browser-side link builders.
 *
 * The Discover URL shape differs between OpenSearch Dashboards 2.x
 * (data-explorer, verified against the 2.19 tree: `#?_a=(discover:(columns,
 * sort),metadata:(indexPattern,view:discover))`) and 3.x, so the deep link
 * is only built for the 2.x shape; everything else falls back to the plain
 * app link. The links are app-relative; callers prepend server.basePath.
 */
export const WAM_ALERTS_INDEX_PATTERN_ID = 'wam-alerts';
export const WAM_CASES_INDEX_PATTERN_ID = 'wam-cases';
export const WAM_OPEN_ALERTS_SEARCH_ID = 'wam-open-alerts';
export const WAM_OPEN_CASES_SEARCH_ID = 'wam-open-cases';

/**
 * Field that carries an alert's severity on the operational projection: 4.x
 * records keep the numeric `rule.level` (`severity_label` is null), 5.0
 * findings keep the label verbatim in `severity_label` (`rule.level` is
 * null). A build only reads the family its target Wazuh line allows, so the
 * saved search names the one that is populated. The assignee field on both
 * alerts and cases is `assigned_to`.
 */
export const WAM_ALERT_SEVERITY_COLUMN: 'rule.level' | 'severity_label' = TARGET_WAZUH_MAJOR >= 5 ? 'severity_label' : 'rule.level';
export const WAM_OPEN_ALERTS_COLUMNS: readonly string[] = ['agent.name', 'rule.description', WAM_ALERT_SEVERITY_COLUMN, 'status', 'assigned_to'];
export const WAM_OPEN_CASES_COLUMNS: readonly string[] = ['title', 'status', 'severity', 'assigned_to', 'created_at'];
export const WAM_OPEN_ALERTS_QUERY = 'status:open OR status:in_progress';
export const WAM_OPEN_CASES_QUERY = 'status:open OR status:in_progress';

export const DISCOVER_APP_PATH = '/app/data-explorer/discover';
export const REPORTING_APP_PATH = '/app/reports-dashboards#/';
export const SAVED_OBJECTS_MANAGEMENT_PATH = '/app/objects';

/** Major.minor of an OSD version string, or null when it cannot be parsed. */
export function parseOsdVersion(version: string | undefined | null): { major: number; minor: number } | null {
  const match = /^(\d+)\.(\d+)/.exec(String(version || '').trim());
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]) };
}

/**
 * True when the target dashboard uses the data-explorer Discover state shape
 * this module knows (OSD 2.10 through 2.x). 3.x and unparsable versions get
 * no deep link.
 */
export function discoverDeepLinkSupported(version: string | undefined | null = TARGET_OSD_VERSION): boolean {
  const parsed = parseOsdVersion(version);
  return Boolean(parsed && parsed.major === 2 && parsed.minor >= 10);
}

/** Rison string literal: always quoted, with `'` and `!` escaped by `!`. */
export function risonString(value: string): string {
  return `'${String(value).replace(/!/g, '!!').replace(/'/g, "!'")}'`;
}

function risonList(values: readonly string[]): string {
  return `!(${values.map(risonString).join(',')})`;
}

export interface DiscoverIndexPatternLinkOptions {
  columns?: readonly string[];
  sortField?: string;
  sortDirection?: 'asc' | 'desc';
  /** Global time range, relative (`now-24h`) or absolute. Omitted = Discover default. */
  timeFrom?: string;
  timeTo?: string;
  osdVersion?: string;
}

/**
 * Deep link to Discover on a provisioned index pattern (2.x shape), or null
 * when the target dashboard's URL shape is not known. App-relative.
 */
export function discoverIndexPatternUrl(indexPatternId: string, options: DiscoverIndexPatternLinkOptions = {}): string | null {
  if (!discoverDeepLinkSupported(options.osdVersion ?? TARGET_OSD_VERSION)) return null;
  const columns = options.columns && options.columns.length ? options.columns : ['_source'];
  const sort = options.sortField
    ? `!(!(${risonString(options.sortField)},${options.sortDirection === 'asc' ? 'asc' : 'desc'}))`
    : '!()';
  const discover = `discover:(columns:${risonList(columns)},isDirty:!f,sort:${sort})`;
  const metadata = `metadata:(indexPattern:${risonString(indexPatternId)},view:discover)`;
  const appState = `_a=(${discover},${metadata})`;
  const global = options.timeFrom && options.timeTo
    ? `&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:${risonString(options.timeFrom)},to:${risonString(options.timeTo)}))`
    : '';
  return `${DISCOVER_APP_PATH}#?${appState}${global}`;
}

/**
 * Deep link to a provisioned saved search (`#/view/<id>`, the 2.x route that
 * `urlForwarding` also maps legacy `/app/discover#/view/<id>` links to), or
 * null when unsure. App-relative.
 */
export function discoverSavedSearchUrl(savedSearchId: string, osdVersion: string | undefined | null = TARGET_OSD_VERSION): string | null {
  if (!discoverDeepLinkSupported(osdVersion)) return null;
  return `${DISCOVER_APP_PATH}#/view/${encodeURIComponent(savedSearchId)}`;
}
