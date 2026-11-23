import {
  DISCOVER_APP_PATH,
  WAM_ALERTS_INDEX_PATTERN_ID,
  WAM_ALERT_SEVERITY_COLUMN,
  WAM_OPEN_ALERTS_COLUMNS,
  WAM_OPEN_CASES_COLUMNS,
  WAM_OPEN_ALERTS_SEARCH_ID,
  discoverDeepLinkSupported,
  discoverIndexPatternUrl,
  discoverSavedSearchUrl,
  parseOsdVersion,
  risonString,
} from './discover_links';

describe('discover links', () => {
  test('saved-search columns only name fields that exist on the projections', () => {
    // Alerts carry rule.level (4.x) or severity_label (5.0), never a top-level `severity`; the assignee field is `assigned_to`.
    expect(['rule.level', 'severity_label']).toContain(WAM_ALERT_SEVERITY_COLUMN);
    expect(WAM_OPEN_ALERTS_COLUMNS).toEqual(['agent.name', 'rule.description', WAM_ALERT_SEVERITY_COLUMN, 'status', 'assigned_to']);
    expect(WAM_OPEN_ALERTS_COLUMNS).not.toContain('severity');
    expect(WAM_OPEN_ALERTS_COLUMNS).not.toContain('assignee');
    expect(WAM_OPEN_CASES_COLUMNS).toEqual(['title', 'status', 'severity', 'assigned_to', 'created_at']);
  });

  test('parseOsdVersion reads major.minor and rejects garbage', () => {
    expect(parseOsdVersion('2.19.5')).toEqual({ major: 2, minor: 19 });
    expect(parseOsdVersion('3.6.0-rc1')).toEqual({ major: 3, minor: 6 });
    expect(parseOsdVersion('')).toBeNull();
    expect(parseOsdVersion(undefined)).toBeNull();
    expect(parseOsdVersion('latest')).toBeNull();
  });

  test('deep links are only built for the 2.10+ data-explorer shape', () => {
    expect(discoverDeepLinkSupported('2.19.5')).toBe(true);
    expect(discoverDeepLinkSupported('2.10.0')).toBe(true);
    expect(discoverDeepLinkSupported('2.9.0')).toBe(false);
    expect(discoverDeepLinkSupported('3.6.0')).toBe(false);
    expect(discoverDeepLinkSupported('')).toBe(false);
    expect(discoverIndexPatternUrl(WAM_ALERTS_INDEX_PATTERN_ID, { osdVersion: '3.6.0' })).toBeNull();
    expect(discoverSavedSearchUrl(WAM_OPEN_ALERTS_SEARCH_ID, '3.6.0')).toBeNull();
  });

  test('risonString quotes and escapes', () => {
    expect(risonString('agent.name')).toBe("'agent.name'");
    expect(risonString("it's!")).toBe("'it!'s!!'");
  });

  test('index pattern deep link carries columns, sort, metadata and the time range', () => {
    const url = discoverIndexPatternUrl(WAM_ALERTS_INDEX_PATTERN_ID, {
      columns: WAM_OPEN_ALERTS_COLUMNS,
      sortField: '@timestamp',
      timeFrom: 'now-24h',
      timeTo: 'now',
      osdVersion: '2.19.5',
    });
    expect(url).toBe(
      `${DISCOVER_APP_PATH}#?_a=(discover:(columns:!('agent.name','rule.description','${WAM_ALERT_SEVERITY_COLUMN}','status','assigned_to'),isDirty:!f,sort:!(!('@timestamp',desc))),metadata:(indexPattern:'wam-alerts',view:discover))` +
        "&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'now-24h',to:'now'))"
    );
  });

  test('index pattern deep link without columns or time falls back to _source and no _g', () => {
    const url = discoverIndexPatternUrl('wam-cases', { osdVersion: '2.19.5' });
    expect(url).toBe(`${DISCOVER_APP_PATH}#?_a=(discover:(columns:!('_source'),isDirty:!f,sort:!()),metadata:(indexPattern:'wam-cases',view:discover))`);
  });

  test('saved search link uses the #/view route', () => {
    expect(discoverSavedSearchUrl(WAM_OPEN_ALERTS_SEARCH_ID, '2.19.5')).toBe(`${DISCOVER_APP_PATH}#/view/wam-open-alerts`);
  });
});
