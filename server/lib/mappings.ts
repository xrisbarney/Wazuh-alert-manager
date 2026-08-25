// Explicit mappings for the fields this plugin owns. Everything else stays
// dynamic so any Wazuh alert field can flow into wazuh-alert-status without
// us having to mirror Wazuh's entire alert schema.

export const alertStatusMapping = {
  dynamic: true,
  // Opportunistic Wazuh fields (data.srcip, data.srcuser, syscheck.path, ...)
  // arrive only for certain decoders and are dynamically mapped. Default string
  // detection makes them `text` with a `.keyword` subfield capped at
  // ignore_above 256, so long values (syscheck paths especially) silently drop
  // out of the aggregatable subfield. Map them straight to keyword at 1024 so
  // entity extraction and facet aggregations see complete values.
  dynamic_templates: [
    {
      data_strings_as_keyword: {
        path_match: 'data.*',
        match_mapping_type: 'string',
        mapping: { type: 'keyword', ignore_above: 1024 },
      },
    },
    {
      syscheck_strings_as_keyword: {
        path_match: 'syscheck.*',
        match_mapping_type: 'string',
        mapping: { type: 'keyword', ignore_above: 1024 },
      },
    },
    {
      mitre_strings_as_keyword: {
        path_match: 'rule.mitre.*',
        match_mapping_type: 'string',
        mapping: { type: 'keyword', ignore_above: 1024 },
      },
    },
  ],
  properties: {
    '@timestamp': { type: 'date' },
    status: { type: 'keyword' },
    case_id: { type: 'keyword' },
    assigned_to: { type: 'keyword' },
    related_alert_ids: { type: 'keyword' },
    ai_analysis: {
      properties: {
        text: { type: 'text' },
        provider: { type: 'keyword' },
        model: { type: 'keyword' },
        generated_at: { type: 'date' },
      },
    },
    updated_at: { type: 'date' },
    updated_by: { type: 'keyword' },
    history: {
      type: 'nested',
      properties: {
        timestamp: { type: 'date' },
        user: { type: 'keyword' },
        action: { type: 'keyword' },
        from: { type: 'keyword' },
        to: { type: 'keyword' },
      },
    },
    agent: {
      properties: {
        id: { type: 'keyword' },
        name: { type: 'keyword' },
        ip: { type: 'keyword' },
      },
    },
    rule: {
      properties: {
        id: { type: 'keyword' },
        level: { type: 'integer' },
        groups: { type: 'keyword' },
        description: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 512 } },
        },
      },
    },
    manager: {
      properties: {
        name: { type: 'keyword' },
      },
    },
  },
};

export const commentsMapping = {
  dynamic: false,
  properties: {
    alert_id: { type: 'keyword' },
    case_id: { type: 'keyword' },
    text: { type: 'text' },
    author: { type: 'keyword' },
    created_at: { type: 'date' },
  },
};

export const casesMapping = {
  dynamic: false,
  properties: {
    title: {
      type: 'text',
      fields: { keyword: { type: 'keyword', ignore_above: 512 } },
    },
    description: { type: 'text' },
    severity: { type: 'keyword' },
    status: { type: 'keyword' },
    assigned_to: { type: 'keyword' },
    alert_ids: { type: 'keyword' },
    // Set on auto-created cases so a correlation rule can find and extend its
    // own still-open case instead of spawning a duplicate. Shape: <ruleId>|<entityValue>.
    correlation_key: { type: 'keyword' },
    created_by: { type: 'keyword' },
    created_at: { type: 'date' },
    updated_by: { type: 'keyword' },
    updated_at: { type: 'date' },
    closed_at: { type: 'date' },
    history: {
      type: 'nested',
      properties: {
        timestamp: { type: 'date' },
        user: { type: 'keyword' },
        action: { type: 'keyword' },
        from: { type: 'keyword' },
        to: { type: 'keyword' },
      },
    },
  },
};

export const rulesMapping = {
  dynamic: false,
  properties: {
    name: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
    enabled: { type: 'boolean' },
    // Legacy top-level fields (pre-trigger model) kept so old docs stay readable.
    entity: { type: 'keyword' },
    windowMinutes: { type: 'integer' },
    threshold: { type: 'integer' },
    caseSeverity: { type: 'keyword' },
    trigger: {
      properties: {
        type: { type: 'keyword' },
        entity: { type: 'keyword' },
        windowMinutes: { type: 'integer' },
        threshold: { type: 'integer' },
      },
    },
    actions: {
      properties: {
        createCase: { type: 'boolean' },
        caseSeverity: { type: 'keyword' },
        setStatus: { type: 'keyword' },
        assignTo: { type: 'keyword' },
      },
    },
    match: {
      properties: {
        ruleGroups: { type: 'keyword' },
        ruleGroupsMode: { type: 'keyword' },
        ruleIds: { type: 'keyword' },
        ruleIdsMode: { type: 'keyword' },
        agentNames: { type: 'keyword' },
        agentNamesMode: { type: 'keyword' },
        minLevel: { type: 'integer' },
      },
    },
    created_by: { type: 'keyword' },
    created_at: { type: 'date' },
    updated_at: { type: 'date' },
    matchCount: { type: 'long' },
    lastFired: { type: 'date' },
  },
};

export const metaMapping = {
  dynamic: false,
  properties: {
    value: { type: 'keyword' },
    updated_at: { type: 'date' },
    holder_id: { type: 'keyword' },
    expires_at: { type: 'date' },
  },
};
