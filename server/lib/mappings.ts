// Explicit mappings for the fields this plugin owns. Everything else stays
// dynamic so any Wazuh alert field can flow into wazuh-alert-status without
// us having to mirror Wazuh's entire alert schema.

export const alertStatusMapping = {
  dynamic: true,
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

export const metaMapping = {
  dynamic: false,
  properties: {
    value: { type: 'keyword' },
    updated_at: { type: 'date' },
  },
};
