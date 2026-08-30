// Explicit mappings for the bounded fields this plugin owns. Unknown fields
// are rejected from the managed projection; raw Wazuh evidence stays in the
// native read-only indices.

export const alertStatusMapping = {
  // v2 stores an explicit operational projection instead of cloning an
  // unbounded Wazuh _source. Raw evidence remains in wazuh-alerts-* and is
  // retrieved by source_index/source_id only when an analyst opens it.
  dynamic: false,
  properties: {
    alert_uid: { type: 'keyword' },
    legacy_id: { type: 'keyword' },
    migrated_from_legacy: { type: 'boolean' },
    source_index: { type: 'keyword' },
    source_id: { type: 'keyword' },
    source_resolved: { type: 'boolean' },
    '@timestamp': { type: 'date' },
    ingested_at: { type: 'date' },
    state_version: { type: 'long' },
    status: { type: 'keyword' },
    case_id: { type: 'keyword' },
    assigned_to: { type: 'keyword' },
    related_alert_ids: { type: 'keyword' },
    reporting: {
      properties: {
        first_assigned_at: { type: 'date' },
        assign_minutes: { type: 'double' },
        closed_at: { type: 'date' },
        resolve_minutes: { type: 'double' },
        assignee_at_close: { type: 'keyword' },
        sla_tier: { type: 'keyword' },
        sla_met: { type: 'boolean' },
        reporting_version: { type: 'integer' },
      },
    },
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
        mitre: {
          properties: {
            id: { type: 'keyword' },
            technique: { type: 'keyword' },
            tactic: { type: 'keyword' },
          },
        },
      },
    },
    manager: {
      properties: {
        name: { type: 'keyword' },
      },
    },
    data: {
      properties: {
        srcip: { type: 'keyword' },
        dstip: { type: 'keyword' },
        srcport: { type: 'integer' },
        dstport: { type: 'integer' },
        srcuser: { type: 'keyword' },
        dstuser: { type: 'keyword' },
        process: { properties: { name: { type: 'keyword' } } },
      },
    },
    decoder: { properties: { name: { type: 'keyword' } } },
    location: { type: 'keyword', ignore_above: 1024 },
    full_log_excerpt: { type: 'text', index: false },
  },
};

export const activityMapping = {
  dynamic: false,
  properties: {
    event_type: { type: 'keyword' },
    target_type: { type: 'keyword' },
    target_id: { type: 'keyword' },
    alert_id: { type: 'keyword' },
    case_id: { type: 'keyword' },
    text: { type: 'text' },
    author: { type: 'keyword' },
    created_at: { type: 'date' },
    timestamp: { type: 'date' },
    user: { type: 'keyword' },
    action: { type: 'keyword' },
    from: { type: 'keyword' },
    to: { type: 'keyword' },
    source: { type: 'keyword' },
    operation_id: { type: 'keyword' },
    rule_revision: { type: 'long' },
  },
};

// Compatibility export while comment routes are transitioned to activity
// events. Both names intentionally describe the same v2 mapping.
export const commentsMapping = activityMapping;

export const casesMapping = {
  dynamic: false,
  properties: {
    case_uid: { type: 'keyword' },
    title: {
      type: 'text',
      fields: { keyword: { type: 'keyword', ignore_above: 512 } },
    },
    description: { type: 'text' },
    severity: { type: 'keyword' },
    status: { type: 'keyword' },
    assigned_to: { type: 'keyword' },
    alert_ids: { type: 'keyword' },
    evidence_count: { type: 'long' },
    // Stable canonical scope used to extend an active automation case.
    correlation_key: { type: 'keyword' },
    correlation_keys: { type: 'keyword' },
    correlation_routing: { type: 'keyword' },
    correlation_provenance: { type: 'object', enabled: false },
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

export const ruleExecutionStateProperties = {
  counters: {
    properties: {
      matchedAlerts: { type: 'long' },
      triggeredEntities: { type: 'long' },
      actionsAttempted: { type: 'long' },
      actionsSucceeded: { type: 'long' },
      actionsSkipped: { type: 'long' },
      actionsConflicted: { type: 'long' },
      actionsFailed: { type: 'long' },
      casesCreated: { type: 'long' },
      casesExtended: { type: 'long' },
      evidenceLinksWritten: { type: 'long' },
    },
  },
  matchCount: { type: 'long' },
  lastFired: { type: 'date' },
};

export const rulesMapping = {
  dynamic: false,
  properties: {
    name: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
    enabled: { type: 'boolean' },
    document_type: { type: 'keyword' },
    rule_id: { type: 'keyword' },
    revision: { type: 'long' },
    effective_from: { type: 'date' },
    state_epoch: { type: 'keyword' },
    schemaVersion: { type: 'integer' },
    priority: { type: 'integer' },
    sortOrder: { type: 'long' },
    processingMode: { type: 'keyword' },
    // Read-only compatibility fields. Canonical v2 writes never populate these.
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
        routing: { type: 'keyword' },
        cooldown: {
          properties: {
            durationMinutes: { type: 'integer' },
          },
        },
        rearm: {
          properties: {
            type: { type: 'keyword' },
            quietPeriodMinutes: { type: 'integer' },
          },
        },
        entityExpression: {
          properties: {
            version: { type: 'integer' },
            groups: {
              type: 'nested',
              properties: {
                id: { type: 'keyword' },
                order: { type: 'integer' },
                predicates: {
                  type: 'nested',
                  properties: {
                    id: { type: 'keyword' },
                    order: { type: 'integer' },
                    entity: { type: 'keyword' },
                    operator: { type: 'keyword' },
                    value: { type: 'keyword' },
                  },
                },
              },
            },
          },
        },
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
    preconditions: {
      properties: {
        statuses: { type: 'keyword' },
        assignment: { type: 'keyword' },
      },
    },
    safety: {
      properties: {
        acknowledgeMatchAll: { type: 'boolean' },
        maxActionsPerRun: { type: 'integer' },
        maxCasesPerRun: { type: 'integer' },
        rateLimit: {
          properties: {
            maxExecutions: { type: 'integer' },
            windowMinutes: { type: 'integer' },
          },
        },
      },
    },
    // Runtime fields belong to document_type=rule_execution companions. They
    // remain mapped here while the evaluator is migrated to this contract.
    ...ruleExecutionStateProperties,
    created_by: { type: 'keyword' },
    created_at: { type: 'date' },
    updated_at: { type: 'date' },
    deleted_at: { type: 'date' },
    deleted_by: { type: 'keyword' },
    changed_at: { type: 'date' },
    changed_by: { type: 'keyword' },
    change_type: { type: 'keyword' },
    operation_id: { type: 'keyword' },
    pending_operation: { type: 'object', enabled: false },
    // Revision snapshots are restored as source documents, not queried by field.
    snapshot: { type: 'object', enabled: false },
  },
};

export const metaMapping = {
  dynamic: false,
  properties: {
    status: { type: 'keyword' },
    value: { type: 'keyword' },
    updated_at: { type: 'date' },
    holder_id: { type: 'keyword' },
    expires_at: { type: 'date' },
    version: { type: 'long' },
    completed_at: { type: 'date' },
    window_from: { type: 'date' },
    window_to: { type: 'date' },
    pit_id: { type: 'keyword', index: false },
  },
};

export const migrationMapping = {
  dynamic: false,
  properties: {
    migration_id: { type: 'keyword' },
    phase: { type: 'keyword' },
    status: { type: 'keyword' },
    checkpoint: { type: 'keyword' },
    legacy_id: { type: 'keyword' },
    alert_uid: { type: 'keyword' },
    source_index: { type: 'keyword' },
    source_resolved: { type: 'boolean' },
    migrated: { type: 'long' },
    failed: { type: 'long' },
    started_at: { type: 'date' },
    updated_at: { type: 'date' },
    completed_at: { type: 'date' },
    details: { type: 'object', enabled: false },
  },
};

export const syncDlqMapping = {
  dynamic: false,
  properties: {
    alert_uid: { type: 'keyword' },
    source_index: { type: 'keyword' },
    source_id: { type: 'keyword' },
    timestamp: { type: 'date' },
    failed_at: { type: 'date' },
    attempts: { type: 'integer' },
    error: { type: 'object', enabled: false },
    source: { type: 'object', enabled: false },
  },
};

// One bounded document per case-alert relationship. The snapshot is compact
// evidence (not a second full alert copy): raw payload, comments, AI output, and
// mutable triage history stay in their own stores.
export const evidenceMapping = {
  dynamic: false,
  properties: {
    case_id: { type: 'keyword' },
    alert_id: { type: 'keyword' },
    relationship_state: { type: 'keyword' }, // linked | held | archived | purged
    hold_reason: { type: 'text', index: false },
    hold_by: { type: 'keyword' },
    hold_since: { type: 'date' },
    archive_index: { type: 'keyword' },
    archive_id: { type: 'keyword' },
    source_index: { type: 'keyword' },
    source_id: { type: 'keyword' },
    linked_at: { type: 'date' },
    archived_at: { type: 'date' },
    purged_at: { type: 'date' },
    snapshot: {
      properties: {
        status: { type: 'keyword' },
        '@timestamp': { type: 'date' },
        assigned_to: { type: 'keyword' },
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
            description: {
              type: 'text',
              fields: { keyword: { type: 'keyword', ignore_above: 512 } },
            },
            mitre: {
              properties: {
                id: { type: 'keyword' },
                technique: { type: 'keyword' },
                tactic: { type: 'keyword' },
              },
            },
          },
        },
        data: {
          properties: {
            srcip: { type: 'keyword' },
            dstip: { type: 'keyword' },
            srcport: { type: 'integer' },
            dstport: { type: 'integer' },
            srcuser: { type: 'keyword' },
            dstuser: { type: 'keyword' },
            process: { properties: { name: { type: 'keyword' } } },
          },
        },
      },
    },
  },
};

export const automationQueueMapping = {
  dynamic: false,
  properties: {
    event_id: { type: 'keyword' },
    alert_uid: { type: 'keyword' },
    event_timestamp: { type: 'date' },
    state: { type: 'keyword' },
    target_state: { type: 'keyword' },
    enqueued_at: { type: 'date' },
    available_at: { type: 'date' },
    claimed_at: { type: 'date' },
    lease_expires_at: { type: 'date' },
    holder_id: { type: 'keyword' },
    worker_lane: { type: 'integer' },
    fencing_generation: { type: 'long' },
    lease_token: { type: 'keyword' },
    ruleset_snapshot: { type: 'keyword' },
    rule_revisions: { type: 'object', enabled: false },
    attempts: { type: 'integer' },
    completed_at: { type: 'date' },
    updated_at: { type: 'date' },
    last_error: { type: 'object', enabled: false },
    payload: { type: 'object', enabled: false },
  },
};

export const automationDlqMapping = {
  dynamic: false,
  properties: {
    event_id: { type: 'keyword' },
    execution_id: { type: 'keyword' },
    alert_uid: { type: 'keyword' },
    ruleset_snapshot: { type: 'keyword' },
    rule_revisions: { type: 'object', enabled: false },
    stage: { type: 'keyword' },
    failed_at: { type: 'date' },
    attempts: { type: 'integer' },
    error: { type: 'object', enabled: false },
    payload: { type: 'object', enabled: false },
  },
};

export const automationExecutionMapping = {
  dynamic: false,
  properties: {
    execution_id: { type: 'keyword' },
    event_id: { type: 'keyword' },
    alert_uid: { type: 'keyword' },
    state: { type: 'keyword' },
    holder_id: { type: 'keyword' },
    worker_lane: { type: 'integer' },
    fencing_generation: { type: 'long' },
    lease_token: { type: 'keyword' },
    ruleset_snapshot: { type: 'keyword' },
    document_type: { type: 'keyword' },
    snapshot_sha256: { type: 'keyword' },
    rules_snapshot: { type: 'object', enabled: false },
    rule_revisions: { type: 'object', enabled: false },
    paused: { type: 'boolean' },
    max_backlog: { type: 'long' },
    max_deferred: { type: 'long' },
    attempts: { type: 'integer' },
    started_at: { type: 'date' },
    lease_expires_at: { type: 'date' },
    completed_at: { type: 'date' },
    updated_at: { type: 'date' },
    applied_rule_ids: { type: 'keyword' },
    counters: {
      properties: {
        matches: { type: 'long' },
        statusChanges: { type: 'long' },
        assignments: { type: 'long' },
        caseLinks: { type: 'long' },
        caseCreations: { type: 'long' },
        skippedBySafety: { type: 'long' },
      },
    },
    last_error: { type: 'object', enabled: false },
  },
};
