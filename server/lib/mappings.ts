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
    // v3: which native family produced the record and how it was normalized.
    // 4.x records: wazuh4_alerts / numeric rule.level / severity_label null.
    // 5.0 records: wazuh5_findings / rule.level null / severity_label verbatim,
    // plus the underlying event location for guarded lazy hydration.
    source_family: { type: 'keyword' },
    source_profile_version: { type: 'integer' },
    severity_label: { type: 'keyword' },
    event_index: { type: 'keyword' },
    event_doc_id: { type: 'keyword' },
    space: { type: 'keyword' },
    '@timestamp': { type: 'date' },
    ingested_at: { type: 'date' },
    state_version: { type: 'long' },
    status: { type: 'keyword' },
    case_id: { type: 'keyword' },
    assigned_to: { type: 'keyword' },
    // Close outcome (step 2.4, MAPPING_VERSION 21): plugin-owned, set by the
    // close paths (case close propagation, alert close, automation).
    disposition: { type: 'keyword' },
    closure_reason: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 512 } } },
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
        // Due timestamps (step 3.2): stamped at first projection, recomputed
        // only by the explicit policy-change backfill.
        sla_due_at: { type: 'date' },
        assign_due_at: { type: 'date' },
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
    // Stored enrichment verdicts written by per-alert lookups (step 6.3).
    // Plugin-owned (see PLUGIN_OWNED_FIELDS in sync_job.ts); bounded by
    // MAX_ALERT_ENRICHMENT_ITEMS / MAX_ALERT_ENRICHMENT_TAGS.
    enrichment: {
      properties: {
        updated_at: { type: 'date' },
        worst_verdict: { type: 'keyword' },
        items: {
          properties: {
            type: { type: 'keyword' },
            value: { type: 'keyword', ignore_above: 2048 },
            source: { type: 'keyword' },
            verdict: { type: 'keyword' },
            score: { type: 'float' },
            tags: { type: 'keyword' },
            link: { type: 'keyword', ignore_above: 2048 },
            checked_at: { type: 'date' },
          },
        },
      },
    },
    updated_at: { type: 'date' },
    updated_by: { type: 'keyword' },
    // SLA escalation scanner markers (step 3.3): breach stamp and the ids of
    // the escalations already applied. Plugin-owned (PLUGIN_OWNED_FIELDS).
    sla: {
      properties: {
        breached_at: { type: 'date' },
        escalated: { type: 'keyword' },
      },
    },
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
        // v3 step 6.1: native fields ingested for indicator extraction.
        url: { type: 'keyword', ignore_above: 2048 },
        hostname: { type: 'keyword' },
        win: { properties: { eventdata: { properties: { ipAddress: { type: 'keyword' } } } } },
        // v3 step 9.4: auditd SYSCALL binary path (MAPPING_VERSION 25).
        audit: { properties: { exe: { type: 'keyword', ignore_above: 1024 } } },
      },
    },
    // 4.x FIM hashes (5.0: file.hash.* projected onto the same shape).
    syscheck: {
      properties: {
        path: { type: 'keyword', ignore_above: 1024 },
        md5_after: { type: 'keyword' },
        sha1_after: { type: 'keyword' },
        sha256_after: { type: 'keyword' },
      },
    },
    // 5.0 ECS related.* (bounded lists).
    related: {
      properties: {
        ip: { type: 'keyword' },
        hosts: { type: 'keyword' },
        hash: { type: 'keyword' },
        user: { type: 'keyword' },
      },
    },
    // Bounded copy of native verdicts: 4.x VirusTotal/Maltiverse sibling
    // alerts and CDB IOC rules, 5.0 wazuh.threat.enrichments[].
    threat: {
      properties: {
        total: { type: 'integer' },
        truncated: { type: 'boolean' },
        sibling_of: { type: 'keyword' },
        integration: { type: 'keyword' },
        matches: {
          properties: {
            source: { type: 'keyword' },
            verdict: { type: 'keyword' },
            matched_field: { type: 'keyword' },
            detail: { type: 'keyword', ignore_above: 512 },
            link: { type: 'keyword', ignore_above: 2048 },
            indicator: {
              properties: {
                id: { type: 'keyword' },
                name: { type: 'keyword', ignore_above: 2048 },
                type: { type: 'keyword' },
                provider: { type: 'keyword' },
                feed: { type: 'keyword' },
                confidence: { type: 'keyword' },
                tags: { type: 'keyword' },
                software: { type: 'keyword' },
              },
            },
          },
        },
      },
    },
    // GeoIP hints: 4.x indexer pipeline GeoLocation (unattributed, stale DB)
    // or 5.0 ECS <entity>.geo/.as. Display only; never a lookup substitute.
    geo: {
      properties: {
        entity: { type: 'keyword' },
        ip: { type: 'keyword' },
        country_name: { type: 'keyword' },
        region_name: { type: 'keyword' },
        city_name: { type: 'keyword' },
        provider: { type: 'keyword' },
        location: { properties: { lat: { type: 'float' }, lon: { type: 'float' } } },
        as: { properties: { number: { type: 'long' }, organization: { type: 'keyword' } } },
      },
    },
    decoder: { properties: { name: { type: 'keyword' } } },
    location: { type: 'keyword', ignore_above: 1024 },
    full_log_excerpt: { type: 'text', index: false },
    // Asset context (step 6.4a): stamped at projection time on every sync
    // from the asset_settings matcher + agent groups (5.0 native, 4.x via the
    // Wazuh API). Deliberately NOT plugin-owned so a settings change is
    // reflected on the next resync. `labels` (4.x agent.labels) is kept in
    // _source for display only and is not indexed.
    asset: {
      properties: {
        criticality: { type: 'keyword' },
        tags: { type: 'keyword' },
        groups: { type: 'keyword' },
        matched_id: { type: 'keyword' },
        matched_by: { type: 'keyword' },
        labels: { type: 'object', enabled: false },
      },
    },
    // Read-only projection of a 5.0 finding's `wazuh.case.*` (step 2.6, Q6;
    // MAPPING_VERSION 22). Re-derived from the source on every resync,
    // reconciled when the case changes later, and deliberately NOT
    // plugin-owned; null on every 4.x record. Never written back to the
    // finding. `id` is reserved: rc2 writes none.
    native_case: {
      properties: {
        id: { type: 'keyword' },
        status: { type: 'keyword' },
        severity: { type: 'keyword' },
        priority: { type: 'keyword' },
        tlp: { type: 'keyword' },
        title: { type: 'keyword', ignore_above: 512 },
        tags: { type: 'keyword' },
        updated_at: { type: 'date' },
      },
    },
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
    // Stored copy of the `_id` every writer in server/lib/activity.ts stamps:
    // the search_after tiebreak of the case timeline (step 2.3, MAPPING_VERSION
    // 20) so no `_id` fielddata is loaded. Older events lack it and sort
    // `_first` within their millisecond.
    event_uid: { type: 'keyword' },
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
    // Close outcome (step 2.4): stored by POST /cases/{id}/close.
    disposition: { type: 'keyword' },
    closure_reason: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 512 } } },
    // created_at + the resolve target of the severity (step 3.2).
    sla_due_at: { type: 'date' },
    // SLA escalation scanner markers (step 3.3).
    sla: {
      properties: {
        breached_at: { type: 'date' },
        escalated: { type: 'keyword' },
      },
    },
    // Case checklist (step 2.1): the task list is read and written whole
    // through server/lib/case_tasks.ts; `task_counts` is the denormalised
    // open/done pair the queue chip and future reporting read. `nested` (like
    // `history`) so a later per-task predicate (owner AND not done, due before
    // X) matches within one task instead of across the flattened list;
    // object -> nested is not an in-place mapping change, so this is decided
    // before MAPPING_VERSION 18 ships.
    tasks: {
      type: 'nested',
      dynamic: false,
      properties: {
        id: { type: 'keyword' },
        title: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
        owner: { type: 'keyword' },
        due_at: { type: 'date' },
        done: { type: 'boolean' },
        done_by: { type: 'keyword' },
        done_at: { type: 'date' },
        created_by: { type: 'keyword' },
        created_at: { type: 'date' },
        order: { type: 'integer' },
      },
    },
    task_counts: {
      properties: {
        open: { type: 'long' },
        done: { type: 'long' },
      },
    },
    // TaskLists applied to the case (step 2.2): the idempotency marker
    // `applyTaskListTasks` checks before appending a task list's tasks again.
    // Added under MAPPING_VERSION 18 (bumped by step 2.1 in the same phase).
    applied_task_lists: {
      type: 'object',
      dynamic: false,
      properties: {
        task_list_id: { type: 'keyword' },
        applied_at: { type: 'date' },
        applied_by: { type: 'keyword' },
      },
    },
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
        disposition: { type: 'keyword' },
        assignTo: { type: 'keyword' },
        // TaskList applied when the rule creates a new case (step 2.2).
        applyTaskListId: { type: 'keyword' },
        // Notify channels (step 1.4, MAPPING_VERSION 23): the bound channel ids a rule notifies.
        notify: { properties: { channelIds: { type: 'keyword' } } },
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
    source_family: { type: 'keyword' },
    document_type: { type: 'keyword' },
    family: { type: 'keyword' },
    pattern: { type: 'keyword' },
    mode: { type: 'keyword' },
    reason: { type: 'keyword', ignore_above: 1024 },
    checked_at: { type: 'date' },
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
        // Step 2.2: task lists applied to cases this execution created, and
        // creations whose task list could not be applied (case kept, logged).
        taskListsApplied: { type: 'long' },
        taskListFailures: { type: 'long' },
        // Step 1.4 (MAPPING_VERSION 23): `rule.action` outbox entries written by
        // the notify action, and notify targets skipped (unknown / disabled
        // channel, disabled outbox, duplicate of an earlier run).
        notificationsEnqueued: { type: 'long' },
        notificationsSkipped: { type: 'long' },
      },
    },
    last_error: { type: 'object', enabled: false },
  },
};

// Enrichment lookup cache (step 6.2): one doc per source/type/value, id =
// sha256('<source_id>:<type>:<value>'). `expires_at` bounds how long a verdict
// is reused; the normalised result keeps only the fields the UI filters on.
export const enrichmentCacheMapping = {
  dynamic: false,
  properties: {
    source_id: { type: 'keyword' },
    kind: { type: 'keyword' },
    type: { type: 'keyword' },
    value: { type: 'keyword', ignore_above: 2048 },
    checked_at: { type: 'date' },
    expires_at: { type: 'date' },
    result: {
      properties: {
        source: { type: 'keyword' },
        verdict: { type: 'keyword' },
        score: { type: 'integer' },
        tags: { type: 'keyword', ignore_above: 256 },
        link: { type: 'keyword', index: false },
        summary: { type: 'keyword', index: false, ignore_above: 2048 },
        checkedAt: { type: 'date' },
      },
    },
  },
};

// Case attachments (step 5.3): links and small files. `data` holds the
// base64 file body; `enabled: false` keeps it in _source without indexing.
export const attachmentsMapping = {
  dynamic: false,
  properties: {
    case_id: { type: 'keyword' },
    kind: { type: 'keyword' },
    name: { type: 'keyword', ignore_above: 512 },
    url: { type: 'keyword', index: false, ignore_above: 2048 },
    content_type: { type: 'keyword' },
    size: { type: 'long' },
    sha256: { type: 'keyword' },
    data: { type: 'object', enabled: false },
    created_by: { type: 'keyword' },
    created_at: { type: 'date' },
  },
};

// TaskLists (step 2.2): reusable task templates. `tasks` is a plain object
// array (never queried per task; the whole list is read and written through
// server/lib/task_lists.ts). Case-insensitive name uniqueness is enforced in
// code over the bounded list (TASK_LISTS_MAX), not by the mapping.
export const taskListsMapping = {
  dynamic: false,
  properties: {
    id: { type: 'keyword' },
    name: { type: 'keyword', ignore_above: 256 },
    description: { type: 'text' },
    tasks: {
      type: 'object',
      dynamic: false,
      properties: {
        title: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
        owner: { type: 'keyword' },
        due_offset_minutes: { type: 'integer' },
        order: { type: 'integer' },
      },
    },
    enabled: { type: 'boolean' },
    created_by: { type: 'keyword' },
    created_at: { type: 'date' },
    updated_by: { type: 'keyword' },
    updated_at: { type: 'date' },
  },
};

// Notification outbox (step 1.2): one document per (event, channel) delivery.
// `payload` is the allowlisted projection the transport sends and `delivery`
// the transport's response summary; both are stored, never indexed. The
// dispatcher's due query runs on status + next_attempt_at (and claimed_at for
// stale `sending` claims); the panel filters on status / channel_id / event
// and pages by created_at + id.
export const notificationsMapping = {
  dynamic: false,
  properties: {
    id: { type: 'keyword' },
    event: { type: 'keyword' },
    channel_id: { type: 'keyword' },
    channel_kind: { type: 'keyword' },
    status: { type: 'keyword' },
    subject: { type: 'keyword', ignore_above: 512 },
    payload: { type: 'object', enabled: false },
    target_type: { type: 'keyword' },
    target_id: { type: 'keyword' },
    attempts: { type: 'integer' },
    created_at: { type: 'date' },
    next_attempt_at: { type: 'date' },
    sent_at: { type: 'date' },
    updated_at: { type: 'date' },
    claimed_by: { type: 'keyword' },
    claimed_at: { type: 'date' },
    last_error: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
    last_status_code: { type: 'integer' },
    delivery: { type: 'object', enabled: false },
    dedupe_key: { type: 'keyword' },
  },
};
