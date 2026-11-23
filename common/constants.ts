export const PLUGIN_ID = 'wazuhAlertManager';
export const PLUGIN_NAME = 'wazuh-alert-manager';

// v2 storage keeps the install-and-go permissions profile of older releases
// while remaining disjoint from Wazuh's native `wazuh-alerts-*` family.
// Write validation uses these exact prefixes; never broaden them to
// `wazuh-alert*` or add a native Wazuh index.
export const MANAGED_INDEX_PREFIXES = [
  'wazuh-alert-status-v2-',
  'wazuh-alert-manager-v2-',
] as const;

export const ALERTS_READ_ALIAS = 'wazuh-alert-status-v2-read';
export const ALERTS_WRITE_ALIAS = 'wazuh-alert-status-v2-write';
// Numeric rollover generations only. Carry-forward staging indices deliberately
// sit outside these templates until an atomic alias cutover.
export const ALERTS_INDEX_PATTERN = 'wazuh-alert-status-v2-0*';
export const ALERTS_INITIAL_INDEX = 'wazuh-alert-status-v2-000001';

export const ACTIVITY_READ_ALIAS = 'wazuh-alert-manager-v2-activity-read';
export const ACTIVITY_WRITE_ALIAS = 'wazuh-alert-manager-v2-activity-write';
export const ACTIVITY_INDEX_PATTERN = 'wazuh-alert-manager-v2-activity-0*';
export const ACTIVITY_INITIAL_INDEX = 'wazuh-alert-manager-v2-activity-000001';

// Rollable case-evidence relationship family. One bounded document per
// case-alert link: archive location, provenance, lifecycle state, optional
// hold, and a compact snapshot sufficient for case context and attack-path
// reconstruction when the full alert is archived or purged.
export const EVIDENCE_READ_ALIAS = 'wazuh-alert-manager-v2-evidence-read';
export const EVIDENCE_WRITE_ALIAS = 'wazuh-alert-manager-v2-evidence-write';
export const EVIDENCE_INDEX_PATTERN = 'wazuh-alert-manager-v2-evidence-0*';
export const EVIDENCE_INITIAL_INDEX = 'wazuh-alert-manager-v2-evidence-000001';

// ALERT_STATUS_INDEX remains as a compatibility symbol for route code while
// its value is now the v2 read alias. New code should prefer the explicit alias.
export const ALERT_STATUS_INDEX = ALERTS_READ_ALIAS;
export const COMMENTS_INDEX = ACTIVITY_READ_ALIAS;

// Cases are alias-backed like the other v2 families. Reads go through the read
// alias (every retained generation is searchable); writes go through the write
// alias (a single numeric generation). CASES_INDEX is the read alias so existing
// case reads keep working; writes must use CASES_WRITE_ALIAS.
export const CASES_READ_ALIAS = 'wazuh-alert-manager-v2-cases-read';
export const CASES_WRITE_ALIAS = 'wazuh-alert-manager-v2-cases-write';
export const CASES_INDEX_PATTERN = 'wazuh-alert-manager-v2-cases-0*';
export const CASES_INITIAL_INDEX = 'wazuh-alert-manager-v2-cases-000001';
// Pre-alias v2 singleton, retained read-only after the cases alias migration.
export const CASES_V2_SINGLETON_INDEX = 'wazuh-alert-manager-v2-cases';
export const CASES_INDEX = CASES_READ_ALIAS;

export const META_INDEX = 'wazuh-alert-manager-v2-meta';
export const RULES_INDEX = 'wazuh-alert-manager-v2-rules';
export const MIGRATION_INDEX = 'wazuh-alert-manager-v2-migration';
export const SYNC_DLQ_INDEX = 'wazuh-alert-manager-v2-sync-dlq';
export const AUTOMATION_QUEUE_INDEX = 'wazuh-alert-manager-v2-automation-queue';
export const AUTOMATION_DLQ_INDEX = 'wazuh-alert-manager-v2-automation-dlq';
export const AUTOMATION_EXECUTIONS_INDEX = 'wazuh-alert-manager-v2-automation-executions';
export const AUTOMATION_RULESET_SNAPSHOT_PREFIX = 'automation-ruleset:';
export const AUTOMATION_SETTINGS_DOC_ID = 'automation-settings';
export const AUTOMATION_WORKER_LEASE_ID = 'automation-worker-lease';
export const AUTOMATION_DEFAULT_MAX_BACKLOG = 10000;
export const AUTOMATION_DEFAULT_MAX_DEFERRED = 50000;
export const AUTOMATION_MAX_ENABLED_RULES = 200;
export const AUTOMATION_MAX_RULE_SNAPSHOT_BYTES = 1024 * 1024;
export const AUTOMATION_ADMISSION_RECONCILE_BATCH = 100;
export const AUTOMATION_BULK_MAX_ACTIONS = 500;
export const AUTOMATION_BULK_MAX_BYTES = 5 * 1024 * 1024;

// Read-only migration inputs. They are never provisioned, mapped, deleted, or
// targeted by normal v2 writes.
export const LEGACY_ALERT_STATUS_INDEX = 'wazuh-alert-status';
export const LEGACY_COMMENTS_INDEX = 'wazuh-alert-manager-comments';
export const LEGACY_CASES_INDEX = 'wazuh-alert-manager-cases';
export const LEGACY_META_INDEX = 'wazuh-alert-manager-meta';
export const LEGACY_RULES_INDEX = 'wazuh-alert-manager-rules';

export const API_ROOT = '/api/wazuh_alert_manager';

export const ALERT_STATUSES = ['open', 'in_progress', 'closed'] as const;

export const CASE_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export const CASE_STATUSES = ['open', 'in_progress', 'closed'] as const;

// Dispositions (step 2.4): the outcome recorded when a case or an alert is
// closed. Stored verbatim as `disposition` (keyword) with an optional free-text
// `closure_reason`; a case close propagates both onto every alert it closes.
// Reopening clears neither (kept for audit); the UI shows the badge only on
// closed records. `undetermined` is what the close route stores when a client
// predating this step closes a case without one.
export const DISPOSITIONS = ['true_positive', 'false_positive', 'benign', 'duplicate', 'undetermined'] as const;
export const DISPOSITION_LABELS: Record<typeof DISPOSITIONS[number], string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
  duplicate: 'Duplicate',
  undetermined: 'Undetermined',
};
/** One-line descriptions shown by the close dialog next to each label. */
export const DISPOSITION_DESCRIPTIONS: Record<typeof DISPOSITIONS[number], string> = {
  true_positive: 'Confirmed malicious or policy-violating activity that needed a response.',
  false_positive: 'The detection fired, but the activity was not what the rule describes.',
  benign: 'Real activity matching the rule, but expected and authorised (no response needed).',
  duplicate: 'Already covered by another alert or case.',
  undetermined: 'Closed without a conclusive outcome.',
};
export const DEFAULT_DISPOSITION: typeof DISPOSITIONS[number] = 'undetermined';
export const CLOSURE_REASON_MAX_LENGTH = 2000;
/** Rules listed by the "false-positive rate by rule" report table (terms on rule.id, exact within the bucket). */
export const DISPOSITION_RULE_BUCKETS_MAX = 25;

export const AI_PROVIDERS = ['openai', 'deepseek', 'gemini', 'anthropic'] as const;

export const AI_SETTINGS_DOC_ID = 'ai_settings';

// Correlation rules: entity types an alert can be grouped by, and the ceiling
// on how many cases one evaluation pass may auto-create (blast-radius guard).
export const CORRELATION_ENTITIES = [
  'agent', 'srcip', 'dstip', 'srcport', 'dstport', 'user', 'dstuser', 'process',
  // Indicator kinds (step 6.1): canonical forms from common/indicators.ts.
  'hash', 'domain', 'url',
] as const;
export const MAX_AUTO_CASES_PER_RUN = 20;


// Bounds for the native threat / context data the projection ingests onto the
// canonical alert record (step 6.1). The sync job copies at most this many
// entries so an enrichment-heavy finding cannot bloat the operational index.
export const MAX_THREAT_MATCHES = 20;
export const MAX_RELATED_VALUES = 50;
export const MAX_GEO_HINTS = 4;
// Bounds for the read-only Wazuh 5.0 `wazuh.case.*` projection (step 2.6,
// decision Q6): copied verbatim onto the canonical record, never written back.
export const NATIVE_CASE_TAGS_MAX = 20;
export const NATIVE_CASE_TAG_MAX_LENGTH = 128;
export const NATIVE_CASE_TITLE_MAX_LENGTH = 512;
export const NATIVE_CASE_VALUE_MAX_LENGTH = 64;
/** Evidence relationships the per-case indicator aggregation reads at most. */
export const MAX_CASE_INDICATOR_ALERTS = 5000;

// Case attachments (step 5.3 builds the routes; 5.2 reads the index
// defensively for the case report, treating "index missing" as "no attachments").
export const ATTACHMENTS_INDEX = 'wazuh-alert-manager-v2-attachments';
export const ATTACHMENT_KINDS = ['link', 'file'] as const;
/** Decoded file size cap (checked on the decoded bytes, never the base64 length). */
export const ATTACHMENT_MAX_FILE_BYTES = 2 * 1024 * 1024;
/** Attachments (links + files) one case may hold. */
export const ATTACHMENT_MAX_PER_CASE = 20;
export const ATTACHMENT_MAX_NAME_LENGTH = 255;
export const ATTACHMENT_MAX_URL_LENGTH = 2048;
/** JSON request cap for POST .../attachments: base64 of 2 MiB plus the envelope. */
export const ATTACHMENT_REQUEST_MAX_BYTES = 3 * 1024 * 1024;
/** Media types a file attachment may declare; anything else is refused on upload and on download. */
export const ATTACHMENT_ALLOWED_CONTENT_TYPES = [
  'text/plain',
  'text/csv',
  'application/json',
  'application/pdf',
  'image/png',
  'image/jpeg',
  'application/zip',
  'application/x-pcap',
  'application/vnd.tcpdump.pcap',
] as const;
// Case tasks (step 2.1): a nested `tasks[]` checklist on the case document
// plus a denormalised `task_counts {open, done}` for the queue chip. Every
// mutation goes through the pure helpers in server/lib/case_tasks.ts.
export const CASE_TASKS_MAX = 100;
export const CASE_TASK_TITLE_MAX_LENGTH = 200;
export const CASE_TASK_OWNER_MAX_LENGTH = 256;
export const TASK_ADDED_ACTION = 'task_added';
export const TASK_UPDATED_ACTION = 'task_updated';
export const TASK_COMPLETED_ACTION = 'task_completed';
export const TASK_REOPENED_ACTION = 'task_reopened';
export const TASK_REMOVED_ACTION = 'task_removed';
// TaskLists (step 2.2): reusable task templates in a fixed managed index.
// Applying one appends its tasks to a case through server/lib/case_tasks.ts
// (idempotent per task list per case via `applied_task_lists` on the case doc).
export const TASK_LISTS_INDEX = 'wazuh-alert-manager-v2-task-lists';
export const TASK_LIST_TASKS_MAX = 50;
export const TASK_LISTS_MAX = 200;
export const TASK_LIST_NAME_MAX_LENGTH = 120;
export const TASK_LIST_DESCRIPTION_MAX_LENGTH = 2000;
export const TASK_LIST_DUE_OFFSET_MIN_MINUTES = 1;
/** One year in minutes. */
export const TASK_LIST_DUE_OFFSET_MAX_MINUTES = 525600;
export const TASK_LIST_CREATED_ACTION = 'task_list_created';
export const TASK_LIST_UPDATED_ACTION = 'task_list_updated';
export const TASK_LIST_DELETED_ACTION = 'task_list_deleted';
export const TASK_LIST_APPLIED_ACTION = 'task_list_applied';
// Case report (step 5.2): evidence relationships paged into one report, how
// many alerts the report lists in full (every resolved alert: the plan asks
// for all linked alerts up to the evidence cap) and the merged timeline cap.
export const MAX_CASE_REPORT_ALERTS = 5000;
export const CASE_REPORT_LISTED_ALERTS = MAX_CASE_REPORT_ALERTS;
export const CASE_REPORT_TIMELINE_LIMIT = 500;
// Case timeline (step 2.3): default page of `GET /cases/{id}/timeline` and the
// evidence cap of the alert source (older relationships beyond it are reported
// through `truncated_alerts`, never silently dropped).
export const CASE_TIMELINE_PAGE = 100;
export const CASE_TIMELINE_ALERTS_MAX = 1000;

// Enrichment sources (step 6.2): the settings document in META_INDEX, the
// fixed cache index and the bounds every source goes through.
export const ENRICHMENT_SETTINGS_DOC_ID = 'enrichment_settings';
export const ENRICHMENT_CACHE_INDEX = 'wazuh-alert-manager-v2-enrichment-cache';
export const ENRICHMENT_SOURCE_KINDS = ['abuseipdb', 'misp', 'generic_http', 'wazuh_cti_local'] as const;
export const ENRICHMENT_VERDICTS = ['malicious', 'suspicious', 'clean', 'unknown'] as const;
/** Indicator types a source can be asked about (subset of common/indicators.ts types). */
export const ENRICHMENT_LOOKUP_TYPES = ['ip', 'domain', 'url', 'hash'] as const;
/** Id of the zero-config built-in source that reads the local 5.0 CTI catalog. */
export const WAZUH_CTI_LOCAL_SOURCE_ID = 'wazuh_cti_local';
export const ENRICHMENT_DEFAULT_TIMEOUT_MS = 8000;
export const ENRICHMENT_MAX_TIMEOUT_MS = 30000;
export const ENRICHMENT_DEFAULT_CACHE_TTL_SECONDS = 3600;
export const ENRICHMENT_MAX_CACHE_TTL_SECONDS = 30 * 24 * 3600;
export const ENRICHMENT_MAX_SOURCES = 20;
export const ENRICHMENT_MAX_TAGS = 25;
/** Indicator types each source kind can answer (shared by the server validator and the settings tab). */
export const ENRICHMENT_KIND_CAPABILITIES: Record<typeof ENRICHMENT_SOURCE_KINDS[number], Array<typeof ENRICHMENT_LOOKUP_TYPES[number]>> = {
  abuseipdb: ['ip'],
  misp: ['ip', 'domain', 'url', 'hash'],
  generic_http: ['ip', 'domain', 'url', 'hash'],
  wazuh_cti_local: ['ip', 'domain', 'url', 'hash'],
};
/** Kinds that cannot work without a stored API key. */
export const ENRICHMENT_KIND_NEEDS_KEY: Record<typeof ENRICHMENT_SOURCE_KINDS[number], boolean> = {
  abuseipdb: true,
  misp: true,
  generic_http: false,
  wazuh_cti_local: false,
};
/**
 * App-relative path of the Wazuh 5.0 CTI Explorer. Not an egress URL and not
 * an `EnrichmentResult.link`: the browser prepends the dashboard basePath and
 * only offers it on 5.0 builds.
 */
export const CTI_EXPLORER_APP_PATH = '/app/cti-explorer';

// Stored enrichment (step 6.3): the bounded `enrichment` object a per-alert
// lookup writes onto the alert record (plugin-owned, mapped, never resynced).
export const MAX_ALERT_ENRICHMENT_ITEMS = 50;
export const MAX_ALERT_ENRICHMENT_TAGS = 10;
/** Queue filter values for `enrichment.worst_verdict` (the UI's `any` = no filter). */
export const ENRICHMENT_VERDICT_FILTERS = ['malicious', 'suspicious', 'clean'] as const;

// Asset criticality (step 6.4a): the settings document in META_INDEX and the
// bounds every entry goes through. Matching precedence is fixed:
// exact name > glob > group > label; first match wins inside a kind.
export const ASSET_SETTINGS_DOC_ID = 'asset_settings';
export const ASSET_CRITICALITIES = ['low', 'medium', 'high', 'critical'] as const;
export const ASSET_MATCH_KINDS = ['name', 'glob', 'group', 'label'] as const;
export const ASSET_MAX_ENTRIES = 500;
export const ASSET_MAX_TAGS = 20;
export const ASSET_MAX_GROUPS = 50;
export const ASSET_MAX_LABELS = 20;
/** 4.x agent groups come from the Wazuh server API; the sync job caches them per agent id for this long. */
export const ASSET_GROUP_CACHE_TTL_MS = 10 * 60 * 1000;

// Scheduled summaries (step 5.4): the settings document in META_INDEX, the
// id prefix of each schedule's stored last run and the bounds a schedule
// goes through. Delivery (channelIds) is wired by phase 1; until then the
// ids are only stored and validated as strings.
export const REPORT_SCHEDULES_DOC_ID = 'report_schedules';
export const REPORT_RUN_DOC_PREFIX = 'report_run:';
export const REPORT_SCHEDULER_LEASE_ID = 'report_scheduler';
export const REPORT_SCHEDULE_CADENCES = ['daily', 'weekly'] as const;
export const REPORT_SCHEDULES_MAX = 20;
export const REPORT_SCHEDULE_MAX_RANGE_DAYS = 90;
export const REPORT_SCHEDULE_MAX_CHANNELS = 20;
export const REPORT_SCHEDULE_TOP_N = 10;
/** Stored Markdown is cut at this many bytes (UTF-8) with a trailing note. */
export const REPORT_RUN_MARKDOWN_MAX_BYTES = 256 * 1024;
/** Scheduler attempts at one slot before a failing schedule waits for its next slot. */
export const REPORT_RUN_MAX_ATTEMPTS = 3;
/** Formats of `GET /reports/export` (step 10.3); PDF is the browser's Save as PDF from the print view of `html`. */
export const REPORT_EXPORT_FORMATS = ['html', 'markdown', 'csv', 'json'] as const;
export type ReportExportFormat = (typeof REPORT_EXPORT_FORMATS)[number];

// SLA policy (step 3.1): the settings document in META_INDEX that holds the
// per-band resolve/assign targets and (from step 3.3) the escalation rules.
// Targets are minutes; the four bands are the numeric ones of
// common/severity.ts (`informational` only comes from a 5.0 label and is
// treated as `low`, exactly like `effectiveLevel`).
export const SLA_POLICY_DOC_ID = 'sla_policy';
export const SLA_BANDS = ['critical', 'high', 'medium', 'low'] as const;
export const SLA_MINUTES_MIN = 1;
/** One year in minutes. */
export const SLA_MINUTES_MAX = 525600;
export const SLA_MAX_ESCALATIONS = 20;
export const SLA_ESCALATION_TARGETS = ['alert', 'case'] as const;
export const SLA_ESCALATION_CONDITIONS = ['unassigned', 'untouched', 'any'] as const;
export const SLA_ESCALATION_MAX_NOTIFY = 20;
/** `getSlaPolicy` caches the stored policy per process for this long; a PUT invalidates the local cache. */
export const SLA_POLICY_CACHE_TTL_MS = 60 * 1000;
export const SLA_POLICY_UPDATED_ACTION = 'sla_policy_updated';
// Due timestamps (step 3.2). `reporting.sla_due_at` / `reporting.assign_due_at`
// on alerts and `sla_due_at` on cases are computed from the policy targets;
// a record is "due soon" inside this many minutes of its resolve due date.
export const SLA_DUE_SOON_MINUTES = 60;
export const SLA_STATES = ['breached', 'due_soon', 'on_track'] as const;
/** META_INDEX doc holding the progress/last run of the due-date backfill a policy change schedules. */
export const SLA_DUE_BACKFILL_DOC_ID = 'sla_due_backfill';
// Escalation scanner (step 3.3): a lease-based tick over open/in_progress
// alerts and open cases that stamps `sla.breached_at` once a due date has
// passed and applies the policy's `escalations[]` once per record
// (`sla.escalated[]` markers). Activity actions `sla_breached` /
// `sla_escalated` are written once per record (and per escalation).
export const SLA_ESCALATION_LEASE_ID = 'sla_escalation';
export const SLA_ESCALATION_STATUS_DOC_ID = 'sla_escalation_status';
/** Escalation candidates applied per tick (across every escalation); the rest wait for the next tick. */
export const SLA_ESCALATION_MAX_ACTIONS_PER_TICK = 500;
/** Breach markers written per tick (alerts and cases each); the rest wait for the next tick. */
export const SLA_BREACH_MAX_PER_TICK = 5000;
/**
 * Default of `sla.escalation.breachNotifyGraceMinutes`: a record whose due
 * date passed more than this long before the tick that stamps it is still
 * stamped (activity, history, badge) but sends no `sla.breached` notification,
 * so enabling SLA enforcement or binding the event on an install with an
 * overdue backlog does not flood the channels. 0 disables the cut-off.
 */
export const SLA_BREACH_NOTIFY_GRACE_MINUTES = 24 * 60;
export const SLA_SCAN_PAGE_SIZE = 500;
export const SLA_ESCALATION_STATUS_MAX_ERRORS = 10;
export const SLA_BREACHED_ACTION = 'sla_breached';
export const SLA_ESCALATED_ACTION = 'sla_escalated';
/** Actor recorded on history entries, activity events and comments the scanner writes. */
export const SLA_ESCALATION_ACTOR = 'system:sla';

// Notifications (phase 1, step 1.1): the settings document in META_INDEX that
// binds delivery channels to events. Two channel kinds: `indexer_channel`
// references a channel of the indexer Notifications plugin (Slack, Teams,
// chime, webhook, email, SNS; CRUD stays in the Notifications app) and is
// driven through an inline Alerting `_execute`; `webhook` is a direct,
// HMAC-signed POST from the dashboard server through the egress policy.
export const NOTIFICATION_SETTINGS_DOC_ID = 'notification_settings';
export const NOTIFICATION_EVENTS = [
  'case.created',
  'case.assigned',
  'case.severity_raised',
  'case.closed',
  'sla.breached',
  'sla.escalated',
  'rule.action',
  'report.scheduled',
] as const;
export const NOTIFICATION_CHANNEL_KINDS = ['indexer_channel', 'webhook'] as const;
/** Channel id shape, shared by the settings validator and the editor (client-side feedback before the 400). */
export const NOTIFICATION_CHANNEL_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export const NOTIFICATION_MAX_CHANNELS = 50;
export const NOTIFICATION_MAX_WEBHOOK_HEADERS = 10;
export const NOTIFICATION_CHANNEL_NAME_MAX_LENGTH = 120;
export const NOTIFICATION_CONFIG_ID_MAX_LENGTH = 256;
/** Most channel ids one automation rule's `notify` action may name (step 1.4). */
export const RULE_NOTIFY_MAX_CHANNELS = 20;
/** `getNotificationChannels` caches the stored settings per process for this long; a PUT invalidates the local cache. */
export const NOTIFICATION_SETTINGS_CACHE_TTL_MS = 30 * 1000;
export const NOTIFICATION_SETTINGS_UPDATED_ACTION = 'notification_settings_updated';
/**
 * Outbox index (step 1.2): one document per (event, channel) delivery with
 * its attempts, backoff and dead-letter state. Fixed singleton, no rollover.
 */
export const NOTIFICATIONS_INDEX = 'wazuh-alert-manager-v2-notifications';
/** Same index as NOTIFICATIONS_INDEX (name used by the transports since 1.1); the inline monitor's search input targets it. */
export const NOTIFICATIONS_OUTBOX_INDEX = NOTIFICATIONS_INDEX;
/**
 * Outbox lifecycle: `pending` (queued), `sending` (claimed by a dispatcher
 * replica; reclaimable after NOTIFICATION_CLAIM_STALE_MS), `sent`, `failed`
 * (retry scheduled at `next_attempt_at`), `dead` (gave up after
 * NOTIFICATION_MAX_ATTEMPTS attempts, or the channel is gone; an administrator
 * can retry it).
 */
export const NOTIFICATION_STATUSES = ['pending', 'sending', 'sent', 'failed', 'dead'] as const;
/** What an outbox entry is about; `target_id` is the case / alert / report id (or a doc id for `system`). */
export const NOTIFICATION_TARGET_TYPES = ['case', 'alert', 'report', 'system'] as const;
/** Delivery attempts before an entry is dead-lettered. */
export const NOTIFICATION_MAX_ATTEMPTS = 5;
/** Delay before the next attempt, indexed by the number of attempts already made (1 -> 30 s, 2 -> 2 min, ...). */
export const NOTIFICATION_BACKOFF_SECONDS = [30, 120, 600, 1800, 3600] as const;
/** Due entries claimed per dispatcher tick, and the outbox list page size. */
export const NOTIFICATION_OUTBOX_PAGE = 50;
export const OUTBOX_PAGE = NOTIFICATION_OUTBOX_PAGE;
/** Largest `limit` the outbox list route accepts. */
export const NOTIFICATION_OUTBOX_LIST_MAX = 200;
/** A `sending` claim older than this is treated as abandoned (crashed replica) and reclaimed. */
export const NOTIFICATION_CLAIM_STALE_MS = 10 * 60 * 1000;
/** A webhook secret that cannot be decrypted (no WAZUH_ALERT_MANAGER_ENCRYPTION_KEY) is retried this much later, not on the backoff table. */
export const NOTIFICATION_MISSING_KEY_RETRY_MS = 60 * 60 * 1000;
/**
 * `report.scheduled` (step 1.3) carries the rendered Markdown of the run in
 * `payload.report.markdown`, cut on a UTF-8 boundary at this many bytes (the
 * Notifications channel message and the webhook body both carry it).
 */
export const NOTIFICATION_REPORT_MARKDOWN_MAX_BYTES = 24 * 1024;
/** Outbox entries per `client.bulk` when an emitter writes a batch (`enqueueMany`). */
export const NOTIFICATION_ENQUEUE_BULK_SIZE = 500;
export const NOTIFICATION_DISPATCHER_LEASE_ID = 'notification_dispatcher';
export const NOTIFICATION_DISPATCHER_STATUS_DOC_ID = 'notification_dispatcher_status';
export const NOTIFICATION_DISPATCHER_STATUS_MAX_ERRORS = 10;
/** The dispatcher renews its lease after this many delivered entries (and whenever a third of the TTL has elapsed). */
export const NOTIFICATION_DISPATCHER_LEASE_RENEW_EVERY = 5;
/** An idle tick (nothing claimed, no errors) rewrites the status doc only when the stored one is older than this. */
export const NOTIFICATION_DISPATCHER_STATUS_IDLE_WRITE_MS = 60 * 1000;
/** Appended to a 403 recorded in `last_error` by either transport. */
export const NOTIFICATION_FORBIDDEN_HINT = 'map role wazuh_alert_manager_notify to the dashboard user';
export const NOTIFICATION_LAST_ERROR_MAX_LENGTH = 1024;
export const NOTIFICATION_RETRIED_ACTION = 'notification_retried';
/** Dashboard app of the indexer Notifications plugin (channel CRUD); prepend server.basePath in the browser. */
export const NOTIFICATIONS_CHANNELS_APP_PATH = '/app/notifications-dashboards#/channels';
/** Notifications config types a channel binding may reference (`email_group` / `smtp_account` are not channels). */
export const NOTIFICATION_INDEXER_CHANNEL_TYPES = ['slack', 'chime', 'webhook', 'email', 'microsoft_teams', 'sns'] as const;
export const NOTIFICATION_CHANNEL_WARNINGS = ['missing_json_content_type', 'disabled_placeholder'] as const;
export const NOTIFICATION_WEBHOOK_TIMEOUT_MS = 10 * 1000;
export const NOTIFICATION_WEBHOOK_MAX_RESPONSE_BYTES = 64 * 1024;
/** Fixed content type of direct webhook deliveries; the signature covers the raw body. */
export const NOTIFICATION_WEBHOOK_CONTENT_TYPE = 'application/json';
