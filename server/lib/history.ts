// Shared painless snippet for appending an audit-history entry to a
// document without clobbering other fields set by concurrent writers
// (e.g. the background sync job).
export const APPEND_HISTORY_SCRIPT_SOURCE = `
  if (ctx._source.history == null) { ctx._source.history = []; }
  ctx._source.history.add(params.entry);
  if (params.fields != null) {
    for (entry in params.fields.entrySet()) {
      ctx._source[entry.getKey()] = entry.getValue();
    }
  }
`;

export interface HistoryEntryInput {
  user: string;
  action: string;
  from?: string | null;
  to?: string | null;
}

export function buildHistoryEntry(input: HistoryEntryInput) {
  return {
    timestamp: new Date().toISOString(),
    user: input.user,
    action: input.action,
    from: input.from ?? null,
    to: input.to ?? null,
  };
}
