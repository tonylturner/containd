export type ConfigSubmission<T> = {
  readonly id: symbol;
  readonly cfg: T;
  readonly raw: Record<string, string>;
  readonly baseRevision?: string;
};

export type ConfigEditor<T> = {
  cfg: T;
  server: T;
  raw: Record<string, string>;
  superseded: boolean;
  pending: ConfigSubmission<T>[];
  baseRevision?: string;
  serverRevision?: string;
  conflictRevision?: string;
  olderView?: boolean;
  revisionRequired?: boolean;
};

export function sameConfig(a: unknown, b: unknown): boolean {
  const serialize = (value: unknown) => JSON.stringify(value, (_key, entry) =>
    entry instanceof Set ? [...entry].sort() : entry);
  return serialize(a) === serialize(b);
}

export function fresh<T>(cfg: T, revision?: string): ConfigEditor<T> {
  return { cfg, server: cfg, raw: {}, superseded: false, pending: [], baseRevision: revision, serverRevision: revision };
}

export function isDirty<T>(editor: ConfigEditor<T>): boolean {
  return Object.keys(editor.raw).length > 0 || !sameConfig(editor.cfg, editor.server)
    || editor.pending.some((submitted) => !sameConfig(editor.cfg, submitted.cfg) || !sameConfig(editor.raw, submitted.raw));
}

export function beginSave<T>(editor: ConfigEditor<T>, submitted: ConfigSubmission<T>): ConfigEditor<T> {
  return { ...editor, pending: [...editor.pending, submitted] };
}

/** A failure ends only its own request and never changes the draft. */
export function failSave<T>(editor: ConfigEditor<T>, submitted: ConfigSubmission<T>): ConfigEditor<T> {
  return { ...editor, pending: editor.pending.filter((entry) => entry.id !== submitted.id) };
}

/** Background reads never discard either structured or unfinished text edits. */
export function adopt<T>(editor: ConfigEditor<T>, next: T, keepEdits = true, revision?: string): ConfigEditor<T> {
  if (!keepEdits) return fresh(next, revision);
  if (!isDirty(editor) && !editor.conflictRevision && !editor.olderView) return { ...fresh(next, revision), pending: editor.pending };
  return { ...editor, server: next, serverRevision: revision, superseded: editor.superseded || revision !== editor.baseRevision || !sameConfig(next, editor.server) };
}

/** Compare the entire submitted draft, not a parsed/normalized wire payload. */
export function accept<T>(editor: ConfigEditor<T>, submitted: ConfigSubmission<T>, next: T, revision?: string): ConfigEditor<T> {
  if (!editor.pending.some((entry) => entry.id === submitted.id)) return editor;
  const settled = failSave(editor, submitted);
  return sameConfig(editor.cfg, submitted.cfg) && sameConfig(editor.raw, submitted.raw)
    ? { ...fresh(next, revision), pending: settled.pending }
    : { ...settled, server: next, superseded: false };
}

/** Apply only an acknowledged mutation, to both copies, not a background snapshot.
 * Deletes discard their row drafts; saves clear only text actually submitted.
 */
export function acceptCollection<T>(
  editor: ConfigEditor<T>,
  update: (cfg: T) => T,
  prefixes: string[] = [],
  submitted?: ConfigSubmission<T>,
  revision?: string,
): ConfigEditor<T> {
  if (submitted && !editor.pending.some((entry) => entry.id === submitted.id)) return editor;
  const raw = Object.fromEntries(Object.entries(editor.raw).filter(([key, value]) =>
    !prefixes.some((prefix) => key.startsWith(prefix)) || (submitted && value !== submitted.raw[key])));
  const settled = submitted ? failSave(editor, submitted) : editor;
  const next = { ...settled, cfg: update(editor.cfg), server: update(editor.server), raw };
  return { ...next, baseRevision: isDirty(next) ? editor.baseRevision : revision ?? editor.baseRevision,
    serverRevision: revision ?? editor.serverRevision, superseded: isDirty(next) && editor.superseded };
}

/** Explicit operator consent only; never called by refresh or save failure. */
export function keepEdits<T>(editor: ConfigEditor<T>): ConfigEditor<T> {
  if (!editor.conflictRevision) return editor;
  return { ...editor, baseRevision: editor.conflictRevision, conflictRevision: undefined, olderView: true, superseded: true, pending: [] };
}

/** Reconcile a collection read after a mutation without replacing unchanged rows'
 * local edits. Capture `before` before sending the mutation, not after a refresh.
 */
export function reconcileRows<T>(rows: T[], before: T[], next: T[], key: (row: T) => string): T[] {
  const previous = new Map(before.map((row) => [key(row), row]));
  const current = new Map(next.map((row) => [key(row), row]));
  const changed = next.filter((row) => !previous.has(key(row)) || !sameConfig(previous.get(key(row)), row));
  const removed = new Set(before.filter((row) => !current.has(key(row))).map(key));
  return changed.reduce((result, row) => upsertRow(result, row, key), rows.filter((row) => !removed.has(key(row))));
}

export function upsertRow<T>(rows: T[], next: T, key: (row: T) => string): T[] {
  return rows.some((row) => key(row) === key(next))
    ? rows.map((row) => key(row) === key(next) ? next : row)
    : [...rows, next];
}
