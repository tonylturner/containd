export type ConfigEditor<T> = {
  cfg: T;
  server: T;
  raw: Record<string, string>;
  superseded: boolean;
};

export function sameConfig(a: unknown, b: unknown): boolean {
  const serialize = (value: unknown) => JSON.stringify(value, (_key, entry) =>
    entry instanceof Set ? [...entry].sort() : entry);
  return serialize(a) === serialize(b);
}

export function fresh<T>(cfg: T): ConfigEditor<T> {
  return { cfg, server: cfg, raw: {}, superseded: false };
}

export function isDirty<T>(editor: ConfigEditor<T>): boolean {
  return Object.keys(editor.raw).length > 0 || !sameConfig(editor.cfg, editor.server);
}

/** Background reads never discard either structured or unfinished text edits. */
export function adopt<T>(editor: ConfigEditor<T>, next: T, keepEdits = true): ConfigEditor<T> {
  if (!keepEdits || !isDirty(editor)) return fresh(next);
  return { ...editor, server: next, superseded: editor.superseded || !sameConfig(next, editor.server) };
}

/** Compare the entire submitted draft, not a parsed/normalized wire payload. */
export function accept<T>(editor: ConfigEditor<T>, submitted: ConfigEditor<T>, next: T): ConfigEditor<T> {
  return sameConfig(editor.cfg, submitted.cfg) && sameConfig(editor.raw, submitted.raw)
    ? fresh(next)
    : { ...editor, server: next, superseded: false };
}

/** Apply only an acknowledged mutation, to both copies, not a background snapshot.
 * Deletes discard their row drafts; saves clear only text actually submitted.
 */
export function acceptCollection<T>(
  editor: ConfigEditor<T>,
  update: (cfg: T) => T,
  prefixes: string[] = [],
  submitted?: ConfigEditor<T>,
): ConfigEditor<T> {
  const raw = Object.fromEntries(Object.entries(editor.raw).filter(([key, value]) =>
    !prefixes.some((prefix) => key.startsWith(prefix)) || (submitted && value !== submitted.raw[key])));
  const next = { ...editor, cfg: update(editor.cfg), server: update(editor.server), raw };
  return { ...next, superseded: isDirty(next) && editor.superseded };
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
