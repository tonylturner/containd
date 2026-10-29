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

export function upsertRow<T>(rows: T[], next: T, key: (row: T) => string): T[] {
  return rows.some((row) => key(row) === key(next))
    ? rows.map((row) => key(row) === key(next) ? next : row)
    : [...rows, next];
}
