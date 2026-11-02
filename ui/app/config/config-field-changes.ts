export type FieldChange =
  | { kind: "value"; label: string; before: string; after: string }
  | { kind: "secret"; label: string }
  | { kind: "order"; label: string; items: string[] }
  | { kind: "item"; label: string; action: "Added" | "Removed" };

type ItemContext = { label: string; root: string };
const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object";
const display = (value: unknown) => value === undefined ? "Not set" : JSON.stringify(value);
const ITEM_LABELS: Record<string, string> = {
  "firewall.rules": "firewall rule",
  zones: "zone",
  interfaces: "interface",
};

/** Only a complete, unique key can safely replace positional array matching. */
function identityKey(before: unknown[], after: unknown[]): "id" | "name" | null {
  const items = [...before, ...after];
  for (const key of ["id", "name"] as const) {
    if (!items.length || !items.every(item =>
      record(item) && !Array.isArray(item) && typeof item[key] === "string" && item[key] !== "")) continue;
    const unique = (values: unknown[]) => new Set(values.map(item => (item as Record<string, string>)[key])).size === values.length;
    return unique(before) && unique(after) ? key : null;
  }
  return null;
}

function keyedChanges(before: unknown[], after: unknown[], key: "id" | "name", path: string, label: string): FieldChange[] {
  const index = (items: unknown[]) => new Map(items.map(item => {
    const value = item as Record<string, unknown>;
    return [value[key] as string, value] as const;
  }));
  const old = index(before);
  const next = index(after);
  const changes: FieldChange[] = [];
  if (before.length && after.length && JSON.stringify([...old.keys()]) !== JSON.stringify([...next.keys()])) {
    changes.push({ kind: "order", label, items: [...next.keys()] });
  }
  for (const id of new Set([...next.keys(), ...old.keys()])) {
    const previous = old.get(id);
    const current = next.get(id);
    const itemLabel = Object.hasOwn(ITEM_LABELS, path) ? ITEM_LABELS[path] : label;
    const item = { label: `${itemLabel} ${id}`, root: path };
    if (!previous || !current) {
      changes.push({ kind: "item", label: item.label, action: current ? "Added" : "Removed" });
    }
    const fields = new Set([...Object.keys(previous ?? {}), ...Object.keys(current ?? {})]);
    for (const field of fields) {
      if (field !== key) changes.push(...fieldChanges(previous?.[field], current?.[field], `${path}.${field}`, item));
    }
  }
  return changes;
}

/** Values come from the API's redacted review snapshot, never a local draft. */
export function fieldChanges(before: unknown, after: unknown, path: string, item?: ItemContext): FieldChange[] {
  if (JSON.stringify(before) === JSON.stringify(after)) return [];
  const label = item ? `${item.label}: ${path.slice(item.root.length + 1)}` : path;
  // Match field names, not item identifiers, and never print secret placeholders.
  if (/password|secret|privateKey|presharedKey|token|credential/i.test(path)) return [{ kind: "secret", label }];
  if ((Array.isArray(before) || before == null) && (Array.isArray(after) || after == null)) {
    const old = before ?? [];
    const next = after ?? [];
    const key = identityKey(old, next);
    if (key) return keyedChanges(old, next, key, path, label);
    if (old.length || next.length) {
      return Array.from({ length: Math.max(old.length, next.length) }, (_, index) =>
        fieldChanges(old[index], next[index], `${path}.${index}`, item)).flat();
    }
  }
  if (record(before) || record(after)) {
    const old = record(before) ? before : {};
    const next = record(after) ? after : {};
    const keys = [...new Set([...Object.keys(old), ...Object.keys(next)])];
    const fields = keys.flatMap(key => fieldChanges(old[key], next[key], `${path}.${key}`, item));
    if (!record(before) && before !== undefined) {
      fields.unshift({ kind: "value", label, before: display(before), after: "Not set" });
    }
    if (!record(after) && after !== undefined) {
      fields.push({ kind: "value", label, before: "Not set", after: display(after) });
    }
    // Empty containers and changes of container type still need a review row.
    return fields.length ? fields : [{ kind: "value", label, before: display(before), after: display(after) }];
  }
  return [{ kind: "value", label, before: display(before), after: display(after) }];
}
