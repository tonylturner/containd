const record = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const names: Record<string, [string, string]> = {
  "firewall.rules": ["Firewall rule", "firewall rules"],
  zones: ["Zone", "zones"],
  interfaces: ["Interface", "interfaces"],
  assets: ["Asset", "assets"],
  objects: ["Object", "objects"],
};
function title(path: string): string {
  const label = path.replaceAll(".", " / ").replace(/([a-z])([A-Z])/g, "$1 $2");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

/** Summarize entities without printing their contents or positional JSON paths. */
export function entityChanges(before: unknown, after: unknown, path: string): string[] {
  if (same(before, after)) return [];
  if (/password|secret|privateKey|presharedKey|token|credential/i.test(path)) {
    return [`${title(path)} changed (hidden).`];
  }
  if ((before == null || Array.isArray(before)) && (after == null || Array.isArray(after))) {
    const old = (before ?? []) as unknown[];
    const next = (after ?? []) as unknown[];
    const all = [...old, ...next];
    const key = (["id", "name"] as const).find(key => all.length > 0 &&
      all.every(v => record(v) && typeof v[key] === "string" && v[key] !== "") &&
      [old, next].every(items => new Set(items.map(v => (v as Record<string, string>)[key])).size === items.length));
    const [singular, plural] = names[path] ?? [title(path), title(path).toLowerCase()];
    if (!key) return [`${title(path)} changed (${old.length} → ${next.length} entries).`];
    const index = (items: unknown[]) => new Map(items.map(v => [(v as Record<string, string>)[key], v]));
    const previous = index(old), current = index(next);
    const added = [...current.keys()].filter(id => !previous.has(id));
    const removed = [...previous.keys()].filter(id => !current.has(id));
    const changed = [...current.keys()].filter(id => previous.has(id) && !same(previous.get(id), current.get(id)));
    const lines: string[] = [];
    for (const [ids, action] of [[added, "added"], [removed, "removed"], [changed, "changed"]] as const) {
      if (ids.length) lines.push(`${ids.length} ${ids.length === 1 ? singular.toLowerCase() : plural} ${action}`);
      if (path !== "firewall.rules") lines.push(...ids.map(id => `${singular} ${id} ${action}`));
    }
    // Membership changes are not themselves reorder operations.
    const retainedOld = [...previous.keys()].filter(id => current.has(id));
    const retainedNew = [...current.keys()].filter(id => previous.has(id));
    if (!same(retainedOld, retainedNew)) lines.push(`${title(path)} order changed`);
    return lines;
  }
  if (record(before) || record(after)) {
    const old = record(before) ? before : {}, next = record(after) ? after : {};
    return [...new Set([...Object.keys(old), ...Object.keys(next)])]
      .flatMap(key => entityChanges(old[key], next[key], `${path}.${key}`));
  }
  return [`${title(path)} changed`];
}
