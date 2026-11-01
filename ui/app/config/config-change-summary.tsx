import type { ConfigDiff } from "../../lib/api-config";
import type { DiffBlock } from "./config-utils";

type Change = { path: string; before: string; after: string };
const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object";
const display = (value: unknown) => value === undefined ? "Not set" : JSON.stringify(value);

/** Values are from the API's redacted review snapshot, never from a local draft. */
function changes(before: unknown, after: unknown, path: string): Change[] {
  if (JSON.stringify(before) === JSON.stringify(after)) return [];
  // Do not expose even redacted placeholders as old/new secret values.
  if (/password|secret|privateKey|presharedKey|token|credential/i.test(path)) {
    return [{ path, before: "changed", after: "changed" }];
  }
  if (record(before) || record(after)) {
    const old = record(before) ? before : {};
    const next = record(after) ? after : {};
    const keys = [...new Set([...Object.keys(old), ...Object.keys(next)])];
    const fields = keys.flatMap(key => changes(old[key], next[key], `${path}.${key}`));
    if (!record(before) && before !== undefined) {
      fields.unshift({ path, before: display(before), after: "Not set" });
    }
    if (!record(after) && after !== undefined) {
      fields.push({ path, before: "Not set", after: display(after) });
    }
    // Empty containers and changes of container type still need a review row.
    return fields.length ? fields : [{ path, before: display(before), after: display(after) }];
  }
  return [{ path, before: display(before), after: display(after) }];
}

export function ConfigChangeSummary({ diff, blocks }: { diff: ConfigDiff; blocks: DiffBlock[] }) {
  const running = diff.running as Record<string, unknown> | null;
  const candidate = diff.candidate as Record<string, unknown> | null;
  return blocks.map(block => (
    <section key={block.key} role="region" aria-label={`${block.label} changes`}
      className="min-w-0 rounded-xs border bg-(--surface) p-4">
      <h2 className="mb-3 text-sm font-semibold text-(--text)">{block.label}</h2>
      {block.hiddenChanges && <p className="text-sm">Secret values changed (hidden).</p>}
      <dl className="space-y-3 text-sm">
        {changes(running?.[block.key], candidate?.[block.key], block.key).map(change => (
          <div key={change.path} className="min-w-0 break-words">
            <dt className="text-xs text-(--text-muted)">{change.path}</dt>
            <dd className="mt-1 whitespace-pre-wrap break-all">
              {change.before === "changed" && change.after === "changed" ? "Secret value changed (hidden)." : (
                <><span aria-label="Old value">{change.before}</span>
                  <span aria-hidden="true"> → </span><span className="sr-only"> to </span>
                  <span aria-label="New value" className="text-mint">{change.after}</span></>
              )}
            </dd>
          </div>
        ))}
        {block.idsBank && <div>
          <dt>IDS rule bank</dt>
          <dd>Running: {block.idsBank.running.count.toLocaleString()} rules → Staged: {block.idsBank.candidate.count.toLocaleString()} rules</dd>
          <dd className="text-xs text-(--text-muted)">Rule bank changed. Exact fingerprints are in Advanced.</dd>
        </div>}
      </dl>
    </section>
  ));
}
