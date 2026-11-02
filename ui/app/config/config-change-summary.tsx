import type { ConfigDiff } from "../../lib/api-config";
import type { DiffBlock } from "./config-utils";
import { fieldChanges } from "./config-field-changes";
import { entityChanges } from "./config-entity-changes";

export function ConfigChangeSummary({ diff, blocks, detailed = false }: { diff: ConfigDiff; blocks: DiffBlock[]; detailed?: boolean }) {
  const running = diff.running as Record<string, unknown> | null;
  const candidate = diff.candidate as Record<string, unknown> | null;
  return blocks.map(block => (
    <section key={block.key} role="region" aria-label={`${block.label}${detailed ? " field" : ""} changes`}
      className="min-w-0 rounded-xs border bg-(--surface) p-4">
      <h2 className="mb-3 text-sm font-semibold text-(--text)">{block.label}</h2>
      {block.hiddenChanges && <p className="text-sm">Secret values changed (hidden).</p>}
      {!detailed && <ul className="space-y-2 text-sm">
        {entityChanges(running?.[block.key], candidate?.[block.key], block.key).map((line, index) =>
          <li key={index} className="break-words">{line}</li>)}
      </ul>}
      <dl className="space-y-3 text-sm">
        {detailed && fieldChanges(running?.[block.key], candidate?.[block.key], block.key).map(change => (
          <div key={`${change.kind}:${change.label}`} className="min-w-0 break-words">
            <dt className="text-xs text-(--text-muted)">{change.label}</dt>
            <dd className="mt-1 whitespace-pre-wrap break-all">
              {change.kind === "secret" ? "Secret value changed (hidden)." :
                change.kind === "order" ? `Order changed: ${change.items.join(", ")}` :
                change.kind === "item" ? change.action : (
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
