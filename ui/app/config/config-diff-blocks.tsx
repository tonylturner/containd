import type { DiffBlock } from "./config-utils";

/** Render the exact snapshot reviewed by a configuration operation. */
export function ConfigDiffBlocks({ blocks }: { blocks: DiffBlock[] }) {
  return blocks.map((block) => (
    <div
      key={block.key}
      role="region"
      aria-label={`${block.label} JSON changes`}
      className="rounded-xs border bg-(--surface) p-4 shadow-card"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-(--text-dim)">Changed block</div>
          <div className="text-sm font-semibold text-(--text)">{block.label}</div>
        </div>
        {block.diff.length > 0 && (
          <div className="text-xs text-(--text-muted)">
            {block.diff.filter((l) => l.type === "add").length} added ·{" "}
            {block.diff.filter((l) => l.type === "del").length} removed
          </div>
        )}
      </div>
      {block.hiddenChanges && (
        <p className="text-sm text-(--text)">Secret values changed (hidden).</p>
      )}
      {block.idsBank && (
        <div className="mb-3 grid gap-1 text-xs text-(--text)">
          <div className="font-semibold">IDS rule bank</div>
          <div>
            Running: {block.idsBank.running.count.toLocaleString()} rules · SHA-256{" "}
            <span className="font-mono">{block.idsBank.running.sha256.slice(0, 12)}</span>
          </div>
          <div>
            Staged: {block.idsBank.candidate.count.toLocaleString()} rules · SHA-256{" "}
            <span className="font-mono">{block.idsBank.candidate.sha256.slice(0, 12)}</span>
          </div>
        </div>
      )}
      {block.diff.length > 0 && (
        <div className="grid gap-1 rounded-xs border bg-black/60 p-3 text-xs text-(--text)">
          {block.diff.map((line, idx) => (
            <div
              key={`${block.key}-${idx}`}
              className={
                line.type === "add"
                  ? "rounded-sm bg-mint/20 px-2 py-0.5 text-mint"
                  : "rounded-sm bg-rose-500/20 px-2 py-0.5 text-rose-200"
              }
            >
              <span className="mr-2 inline-block w-3 text-center">
                {line.type === "add" ? "+" : "-"}
              </span>
              <span className="break-all font-mono whitespace-pre-wrap">{line.line}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  ));
}
