"use client";

/** Presentation only: each caller supplies independent saved and live observations. */
export function ServiceStatusStrip({ configured, running, attention, updated, note, summary, label = "Service status" }: {
  configured?: boolean | string;
  running?: boolean;
  attention?: string;
  updated?: string;
  note?: string;
  summary?: ReactNode;
  label?: string;
}) {
  return (
    <section aria-label={label} className="mb-4 flex flex-wrap gap-x-6 gap-y-2 rounded-xs border bg-(--surface) px-4 py-3 text-sm break-words">
      <span title="Candidate editor settings, not live protection">Configured: {typeof configured === "boolean" ? configured ? "enabled" : "disabled" : configured ?? "Unknown"}</span>
      <span>Running: {typeof running === "boolean" ? running ? "yes" : "no" : "Unknown"}</span>
      <span className={attention ? "text-amber" : "text-(--text-muted)"}>Attention: {attention || "No fault reported; not proof of protection"}</span>
      <span className="text-(--text-muted)">Updated time: {updated || "Unknown"}</span>
      {summary && <div className="basis-full">{summary}</div>}
      {note && <p className="basis-full text-(--text-muted)">{note}</p>}
    </section>
  );
}
