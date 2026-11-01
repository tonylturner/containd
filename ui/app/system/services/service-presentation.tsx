"use client";

import { useId, useState, type ReactNode } from "react";

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

/** Diagnostics stay inspectable without competing with essential settings. */
export function ServiceDisclosure({ children, title, defaultOpen = false, indicator }: {
  children: ReactNode;
  title: string;
  defaultOpen?: boolean;
  indicator?: string;
}) {
  const id = useId();
  const [state, setState] = useState({ preset: defaultOpen, open: defaultOpen });
  // Loaded non-default settings must open even when they arrive after mount.
  if (state.preset !== defaultOpen) setState({ preset: defaultOpen, open: defaultOpen });
  return (
    <section className="my-3 min-w-0 rounded-xs border p-3">
      <button type="button" aria-expanded={state.open} aria-controls={id}
        onClick={() => setState({ ...state, open: !state.open })}
        className="text-left text-sm text-(--text) focus-visible:outline-2 focus-visible:outline-(--amber)">
        <span>{title}</span> <span aria-hidden="true">{state.open ? "−" : "+"}</span>
      </button>
      {indicator && <span className="ml-2 text-xs text-(--text-muted)">{indicator}</span>}
      <div id={id} hidden={!state.open} className="mt-3 min-w-0 break-words">{children}</div>
    </section>
  );
}
