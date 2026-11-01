"use client";

import { useId, useState, type ReactNode } from "react";

/** Diagnostic content stays mounted so toggling does not discard local edits. */
export function Disclosure({ title, children, defaultOpen = false, indicator }: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
  indicator?: string;
}) {
  const id = useId();
  const [state, setState] = useState({ basis: defaultOpen, open: defaultOpen });
  // Incoming saved values open the section; removing them must not close it.
  // An unchanged default leaves the operator's explicit choice alone.
  if (state.basis !== defaultOpen) setState({ basis: defaultOpen, open: defaultOpen || state.open });
  const open = state.open;
  return (
    <section className="min-w-0 rounded-xs border bg-(--surface) p-4">
      <button type="button" aria-expanded={open} aria-controls={id}
        onClick={() => setState({ basis: defaultOpen, open: !open })}
        className="flex w-full items-center gap-2 text-left text-sm font-semibold text-(--text) transition-ui focus-visible:outline-2 focus-visible:outline-(--amber)">
        <span aria-hidden="true">{open ? "−" : "+"}</span>{title}
      </button>
      {indicator && <p className="mt-1 text-xs text-(--text-muted)">{indicator}</p>}
      <div id={id} hidden={!open} className="mt-3 min-w-0 space-y-3 break-words">{children}</div>
    </section>
  );
}
