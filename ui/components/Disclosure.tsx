"use client";

import { useId, useState, type ReactNode } from "react";

/** Diagnostic content stays mounted so toggling does not discard local edits. */
export function Disclosure({ title, children, defaultOpen = false }: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const id = useId();
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="min-w-0 rounded-xs border bg-(--surface) p-4">
      <button type="button" aria-expanded={open} aria-controls={id}
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 text-left text-sm font-semibold text-(--text) transition-ui">
        <span aria-hidden="true">{open ? "−" : "+"}</span>{title}
      </button>
      <div id={id} hidden={!open} className="mt-3 min-w-0">{children}</div>
    </section>
  );
}
