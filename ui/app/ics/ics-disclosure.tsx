"use client";

import { useId, useState, type ReactNode } from "react";

/** Local inspection details; saved constraints remain discoverable when closed. */
export function ICSDisclosure({ title, attention, defaultOpen = false, children }: {
  title: string;
  attention?: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const id = useId();
  const [state, setState] = useState({ basis: defaultOpen, open: defaultOpen });
  if (state.basis !== defaultOpen) setState({ basis: defaultOpen, open: defaultOpen || state.open });
  const open = state.open;
  return (
    <div className="min-w-0 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" aria-expanded={open} aria-controls={id}
          onClick={() => setState({ basis: defaultOpen, open: !open })}
          className="rounded-xs border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui">
          {title}
        </button>
        {attention && <span className="text-xs text-(--text-muted)">{attention}</span>}
      </div>
      <div id={id} hidden={!open} className="space-y-3 text-xs text-(--text-muted)">{children}</div>
    </div>
  );
}
