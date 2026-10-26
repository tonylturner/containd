"use client";

import React from "react";

export function InfoTip({ label }: { label: string }) {
  return (
    <span className="relative inline-flex items-center group">
      <span
        role="img"
        aria-label={`Info: ${label}`}
        tabIndex={0}
        className="flex items-center justify-center rounded-xs border bg-(--surface2) font-mono text-[10px] text-(--text-dim) transition-ui group-hover:text-(--amber) focus-visible:shadow-focus-ring outline-hidden"
      >
        i
      </span>
      <span role="tooltip" className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 w-64 -translate-x-1/2 rounded-xs border bg-(--surface) px-3 py-2 font-mono text-[11px] text-(--text) opacity-0 shadow-card-lg transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100">
        {label}
      </span>
    </span>
  );
}
