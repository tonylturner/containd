"use client";

import React from "react";

export function InfoTip({ label }: { label: string }) {
  return (
    <span className="relative inline-flex items-center group">
      <span
        aria-label={label}
        className="flex h-4.5 w-4.5 items-center justify-center rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] font-mono text-[10px] text-[var(--text-dim)] transition-ui group-hover:border-amber-500/30 group-hover:text-[var(--amber)]"
      >
        i
      </span>
      <span className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 w-64 -translate-x-1/2 rounded-sm border border-amber-500/[0.2] bg-[var(--surface)] px-3 py-2 font-mono text-[11px] text-[var(--text)] opacity-0 shadow-card-lg transition-opacity duration-150 group-hover:opacity-100">
        {label}
      </span>
    </span>
  );
}
