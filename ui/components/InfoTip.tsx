"use client";

import React from "react";

export function InfoTip({ label }: { label: string }) {
  return (
    <span className="relative inline-flex items-center group">
      <span
        aria-label={label}
        className="flex h-4.5 w-4.5 items-center justify-center rounded-full border border-white/[0.08] bg-white/[0.04] text-[10px] text-slate-400 transition-ui group-hover:border-blue-500/30 group-hover:text-blue-400"
      >
        i
      </span>
      <span className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 w-64 -translate-x-1/2 rounded-lg border border-white/[0.08] bg-surface-raised px-3 py-2 text-xs text-slate-300 opacity-0 shadow-card-lg transition-opacity duration-150 group-hover:opacity-100">
        {label}
      </span>
    </span>
  );
}
