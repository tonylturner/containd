"use client";

import React from "react";

export function InfoTip({ label }: { label: string }) {
  return (
    <span className="relative inline-flex items-center group">
      <span
        aria-label={label}
        className="flex h-5 w-5 items-center justify-center rounded-full border border-white/10 bg-white/5 text-[10px] text-slate-300"
      >
        i
      </span>
      <span className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 w-64 -translate-x-1/2 rounded-lg border border-white/10 bg-black/90 px-3 py-2 text-xs text-slate-200 opacity-0 shadow-lg backdrop-blur transition-opacity duration-150 group-hover:opacity-100">
        {label}
      </span>
    </span>
  );
}
