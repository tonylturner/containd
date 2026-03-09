"use client";
import React from "react";

export function SearchBar({ value, onChange, placeholder }: {
  value: string; onChange: (s: string) => void; placeholder?: string;
}) {
  return (
    <div className="relative">
      <svg className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.35-4.35" />
      </svg>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder ?? "Search..."}
        className="w-full rounded-lg border border-white/[0.08] bg-white/[0.04] py-1.5 pl-9 pr-3 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus:bg-white/[0.06] focus-visible:shadow-focus-ring outline-none"
      />
    </div>
  );
}

export function SortableHeader({ label, sortKey, currentSort, currentDir, onSort }: {
  label: string; sortKey: string; currentSort: string; currentDir: "asc" | "desc"; onSort: (k: string) => void;
}) {
  const active = currentSort === sortKey;
  return (
    <th
      className="cursor-pointer select-none whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wider text-slate-500 transition-ui hover:text-slate-200"
      onClick={() => onSort(sortKey)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active && (
          <span className="text-blue-400">{currentDir === "asc" ? "\u25B2" : "\u25BC"}</span>
        )}
      </span>
    </th>
  );
}

export function Pagination({ page, totalPages, totalItems, onPage }: {
  page: number; totalPages: number; totalItems: number; onPage: (p: number) => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between border-t border-white/[0.06] px-4 py-2.5 text-xs text-slate-400">
      <span>{totalItems} items</span>
      <div className="flex items-center gap-1">
        <button
          disabled={page <= 0}
          onClick={() => onPage(page - 1)}
          className="rounded-md bg-white/[0.04] px-2.5 py-1 transition-ui hover:bg-white/[0.08] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Prev
        </button>
        <span className="px-2 py-1 tabular-nums">{page + 1} / {totalPages}</span>
        <button
          disabled={page >= totalPages - 1}
          onClick={() => onPage(page + 1)}
          className="rounded-md bg-white/[0.04] px-2.5 py-1 transition-ui hover:bg-white/[0.08] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
    </div>
  );
}
