"use client";
import React from "react";

export function SearchBar({ value, onChange, placeholder }: {
  value: string; onChange: (s: string) => void; placeholder?: string;
}) {
  return (
    <div className="relative">
      <svg className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-dim)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.35-4.35" />
      </svg>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder ?? "Search..."}
        className="input-industrial w-full py-1.5 pl-9 pr-3 text-sm"
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
      className="cursor-pointer select-none whitespace-nowrap px-4 py-2.5 text-left font-mono text-[9px] font-medium uppercase tracking-[2px] text-[var(--text-dim)] transition-ui hover:text-[var(--text)]"
      onClick={() => onSort(sortKey)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active && (
          <span className="text-[var(--amber)]">{currentDir === "asc" ? "\u25B2" : "\u25BC"}</span>
        )}
      </span>
    </th>
  );
}

export function Pagination({ page, totalPages, totalItems, onPage, pageSize, onPageSize, pageSizeOptions }: {
  page: number; totalPages: number; totalItems: number; onPage: (p: number) => void;
  pageSize?: number; onPageSize?: (s: number) => void; pageSizeOptions?: number[];
}) {
  return (
    <div className="flex items-center justify-between border-t border-amber-500/[0.1] px-4 py-2.5 font-mono text-[10px] text-[var(--text-dim)]">
      <span>{totalItems} items</span>
      <div className="flex items-center gap-1">
        <button
          disabled={page <= 0}
          onClick={() => onPage(page - 1)}
          className="rounded-sm bg-[var(--surface2)] px-2.5 py-1 transition-ui hover:bg-amber-500/[0.1] hover:text-[var(--text)] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Prev
        </button>
        <span className="px-2 py-1 tabular-nums">{page + 1} / {totalPages}</span>
        <button
          disabled={page >= totalPages - 1}
          onClick={() => onPage(page + 1)}
          className="rounded-sm bg-[var(--surface2)] px-2.5 py-1 transition-ui hover:bg-amber-500/[0.1] hover:text-[var(--text)] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
      {totalPages > 1 && (
        <div className="flex items-center gap-1">
          <button
            disabled={page <= 0}
            onClick={() => onPage(page - 1)}
            className="rounded-sm bg-[var(--surface2)] px-2.5 py-1 transition-ui hover:bg-amber-500/[0.1] hover:text-[var(--text)] disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Prev
          </button>
          <span className="px-2 py-1 tabular-nums">{page + 1} / {totalPages}</span>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => onPage(page + 1)}
            className="rounded-sm bg-[var(--surface2)] px-2.5 py-1 transition-ui hover:bg-amber-500/[0.1] hover:text-[var(--text)] disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
