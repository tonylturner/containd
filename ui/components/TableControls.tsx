"use client";
import React from "react";

export function SearchBar({ value, onChange, placeholder }: {
  value: string; onChange: (s: string) => void; placeholder?: string;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder ?? "Search..."}
      className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-white placeholder:text-slate-500 focus:border-white/20 focus:outline-none"
    />
  );
}

export function SortableHeader({ label, sortKey, currentSort, currentDir, onSort }: {
  label: string; sortKey: string; currentSort: string; currentDir: "asc" | "desc"; onSort: (k: string) => void;
}) {
  const active = currentSort === sortKey;
  return (
    <th
      className="cursor-pointer select-none px-4 py-2 text-left text-xs font-medium uppercase text-slate-400 hover:text-white"
      onClick={() => onSort(sortKey)}
    >
      {label} {active ? (currentDir === "asc" ? "\u25B2" : "\u25BC") : ""}
    </th>
  );
}

export function Pagination({ page, totalPages, totalItems, onPage }: {
  page: number; totalPages: number; totalItems: number; onPage: (p: number) => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between border-t border-white/5 px-4 py-2 text-xs text-slate-400">
      <span>{totalItems} items</span>
      <div className="flex gap-2">
        <button disabled={page <= 0} onClick={() => onPage(page - 1)}
          className="rounded bg-white/5 px-2 py-1 hover:bg-white/10 disabled:opacity-30">Prev</button>
        <span className="px-2 py-1">{page + 1} / {totalPages}</span>
        <button disabled={page >= totalPages - 1} onClick={() => onPage(page + 1)}
          className="rounded bg-white/5 px-2 py-1 hover:bg-white/10 disabled:opacity-30">Next</button>
      </div>
    </div>
  );
}
