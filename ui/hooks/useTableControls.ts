"use client";
import { useMemo, useState } from "react";

interface TableControls<T> {
  data: T[];
  search: string;
  setSearch: (s: string) => void;
  sortKey: string;
  sortDir: "asc" | "desc";
  setSort: (key: string) => void;
  page: number;
  setPage: (p: number) => void;
  pageSize: number;
  setPageSize: (s: number) => void;
  totalPages: number;
  totalItems: number;
}

export function useTableControls<T extends Record<string, any>>(
  items: T[],
  opts?: {
    defaultSort?: string;
    defaultDir?: "asc" | "desc";
    defaultPageSize?: number;
    searchKeys?: string[];
  }
): TableControls<T> {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState(opts?.defaultSort ?? "");
  const [sortDir, setSortDir] = useState<"asc" | "desc">(opts?.defaultDir ?? "asc");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(opts?.defaultPageSize ?? 25);
  const searchKeys = useMemo(() => opts?.searchKeys ?? [], [opts?.searchKeys]);

  const setSort = (key: string) => {
    if (key === sortKey) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
    setPage(0);
  };

  const filtered = useMemo(() => {
    if (!search.trim()) return items;
    const q = search.toLowerCase();
    return items.filter(item =>
      searchKeys.length > 0
        ? searchKeys.some(k => String(item[k] ?? "").toLowerCase().includes(q))
        : Object.values(item).some(v => String(v ?? "").toLowerCase().includes(q))
    );
  }, [items, search, searchKeys]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const av = a[sortKey] ?? "";
      const bv = b[sortKey] ?? "";
      const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const clamped = Math.min(page, totalPages - 1);
  const data = sorted.slice(clamped * pageSize, (clamped + 1) * pageSize);

  return {
    data, search, setSearch, sortKey, sortDir, setSort,
    page: clamped, setPage, pageSize, setPageSize,
    totalPages, totalItems: sorted.length,
  };
}
