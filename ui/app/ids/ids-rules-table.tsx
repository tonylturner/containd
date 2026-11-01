"use client";

import { useMemo, useState } from "react";

import type { IDSRule } from "../../lib/api";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { Pagination, SearchBar } from "../../components/TableControls";

import {
  type AdvancedFilters,
  EMPTY_FILTERS,
  FormatBadge,
  isRuleEnabled,
  PAGE_SIZES,
  ruleMatchesAdvanced,
  ruleMatchesFilter,
  SEVERITY_ORDER,
} from "./ids-shared";

export function RulesTable({
  rules,
  canEdit,
  mutationDisabled = false,
  onEdit,
  onDelete,
  onBulkDelete,
  onBulkToggle,
  onToggleRule,
}: {
  rules: IDSRule[];
  canEdit: boolean;
  mutationDisabled?: boolean;
  onEdit: (r: IDSRule) => void;
  onDelete: (id: string) => void;
  onBulkDelete: (ids: string[]) => void;
  onBulkToggle: (ids: string[], enabled: boolean) => void;
  onToggleRule: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [advOpen, setAdvOpen] = useState(false);
  const [adv, setAdv] = useState<AdvancedFilters>(EMPTY_FILTERS);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [sortKey, setSortKey] = useState("");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const protos = useMemo(() => {
    const s = new Set<string>();
    for (const r of rules) {
      if (r.proto) {
        s.add(r.proto);
      }
    }
    return Array.from(s).sort();
  }, [rules]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return rules.filter((r) => {
      if (q && !ruleMatchesFilter(r, q)) {
        return false;
      }
      if (!ruleMatchesAdvanced(r, adv)) {
        return false;
      }
      return true;
    });
  }, [rules, search, adv]);

  const sorted = useMemo(() => {
    if (!sortKey) {
      return filtered;
    }
    return [...filtered].sort((a, b) => {
      let av: string | number = "";
      let bv: string | number = "";
      if (sortKey === "severity") {
        av = SEVERITY_ORDER[a.severity ?? "low"] ?? 9;
        bv = SEVERITY_ORDER[b.severity ?? "low"] ?? 9;
      } else if (sortKey === "enabled") {
        av = isRuleEnabled(a) ? 0 : 1;
        bv = isRuleEnabled(b) ? 0 : 1;
      } else {
        av = String((a as Record<string, unknown>)[sortKey] ?? "");
        bv = String((b as Record<string, unknown>)[sortKey] ?? "");
      }
      const cmp =
        typeof av === "number" && typeof bv === "number"
          ? av - bv
          : String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const clampedPage = Math.min(page, totalPages - 1);
  const pageData = sorted.slice(
    clampedPage * pageSize,
    (clampedPage + 1) * pageSize,
  );

  const allOnPageSelected =
    pageData.length > 0 && pageData.every((r) => selected.has(r.id));
  const someSelected = selected.size > 0;

  function toggleAll() {
    if (allOnPageSelected) {
      const next = new Set(selected);
      for (const r of pageData) {
        next.delete(r.id);
      }
      setSelected(next);
    } else {
      const next = new Set(selected);
      for (const r of pageData) {
        next.add(r.id);
      }
      setSelected(next);
    }
  }

  function toggleOne(id: string) {
    const next = new Set(selected);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelected(next);
  }

  function selectAllFiltered() {
    setSelected(new Set(filtered.map((r) => r.id)));
  }

  function clearSelection() {
    setSelected(new Set());
  }

  function doSort(key: string) {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
    setPage(0);
  }

  const hasAdvFilters =
    adv.format || adv.severity || adv.proto || adv.status;

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchBar value={search} onChange={(value) => { setSearch(value); setPage(0); }} placeholder="Search rules..." className="min-w-[200px] max-w-lg flex-1" />
        <button
          onClick={() => setAdvOpen(!advOpen)}
          className={`rounded-xs border px-3 py-1.5 text-xs transition-ui ${
            hasAdvFilters
              ? ""
              : "bg-(--surface2) text-(--text-muted) hover:text-(--text)"
          }`}
        >
          Filters{hasAdvFilters ? " *" : ""}
        </button>
        {hasAdvFilters && (
          <button
            onClick={() => { setAdv(EMPTY_FILTERS); setPage(0); }}
            className="text-xs text-(--text-muted) transition-ui hover:text-(--text)"
          >
            Clear
          </button>
        )}
      </div>

      {advOpen && (
        <div className="mb-3 grid grid-cols-2 gap-2 rounded-xs border bg-(--surface) p-3 sm:grid-cols-4">
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-(--text-dim)">
              Format
            </label>
            <select
              value={adv.format}
              onChange={(e) => { setAdv({ ...adv, format: e.target.value }); setPage(0); }}
              className="input-industrial w-full text-xs"
            >
              <option value="">All</option>
              <option value="native">Native</option>
              <option value="suricata">Suricata</option>
              <option value="snort">Snort</option>
              <option value="yara">YARA</option>
              <option value="sigma">Sigma</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-(--text-dim)">
              Severity
            </label>
            <select
              value={adv.severity}
              onChange={(e) => { setAdv({ ...adv, severity: e.target.value }); setPage(0); }}
              className="input-industrial w-full text-xs"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-(--text-dim)">
              Protocol
            </label>
            <select
              value={adv.proto}
              onChange={(e) => { setAdv({ ...adv, proto: e.target.value }); setPage(0); }}
              className="input-industrial w-full text-xs"
            >
              <option value="">All</option>
              {protos.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-(--text-dim)">
              Status
            </label>
            <select
              value={adv.status}
              onChange={(e) => { setAdv({ ...adv, status: e.target.value }); setPage(0); }}
              className="input-industrial w-full text-xs"
            >
              <option value="">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>
      )}

      {someSelected && canEdit && (
        <div className="mb-3 flex items-center gap-2 rounded-xs border px-3 py-2">
          <span className="tabular-nums text-xs">
            {selected.size} selected
          </span>
          {selected.size < filtered.length && (
            <button
              onClick={selectAllFiltered}
              className="text-xs underline"
            >
              Select all {filtered.length.toLocaleString()} filtered
            </button>
          )}
          <button
            onClick={clearSelection}
            className="text-xs text-(--text-muted) hover:text-(--text)"
          >
            Clear
          </button>
          <span className="flex-1" />
          <button
            disabled={mutationDisabled}
            onClick={() => onBulkToggle(Array.from(selected), true)}
            className="rounded-xs border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-xs text-emerald-400 transition-ui hover:bg-emerald-500/20"
          >
            Enable
          </button>
          <button
            disabled={mutationDisabled}
            onClick={() => onBulkToggle(Array.from(selected), false)}
            className="rounded-xs border bg-(--surface2) px-2.5 py-1 text-xs text-(--text-muted) transition-ui"
          >
            Disable
          </button>
          <button
            disabled={mutationDisabled}
            onClick={() => {
              onBulkDelete(Array.from(selected));
              clearSelection();
            }}
            className="rounded-xs border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/20"
          >
            Delete
          </button>
        </div>
      )}

      <div className="overflow-hidden rounded-xs border bg-(--surface) shadow-card">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-(--surface) text-left">
              <tr>
                {canEdit && (
                  <th className="w-8 px-3 py-2.5">
                    <input
                      type="checkbox"
                      checked={allOnPageSelected && pageData.length > 0}
                      onChange={toggleAll}
                      className="h-3.5 w-3.5 rounded-sm border-white/20 bg-(--surface)"
                    />
                  </th>
                )}
                <SortHeader
                  label="Status"
                  sortKey="enabled"
                  current={sortKey}
                  dir={sortDir}
                  onSort={doSort}
                />
                <SortHeader
                  label="ID"
                  sortKey="id"
                  current={sortKey}
                  dir={sortDir}
                  onSort={doSort}
                />
                <SortHeader
                  label="Title"
                  sortKey="title"
                  current={sortKey}
                  dir={sortDir}
                  onSort={doSort}
                />
                <SortHeader
                  label="Format"
                  sortKey="sourceFormat"
                  current={sortKey}
                  dir={sortDir}
                  onSort={doSort}
                />
                <SortHeader
                  label="Proto"
                  sortKey="proto"
                  current={sortKey}
                  dir={sortDir}
                  onSort={doSort}
                />
                <SortHeader
                  label="Severity"
                  sortKey="severity"
                  current={sortKey}
                  dir={sortDir}
                  onSort={doSort}
                />
                <th className="px-4 py-2.5 text-right text-[9px] font-medium uppercase tracking-[2px] text-(--text-dim)">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {pageData.length === 0 && (
                <tr>
                  <td className="px-4 py-8" colSpan={canEdit ? 8 : 7}>
                    <EmptyState
                      title={
                        rules.length === 0
                          ? "No IDS rules configured"
                          : "No rules match filters"
                      }
                      description={
                        rules.length === 0
                          ? "Import Suricata, Snort, YARA, or Sigma rules to enable intrusion detection."
                          : "Adjust your search or filters."
                      }
                    />
                  </td>
                </tr>
              )}
              {pageData.map((r) => {
                const enabled = isRuleEnabled(r);
                return (
                  <tr
                    key={r.id}
                    className={`table-row-hover border-t transition-ui ${!enabled ? "opacity-50" : ""}`}
                  >
                    {canEdit && (
                      <td className="w-8 px-3 py-2.5">
                        <input
                          type="checkbox"
                          checked={selected.has(r.id)}
                          onChange={() => toggleOne(r.id)}
                          className="h-3.5 w-3.5 rounded-sm border-white/20 bg-(--surface)"
                        />
                      </td>
                    )}
                    <td className="px-4 py-2.5">
                      {canEdit ? (
                        <button
                          disabled={mutationDisabled}
                          onClick={() => onToggleRule(r.id)}
                          title={enabled ? "Click to disable" : "Click to enable"}
                          className={`inline-flex h-5 w-9 items-center rounded-full transition-colors ${enabled ? "bg-emerald-500/30" : "bg-white/10"}`}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 rounded-full transition-transform ${enabled ? "translate-x-[18px] bg-emerald-400" : "translate-x-[3px] bg-white/30"}`}
                          />
                        </button>
                      ) : (
                        <span
                          className={`inline-block h-2 w-2 rounded-full ${enabled ? "bg-emerald-400" : "bg-white/20"}`}
                        />
                      )}
                    </td>
                    <td
                      className="max-w-[160px] truncate px-4 py-2.5 font-mono text-[11px] text-(--text)"
                      title={r.id}
                    >
                      {r.id}
                    </td>
                    <td
                      className="max-w-[280px] truncate px-4 py-2.5 text-(--text)"
                      title={r.title || r.message}
                    >
                      {r.title || r.message || "\u2014"}
                    </td>
                    <td className="px-4 py-2.5">
                      <FormatBadge format={r.sourceFormat} />
                    </td>
                    <td className="px-4 py-2.5 text-xs text-(--text)">
                      {r.proto || "\u2014"}
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge
                        variant={
                          r.severity === "critical" || r.severity === "high"
                            ? "error"
                            : r.severity === "medium"
                              ? "warning"
                              : "success"
                        }
                      >
                        {r.severity || "low"}
                      </StatusBadge>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-right">
                      {canEdit && (
                        <>
                          <button
                            disabled={mutationDisabled}
                            onClick={() => onEdit(r)}
                            className="mr-1.5 rounded-xs border bg-(--surface2) px-2 py-0.5 text-[11px] transition-ui"
                          >
                            Edit
                          </button>
                          <button
                            disabled={mutationDisabled}
                            onClick={() => onDelete(r.id)}
                            className="rounded-xs px-2 py-0.5 text-[11px] text-red-400 transition-ui hover:bg-red-500/10"
                          >
                            Del
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <Pagination
          page={clampedPage}
          totalPages={totalPages}
          totalItems={sorted.length}
          onPage={setPage}
          pageSize={pageSize}
          onPageSize={(s) => {
            setPageSize(s);
            setPage(0);
          }}
          pageSizeOptions={PAGE_SIZES}
        />
      </div>
    </>
  );
}

function SortHeader({
  label,
  sortKey,
  current,
  dir,
  onSort,
}: {
  label: string;
  sortKey: string;
  current: string;
  dir: "asc" | "desc";
  onSort: (k: string) => void;
}) {
  const active = current === sortKey;
  return (
    <th
      className="cursor-pointer select-none whitespace-nowrap px-4 py-2.5 text-left text-[9px] font-medium uppercase tracking-[2px] text-(--text-dim) transition-ui hover:text-(--text)"
      onClick={() => onSort(sortKey)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active && (
          <span className="text-(--amber)">
            {dir === "asc" ? "\u25B2" : "\u25BC"}
          </span>
        )}
      </span>
    </th>
  );
}
