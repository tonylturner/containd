"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Shell } from "../../components/Shell";
import { api, isAdmin, type IDSConfig, type IDSRule } from "../../lib/api";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import {
  ConfirmDialog,
  useConfirm,
} from "../../components/ConfirmDialog";

export default function IDSPage() {
  const canEdit = isAdmin();
  const [ids, setIds] = useState<IDSConfig>({ enabled: false, rules: [] });
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [editing, setEditing] = useState<IDSRule | null>(null);
  const confirm = useConfirm();

  async function refresh() {
    const [cfg, src] = await Promise.all([api.getIDS(), api.getIDSSources()]);
    setIds(cfg ?? { enabled: false, rules: [] });
    setSources(src ?? []);
  }

  useEffect(() => { refresh(); }, []);

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    const saved = await api.setIDS(ids);
    if (!saved) { setError("Failed to save IDS rules."); return; }
    setIds(saved);
    flashSuccess("Rules saved.");
  }

  function onDelete(id: string) {
    if (!canEdit) return;
    confirm.open({
      title: "Remove IDS Rule",
      message: `Are you sure you want to remove rule "${id}"? This change is not saved until you click Save.`,
      confirmLabel: "Remove",
      variant: "danger",
      onConfirm: () => {
        const existing = ids.rules ?? [];
        setIds({ ...ids, rules: existing.filter((r) => r.id !== id) });
      },
    });
  }

  const rules = useMemo(() => ids.rules ?? [], [ids.rules]);
  const groups = useMemo(() => ids.ruleGroups ?? [], [ids.ruleGroups]);
  const enabledCount = useMemo(() => rules.filter(isRuleEnabled).length, [rules]);

  const tabs = [
    { key: "rules" as const, label: "Rules", count: rules.length },
    { key: "groups" as const, label: "Groups", count: groups.length },
    { key: "import" as const, label: "Import" },
    { key: "export" as const, label: "Export" },
    { key: "sources" as const, label: "Sources", count: sources.length },
  ];

  return (
    <Shell
      title="IDS Rules"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Save
            </button>
          )}
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="mb-6 flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-[var(--text)]">
          <input
            type="checkbox"
            checked={!!ids.enabled}
            disabled={!canEdit}
            onChange={(e) => setIds({ ...ids, enabled: e.target.checked })}
            className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
          />
          Enable native IDS
        </label>
        <span className="ml-auto text-xs text-[var(--text-muted)] tabular-nums">
          {enabledCount.toLocaleString()} / {rules.length.toLocaleString()} rules enabled
        </span>
      </div>

      {canEdit && (
        <SigmaImportCard
          value={sigmaText}
          onChange={setSigmaText}
          onConvert={onConvertSigma}
        />
      )}

      <div className="mt-6 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Proto/Kind</th>
              <th className="px-4 py-3">When</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-8" colSpan={6}>
                  <EmptyState
                    title="No IDS rules configured"
                    description="Upload Suricata rules or create custom rules to enable intrusion detection."
                  />
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {r.title || r.message || "\u2014"}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {(r.proto || "*") + " / " + (r.kind || "*")}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  <span title={conditionSummary(r.when)}>
                    {conditionSummary(r.when) || "\u2014"}
                  </span>
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
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
                <td className="px-4 py-3 text-right">
                  {canEdit && (
                    <>
                      <button
                        onClick={() => setEditing(r)}
                        className="mr-2 rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => onDelete(r.id)}
                        className="rounded-md px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                      >
                        Remove
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {activeTab === "rules" && (
        <RulesTable rules={rules} canEdit={canEdit} onEdit={setEditing} onDelete={onDelete}
          onBulkDelete={onBulkDelete} onBulkToggle={onBulkToggle} onToggleRule={onToggleRule} />
      )}
      {activeTab === "groups" && (
        <GroupsPanel groups={groups} rules={rules} canEdit={canEdit}
          onUpdate={(g) => setIds((prev) => ({ ...prev, ruleGroups: g }))} />
      )}
      {activeTab === "import" && canEdit && (
        <ImportPanel onImported={(msg) => { flashSuccess(msg); refresh(); setActiveTab("rules"); }} onError={setError} />
      )}
      {activeTab === "import" && !canEdit && (
        <div className="py-8 text-center text-sm text-[var(--text-muted)]">Import is disabled in view-only mode.</div>
      )}
      {activeTab === "export" && <ExportPanel ruleCount={rules.length} />}
      {activeTab === "sources" && <SourcesCatalog sources={sources} />}

      {editing && canEdit && (
        <EditRuleModal rule={editing} onClose={() => setEditing(null)} onSave={(newRule) => {
          setIds((prev) => ({ ...prev, rules: (prev.rules ?? []).map((r) => r.id === editing.id ? newRule : r) }));
          setEditing(null);
        }} />
      )}

      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}

/* ══════════════════════════════════════════════════════════════
   Rules Table — pagination, advanced filters, bulk select
   ══════════════════════════════════════════════════════════════ */

function RulesTable({
  rules, canEdit, onEdit, onDelete, onBulkDelete, onBulkToggle, onToggleRule,
}: {
  rules: IDSRule[];
  canEdit: boolean;
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

  // Derive unique protos for filter dropdown
  const protos = useMemo(() => {
    const s = new Set<string>();
    for (const r of rules) if (r.proto) s.add(r.proto);
    return Array.from(s).sort();
  }, [rules]);

  // Filter
  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return rules.filter((r) => {
      if (q && !ruleMatchesFilter(r, q)) return false;
      if (!ruleMatchesAdvanced(r, adv)) return false;
      return true;
    });
  }, [rules, search, adv]);

  // Sort
  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
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
      const cmp = typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  // Paginate
  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const clampedPage = Math.min(page, totalPages - 1);
  const pageData = sorted.slice(clampedPage * pageSize, (clampedPage + 1) * pageSize);

  // Reset page on filter change
  useEffect(() => { setPage(0); }, [search, adv, pageSize]);

  // Selection helpers
  const allOnPageSelected = pageData.length > 0 && pageData.every((r) => selected.has(r.id));
  const someSelected = selected.size > 0;

  function toggleAll() {
    if (allOnPageSelected) {
      const next = new Set(selected);
      for (const r of pageData) next.delete(r.id);
      setSelected(next);
    } else {
      const next = new Set(selected);
      for (const r of pageData) next.add(r.id);
      setSelected(next);
    }
  }

  function toggleOne(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelected(next);
  }

  function selectAllFiltered() {
    setSelected(new Set(filtered.map((r) => r.id)));
  }

  function clearSelection() {
    setSelected(new Set());
  }

  function doSort(key: string) {
    if (key === sortKey) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
    setPage(0);
  }

  const hasAdvFilters = adv.format || adv.severity || adv.proto || adv.status;

  return (
    <>
      {/* Search + advanced toggle */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-lg">
          <svg className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-dim)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
          </svg>
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules..."
            className="input-industrial w-full py-1.5 pl-9 pr-3 text-sm" />
        </div>
        <button onClick={() => setAdvOpen(!advOpen)}
          className={`rounded-sm border px-3 py-1.5 text-xs transition-ui ${
            hasAdvFilters
              ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
              : "border-amber-500/[0.15] bg-[var(--surface2)] text-[var(--text-muted)] hover:text-[var(--text)]"
          }`}>
          Filters{hasAdvFilters ? " *" : ""}
        </button>
        {hasAdvFilters && (
          <button onClick={() => setAdv(EMPTY_FILTERS)} className="text-xs text-[var(--text-muted)] hover:text-[var(--text)] transition-ui">
            Clear
          </button>
        )}
      </div>

      {/* Advanced filters */}
      {advOpen && (
        <div className="mb-3 grid grid-cols-2 gap-2 rounded-sm border border-amber-500/[0.1] bg-[var(--surface)] p-3 sm:grid-cols-4">
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-[var(--text-dim)]">Format</label>
            <select value={adv.format} onChange={(e) => setAdv({ ...adv, format: e.target.value })} className="input-industrial w-full text-xs">
              <option value="">All</option>
              <option value="native">Native</option>
              <option value="suricata">Suricata</option>
              <option value="snort">Snort</option>
              <option value="yara">YARA</option>
              <option value="sigma">Sigma</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-[var(--text-dim)]">Severity</label>
            <select value={adv.severity} onChange={(e) => setAdv({ ...adv, severity: e.target.value })} className="input-industrial w-full text-xs">
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-[var(--text-dim)]">Protocol</label>
            <select value={adv.proto} onChange={(e) => setAdv({ ...adv, proto: e.target.value })} className="input-industrial w-full text-xs">
              <option value="">All</option>
              {protos.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wider text-[var(--text-dim)]">Status</label>
            <select value={adv.status} onChange={(e) => setAdv({ ...adv, status: e.target.value })} className="input-industrial w-full text-xs">
              <option value="">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>
      )}

      {/* Bulk actions bar */}
      {someSelected && canEdit && (
        <div className="mb-3 flex items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-amber-500/[0.04] px-3 py-2">
          <span className="text-xs text-amber-400 tabular-nums">{selected.size} selected</span>
          {selected.size < filtered.length && (
            <button onClick={selectAllFiltered} className="text-xs text-amber-400 underline hover:text-amber-300">
              Select all {filtered.length.toLocaleString()} filtered
            </button>
          )}
          <button onClick={clearSelection} className="text-xs text-[var(--text-muted)] hover:text-[var(--text)]">Clear</button>
          <span className="flex-1" />
          <button onClick={() => onBulkToggle(Array.from(selected), true)}
            className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-xs text-emerald-400 transition-ui hover:bg-emerald-500/20">
            Enable
          </button>
          <button onClick={() => onBulkToggle(Array.from(selected), false)}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2.5 py-1 text-xs text-[var(--text-muted)] transition-ui hover:bg-amber-500/[0.08]">
            Disable
          </button>
          <button onClick={() => { onBulkDelete(Array.from(selected)); clearSelection(); }}
            className="rounded-sm border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/20">
            Delete
          </button>
        </div>
      )}

      {/* Table */}
      <div className="overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-[var(--surface)] text-left">
              <tr>
                {canEdit && (
                  <th className="w-8 px-3 py-2.5">
                    <input type="checkbox" checked={allOnPageSelected && pageData.length > 0}
                      onChange={toggleAll} className="h-3.5 w-3.5 rounded border-white/20 bg-[var(--surface)]" />
                  </th>
                )}
                <SortHeader label="Status" sortKey="enabled" current={sortKey} dir={sortDir} onSort={doSort} />
                <SortHeader label="ID" sortKey="id" current={sortKey} dir={sortDir} onSort={doSort} />
                <SortHeader label="Title" sortKey="title" current={sortKey} dir={sortDir} onSort={doSort} />
                <SortHeader label="Format" sortKey="sourceFormat" current={sortKey} dir={sortDir} onSort={doSort} />
                <SortHeader label="Proto" sortKey="proto" current={sortKey} dir={sortDir} onSort={doSort} />
                <SortHeader label="Severity" sortKey="severity" current={sortKey} dir={sortDir} onSort={doSort} />
                <th className="px-4 py-2.5 text-right text-[9px] font-medium uppercase tracking-[2px] text-[var(--text-dim)]">Actions</th>
              </tr>
            </thead>
            <tbody>
              {pageData.length === 0 && (
                <tr>
                  <td className="px-4 py-8" colSpan={canEdit ? 8 : 7}>
                    <EmptyState
                      title={rules.length === 0 ? "No IDS rules configured" : "No rules match filters"}
                      description={rules.length === 0
                        ? "Import Suricata, Snort, YARA, or Sigma rules to enable intrusion detection."
                        : "Adjust your search or filters."}
                    />
                  </td>
                </tr>
              )}
              {pageData.map((r) => {
                const enabled = isRuleEnabled(r);
                return (
                  <tr key={r.id} className={`border-t border-amber-500/[0.1] table-row-hover transition-ui ${!enabled ? "opacity-50" : ""}`}>
                    {canEdit && (
                      <td className="w-8 px-3 py-2.5">
                        <input type="checkbox" checked={selected.has(r.id)}
                          onChange={() => toggleOne(r.id)} className="h-3.5 w-3.5 rounded border-white/20 bg-[var(--surface)]" />
                      </td>
                    )}
                    <td className="px-4 py-2.5">
                      {canEdit ? (
                        <button onClick={() => onToggleRule(r.id)} title={enabled ? "Click to disable" : "Click to enable"}
                          className={`inline-flex h-5 w-9 items-center rounded-full transition-colors ${enabled ? "bg-emerald-500/30" : "bg-white/10"}`}>
                          <span className={`inline-block h-3.5 w-3.5 rounded-full transition-transform ${enabled ? "translate-x-[18px] bg-emerald-400" : "translate-x-[3px] bg-white/30"}`} />
                        </button>
                      ) : (
                        <span className={`inline-block h-2 w-2 rounded-full ${enabled ? "bg-emerald-400" : "bg-white/20"}`} />
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-[var(--text)] max-w-[160px] truncate" title={r.id}>
                      {r.id}
                    </td>
                    <td className="px-4 py-2.5 text-[var(--text)] max-w-[280px] truncate" title={r.title || r.message}>
                      {r.title || r.message || "\u2014"}
                    </td>
                    <td className="px-4 py-2.5"><FormatBadge format={r.sourceFormat} /></td>
                    <td className="px-4 py-2.5 text-[var(--text)] text-xs">{r.proto || "\u2014"}</td>
                    <td className="px-4 py-2.5">
                      <StatusBadge variant={r.severity === "critical" || r.severity === "high" ? "error" : r.severity === "medium" ? "warning" : "success"}>
                        {r.severity || "low"}
                      </StatusBadge>
                    </td>
                    <td className="px-4 py-2.5 text-right whitespace-nowrap">
                      {canEdit && (
                        <>
                          <button onClick={() => onEdit(r)}
                            className="mr-1.5 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-0.5 text-[11px] transition-ui hover:bg-amber-500/[0.08]">
                            Edit
                          </button>
                          <button onClick={() => onDelete(r.id)}
                            className="rounded-sm px-2 py-0.5 text-[11px] text-red-400 transition-ui hover:bg-red-500/10">
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
        <Pagination page={clampedPage} totalPages={totalPages} totalItems={sorted.length}
          onPage={setPage} pageSize={pageSize} onPageSize={(s) => { setPageSize(s); setPage(0); }} pageSizeOptions={PAGE_SIZES} />
      </div>
    </>
  );
}

function SortHeader({ label, sortKey, current, dir, onSort }: {
  label: string; sortKey: string; current: string; dir: "asc" | "desc"; onSort: (k: string) => void;
}) {
  const active = current === sortKey;
  return (
    <th className="cursor-pointer select-none whitespace-nowrap px-4 py-2.5 text-left text-[9px] font-medium uppercase tracking-[2px] text-[var(--text-dim)] transition-ui hover:text-[var(--text)]"
      onClick={() => onSort(sortKey)}>
      <span className="inline-flex items-center gap-1">
        {label}
        {active && <span className="text-[var(--amber)]">{dir === "asc" ? "\u25B2" : "\u25BC"}</span>}
      </span>
    </th>
  );
}

/* ── Groups Panel ── */

function GroupsPanel({ groups, rules, canEdit, onUpdate }: {
  groups: RuleGroup[]; rules: IDSRule[]; canEdit: boolean; onUpdate: (g: RuleGroup[]) => void;
}) {
  const [name, setName] = useState("");
  const [filter, setFilter] = useState("");

  // Compute stats per group
  const groupStats = useMemo(() => {
    const stats: Record<string, number> = {};
    for (const g of groups) {
      if (!g.filter) { stats[g.id] = rules.length; continue; }
      stats[g.id] = rules.filter((r) => groupFilterMatch(r, g.filter ?? "")).length;
    }
    return stats;
  }, [groups, rules]);

  function onCreate() {
    if (!name.trim()) return;
    const id = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-");
    if (groups.some((g) => g.id === id)) return;
    onUpdate([...groups, { id, name: name.trim(), filter: filter.trim(), enabled: true }]);
    setName(""); setFilter("");
  }

  function onToggle(id: string) {
    onUpdate(groups.map((g) => g.id === id ? { ...g, enabled: !g.enabled } : g));
  }

  function onRemove(id: string) {
    onUpdate(groups.filter((g) => g.id !== id));
  }

  return (
    <Card title="Import Sigma Rule" titleRight={
      <input
        type="file"
        accept=".yml,.yaml,text/yaml"
        onChange={onFile}
        className="text-xs text-[var(--text)]"
      />
    }>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste Sigma YAML here"
        rows={8}
        className="w-full input-industrial font-mono text-xs"
      />
      <div className="mt-2 flex justify-end">
        <button
          onClick={onConvert}
          disabled={!value.trim()}
          className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
        >
          Convert & Add
        </button>
      </div>
    </Card>
  );
}

function groupFilterMatch(r: IDSRule, filter: string): boolean {
  const parts = filter.split(/\s+AND\s+/i);
  return parts.every((p) => {
    const [key, val] = p.split(":");
    if (!key || !val) return true;
    const k = key.trim().toLowerCase();
    const v = val.trim().toLowerCase();
    switch (k) {
      case "proto": return (r.proto ?? "").toLowerCase() === v;
      case "format": case "sourceformat": return (r.sourceFormat ?? "native").toLowerCase() === v;
      case "severity": return (r.severity ?? "low").toLowerCase() === v;
      case "kind": return (r.kind ?? "").toLowerCase() === v;
      default: return (r.id.toLowerCase().includes(v) || (r.title ?? "").toLowerCase().includes(v));
    }
  });
}

/* ── Format Badge ── */

function FormatBadge({ format }: { format?: string }) {
  const f = format || "native";
  const color = FORMAT_BADGE_COLOR[f] ?? FORMAT_BADGE_COLOR.native;
  return (
    <span className={`inline-block rounded-sm border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${color}`}>
      {f}
    </span>
  );
}

/* ── Import Panel ── */

function ImportPanel({ onImported, onError }: { onImported: (msg: string) => void; onError: (msg: string) => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [format, setFormat] = useState("");
  const [importing, setImporting] = useState(false);
  const [sigmaText, setSigmaText] = useState("");
  const [sigmaConverting, setSigmaConverting] = useState(false);

  async function onFileImport() {
    const file = fileRef.current?.files?.[0];
    if (!file) return;
    setImporting(true); onError("");
    const result = await api.importIDSRules(file, format || undefined);
    setImporting(false);
    if (!result) { onError("Import failed. Check the file format and try again."); return; }
    onImported(`Imported ${result.imported} rule${result.imported !== 1 ? "s" : ""} (${result.skipped} skipped). Format: ${result.format}. Total: ${result.total}.`);
    if (fileRef.current) fileRef.current.value = "";
  }

  async function onSigmaConvert() {
    if (!sigmaText.trim()) return;
    setSigmaConverting(true); onError("");
    const rule = await api.convertSigma(sigmaText);
    setSigmaConverting(false);
    if (!rule) { onError("Sigma conversion failed. Check YAML syntax."); return; }
    onImported(`Converted Sigma rule: ${rule.id}. Click Save to persist.`);
    setSigmaText("");
  }

  return (
    <div className="space-y-4">
      <Card title="Import from file">
        <p className="mb-3 text-xs text-[var(--text-muted)]">Upload Suricata (.rules), Snort (.rules), YARA (.yar), or Sigma (.yml). Format is auto-detected.</p>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[200px]">
            <label className="mb-1 block text-xs text-[var(--text-muted)]">Rule file</label>
            <input ref={fileRef} type="file" accept=".rules,.yar,.yara,.yml,.yaml"
              className="w-full text-sm text-[var(--text)] file:mr-3 file:rounded-sm file:border file:border-amber-500/[0.15] file:bg-[var(--surface2)] file:px-3 file:py-1.5 file:text-xs file:text-[var(--text)] file:transition-ui hover:file:bg-amber-500/[0.08]" />
          </div>
          <div>
            <label className="mb-1 block text-xs text-[var(--text-muted)]">Format</label>
            <select value={format} onChange={(e) => setFormat(e.target.value)} className="input-industrial text-sm">
              {FORMAT_OPTIONS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
          </div>
          <button onClick={onFileImport} disabled={importing}
            className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
            {importing ? "Importing..." : "Import"}
          </button>
        </div>
      </Card>
      <Card title="Paste Sigma YAML">
        <textarea value={sigmaText} onChange={(e) => setSigmaText(e.target.value)}
          placeholder="Paste a single Sigma YAML rule here..." rows={8}
          className="w-full input-industrial font-mono text-xs" />
        <div className="mt-2 flex justify-end">
          <button onClick={onSigmaConvert} disabled={!sigmaText.trim() || sigmaConverting}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
            {sigmaConverting ? "Converting..." : "Convert & Add"}
          </button>
        </div>
      </Card>
    </div>
  );
}

/* ── Export Panel ── */

function ExportPanel({ ruleCount }: { ruleCount: number }) {
  const [exporting, setExporting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function doExport(format: string) {
    setExporting(format); setError(null);
    const ok = await api.exportIDSRules(format);
    setExporting(null);
    if (!ok) setError(`Export failed for ${format}.`);
  }

  return (
    <Card title="Export rules">
      <p className="mb-4 text-xs text-[var(--text-muted)]">
        Export all {ruleCount} rule{ruleCount !== 1 ? "s" : ""} in your chosen format.
      </p>
      {error && <div className="mb-3 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">{error}</div>}
      {ruleCount === 0 ? (
        <p className="text-sm text-[var(--text-muted)]">No rules to export.</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {EXPORT_FORMATS.map((f) => (
            <button key={f.value} onClick={() => doExport(f.value)} disabled={exporting !== null}
              className="flex flex-col items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] p-4 text-center transition-ui hover:border-amber-500/30 hover:bg-amber-500/[0.06] disabled:opacity-50">
              <FormatBadge format={f.value} />
              <span className="text-sm text-[var(--text)]">{f.label}</span>
              <span className="text-[10px] text-[var(--text-muted)]">{exporting === f.value ? "Downloading..." : "Download"}</span>
            </button>
          ))}
        </div>
      )}
    </Card>
  );
}

/* ── Sources Catalog ── */

function SourcesCatalog({ sources }: { sources: IDSRuleSource[] }) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-[var(--text-muted)]">
        Community rule repositories. Download externally, then import via the Import tab. GPL sets are not shipped.
      </p>
      {sources.length === 0 ? (
        <EmptyState title="No rule sources" description="Catalog is empty." />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {sources.map((s) => (
            <div key={s.id} className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] p-4 transition-ui">
              <div className="mb-2 flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-[var(--text)]">{s.name}</h3>
                  <p className="mt-0.5 text-xs text-[var(--text-muted)]">{s.description}</p>
                </div>
                <FormatBadge format={s.format} />
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className={`rounded-sm border px-1.5 py-0.5 ${
                  s.license === "MIT" || s.license === "CC0-1.0" ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                    : s.license.startsWith("GPL") ? "border-orange-500/20 bg-orange-500/10 text-orange-400"
                    : "border-blue-500/20 bg-blue-500/10 text-blue-400"
                }`}>{s.license}</span>
                <a href={s.url} target="_blank" rel="noopener noreferrer"
                  className="text-amber-400 hover:text-amber-300 transition-ui truncate">
                  {s.url.replace(/^https?:\/\//, "").split("/").slice(0, 3).join("/")}
                </a>
              </div>
              {s.licenseNote && <p className="mt-2 text-[10px] text-orange-400/80">{s.licenseNote}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Edit Modal ── */

function EditRuleModal({ rule, onClose, onSave }: { rule: IDSRule; onClose: () => void; onSave: (r: IDSRule) => void }) {
  const [text, setText] = useState(JSON.stringify(rule, null, 2));
  const [err, setErr] = useState<string | null>(null);

  function save() {
    setErr(null);
    try {
      const parsed = JSON.parse(text) as IDSRule;
      if (!parsed.id) { setErr("Rule must have an id."); return; }
      onSave(parsed);
    } catch { setErr("Invalid JSON."); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-3xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[var(--text)]">
            Edit IDS rule {rule.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
          >
            Close
          </button>
        </div>
        {err && (
          <div className="mb-3 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            {err}
          </div>
        )}
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={14}
          className="w-full input-industrial font-mono text-xs"
        />
        <div className="mt-3 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
          >
            Save rule
          </button>
        </div>
      </div>
    </div>
  );
}
