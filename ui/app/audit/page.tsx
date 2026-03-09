 "use client";

import { useEffect, useState } from "react";

import { api, type AuditRecord } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { EmptyState } from "../../components/EmptyState";
import { useTableControls } from "../../hooks/useTableControls";
import { SearchBar, SortableHeader, Pagination } from "../../components/TableControls";

export default function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    const list = await api.listAudit();
    if (!list) {
      setError("Failed to load audit records.");
      setRecords([]);
      return;
    }
    setRecords(list);
  }

  const table = useTableControls(records, {
    defaultSort: "timestamp",
    defaultDir: "desc",
    searchKeys: ["actor", "action", "target"],
  });

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Shell
      title="Audit Log"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10 transition-ui"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-sm border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      <div className="mb-3 flex items-center gap-3">
        <SearchBar value={table.search} onChange={table.setSearch} placeholder="Search audit log..." />
      </div>

      {records.length === 0 && table.data.length === 0 ? (
        <EmptyState
          title="No audit records yet"
          description="Administrative actions will appear here automatically."
        />
      ) : (
      <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] overflow-hidden shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-white/[0.03]">
            <tr>
              <SortableHeader label="Time" sortKey="timestamp" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Actor" sortKey="actor" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Source" sortKey="source" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Action" sortKey="action" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Target" sortKey="target" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Result" sortKey="result" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
            </tr>
          </thead>
          <tbody>
            {table.data.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={6}>
                  No audit records match your search.
                </td>
              </tr>
            )}
            {table.data.map((r) => (
              <tr key={r.id} className="border-t border-white/[0.06] table-row-hover transition-ui">
                <td className="px-4 py-3 text-slate-200">
                  {new Date(r.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">{r.actor}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.source}</td>
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {r.action}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">{r.target}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pagination page={table.page} totalPages={table.totalPages} totalItems={table.totalItems} onPage={table.setPage} />
      </div>
      )}
    </Shell>
  );
}
