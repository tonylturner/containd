 "use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useCallback, useState } from "react";

import { getEvidenceStatus, type AuditPersistenceStatus } from "../../lib/api-evidence";
import { EvidenceBannerAudit } from "../../components/EvidenceBannerAudit";
import { api, type AuditRecord } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { EmptyState } from "../../components/EmptyState";
import { useTableControls } from "../../hooks/useTableControls";
import { SearchBar, SortableHeader, Pagination } from "../../components/TableControls";

export default function AuditPage() {
  const [persistence, setPersistence] = useState<AuditPersistenceStatus | null>(null);
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  const { loading, refresh } = useAsyncRefresh(useCallback(async () => {
    const [list, evidence] = await Promise.all([api.listAudit(), getEvidenceStatus()]);
    setPersistence(evidence?.audit ?? null);
    setError(null);
    if (!list) {
      setError("Failed to load audit records.");
      setRecords([]);
      return;
    }
    setRecords(list);
  }, []));

  const table = useTableControls(records, {
    defaultSort: "timestamp",
    defaultDir: "desc",
    searchKeys: ["actor", "action", "target"],
  });

  return (
    <Shell
      title="Audit Log"
      actions={
        <button
          onClick={refresh}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
        >
          Refresh
        </button>
      }
    >
      <EvidenceBannerAudit audit={persistence} loading={loading} />
      {!loading && error && (
        <div className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      <div className="mb-3 flex items-center gap-3">
        <SearchBar value={table.search} onChange={table.setSearch} placeholder="Search audit log..." />
      </div>

      {records.length === 0 && table.data.length === 0 ? (
        <EmptyState
          title="No audit records yet"
          description="Only successfully persisted actions appear here. An empty table does not prove no actions occurred; check audit persistence above."
        />
      ) : (
      <div className="rounded-xs border bg-(--surface) overflow-hidden shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-(--surface)">
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
                <td className="px-4 py-4 text-(--text-muted)" colSpan={6}>
                  No audit records match your search.
                </td>
              </tr>
            )}
            {table.data.map((r) => (
              <tr key={r.id} className="border-t table-row-hover transition-ui">
                <td className="px-4 py-3 text-(--text)">
                  {new Date(r.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-(--text)">{r.actor}</td>
                <td className="px-4 py-3 text-(--text)">{r.source}</td>
                <td className="px-4 py-3 font-mono text-xs text-(--text)">
                  {r.action}
                </td>
                <td className="px-4 py-3 text-(--text)">{r.target}</td>
                <td className="px-4 py-3 text-(--text)">{r.result}</td>
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
