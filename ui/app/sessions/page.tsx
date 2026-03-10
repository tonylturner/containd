"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api, isAdmin, type ConntrackEntry } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";

type Filter = {
  q: string;
};

function normalizeProto(p: string | undefined): string {
  return (p ?? "").toLowerCase().trim();
}

export default function SessionsPage() {
  const canKill = isAdmin();
  const confirm = useConfirm();
  const [entries, setEntries] = useState<ConntrackEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<Filter>({ q: "" });
  const [limit, setLimit] = useState(500);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    const data = await api.listConntrack(limit);
    if (!data) {
      setError("Failed to load conntrack table (engine unreachable or conntrack unavailable).");
      setEntries([]);
      setLoading(false);
      return;
    }
    setEntries(data);
    setLoading(false);
  }, [limit]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const filtered = useMemo(() => {
    const q = filter.q.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((e) => {
      const hay = [
        e.proto,
        e.state ?? "",
        e.src ?? "",
        e.sport ?? "",
        e.dst ?? "",
        e.dport ?? "",
        e.mark ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [entries, filter.q]);

  async function kill(e: ConntrackEntry) {
    if (!canKill) return;
    setError(null);
    const proto = normalizeProto(e.proto);
    const src = (e.src ?? "").trim();
    const dst = (e.dst ?? "").trim();
    const sport = e.sport ? Number(e.sport) : undefined;
    const dport = e.dport ? Number(e.dport) : undefined;
    if (!proto || !src || !dst) {
      setError("Cannot kill: missing tuple fields.");
      return;
    }
    const res = await api.killConntrack({ proto, src, dst, sport, dport });
    if (!res) {
      setError("Kill failed (not supported, not found, or permission denied).");
      return;
    }
    await refresh();
  }

  function handleKill(e: ConntrackEntry) {
    confirm.open({
      title: "Kill Session",
      message: `Terminate ${e.proto ?? "?"} session ${e.src ?? "?"}:${e.sport ?? "?"} → ${e.dst ?? "?"}:${e.dport ?? "?"}? This is best-effort and cannot be undone.`,
      confirmLabel: "Kill",
      variant: "danger",
      onConfirm: () => kill(e),
    });
  }

  return (
    <Shell
      title="Sessions"
      actions={
        <div className="flex items-center gap-2">
          <input
            value={filter.q}
            onChange={(e) => setFilter({ q: e.target.value })}
            placeholder="Filter (ip, port, proto, state)…"
            className="input-industrial w-64"
          />
          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value) || 200)}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1.5 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
          >
            <option value="200">200</option>
            <option value="500">500</option>
            <option value="2000">2000</option>
          </select>
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.1]"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!canKill && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: session kill requires admin.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {!loading && filtered.length === 0 ? (
        <EmptyState
          title="No sessions to display"
          description={entries.length === 0 ? "No conntrack entries found. The engine may be unreachable or conntrack unavailable." : "No sessions match the current filter."}
        />
      ) : (
        <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] overflow-hidden shadow-card">
          <div className="flex items-center justify-between px-4 py-3">
            <div>
              <div className="text-sm text-[var(--text)]">
                {loading ? "Loading…" : `${filtered.length} shown / ${entries.length} total`}
              </div>
              <div className="text-xs text-[var(--text-muted)]">
                Conntrack is kernel state. Kill is best-effort (IPv4 tcp/udp/icmp only for now).
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)]">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Proto</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">State</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Src</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Sport</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Dst</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Dport</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Mark</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Assured</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">TTL</th>
                  <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, idx) => (
                  <tr key={`${e.proto}-${e.src}-${e.sport}-${e.dst}-${e.dport}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                    <td className="px-4 py-3 font-medium text-[var(--text)]">{e.proto || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.state || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.src || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.sport || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.dst || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.dport || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.mark || "—"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.assured ? "yes" : "no"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{e.timeoutSecs ? `${e.timeoutSecs}s` : "—"}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        disabled={!canKill}
                        onClick={() => handleKill(e)}
                        className={
                          canKill
                            ? "rounded-sm px-3 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                            : "rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1 text-xs text-[var(--text-dim)]"
                        }
                        title={canKill ? "Delete conntrack entry (best-effort)" : "Admin only"}
                      >
                        Kill
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
