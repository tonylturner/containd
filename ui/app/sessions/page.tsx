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
            className="w-64 rounded-lg border border-white/10 bg-black/40 px-3 py-1.5 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 outline-none"
          />
          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value) || 200)}
            className="rounded-lg border border-white/10 bg-black/40 px-2 py-1.5 text-sm text-white transition-ui focus:border-blue-500/40 outline-none"
          >
            <option value="200">200</option>
            <option value="500">500</option>
            <option value="2000">2000</option>
          </select>
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!canKill && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
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
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] overflow-hidden shadow-card">
          <div className="flex items-center justify-between px-4 py-3">
            <div>
              <div className="text-sm text-slate-200">
                {loading ? "Loading…" : `${filtered.length} shown / ${entries.length} total`}
              </div>
              <div className="text-xs text-slate-400">
                Conntrack is kernel state. Kill is best-effort (IPv4 tcp/udp/icmp only for now).
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-white/[0.03]">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Proto</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">State</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Src</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Sport</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Dst</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Dport</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Mark</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">Assured</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500">TTL</th>
                  <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-slate-500">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, idx) => (
                  <tr key={`${e.proto}-${e.src}-${e.sport}-${e.dst}-${e.dport}-${idx}`} className="table-row-hover transition-ui border-t border-white/[0.06]">
                    <td className="px-4 py-3 font-medium text-white">{e.proto || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.state || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.src || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.sport || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.dst || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.dport || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.mark || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.assured ? "yes" : "no"}</td>
                    <td className="px-4 py-3 text-slate-200">{e.timeoutSecs ? `${e.timeoutSecs}s` : "—"}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        disabled={!canKill}
                        onClick={() => handleKill(e)}
                        className={
                          canKill
                            ? "rounded-lg px-3 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                            : "rounded-lg border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-500"
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
