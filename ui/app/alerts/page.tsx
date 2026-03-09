"use client";

import { useEffect, useMemo, useState } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { StatusBadge } from "../../components/StatusBadge";
import { EmptyState } from "../../components/EmptyState";

const severityVariant = (sev: string) => {
  switch (sev) {
    case "critical":
      return "error" as const;
    case "high":
      return "warning" as const;
    case "medium":
      return "info" as const;
    default:
      return "neutral" as const;
  }
};

export default function AlertsPage() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(true);

  async function refresh() {
    setError(null);
    const list = await api.listEvents(2000);
    if (!list) { setError("Failed to load alerts."); return; }
    setEvents(list);
  }

  useEffect(() => {
    refresh();
    if (!live) return;
    const id = setInterval(refresh, 10000);
    return () => clearInterval(id);
  }, [live]);

  const alerts = useMemo(() => {
    let list = events.filter((e) => e.proto === "ids" && e.kind === "alert");
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((ev) => {
        const msg = String(ev.attributes?.["message"] ?? "");
        const ruleId = String(ev.attributes?.["rule_id"] ?? "");
        const sev = String(ev.attributes?.["severity"] ?? "");
        return msg.toLowerCase().includes(q) || ruleId.toLowerCase().includes(q) ||
          sev.toLowerCase().includes(q) || (ev.srcIp ?? "").includes(q) || (ev.dstIp ?? "").includes(q);
      });
    }
    if (sevFilter) {
      list = list.filter((ev) => String(ev.attributes?.["severity"] ?? "low") === sevFilter);
    }
    return list;
  }, [events, search, sevFilter]);

  const totalPages = Math.max(1, Math.ceil(alerts.length / pageSize));
  const clampedPage = Math.min(page, totalPages - 1);
  const pageData = alerts.slice(clampedPage * pageSize, (clampedPage + 1) * pageSize);

  useEffect(() => { setPage(0); }, [search, sevFilter, pageSize]);

  // Severity summary
  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const ev of alerts) {
      const s = String(ev.attributes?.["severity"] ?? "low") as keyof typeof c;
      if (s in c) c[s]++;
    }
    return c;
  }, [alerts]);

  return (
    <Shell
      title="IDS Alerts"
      actions={
        <div className="flex items-center gap-3">
          <button
            onClick={() => setLive((v) => !v)}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              live
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                : "border-white/10 bg-white/5 text-slate-400 hover:bg-white/10"
            }`}
          >
            {live && (
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
              </span>
            )}
            {live ? "Live" : "Paused"}
          </button>
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-white/10 hover:text-white"
          >
            Refresh
          </button>
        </div>
      }
    >
      {error && <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</div>}

      {alerts.length === 0 ? (
        <EmptyState
          title="No IDS alerts"
          description="No intrusion detection alerts have been recorded yet. Alerts will appear here when the IDS engine detects suspicious activity."
        />
      ) : (
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="bg-white/[0.03] text-xs font-medium uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Message</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Destination</th>
                <th className="px-4 py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((ev) => {
                const sev =
                  (ev.attributes?.["severity"] as string | undefined) ?? "low";
                const msg =
                  (ev.attributes?.["message"] as string | undefined) ??
                  (ev.attributes?.["rule_id"] as string | undefined) ??
                  "IDS alert";
                return (
                  <tr
                    key={ev.id}
                    className="table-row-hover transition-ui border-t border-white/[0.06]"
                  >
                    <td className="px-4 py-3 font-medium text-white">{msg}</td>
                    <td className="px-4 py-3">
                      <StatusBadge variant={severityVariant(sev)} dot>
                        {sev}
                      </StatusBadge>
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {ev.srcIp}:{ev.srcPort}
                      {ev.transport ? ` (${ev.transport})` : ""}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {ev.dstIp}:{ev.dstPort}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Shell>
  );
}
