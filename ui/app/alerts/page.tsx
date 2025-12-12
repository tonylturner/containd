"use client";

import { useEffect, useMemo, useState } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function AlertsPage() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    const list = await api.listEvents(500);
    if (!list) {
      setError("Failed to load alerts.");
      return;
    }
    setEvents(list);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, []);

  const alerts = useMemo(
    () => events.filter((e) => e.proto === "ids" && e.kind === "alert"),
    [events],
  );

  return (
    <Shell
      title="IDS Alerts"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      {alerts.length === 0 && (
        <div className="rounded-xl border border-white/10 bg-white/5 p-6 text-center text-sm text-slate-400">
          No IDS alerts yet.
        </div>
      )}

      <div className="space-y-2">
        {alerts.map((ev) => {
          const sev =
            (ev.attributes?.["severity"] as string | undefined) ?? "low";
          const msg =
            (ev.attributes?.["message"] as string | undefined) ??
            (ev.attributes?.["rule_id"] as string | undefined) ??
            "IDS alert";
          return (
            <div
              key={ev.id}
              className="rounded-xl border border-white/10 bg-black/30 p-4"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-white">{msg}</span>
                  <span
                    className={
                      sev === "critical" || sev === "high"
                        ? "rounded-full bg-amber/20 px-2 py-0.5 text-xs text-amber"
                        : sev === "medium"
                          ? "rounded-full bg-white/10 px-2 py-0.5 text-xs text-slate-200"
                          : "rounded-full bg-mint/20 px-2 py-0.5 text-xs text-mint"
                    }
                  >
                    {sev}
                  </span>
                </div>
                <div className="text-xs text-slate-400">
                  {new Date(ev.timestamp).toLocaleString()}
                </div>
              </div>
              <div className="mt-1 text-xs text-slate-300">
                {ev.srcIp}:{ev.srcPort} → {ev.dstIp}:{ev.dstPort}{" "}
                {ev.transport ? `(${ev.transport})` : ""}
              </div>
              {ev.attributes && (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-slate-200">
                  {JSON.stringify(ev.attributes, null, 2)}
                </pre>
              )}
            </div>
          );
        })}
      </div>
    </Shell>
  );
}

