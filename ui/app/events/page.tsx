"use client";

import { useEffect, useState } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function EventsPage() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "service" | "dpi" | "firewall">(
    "all",
  );

  async function refresh() {
    setError(null);
    const list = await api.listEvents();
    if (!list) {
      setError("Failed to load events.");
      return;
    }
    setEvents(list);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, []);

  return (
    <Shell
      title="Events"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
        <select
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200"
          value={filter}
          onChange={(e) => setFilter(e.target.value as any)}
        >
          <option value="all">All</option>
          <option value="service">Service events</option>
          <option value="dpi">DPI/IDS</option>
          <option value="firewall">Firewall</option>
        </select>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="space-y-2">
        {events.length === 0 && (
          <div className="rounded-xl border border-white/10 bg-white/5 p-6 text-center text-sm text-slate-400">
            No events yet. Enable DPI mock or capture to generate events.
          </div>
        )}
        {events
          .filter((ev) => {
            if (filter === "all") return true;
            if (filter === "service") return ev.kind.startsWith("service.");
            if (filter === "firewall") return ev.proto === "firewall";
            if (filter === "dpi") return ev.proto !== "firewall" && !ev.kind.startsWith("service.");
            return true;
          })
          .map((ev) => (
          <div
            key={ev.id}
            className="rounded-xl border border-white/10 bg-black/30 p-4"
          >
            <div className="flex items-center justify-between">
              <div className="text-sm font-semibold text-white">
                {ev.proto.toUpperCase()} / {ev.kind}
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
        ))}
      </div>
    </Shell>
  );
}
