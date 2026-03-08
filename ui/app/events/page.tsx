"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";

function EventsInner() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "service" | "dpi" | "firewall" | "proxy">(
    "all",
  );
  const [kindPrefix, setKindPrefix] = useState<string>("");
  const [onlyDetections, setOnlyDetections] = useState(false);
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(false);

  const filteredEvents = useMemo(
    () =>
      events
        .filter((ev) => {
          if (filter === "all") return true;
          if (filter === "service") return ev.kind.startsWith("service.");
          if (filter === "proxy") {
            return ev.kind.startsWith("service.envoy.") || ev.kind.startsWith("service.nginx.");
          }
          if (filter === "firewall") return ev.proto === "firewall";
          if (filter === "dpi") return ev.proto !== "firewall" && !ev.kind.startsWith("service.");
          return true;
        })
        .filter((ev) => {
          if (!kindPrefix.trim()) return true;
          return ev.kind.startsWith(kindPrefix.trim());
        })
        .filter((ev) => {
          if (!onlyDetections) return true;
          return ev.kind === "service.av.detected" || ev.kind === "service.av.block_flow";
        }),
    [events, filter, kindPrefix, onlyDetections],
  );

  async function refresh() {
    setError(null);
    setLoading(true);
    const list = await api.listEvents();
    if (!list) {
      setError("Failed to load events.");
      setLoading(false);
      return;
    }
    setEvents(list);
    setLoading(false);
  }

  useEffect(() => {
    const type = searchParams.get("filter");
    const avOnly = searchParams.get("av") === "1";
    if (type === "service" || type === "dpi" || type === "firewall" || type === "proxy") {
      setFilter(type);
    }
    const kindPref = searchParams.get("kind");
    if (kindPref) {
      setKindPrefix(kindPref);
    }
    if (avOnly) setOnlyDetections(true);
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [searchParams]);

  return (
    <Shell
      title="Events"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setFilter("proxy");
                setKindPrefix("service.envoy");
              }}
              className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-200 hover:bg-white/10"
            >
              Envoy
            </button>
            <button
              onClick={() => {
                setFilter("proxy");
                setKindPrefix("service.nginx");
              }}
              className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-200 hover:bg-white/10"
            >
              Nginx
            </button>
          </div>
          <select
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200"
            value={filter}
            onChange={(e) => setFilter(e.target.value as any)}
          >
            <option value="all">All</option>
            <option value="service">Service events</option>
            <option value="proxy">Proxy</option>
            <option value="dpi">DPI/IDS</option>
            <option value="firewall">Firewall</option>
          </select>
          <input
            type="text"
            placeholder="Filter by kind prefix (e.g., service.dhcp.reservation)"
            value={kindPrefix}
            onChange={(e) => setKindPrefix(e.target.value)}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200"
          />
          <label className="flex items-center gap-2 text-xs text-slate-200">
            <input
              type="checkbox"
              checked={onlyDetections}
              onChange={(e) => setOnlyDetections(e.target.checked)}
              className="h-4 w-4"
            />
            Show AV detections only
          </label>
        </div>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}
      <div className="mb-3 flex flex-wrap gap-2 text-xs text-slate-300">
        <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5">
          Envoy events: {events.filter((e) => e.kind.startsWith("service.envoy.")).length}
        </div>
        <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5">
          Nginx events: {events.filter((e) => e.kind.startsWith("service.nginx.")).length}
        </div>
        <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5">
          Service events: {events.filter((e) => e.kind.startsWith("service.")).length}
        </div>
      </div>

      <div className="space-y-2">
        {loading && <div className="rounded-xl border border-white/10 bg-white/5 p-6 text-sm text-slate-400">Loading…</div>}
        {!loading && events.length === 0 && (
          <div className="rounded-xl border border-white/10 bg-white/5 p-6 text-center text-sm text-slate-400">
            No events yet. Enable DPI capture or learning mode to generate events.
          </div>
        )}
        {!loading && filteredEvents
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

export default function EventsPage() {
  return (
    <Suspense fallback={<div className="p-4 text-slate-200">Loading events…</div>}>
      <EventsInner />
    </Suspense>
  );
}
