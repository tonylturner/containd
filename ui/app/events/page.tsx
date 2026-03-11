"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";

type EventFilter = "all" | "service" | "dpi" | "firewall" | "proxy";

const FILTER_OPTIONS: Array<{ value: EventFilter; label: string }> = [
  { value: "all", label: "All activity" },
  { value: "service", label: "Service health" },
  { value: "proxy", label: "Proxy activity" },
  { value: "dpi", label: "DPI / ICS" },
  { value: "firewall", label: "Firewall decisions" },
];

function eventHeadline(ev: TelemetryEvent): string {
  if (ev.kind === "service.av.detected") return "Antivirus detection";
  if (ev.kind === "service.av.block_flow") return "Antivirus blocked flow";
  if (ev.kind.startsWith("service.envoy.")) return "Envoy proxy event";
  if (ev.kind.startsWith("service.nginx.")) return "Nginx proxy event";
  if (ev.kind.startsWith("service.dhcp.")) return "DHCP service event";
  if (ev.kind.startsWith("service.")) return "System service event";
  if (ev.proto === "firewall") return "Firewall decision";
  if (ev.proto) return `${ev.proto.toUpperCase()} telemetry`;
  return "Telemetry event";
}

function eventSubtitle(ev: TelemetryEvent): string {
  const parts = [ev.kind];
  if (ev.proto && ev.proto !== "firewall") parts.push(ev.proto.toUpperCase());
  if (ev.transport) parts.push(ev.transport.toUpperCase());
  return parts.join(" · ");
}

function EventsInner() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<EventFilter>("all");
  const [kindPrefix, setKindPrefix] = useState<string>("");
  const [onlyDetections, setOnlyDetections] = useState(false);
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [live, setLive] = useState(true);

  async function manualRefresh() {
    setError(null);
    setLoading(true);
    try {
      const list = await api.listEvents();
      if (!list) { setError("Failed to load events."); setLoading(false); return; }
      setEvents(list);
      setLoading(false);
    } catch {
      setError("Failed to load events.");
      setLoading(false);
    }
  }

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
  const detectionCount = useMemo(
    () => events.filter((ev) => ev.kind === "service.av.detected" || ev.kind === "service.av.block_flow").length,
    [events],
  );
  const proxyCount = useMemo(
    () => events.filter((ev) => ev.kind.startsWith("service.envoy.") || ev.kind.startsWith("service.nginx.")).length,
    [events],
  );
  const serviceCount = useMemo(
    () => events.filter((ev) => ev.kind.startsWith("service.")).length,
    [events],
  );

  // Progressive rendering: show PAGE_SIZE items at a time
  const PAGE_SIZE = 50;
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  // Reset visible count when filters change
  useEffect(() => {
    setVisibleCount(PAGE_SIZE);
  }, [filter, kindPrefix, onlyDetections]);

  const visibleEvents = useMemo(
    () => filteredEvents.slice(0, visibleCount),
    [filteredEvents, visibleCount],
  );

  const hasMore = visibleCount < filteredEvents.length;

  const loadMore = useCallback(() => {
    setVisibleCount((prev) => Math.min(prev + PAGE_SIZE, filteredEvents.length));
  }, [filteredEvents.length]);

  // IntersectionObserver for infinite scroll
  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) loadMore();
      },
      { rootMargin: "200px" },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [loadMore]);

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

    const controller = new AbortController();

    async function refresh() {
      setError(null);
      setLoading(true);
      try {
        const list = await api.listEvents(500, controller.signal);
        if (!list) {
          setError("Failed to load events.");
          setLoading(false);
          return;
        }
        setEvents(list);
        setLoading(false);
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setError("Failed to load events.");
        setLoading(false);
      }
    }

    refresh();
    if (!live) return () => controller.abort();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, 10000);
    const onVisible = () => { if (!document.hidden) refresh(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [searchParams, live]);

  return (
    <Shell
      title="Events"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => setLive((v) => !v)}
            className={`inline-flex items-center gap-1.5 rounded-sm border px-3 py-1.5 text-xs font-medium transition-colors ${
              live
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                : "border-amber-500/[0.15] bg-[var(--surface2)] text-[var(--text-muted)] hover:bg-amber-500/[0.1]"
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
            onClick={manualRefresh}
            className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.06]"
          >
            Refresh
          </button>
        </div>
      }
    >
      {/* Filter bar */}
      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
        <div className="w-full text-xs text-[var(--text-muted)]">
          Use Events for raw telemetry and service activity. Use Flows for active connections and Alerts for IDS triage.
        </div>
        {FILTER_OPTIONS.map((option) => (
          <button
            key={option.value}
            onClick={() => setFilter(option.value)}
            className={
              filter === option.value
                ? "transition-ui rounded-sm border border-amber-500/30 bg-amber-500/[0.1] px-3 py-1.5 text-xs text-[var(--text)]"
                : "transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
            }
          >
            {option.label}
          </button>
        ))}
        <button
          onClick={() => {
            setFilter("proxy");
            setKindPrefix("service.envoy");
          }}
          className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
        >
          Envoy only
        </button>
        <button
          onClick={() => {
            setFilter("proxy");
            setKindPrefix("service.nginx");
          }}
          className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
        >
          Nginx only
        </button>
        <select
          className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
          value={filter}
          onChange={(e) => setFilter(e.target.value as EventFilter)}
        >
          {FILTER_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Event name starts with... (optional)"
          value={kindPrefix}
          onChange={(e) => setKindPrefix(e.target.value)}
          className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
        />
        <label className="flex items-center gap-2 text-xs text-[var(--text)]">
          <input
            type="checkbox"
            checked={onlyDetections}
            onChange={(e) => setOnlyDetections(e.target.checked)}
            className="h-4 w-4"
          />
          Show AV detections only
        </label>
        {(filter !== "all" || kindPrefix.trim() || onlyDetections) && (
          <button
            onClick={() => {
              setFilter("all");
              setKindPrefix("");
              setOnlyDetections(false);
            }}
            className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
          >
            Clear filters
          </button>
        )}
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <div className="mb-3 flex flex-wrap gap-2 text-xs text-[var(--text)]">
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs">
          Showing: {visibleEvents.length} of {filteredEvents.length}
        </div>
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs">
          Proxy events: {proxyCount}
        </div>
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs">
          Service events: {serviceCount}
        </div>
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs">
          AV detections: {detectionCount}
        </div>
      </div>

      <div className="space-y-2">
        {loading && <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-6 text-sm text-[var(--text-muted)]">Loading...</div>}
        {!loading && events.length === 0 && (
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-6 text-center text-sm text-[var(--text-muted)]">
            No events yet. Enable DPI capture or learning mode to generate events.
          </div>
        )}
        {!loading && filteredEvents.length > 0 && (
          <div className="mb-2 text-xs text-[var(--text-muted)]">
            Showing {visibleEvents.length} of {filteredEvents.length} events
          </div>
        )}
        {!loading && visibleEvents
          .map((ev) => (
          <div
            key={ev.id}
            className="table-row-hover rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4"
          >
            <div className="flex items-center justify-between">
              <div className="text-sm font-semibold text-[var(--text)]">
                {eventHeadline(ev)}
              </div>
              <div className="text-xs text-[var(--text-muted)]">
                {new Date(ev.timestamp).toLocaleString()}
              </div>
            </div>
            <div className="mt-1 text-xs text-[var(--text-muted)]">
              {eventSubtitle(ev)}
            </div>
            <div className="mt-1 text-xs text-[var(--text)]">
              {ev.srcIp}:{ev.srcPort} → {ev.dstIp}:{ev.dstPort}{" "}
              {ev.transport ? `(${ev.transport})` : ""}
            </div>
            {ev.attributes && (
              <pre className="mt-2 overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-[var(--text)]">
                {JSON.stringify(ev.attributes, null, 2)}
              </pre>
            )}
          </div>
        ))}
        {/* Infinite scroll sentinel */}
        {hasMore && (
          <div ref={sentinelRef} className="flex items-center justify-center py-4">
            <button
              onClick={loadMore}
              className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-2 text-sm text-[var(--text-muted)] hover:bg-amber-500/[0.06]"
            >
              Load more ({filteredEvents.length - visibleCount} remaining)
            </button>
          </div>
        )}
      </div>
    </Shell>
  );
}

export default function EventsPage() {
  return (
    <Suspense fallback={<div className="p-4 text-[var(--text)]">Loading events...</div>}>
      <EventsInner />
    </Suspense>
  );
}
