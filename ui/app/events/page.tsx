"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { StatusBadge } from "../../components/StatusBadge";
import { describeICSEvidence } from "./iec104-evidence";

type EventFilter = "all" | "service" | "dpi" | "firewall" | "proxy" | "iec104";

const FILTER_OPTIONS: Array<{ value: EventFilter; label: string }> = [
  { value: "all", label: "All activity" },
  { value: "service", label: "Service health" },
  { value: "proxy", label: "Proxy activity" },
  { value: "dpi", label: "DPI / ICS" },
  { value: "iec104", label: "IEC 104" },
  { value: "firewall", label: "Firewall decisions" },
];

function eventHeadline(ev: TelemetryEvent): string {
  const evidence = describeICSEvidence(ev);
  if (evidence) return evidence.headline;
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
  const searchParams = useSearchParams();
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<EventFilter>(() => { const type = searchParams.get("filter"); return FILTER_OPTIONS.some((option) => option.value === type) ? type as EventFilter : "all"; });
  const [kindPrefix, setKindPrefix] = useState(searchParams.get("kind") || "");
  const [onlyDetections, setOnlyDetections] = useState(searchParams.get("av") === "1");
  const [sessionFilter, setSessionFilter] = useState(searchParams.get("session") || "");
  const [flowFilter, setFlowFilter] = useState(searchParams.get("flow") || "");
  const [apdu, setAPDU] = useState(searchParams.get("apdu") || "");
  const [protocol, setProtocol] = useState(searchParams.get("protocol") || "");
  const [decision, setDecision] = useState(searchParams.get("decision") || "");
  const [verdict, setVerdict] = useState(searchParams.get("verdict") || "");
  const [since, setSince] = useState(searchParams.get("since") || "");
  const [cursor, setCursor] = useState(searchParams.get("cursor") || "");
  const [nextCursor, setNextCursor] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [live, setLive] = useState(true);
  const requestRef = useRef<AbortController | null>(null);
  const query = useMemo(() => ({
    session: sessionFilter, flow: flowFilter, apdu, protocol, decision, verdict, since, cursor,
    kind: kindPrefix.trim(), category: filter, detections: onlyDetections ? "1" : "",
  }), [sessionFilter, flowFilter, apdu, protocol, decision, verdict, since, cursor, kindPrefix, filter, onlyDetections]);

  const refresh = useCallback(async (olderCursor?: string) => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    setError(null);
    setLoading(true);
    try {
      const page = await api.queryEvents({ ...query, cursor: olderCursor || query.cursor }, controller.signal);
      if (controller.signal.aborted) return;
      if (!page) { setEvents([]); setNextCursor(""); setTruncated(false); setError("Failed to load events. Check query bounds and engine availability."); return; }
      setEvents((previous) => olderCursor ? [...previous, ...page.events.filter((ev) => !previous.some((old) => old.id === ev.id))] : page.events);
      setNextCursor(page.nextCursor || "");
      setTruncated(page.historyTruncated);
      if (page.engineError) setError(`Engine evidence unavailable: ${page.engineError}`);
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      setEvents([]); setNextCursor(""); setTruncated(false);
      setError("Failed to load events.");
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [query]);

  function manualRefresh() { void refresh(); }
  const filteredEvents = events;
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
  }, [query]);

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
    setFilter(FILTER_OPTIONS.some((option) => option.value === type) ? type as EventFilter : "all");
    setSessionFilter(searchParams.get("session") || "");
    setFlowFilter(searchParams.get("flow") || "");
    setAPDU(searchParams.get("apdu") || "");
    setKindPrefix(searchParams.get("kind") || "");
    setProtocol(searchParams.get("protocol") || "");
    setDecision(searchParams.get("decision") || "");
    setVerdict(searchParams.get("verdict") || "");
    setSince(searchParams.get("since") || "");
    setCursor(searchParams.get("cursor") || "");
    setOnlyDetections(searchParams.get("av") === "1");
  }, [searchParams]);

  useEffect(() => {
    setEvents([]); setNextCursor(""); setTruncated(false);
    void refresh();
    if (!live) return () => requestRef.current?.abort();
    const id = setInterval(() => { if (!document.hidden) void refresh(); }, 10000);
    const onVisible = () => { if (!document.hidden) void refresh(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      requestRef.current?.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [refresh, live]);

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
        {([
          ["Session ID", sessionFilter, setSessionFilter], ["Flow ID", flowFilter, setFlowFilter],
          ["APDU ID", apdu, setAPDU], ["Protocol", protocol, setProtocol], ["Decision", decision, setDecision],
          ["Verdict / outcome", verdict, setVerdict], ["Since (RFC3339)", since, setSince],
          ["Cursor", cursor, setCursor],
        ] as const).map(([label, value, setValue]) => (
          <label key={label} className="flex flex-col gap-1 text-xs text-[var(--text)]">
            {label}
            <input aria-label={label} value={value} onChange={(e) => setValue(e.target.value)}
              className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm outline-none focus:border-amber-500/40" />
          </label>
        ))}
        <label className="flex items-center gap-2 text-xs text-[var(--text)]">
          <input
            type="checkbox"
            checked={onlyDetections}
            onChange={(e) => setOnlyDetections(e.target.checked)}
            className="h-4 w-4"
          />
          Show AV detections only
        </label>
        {sessionFilter && (
          <button
            onClick={() => setSessionFilter("")}
            title="Clear session filter"
            className="transition-ui rounded-sm border border-amber-500/30 bg-amber-500/[0.1] px-3 py-1.5 font-mono text-xs text-[var(--text)]"
          >
            Session {sessionFilter} ×
          </button>
        )}
        {(filter !== "all" || kindPrefix.trim() || onlyDetections || sessionFilter || flowFilter || apdu || protocol || decision || verdict || since || cursor) && (
          <button
            onClick={() => {
              setFilter("all");
              setKindPrefix("");
              setOnlyDetections(false);
              setSessionFilter("");
              setFlowFilter(""); setAPDU(""); setProtocol(""); setDecision(""); setVerdict(""); setSince(""); setCursor("");
            }}
            className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
          >
            Clear filters
          </button>
        )}
      </div>

      {truncated && <p role="status" className="mb-3 text-sm text-[var(--text-muted)]">Retained evidence only: history may have gaps from eviction or restart. Pagination cannot recover missing events.</p>}
      {nextCursor && <button disabled={live || loading} onClick={() => void refresh(nextCursor)} className="mb-3 rounded-sm border border-amber-500/[0.15] px-3 py-1.5 text-sm disabled:opacity-50">{live ? "Pause live updates to load older evidence" : "Load older evidence"}</button>}
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
            No retained events match this query. Clear filters or check the session and time bounds.
          </div>
        )}
        {!loading && filteredEvents.length > 0 && (
          <div className="mb-2 text-xs text-[var(--text-muted)]">
            Showing {visibleEvents.length} of {filteredEvents.length} events
          </div>
        )}
        {!loading && visibleEvents
          .map((ev) => {
          const evidence = describeICSEvidence(ev);
          return (
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
            {evidence && (
              <div className="mt-2 space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge variant={evidence.variant} dot>{evidence.badge}</StatusBadge>
                  <span className="text-xs text-[var(--text)]">{evidence.message}</span>
                  {evidence.sessionId && evidence.sessionId !== sessionFilter && (
                    <button
                      onClick={() => setSessionFilter(evidence.sessionId)}
                      className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-0.5 text-[10px] text-[var(--text)] hover:bg-amber-500/[0.06]"
                    >
                      Show session
                    </button>
                  )}
                </div>
                <div className="grid gap-x-4 gap-y-0.5 text-xs sm:grid-cols-2">
                  {evidence.rows.map((row) => (
                    <div key={row.label} className="flex gap-2">
                      <span className="shrink-0 text-[var(--text-dim)]">{row.label}</span>
                      <span className="break-all font-mono text-[11px] text-[var(--text)]">{row.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {ev.attributes && (
              <pre className="mt-2 overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-[var(--text)]">
                {JSON.stringify(ev.attributes, null, 2)}
              </pre>
            )}
          </div>
          );
        })}
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
