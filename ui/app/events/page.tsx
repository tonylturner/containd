"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";
import { api, type TelemetryEvent } from "../../lib/api";
import { formatEndpoint } from "../../lib/endpoint";
import { Shell } from "../../components/Shell";
import { StatusBadge } from "../../components/StatusBadge";
import { IdentificationBadge } from "../flows/identification-badge";
import { describeICSEvidence } from "./iec104-evidence";
import { EventInspection } from "./event-inspection";

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
  if (ev.proto === "identify" && ev.kind === "identification") return "Content identification";
  const evidence = describeICSEvidence(ev);
  if (evidence) return evidence.headline;
  if (ev.kind === "service.av.detected") return "Antivirus detection";
  if (ev.kind === "service.av.block_flow") return "Antivirus blocked flow";
  if (ev.kind.startsWith("service.envoy.")) return "Forward-proxy event";
  if (ev.kind.startsWith("service.nginx.")) return "Reverse-proxy event";
  if (ev.kind.startsWith("service.dhcp.")) return "DHCP service event";
  if (ev.kind.startsWith("service.")) return "System service event";
  if (ev.proto === "firewall") return "Firewall decision";
  if (ev.proto) return `${ev.proto.toUpperCase()} telemetry`;
  return "Telemetry event";
}

function EventsInner() {
  const searchParams = useSearchParams();
  const [live, setLive] = useState(true);
  return <EventsContent key={searchParams.toString()} live={live} setLive={setLive} />;
}

function EventsContent({ live, setLive }: { live: boolean; setLive: React.Dispatch<React.SetStateAction<boolean>> }) {
  const searchParams = useSearchParams();
  const [filter, setFilter] = useState<EventFilter>(() => { const type = searchParams.get("filter"); return FILTER_OPTIONS.some((option) => option.value === type) ? type as EventFilter : "all"; });
  const [kindPrefix, setKindPrefix] = useState(searchParams.get("kind") || "");
  const [onlyDetections, setOnlyDetections] = useState(searchParams.get("av") === "1");
  const [sessionFilter, setSessionFilter] = useState(searchParams.get("session") || "");
  const [flowFilter, setFlowFilter] = useState(searchParams.get("flow") || "");
  const [apdu, setAPDU] = useState(searchParams.get("apdu") || "");
  const [protocol, setProtocol] = useState(searchParams.get("protocol") || "");
  const [ruleId, setRuleId] = useState(searchParams.get("ruleId") || "");
  const [mode, setMode] = useState(searchParams.get("mode") || "");
  const [decision, setDecision] = useState(searchParams.get("decision") || "");
  const [verdict, setVerdict] = useState(searchParams.get("verdict") || "");
  const [since, setSince] = useState(searchParams.get("since") || "");
  const [detailErrors, setDetailErrors] = useState<Record<string, boolean>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [advancedOpen, setAdvancedOpen] = useState<boolean | null>(null);
  const [cursor, setCursor] = useState(searchParams.get("cursor") || "");
  const filtersOpen = advancedOpen ?? Boolean(sessionFilter || flowFilter || ruleId || mode || apdu || protocol || decision || verdict || since || cursor);
  const requestRef = useRef<AbortController | null>(null);
  const query = useMemo(() => ({
    session: sessionFilter, flow: flowFilter, ruleId, mode, apdu, protocol, decision, verdict, since, cursor,
    kind: kindPrefix.trim(), category: filter, detections: onlyDetections ? "1" : "",
  }), [ruleId, mode, sessionFilter, flowFilter, apdu, protocol, decision, verdict, since, cursor, kindPrefix, filter, onlyDetections]);

  const queryKey = JSON.stringify([query, live]);
  const [result, setResult] = useState<{
    key: string; events: TelemetryEvent[]; nextCursor: string; truncated: boolean; error: string | null;
  } | null>(null);
  const events = useMemo(() => result?.key === queryKey ? result.events : [], [result, queryKey]);
  const nextCursor = result?.key === queryKey ? result.nextCursor : "";
  const truncated = result?.key === queryKey && result.truncated;

  const { loading, refresh } = useAsyncRefresh(useCallback(async (olderCursor?: string) => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    try {
      const page = await api.queryEvents({ ...query, cursor: olderCursor || query.cursor }, controller.signal);
      if (controller.signal.aborted) return;
      if (!page) {
        setResult({ key: queryKey, events: [], nextCursor: "", truncated: false,
          error: "Failed to load events. Check filters and traffic-monitoring availability." });
        return;
      }
      setResult((previous) => {
        const earlier = previous?.key === queryKey ? previous.events : [];
        return { key: queryKey,
          events: olderCursor ? [...earlier, ...page.events.filter((ev) => !earlier.some((old) => old.id === ev.id))] : page.events,
          nextCursor: page.nextCursor || "", truncated: page.historyTruncated,
          error: page.engineError ? `Engine evidence unavailable: ${page.engineError}` : null,
        };
      });
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      setResult({ key: queryKey, events: [], nextCursor: "", truncated: false, error: "Failed to load events." });
    }
  }, [query, queryKey]));
  const error = !loading && result?.key === queryKey ? result.error : null;

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
  const [windowSize, setWindowSize] = useState({ key: queryKey, count: PAGE_SIZE });
  const visibleCount = windowSize.key === queryKey ? windowSize.count : PAGE_SIZE;
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  const visibleEvents = useMemo(
    () => filteredEvents.slice(0, visibleCount),
    [filteredEvents, visibleCount],
  );

  const hasMore = visibleCount < filteredEvents.length;

  const loadMore = useCallback(() => {
    setWindowSize((prev) => ({ key: queryKey, count: Math.min((prev.key === queryKey ? prev.count : PAGE_SIZE) + PAGE_SIZE, filteredEvents.length) }));
  }, [filteredEvents.length, queryKey]);

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
            className={`inline-flex items-center gap-1.5 rounded-xs border px-3 py-1.5 text-xs font-medium transition-colors ${
              live
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                : "bg-(--surface2) text-(--text-muted) "
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
            className="transition-ui rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text)"
          >
            Refresh
          </button>
        </div>
      }
    >
      {/* Filter bar */}
      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xs border bg-(--surface) px-4 py-3">
        <div className="w-full text-xs text-(--text-muted)">
          Use Events for activity records and service activity. Use Flows for active connections and Alerts for IDS triage.
        </div>
        {FILTER_OPTIONS.map((option) => (
          <button
            key={option.value}
            onClick={() => setFilter(option.value)}
            className={
              filter === option.value
                ? "transition-ui rounded-xs border px-3 py-1.5 text-xs text-(--text)"
                : "transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text) "
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
          className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text)"
        >
          Envoy only
        </button>
        <button
          onClick={() => {
            setFilter("proxy");
            setKindPrefix("service.nginx");
          }}
          className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text)"
        >
          Nginx only
        </button>
        <select
          className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) outline-hidden focus-visible:shadow-focus-ring"
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
          className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) outline-hidden focus-visible:shadow-focus-ring"
        />
        <div className="w-full rounded-xs border p-3">
          <button type="button" className="text-xs" aria-expanded={filtersOpen} aria-controls="advanced-event-filters"
            onClick={() => setAdvancedOpen(!filtersOpen)}>Advanced event filters</button>
          <div id="advanced-event-filters" hidden={!(filtersOpen)} className={(filtersOpen) ? "mt-2 flex flex-wrap gap-2" : "hidden"}>
            {([
              ["Session ID", sessionFilter, setSessionFilter], ["Flow ID", flowFilter, setFlowFilter],
              ["Rule ID", ruleId, setRuleId], ["Mode", mode, setMode],
              ["APDU ID", apdu, setAPDU], ["Protocol", protocol, setProtocol], ["Decision", decision, setDecision],
              ["Verdict / outcome", verdict, setVerdict], ["Since (RFC3339)", since, setSince],
              ["Cursor", cursor, setCursor],
            ] as const).map(([label, value, setValue]) => (
              <label key={label} className="flex flex-col gap-1 text-xs text-(--text)">
                {label}
                <input aria-label={label} value={value} onChange={(e) => setValue(e.target.value)}
                  className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm outline-hidden" />
              </label>
            ))}
          </div>
        </div>
        <label className="flex items-center gap-2 text-xs text-(--text)">
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
            className="transition-ui rounded-xs border px-3 py-1.5 font-mono text-xs text-(--text)"
          >
            Session {sessionFilter} ×
          </button>
        )}
        {(filter !== "all" || kindPrefix.trim() || onlyDetections || sessionFilter || flowFilter || apdu || protocol || decision || verdict || since || cursor || ruleId || mode) && (
          <button
            onClick={() => {
              setFilter("all");
              setKindPrefix("");
              setOnlyDetections(false);
              setSessionFilter("");
              setRuleId(""); setMode("");
              setFlowFilter(""); setAPDU(""); setProtocol(""); setDecision(""); setVerdict(""); setSince(""); setCursor("");
            }}
            className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text)"
          >
            Clear filters
          </button>
        )}
      </div>

      {truncated && <p role="status" className="mb-3 text-sm text-(--text-muted)">Retained evidence only: history may have gaps from eviction or restart. Pagination cannot recover missing events.</p>}
      {nextCursor && <button disabled={live || loading} onClick={() => void refresh(nextCursor)} className="mb-3 rounded-xs border px-3 py-1.5 text-sm disabled:opacity-50">{live ? "Pause live updates to load older evidence" : "Load older evidence"}</button>}
      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          Traffic records unavailable. Check filters and retry with Refresh.
          <p className="mt-2">{error}</p>
          <details className="mt-2"><summary className="cursor-pointer">Technical details</summary><pre className="overflow-x-auto">{JSON.stringify(query, null, 2)}</pre></details>
        </div>
      )}
      <div className="mb-3 flex flex-wrap gap-2 text-xs text-(--text)">
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5 text-xs">
          Showing: {visibleEvents.length} of {filteredEvents.length}
        </div>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5 text-xs">
          Proxy events: {proxyCount}
        </div>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5 text-xs">
          Service events: {serviceCount}
        </div>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5 text-xs">
          AV detections: {detectionCount}
        </div>
      </div>

      <div className="space-y-2">
        {loading && <div className="rounded-xs border bg-(--surface) p-6 text-sm text-(--text-muted)">Loading...</div>}
        {!loading && events.length === 0 && (
          <div className="rounded-xs border bg-(--surface) p-6 text-center text-sm text-(--text-muted)">
            No retained events match this query. Clear filters or check the session and time bounds.
          </div>
        )}
        {!loading && filteredEvents.length > 0 && (
          <div className="mb-2 text-xs text-(--text-muted)">
            Showing {visibleEvents.length} of {filteredEvents.length} events
          </div>
        )}
        {!loading && visibleEvents
          .map((ev) => {
          const evidence = describeICSEvidence(ev);
          return (
          <div
            key={ev.id}
            className="table-row-hover min-w-0 wrap-anywhere rounded-xs border bg-(--surface) p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-semibold text-(--text)">
                <span>{eventHeadline(ev)}</span>
                <span className="ml-2 text-xs font-normal text-(--text-muted)">{ev.kind}</span>
              </div>
              <div className="text-xs text-(--text-muted)">
                {new Date(ev.timestamp).toLocaleString()}
              </div>
            </div>
            <div className="mt-1 text-xs text-(--text)">
              {formatEndpoint(ev.srcIp, ev.srcPort)} → {formatEndpoint(ev.dstIp, ev.dstPort)}{" "}
              {ev.transport ? `(${ev.transport})` : ""}
            </div>
            {ev.kind === "identification" && ev.proto === "identify" && ev.attributes && (
              <div className="mt-2">
                <IdentificationBadge identification={ev.attributes} />
              </div>
            )}
            {ev.attributes?.observation_only === true && (
              <StatusBadge variant="neutral" className="mt-2">
                Observation only
              </StatusBadge>
            )}
            {evidence && (
              <div className="mt-2 space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge variant={evidence.variant} dot>{evidence.badge}</StatusBadge>
                  <span className="text-xs text-(--text)">{evidence.message}</span>
                  {evidence.sessionId && evidence.sessionId !== sessionFilter && (
                    <button
                      onClick={() => setSessionFilter(evidence.sessionId)}
                      className="transition-ui rounded-xs border bg-(--surface2) px-2 py-0.5 text-[10px] text-(--text)"
                    >
                      Show session
                    </button>
                  )}
                </div>
              </div>
            )}
            {!evidence && typeof ev.attributes?.error === "string" && <p className="mt-2 text-xs text-amber">{ev.attributes.error}</p>}
            {detailErrors[ev.id] && <p role="status" className="mt-2 text-xs text-amber">Event detail unavailable; it may have left retention. Open Inspect event to retry.</p>}
            <button type="button" aria-expanded={!!expanded[ev.id]} aria-controls={`event-inspection-${ev.id}`}
              onClick={() => setExpanded(old => ({ ...old, [ev.id]: !old[ev.id] }))}
              className="mt-2 rounded-xs border px-2 py-1 text-xs">Inspect event</button>
            <EventInspection event={ev} open={!!expanded[ev.id]}
              onError={failed => setDetailErrors(old => ({ ...old, [ev.id]: failed }))} />
          </div>
          );
        })}
        {/* Infinite scroll sentinel */}
        {hasMore && (
          <div ref={sentinelRef} className="flex items-center justify-center py-4">
            <button
              onClick={loadMore}
              className="transition-ui rounded-xs border bg-(--surface) px-4 py-2 text-sm text-(--text-muted)"
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
    <Suspense fallback={<div className="p-4 text-(--text)">Loading events...</div>}>
      <EventsInner />
    </Suspense>
  );
}
