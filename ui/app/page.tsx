"use client";

import { useEffect, useMemo, useState, useCallback } from "react";
import Link from "next/link";

import {
  type DashboardData,
  type TelemetryEvent,
  type Zone,
  type FlowSummary,
  type ServicesStatus,
  type SystemStats,
  api,
} from "../lib/api";
import { Shell } from "../components/Shell";
import dynamic from "next/dynamic";
import {
  EventStream,
  ServiceGrid,
  SetupChecklist,
  SystemHealthPanel,
  TrafficCounter,
  type InterfaceBindings,
} from "./dashboard-panels";
import {
  buildZoneSparklines,
  buildZoneThreatMap,
  deriveServices,
  NetworkPulseCanvas,
  NetworkPulseStats,
  TrafficChart,
  ZoneList,
} from "./dashboard-visuals";

const Console = dynamic(
  () => import("../components/Console").then((m) => m.Console),
  { ssr: false, loading: () => <div style={{ padding: 16, color: "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 11 }}>Loading console...</div> },
);
import { Skeleton } from "../components/Skeleton";

// ── Main Dashboard ─────────────────────────────────────────────────────

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [zones, setZones] = useState<Zone[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [servicesStatus, setServicesStatus] = useState<ServicesStatus | null>(null);
  const [configDirty, setConfigDirty] = useState<boolean | null>(null);
  const [interfaceBindings, setInterfaceBindings] = useState<InterfaceBindings | null>(null);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [dashboardUnavailable, setDashboardUnavailable] = useState(false);
  const [eventsUnavailable, setEventsUnavailable] = useState(false);
  const [zonesUnavailable, setZonesUnavailable] = useState(false);
  const [statsUnavailable, setStatsUnavailable] = useState(false);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [now, setNow] = useState<number | null>(null);
  const clock = now === null ? "" : new Date(now).toLocaleTimeString("en-US", { hour12: false });
  const [simRunning, setSimRunning] = useState<boolean | null>(null);
  const [simUnavailable, setSimUnavailable] = useState(false);
  const [flowsUnavailable, setFlowsUnavailable] = useState(false);
  const [simToggling, setSimToggling] = useState(false);

  // Clock
  useEffect(() => {
    const tick = () => setNow(Date.now());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // Data fetching
  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    const load = () => {
      api.getDashboard(signal).then((r) => { setData(r); setDashboardUnavailable(r === null); }).catch(() => { if (!signal.aborted) { setData(null); setDashboardUnavailable(true); } });
      api.listZones(signal).then(snapshot => { setZones(snapshot?.data ?? []); setZonesUnavailable(!snapshot); }).catch(() => { if (!signal.aborted) { setZones([]); setZonesUnavailable(true); } });
      Promise.all([api.listInterfaces(signal), api.listInterfaceState(signal)]).then(([configured, runtime]) => {
        setInterfaceBindings(configured?.data && runtime ? { configured: configured.data, runtime } : null);
      }).catch(() => { if (!signal.aborted) setInterfaceBindings(null); });
      api.listEvents(50, signal).then((r) => { setEvents(r ?? []); setEventsUnavailable(r === null); }).catch(() => { if (!signal.aborted) { setEvents([]); setEventsUnavailable(true); } });
      api.listFlows(100, signal).then((r) => { setFlowsUnavailable(r === null); setFlows(r ?? []); }).catch(() => { if (!signal.aborted) setFlowsUnavailable(true); });
      api.getSystemStats(signal).then((r) => { setStats(r); setStatsUnavailable(r === null); }).catch(() => { if (!signal.aborted) { setStats(null); setStatsUnavailable(true); } });
      api.getServicesStatus(signal).then(setServicesStatus).catch(() => { if (!signal.aborted) setServicesStatus(null); });
      api.getSimulationStatus(signal).then((r) => { setSimUnavailable(r === null); setSimRunning(r?.running ?? null); }).catch(() => { if (!signal.aborted) { setSimUnavailable(true); setSimRunning(null); } });
      api.diffConfig().then(snapshot => (snapshot?.data ?? null)).then((r) => {
        if (!r) { setConfigDirty(null); return; }
        const running = JSON.stringify(r.running ?? null);
        const candidate = JSON.stringify(r.candidate ?? null);
        setConfigDirty(running !== candidate);
      }).catch(() => { if (!signal.aborted) setConfigDirty(null); });
    };
    load();
    const id = setInterval(() => { if (!document.hidden) load(); }, 10_000);
    const onVisible = () => { if (!document.hidden) load(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  const toggleSimulation = useCallback(async () => {
    setSimToggling(true);
    try {
      const r = simRunning
        ? await api.stopSimulation()
        : await api.startSimulation();
      setSimUnavailable(r === null);
      setSimRunning(r?.running ?? null);
    } finally {
      setSimToggling(false);
    }
  }, [simRunning]);

  async function retrySimulation() {
    const result = await api.getSimulationStatus();
    setSimUnavailable(result === null);
    setSimRunning(result?.running ?? null);
  }

  async function retryFlows() {
    const result = await api.listFlows(100);
    setFlowsUnavailable(result === null);
    setFlows(result ?? []);
  }

  const health = data?.health ?? null;
  const eventStats = data?.eventStats ?? null;
  const alertCountsKnown = Number.isFinite(eventStats?.idsAlerts) && Number.isFinite(eventStats?.avDetections);
  const hasAlerts =
    alertCountsKnown && eventStats &&
    (eventStats.idsAlerts > 0 || eventStats.avDetections > 0);

  const services = useMemo(() => deriveServices(servicesStatus, events), [servicesStatus, events]);
  const zoneThreatMap = useMemo(() => buildZoneThreatMap(events, zones), [events, zones]);
  const zoneSparklineMap = useMemo(() => buildZoneSparklines(events, zones), [events, zones]);

  return (
    <Shell title="Dashboard">
      {/* ── Topbar row ──────────────────────────────────────── */}
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-4">
          {health ? (
            <div className="flex items-center gap-2.5">
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  !alertCountsKnown ? "bg-slate-500" : hasAlerts ? "animate-pulse" : "bg-emerald-400"
                }`}
              />
              <span className="text-sm font-semibold text-white tracking-wide">
                {health.hostname ?? "containd"}
              </span>
              <span className="text-xs text-slate-500">
                {!alertCountsKnown ? "Recent IDS/AV alerts unavailable" : hasAlerts ? "Recent IDS/AV alerts" : "No recent IDS/AV alerts"}
              </span>
            </div>
          ) : (
            <Skeleton className="h-5 w-48" />
          )}
          {health?.build && (
            <span className="hidden sm:inline text-2xs font-mono">
              {health.build === "dev" ? "local build" : `v${health.build}`}
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 text-2xs font-mono text-slate-500">
          {services.slice(0, 4).map((s) => (
            <Link
              key={s.name}
              href={s.href}
              className="flex items-center gap-1.5 hover:text-slate-300 transition-colors"
            >
              {s.name}
              <span
                className={`inline-block h-1.5 w-1.5 rounded-full ${
                  s.active ? "bg-emerald-400" : "bg-slate-600"
                }`}
              />
            </Link>
          ))}
          {simUnavailable && <div role="status" className="text-red-400">Simulation unavailable <button onClick={retrySimulation} className="ml-2 rounded-xs border border-red-500/30 px-2 py-1">Retry</button></div>}
          {simRunning === true && <span role="status" className="text-amber">Simulation active</span>}
          <span className="tabular-nums">{clock}</span>
        </div>
      </div>

      {/* ── Needs attention ─────────────────────────────────── */}
      {hasAlerts && (
        <div className="mb-5 rounded-lg border px-4 py-3 animate-fade-in">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <svg
              width="14"
              height="14"
              viewBox="0 0 14 14"
              fill="none"
              className="shrink-0"
            >
              <path
                d="M7 1L13 13H1L7 1Z"
                stroke="currentColor"
                strokeWidth="1.5"
              />
            </svg>
            {eventStats!.idsAlerts > 0 && (
              <Link
                href="/alerts/"
                className="transition-colors"
              >
                {eventStats!.idsAlerts} IDS alert
                {eventStats!.idsAlerts !== 1 ? "s" : ""}
              </Link>
            )}
            {eventStats!.avDetections > 0 && (
              <Link
                href="/events/?av=1"
                className="text-red-400 hover:text-red-300 transition-colors"
              >
                {eventStats!.avDetections} AV detection
                {eventStats!.avDetections !== 1 ? "s" : ""}
              </Link>
            )}
          </div>
        </div>
      )}

      {dashboardUnavailable && <p role="alert" className="mb-3 text-sm text-red-400">Dashboard unavailable — previous totals are not current. Check Monitoring or retry on the next refresh.</p>}
      {eventsUnavailable && <p role="alert" className="mb-3 text-sm text-red-400">Recent events unavailable — activity and zone signals are unknown.</p>}
      {statsUnavailable && <p role="alert" className="mb-3 text-sm text-red-400">System telemetry unavailable — resource usage is unknown.</p>}
      {flowsUnavailable && <div role="status" className="mb-3 text-sm text-red-400">Flows unavailable — the engine could not be reached. <button onClick={retryFlows} className="ml-2 rounded-xs border px-3 py-1">Retry</button></div>}
      {zonesUnavailable && <p role="alert" className="mb-3 text-sm text-amber">Zones unavailable — zone configuration is unknown.</p>}
      {services.filter(service => service.detail === "Scanner unavailable" || service.detail === "Stopped" || (service.errorRate ?? 0) > 0).map(service => (
        <p key={service.name} role="status" className="mb-3 text-sm text-amber">{service.name}: {service.detail}{(service.errorRate ?? 0) > 0 ? ` · ${service.errorRate!.toFixed(1)} err/min` : ""} — <Link className="underline" href={service.href}>Check service</Link></p>
      ))}
      <SetupChecklist
        counts={data?.counts}
        interfaceBindings={interfaceBindings}
        configDirty={configDirty}
        isAdmin={data?.user?.role === "admin"}
      />

      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm">
        <h2>Traffic and resources</h2>
        <Link href="/monitoring/" className="underline">Monitoring</Link>
      </div>
      <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Traffic Chart */}
        <div className="rounded-xl border border-white/8 bg-white/3 shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Traffic
            <span className="ml-2 text-2xs font-normal normal-case tracking-normal text-slate-500">
              60s window
            </span>
          </h3>
          <div className="h-[120px] mb-3">
            <TrafficChart events={events} />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <TrafficCounter
              label="Total Events"
              value={eventStats?.total ?? null}
              color=""
            />
            <TrafficCounter
              label="IDS Alerts"
              value={eventStats?.idsAlerts ?? null}
              color="text-red-400"
            />
            {!flowsUnavailable && <TrafficCounter
              label="Active Flows"
              value={
                flows.filter((f) => {
                  if (!f.lastSeen) return false;
                  return now !== null && now - new Date(f.lastSeen).getTime() < 120_000;
                }).length
              }
              color="text-emerald-400"
            />}
          </div>
        </div>

        {/* System Health */}
        <div className="rounded-xl border border-white/8 bg-white/3 shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            System Health
          </h3>
          <SystemHealthPanel stats={stats} data={data} />
        </div>

      </div>
      <div className="my-4">
        <button type="button" aria-expanded={detailsOpen} aria-controls="dashboard-details"
          onClick={() => setDetailsOpen(v => !v)} className="rounded-xs border px-3 py-2 text-sm">
          Dashboard details — Network Pulse, Zone Status, Service Health, Event Stream
        </button>
        <span className="ml-2 text-xs text-(--text-muted)">{eventsUnavailable || zonesUnavailable ? "Zone and activity signals unknown" : `${events.length} recent events`} · {services.filter(s => s.active === null).length} service states unknown{!eventsUnavailable && !zonesUnavailable && ` · ${Object.values(zoneThreatMap).filter(zone => zone.alerts > 0).length} zones with alerts`}</span>
      </div>
      <div id="dashboard-details" hidden={!detailsOpen} className={detailsOpen ? "grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-2" : "hidden"}>
        {/* Network Pulse */}
        <div className="rounded-xl border border-white/8 bg-white/3 shadow-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/6">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Network Pulse
            </h3>
            {!flowsUnavailable && <NetworkPulseStats flows={flows} eventStats={eventStats} />}
          </div>
          {flowsUnavailable || eventsUnavailable || zonesUnavailable ? <div className="p-4 text-sm text-amber">Network Pulse unavailable — see the traffic status above.</div> : <div className="h-[220px]">
            <NetworkPulseCanvas zones={zones} threatMap={zoneThreatMap} />
          </div>}
        </div>

        {/* Zone Status */}
        <div className="rounded-xl border border-white/8 bg-white/3 shadow-card p-4 overflow-y-auto max-h-[520px]">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Zone Status
          </h3>
          {eventsUnavailable || zonesUnavailable ? <p className="text-xs text-amber">Zone activity unknown — check the traffic status above.</p> : zones.length > 0 ? (
            <ZoneList zones={zones} threatMap={zoneThreatMap} sparklineMap={zoneSparklineMap} />
          ) : (
            <Skeleton className="h-32 w-full" />
          )}
        </div>

        {/* Services */}
        <div className="rounded-xl border border-white/8 bg-white/3 shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Service Health
          </h3>
          <ServiceGrid services={services} />
        </div>

        {/* Event Stream */}
        <div className="rounded-xl border border-white/8 bg-white/3 shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Event Stream
          </h3>
          {eventsUnavailable ? <p className="text-xs text-amber">Recent events unavailable.</p> : <EventStream events={events} />}
        </div>

      </div>

      <div className="mt-5">
        <button type="button" aria-expanded={toolsOpen} aria-controls="dashboard-tools"
          onClick={() => setToolsOpen(v => !v)} className="rounded-xs border px-3 py-2 text-sm">Tools</button>
        {simRunning === true && <span className="ml-3 text-xs text-amber">Simulation active — open Tools to stop</span>}
        <div id="dashboard-tools" hidden={!toolsOpen} className={toolsOpen ? "mt-3 space-y-3" : "hidden"}>
          <p className="text-xs text-(--text-muted)">Simulation controls and CLI commands act immediately; they do not stage settings.</p>
          {simRunning !== null && (
            <button
              type="button"
              onClick={toggleSimulation}
              disabled={simToggling}
              className="flex items-center gap-2 text-2xs font-mono"
              title={simRunning ? "Stop traffic simulation" : "Start traffic simulation"}
            >
              <span className={`text-2xs ${simRunning ? "" : "text-slate-500"}`}>SIM</span>
              <span
                className={`relative inline-flex h-4 w-8 items-center rounded-[2px] transition-colors ${
                  simRunning ? "" : "bg-white/10"
                }`}
              >
                <span className={`inline-block h-3 w-3 rounded-[1px] bg-white transition-transform ${
                  simRunning ? "translate-x-4" : "translate-x-0.5"
                }`} />
              </span>
            </button>
          )}

          <button
            type="button"
            aria-expanded={consoleOpen} aria-controls="dashboard-console"
            onClick={() => setConsoleOpen((v) => !v)}
            className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-slate-500 transition-colors hover:text-slate-300"
          >
            <svg
              viewBox="0 0 24 24"
              className="h-3.5 w-3.5"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
            >
              <polyline points="4,17 10,11 4,5" />
              <line x1="12" y1="19" x2="20" y2="19" />
            </svg>
            CLI Console
            <svg
              viewBox="0 0 24 24"
              className={`h-3 w-3 transition-transform duration-200 ${
                consoleOpen ? "rotate-180" : ""
              }`}
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
            >
              <polyline points="6,9 12,15 18,9" />
            </svg>
          </button>
          <div id="dashboard-console" hidden={!consoleOpen}>{consoleOpen && <Console />}</div>
        </div>
      </div>
    </Shell>
  );
}
