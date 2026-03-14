"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";

import {
  type DashboardData,
  type TelemetryEvent,
  type Zone,
  type FlowSummary,
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
  const [configDirty, setConfigDirty] = useState<boolean | null>(null);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [clock, setClock] = useState("");
  const [simRunning, setSimRunning] = useState<boolean | null>(null);
  const [simToggling, setSimToggling] = useState(false);

  // Clock
  useEffect(() => {
    const tick = () =>
      setClock(new Date().toLocaleTimeString("en-US", { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // Data fetching
  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    const load = () => {
      api.getDashboard(signal).then((r) => r && setData(r)).catch(() => {});
      api.listZones(signal).then((r) => r && setZones(r)).catch(() => {});
      api.listEvents(50, signal).then((r) => r && setEvents(r)).catch(() => {});
      api.listFlows(100, signal).then((r) => r && setFlows(r)).catch(() => {});
      api.getSystemStats(signal).then((r) => r && setStats(r)).catch(() => {});
      api.getSimulationStatus(signal).then((r) => r && setSimRunning(r.running)).catch(() => {});
      api.diffConfig().then((r) => {
        if (!r) return;
        const running = JSON.stringify(r.running ?? null);
        const candidate = JSON.stringify(r.candidate ?? null);
        setConfigDirty(running !== candidate);
      }).catch(() => {});
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
      if (r) setSimRunning(r.running);
    } finally {
      setSimToggling(false);
    }
  }, [simRunning]);

  const health = data?.health ?? null;
  const eventStats = data?.eventStats ?? null;
  const servicesStatus = data?.services ?? null;
  const hasAlerts =
    eventStats &&
    (eventStats.idsAlerts > 0 || eventStats.avDetections > 0);

  // Derive services list from real status data, with sparklines from event history
  const services = deriveServices(servicesStatus, events);

  // Per-zone threat posture: count IDS alerts per zone from events
  const zoneThreatMap = buildZoneThreatMap(events, zones);

  // Per-zone traffic sparklines: bucket events by zone over 60s
  const zoneSparklineMap = buildZoneSparklines(events, zones);

  return (
    <Shell title="Dashboard">
      {/* ── Topbar row ──────────────────────────────────────── */}
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-4">
          {health ? (
            <div className="flex items-center gap-2.5">
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  hasAlerts ? "bg-amber-400 animate-pulse" : "bg-emerald-400"
                }`}
              />
              <span className="text-sm font-semibold text-white tracking-wide">
                {health.hostname ?? "containd"}
              </span>
              <span className="text-xs text-slate-500">
                {hasAlerts ? "Alerts active" : "All systems nominal"}
              </span>
            </div>
          ) : (
            <Skeleton className="h-5 w-48" />
          )}
          {health?.build && (
            <span className="hidden sm:inline text-2xs text-amber-500/60 font-mono">
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
          {simRunning !== null && (
            <button
              type="button"
              onClick={toggleSimulation}
              disabled={simToggling}
              className="flex items-center gap-2 text-2xs font-mono"
              title={simRunning ? "Stop traffic simulation" : "Start traffic simulation"}
            >
              <span className={`text-2xs ${simRunning ? "text-amber-400" : "text-slate-500"}`}>SIM</span>
              <span
                className={`relative inline-flex h-4 w-8 items-center rounded-[2px] transition-colors ${
                  simRunning ? "bg-amber-500" : "bg-white/10"
                }`}
              >
                <span className={`inline-block h-3 w-3 rounded-[1px] bg-white transition-transform ${
                  simRunning ? "translate-x-4" : "translate-x-0.5"
                }`} />
              </span>
            </button>
          )}
          <span className="text-amber-500/80 tabular-nums">{clock}</span>
        </div>
      </div>

      <SetupChecklist
        counts={data?.counts}
        configDirty={configDirty}
        isAdmin={data?.user?.role === "admin"}
      />

      {/* ── Needs attention ─────────────────────────────────── */}
      {hasAlerts && (
        <div className="mb-5 rounded-lg border border-amber-500/20 bg-amber-500/[0.06] px-4 py-3 animate-fade-in">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <svg
              width="14"
              height="14"
              viewBox="0 0 14 14"
              fill="none"
              className="text-amber-400 flex-shrink-0"
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
                className="text-amber-300 hover:text-amber-200 transition-colors"
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

      {/* ── Main grid ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1fr_320px] gap-4">
        {/* Network Pulse — spans 2 cols */}
        <div className="lg:col-span-2 rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Network Pulse
            </h3>
            <NetworkPulseStats flows={flows} eventStats={eventStats} />
          </div>
          <div className="h-[220px]">
            <NetworkPulseCanvas zones={zones} flows={flows} events={events} />
          </div>
        </div>

        {/* Zone Status — right column, spans 2 rows */}
        <div className="lg:row-span-2 rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4 overflow-y-auto max-h-[520px]">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Zone Status
          </h3>
          {zones.length > 0 ? (
            <ZoneList zones={zones} threatMap={zoneThreatMap} sparklineMap={zoneSparklineMap} />
          ) : (
            <Skeleton className="h-32 w-full" />
          )}
        </div>

        {/* Services */}
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Service Health
          </h3>
          <ServiceGrid services={services} />
        </div>

        {/* Traffic Chart */}
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Traffic
            <span className="ml-2 text-2xs font-normal normal-case tracking-normal text-slate-500">
              {events.some((e) => {
                if (!e.timestamp) return false;
                return Date.now() - new Date(e.timestamp).getTime() < 60_000;
              }) ? "60s window" : "24h baseline"}
            </span>
          </h3>
          <div className="h-[120px] mb-3">
            <TrafficChart events={events} />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <TrafficCounter
              label="Total Events"
              value={eventStats?.total ?? 0}
              color="text-amber-400"
            />
            <TrafficCounter
              label="IDS Alerts"
              value={eventStats?.idsAlerts ?? 0}
              color="text-red-400"
            />
            <TrafficCounter
              label="Active Flows"
              value={
                flows.filter((f) => {
                  if (!f.lastSeen) return false;
                  return Date.now() - new Date(f.lastSeen).getTime() < 120_000;
                }).length
              }
              color="text-emerald-400"
            />
          </div>
        </div>

        {/* Event Stream — spans 2 cols */}
        <div className="lg:col-span-2 rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Event Stream
          </h3>
          <EventStream events={events} />
        </div>

        {/* System Health — replaces old stats row */}
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            System Health
          </h3>
          <SystemHealthPanel stats={stats} data={data} />
        </div>
      </div>

      {/* ── Console (collapsible) ──────────────────────────── */}
      <div className="mt-5">
        <button
          type="button"
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
        {consoleOpen && (
          <div className="animate-fade-in">
            <Console />
          </div>
        )}
      </div>
    </Shell>
  );
}
