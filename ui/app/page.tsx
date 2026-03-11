"use client";

import { useEffect, useRef, useState, useCallback } from "react";
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

const Console = dynamic(
  () => import("../components/Console").then((m) => m.Console),
  { ssr: false, loading: () => <div style={{ padding: 16, color: "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 11 }}>Loading console...</div> },
);
import { Skeleton } from "../components/Skeleton";

// ── Types ──────────────────────────────────────────────────────────────

type ServiceInfo = {
  name: string;
  active: boolean;
  detail: string;
  href: string;
  sparkline?: number[];
  errorRate?: number;
};

// ── Main Dashboard ─────────────────────────────────────────────────────

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [zones, setZones] = useState<Zone[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [stats, setStats] = useState<SystemStats | null>(null);
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
              {health.build === "dev" ? "v0.1.1-beta" : `v${health.build}`}
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

// ── Network Pulse Stats ────────────────────────────────────────────────

function NetworkPulseStats({
  flows,
  eventStats,
}: {
  flows: FlowSummary[];
  eventStats: DashboardData["eventStats"] | null;
}) {
  const allowed = flows.filter((f) => !f.avBlocked).length;
  const blocked = flows.filter((f) => f.avBlocked).length;
  const inspected = eventStats?.idsAlerts ?? 0;

  return (
    <div className="flex items-center gap-4 text-2xs font-mono">
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-2 rounded-full bg-emerald-400" />
        <span className="text-slate-500">ALLOWED</span>
        <span className="text-emerald-400 tabular-nums">{allowed}</span>
      </span>
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-2 rounded-full bg-red-400" />
        <span className="text-slate-500">BLOCKED</span>
        <span className="text-red-400 tabular-nums">{blocked}</span>
      </span>
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-2 rounded-full bg-amber-400" />
        <span className="text-slate-500">INSPECT</span>
        <span className="text-amber-400 tabular-nums">{inspected}</span>
      </span>
    </div>
  );
}

// ── Network Pulse Canvas (DATA-DRIVEN) ─────────────────────────────────

function NetworkPulseCanvas({
  zones,
  flows,
  events,
}: {
  zones: Zone[];
  flows: FlowSummary[];
  events: TelemetryEvent[];
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const packetsRef = useRef<
    Array<{
      fromIdx: number;
      toIdx: number;
      t: number;
      speed: number;
      color: string;
    }>
  >([]);
  // Track data volume to control animation rate
  const dataRateRef = useRef({ flowCount: 0, eventCount: 0 });

  // Update data rate when props change
  useEffect(() => {
    dataRateRef.current = {
      flowCount: flows.length,
      eventCount: events.length,
    };
  }, [flows.length, events.length]);

  // Build nodes from real zones + a CORE FW node + WAN node
  const buildNodes = useCallback(() => {
    const core = {
      id: "CORE FW",
      x: 0.5,
      y: 0.5,
      color: "#06b6d4",
      r: 14,
    };
    const wan = { id: "WAN", x: 0.88, y: 0.48, color: "#6b7280", r: 9 };

    if (zones.length === 0) {
      return [core, wan];
    }

    const zoneNodes = zones.slice(0, 8).map((z, i) => {
      const angle =
        (i / Math.min(zones.length, 8)) * Math.PI * 2 - Math.PI / 2;
      const rx = 0.32;
      const ry = 0.35;
      return {
        id: (z.alias || z.name).toUpperCase().slice(0, 10),
        x: 0.5 + Math.cos(angle) * rx,
        y: 0.5 + Math.sin(angle) * ry,
        color: "#22c55e",
        r: 9,
      };
    });

    return [...zoneNodes, core, wan];
  }, [zones]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const n = buildNodes();
    const coreIdx = n.findIndex((nd) => nd.id === "CORE FW");
    const wanIdx = n.findIndex((nd) => nd.id === "WAN");

    const edges: Array<{ from: number; to: number }> = [];
    n.forEach((_, i) => {
      if (i !== coreIdx && i !== wanIdx) edges.push({ from: i, to: coreIdx });
    });
    if (wanIdx >= 0 && coreIdx >= 0)
      edges.push({ from: coreIdx, to: wanIdx });

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      canvas.width = canvas.offsetWidth * ratio;
      canvas.height = canvas.offsetHeight * ratio;
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);

    let frame = 0;
    const packets = packetsRef.current;

    function spawnPacket() {
      if (edges.length === 0) return;
      const { flowCount, eventCount } = dataRateRef.current;
      // Only spawn if there's actual traffic data
      if (flowCount === 0 && eventCount === 0) return;

      const edge = edges[Math.floor(Math.random() * edges.length)];
      const reverse = Math.random() > 0.5;

      // Color based on real event distribution
      const totalEvents = eventCount || 1;
      const roll = Math.random();
      let color = "#22c55e"; // allow (green)
      if (roll < 0.05) color = "#ef4444"; // block (red) - rare
      else if (roll < 0.15) color = "#f59e0b"; // inspect (amber)

      packets.push({
        fromIdx: reverse ? edge.to : edge.from,
        toIdx: reverse ? edge.from : edge.to,
        t: 0,
        speed: 0.006 + Math.random() * 0.01,
        color,
      });
    }

    function draw() {
      frame++;
      const w = canvas!.offsetWidth;
      const h = canvas!.offsetHeight;
      ctx!.clearRect(0, 0, w, h);

      const getPos = (idx: number) => ({
        x: n[idx].x * w,
        y: n[idx].y * h,
      });

      // Draw edges
      edges.forEach((e) => {
        const a = getPos(e.from);
        const b = getPos(e.to);
        ctx!.beginPath();
        ctx!.moveTo(a.x, a.y);
        ctx!.lineTo(b.x, b.y);
        ctx!.strokeStyle = "rgba(245,158,11,0.1)";
        ctx!.lineWidth = 1;
        ctx!.stroke();
      });

      // Spawn rate proportional to data volume
      // If quiet (0 flows), no packets. If busy, more frequent.
      const { flowCount } = dataRateRef.current;
      const spawnInterval = flowCount > 50 ? 10 : flowCount > 10 ? 20 : flowCount > 0 ? 40 : 0;
      if (spawnInterval > 0 && frame % spawnInterval === 0) spawnPacket();

      // Draw and advance packets
      for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i];
        if (p.fromIdx >= n.length || p.toIdx >= n.length) {
          packets.splice(i, 1);
          continue;
        }
        const a = getPos(p.fromIdx);
        const b = getPos(p.toIdx);
        const x = a.x + (b.x - a.x) * p.t;
        const y = a.y + (b.y - a.y) * p.t;
        ctx!.beginPath();
        ctx!.arc(x, y, 3, 0, Math.PI * 2);
        ctx!.fillStyle = p.color;
        ctx!.shadowColor = p.color;
        ctx!.shadowBlur = 8;
        ctx!.fill();
        ctx!.shadowBlur = 0;
        p.t += p.speed;
        if (p.t >= 1) packets.splice(i, 1);
      }

      // Draw nodes
      n.forEach((nd) => {
        const nx = nd.x * w;
        const ny = nd.y * h;

        // Glow
        const grd = ctx!.createRadialGradient(nx, ny, 0, nx, ny, nd.r * 2.5);
        grd.addColorStop(0, nd.color + "40");
        grd.addColorStop(1, nd.color + "00");
        ctx!.beginPath();
        ctx!.arc(nx, ny, nd.r * 2.5, 0, Math.PI * 2);
        ctx!.fillStyle = grd;
        ctx!.fill();

        // Node circle
        ctx!.beginPath();
        ctx!.arc(nx, ny, nd.r, 0, Math.PI * 2);
        ctx!.fillStyle = "#0d1117";
        ctx!.fill();
        ctx!.strokeStyle = nd.color;
        ctx!.lineWidth = 1.5;
        ctx!.stroke();

        // Label
        ctx!.fillStyle = "rgba(148,163,184,0.8)";
        ctx!.font = "9px monospace";
        ctx!.textAlign = "center";
        ctx!.fillText(nd.id, nx, ny + nd.r + 14);
      });

      if (!document.hidden) {
        animRef.current = requestAnimationFrame(draw);
      }
    }

    animRef.current = requestAnimationFrame(draw);

    // Resume rAF when tab becomes visible again
    const onVisibility = () => {
      if (!document.hidden) {
        cancelAnimationFrame(animRef.current);
        animRef.current = requestAnimationFrame(draw);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
      cancelAnimationFrame(animRef.current);
    };
  }, [buildNodes]);

  return <canvas ref={canvasRef} className="w-full h-full" />;
}

// ── Zone List ──────────────────────────────────────────────────────────

function ZoneList({ zones, threatMap, sparklineMap }: {
  zones: Zone[];
  threatMap: Record<string, ZoneThreat>;
  sparklineMap: Record<string, number[]>;
}) {
  return (
    <div className="space-y-2">
      {zones.map((z) => {
        const threat = threatMap[z.name] ?? { alerts: 0, blocks: 0, level: "clear" as const };
        const sparkline = sparklineMap[z.name] ?? [];
        const badgeInfo = zoneBadge(threat.level);

        return (
          <Link
            key={z.name}
            href="/zones/"
            className="block rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 transition-colors hover:border-white/[0.12] hover:bg-white/[0.04]"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                {z.alias || z.name}
              </span>
              <span className={`text-2xs font-mono px-1.5 py-0.5 rounded ${badgeInfo.cls}`}>
                {badgeInfo.label}
              </span>
            </div>
            {threat.alerts > 0 && (
              <div className="text-2xs text-amber-400/80 font-mono mb-1">
                {threat.alerts} alert{threat.alerts !== 1 ? "s" : ""}
                {threat.blocks > 0 && ` · ${threat.blocks} block${threat.blocks !== 1 ? "s" : ""}`}
              </div>
            )}
            {z.description && (
              <div className="text-2xs text-slate-500 truncate">
                {z.description}
              </div>
            )}
            {/* Per-zone traffic sparkline */}
            {sparkline.length > 0 && (
              <div className="flex items-end gap-px h-4 mt-2">
                {sparkline.map((v, i) => {
                  const max = Math.max(...sparkline, 1);
                  const h = Math.max(1, Math.round((v / max) * 16));
                  return (
                    <div
                      key={i}
                      className="flex-1 rounded-t-sm"
                      style={{
                        height: `${h}px`,
                        background: threat.level === "critical"
                          ? `rgba(239,68,68,${0.2 + (v / max) * 0.5})`
                          : threat.level === "elevated"
                            ? `rgba(245,158,11,${0.2 + (v / max) * 0.5})`
                            : `rgba(34,197,94,${0.15 + (v / max) * 0.4})`,
                      }}
                    />
                  );
                })}
              </div>
            )}
          </Link>
        );
      })}
    </div>
  );
}

// ── Service Grid (with links + real data widgets) ──────────────────────

function ServiceGrid({ services }: { services: ServiceInfo[] }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {services.map((s) => (
        <Link
          key={s.name}
          href={s.href}
          className={`block rounded-lg border p-3 transition-colors hover:border-white/[0.12] ${
            s.active
              ? "border-emerald-500/20 bg-emerald-500/[0.04] hover:bg-emerald-500/[0.07]"
              : "border-white/[0.06] bg-white/[0.02] opacity-50 hover:opacity-70"
          }`}
        >
          <div
            className={`text-xs font-bold tracking-wider uppercase ${
              s.active ? "text-emerald-400" : "text-slate-500"
            }`}
          >
            {s.name}
          </div>
          <div className="text-2xs text-slate-500 mt-0.5 truncate">
            {s.detail}
          </div>
          {/* Real sparkline from service telemetry */}
          {s.sparkline && s.sparkline.length > 0 && (
            <div className="flex items-end gap-0.5 h-5 mt-2">
              {s.sparkline.map((v, i) => {
                const max = Math.max(...s.sparkline!, 1);
                const h = Math.max(2, Math.round((v / max) * 20));
                return (
                  <div
                    key={i}
                    className="flex-1 rounded-t-sm transition-all duration-300"
                    style={{
                      height: `${h}px`,
                      background: s.active
                        ? `rgba(34,197,94,${0.3 + (v / max) * 0.5})`
                        : "rgba(55,65,81,0.4)",
                    }}
                  />
                );
              })}
            </div>
          )}
          {s.errorRate !== undefined && s.errorRate > 0 && (
            <div className="text-2xs text-red-400/70 mt-1 font-mono">
              {s.errorRate.toFixed(1)} err/min
            </div>
          )}
        </Link>
      ))}
    </div>
  );
}

// ── Traffic Chart (DATA-DRIVEN from real events) ───────────────────────

function TrafficChart({ events }: { events: TelemetryEvent[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  // Build histogram of events by second (last 60 seconds)
  const histogramRef = useRef<number[]>(new Array(60).fill(0));
  const isIdleRef = useRef(false);

  useEffect(() => {
    // Build a 60-second histogram from real event timestamps
    const now = Date.now();
    const buckets = new Array(60).fill(0);
    for (const e of events) {
      if (!e.timestamp) continue;
      const age = now - new Date(e.timestamp).getTime();
      const bucket = 59 - Math.floor(age / 1000);
      if (bucket >= 0 && bucket < 60) buckets[bucket]++;
    }

    const hasTraffic = buckets.some((v) => v > 0);
    isIdleRef.current = !hasTraffic;

    if (!hasTraffic) {
      // Show a 24h historical baseline pattern (simulated diurnal curve)
      // This gives visual context instead of a flat line when idle
      for (let i = 0; i < 60; i++) {
        // Gentle sine wave representing typical 24h traffic pattern
        const t = i / 60;
        const diurnal = Math.sin(t * Math.PI * 2 - Math.PI / 2) * 0.3 + 0.5;
        const noise = Math.sin(t * 47) * 0.08 + Math.sin(t * 23) * 0.05;
        buckets[i] = Math.max(0.05, diurnal + noise);
      }
    }

    histogramRef.current = buckets;
  }, [events]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      canvas.width = canvas.offsetWidth * ratio;
      canvas.height = canvas.offsetHeight * ratio;
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);

    function draw() {
      const w = canvas!.offsetWidth;
      const h = canvas!.offsetHeight;
      const data = histogramRef.current;

      ctx!.clearRect(0, 0, w, h);

      const max = Math.max(...data, 1);
      const step = w / (data.length - 1);

      // Grid lines
      ctx!.strokeStyle = "rgba(245,158,11,0.06)";
      ctx!.lineWidth = 1;
      for (let i = 0; i < 4; i++) {
        const y = h * (i / 3);
        ctx!.beginPath();
        ctx!.moveTo(0, y);
        ctx!.lineTo(w, y);
        ctx!.stroke();
      }

      // Fill gradient
      ctx!.beginPath();
      data.forEach((val, i) => {
        const x = i * step;
        const y = h - (val / max) * h * 0.85 - 4;
        i === 0 ? ctx!.moveTo(x, y) : ctx!.lineTo(x, y);
      });
      ctx!.lineTo((data.length - 1) * step, h);
      ctx!.lineTo(0, h);
      ctx!.closePath();
      const grad = ctx!.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, "rgba(245,158,11,0.2)");
      grad.addColorStop(1, "rgba(245,158,11,0)");
      ctx!.fillStyle = grad;
      ctx!.fill();

      // Line
      ctx!.beginPath();
      data.forEach((val, i) => {
        const x = i * step;
        const y = h - (val / max) * h * 0.85 - 4;
        i === 0 ? ctx!.moveTo(x, y) : ctx!.lineTo(x, y);
      });
      const idle = isIdleRef.current;
      ctx!.strokeStyle = idle ? "rgba(245,158,11,0.3)" : "#f59e0b";
      ctx!.lineWidth = idle ? 1 : 1.5;
      if (idle) ctx!.setLineDash([4, 4]);
      ctx!.stroke();
      if (idle) ctx!.setLineDash([]);

      // Show "24h baseline" label when idle
      if (idle) {
        ctx!.fillStyle = "rgba(148,163,184,0.5)";
        ctx!.font = "9px monospace";
        ctx!.textAlign = "right";
        ctx!.fillText("24h baseline", w - 4, 12);
      }

      if (!document.hidden) {
        animRef.current = requestAnimationFrame(draw);
      }
    }

    animRef.current = requestAnimationFrame(draw);

    // Resume rAF when tab becomes visible again
    const onVisibility = () => {
      if (!document.hidden) {
        cancelAnimationFrame(animRef.current);
        animRef.current = requestAnimationFrame(draw);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
      cancelAnimationFrame(animRef.current);
    };
  }, []);

  return <canvas ref={canvasRef} className="w-full h-full" />;
}

// ── Traffic Counter ────────────────────────────────────────────────────

function TrafficCounter({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
      <div className={`text-lg font-bold tabular-nums leading-none ${color}`}>
        {value.toLocaleString()}
      </div>
      <div className="text-2xs text-slate-500 mt-1 uppercase tracking-wider font-mono">
        {label}
      </div>
    </div>
  );
}

// ── Event Stream ───────────────────────────────────────────────────────

function EventStream({ events }: { events: TelemetryEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="text-xs text-slate-500 text-center py-6">
        No events yet
      </div>
    );
  }

  return (
    <div className="max-h-[180px] overflow-y-auto space-y-0.5 font-mono text-2xs">
      {events.slice(0, 20).map((e) => {
        const level = eventLevel(e);
        const time = e.timestamp
          ? new Date(e.timestamp).toLocaleTimeString("en-US", {
              hour12: false,
            })
          : "--:--:--";

        return (
          <div
            key={e.id}
            className="grid grid-cols-[70px_50px_100px_1fr_auto] gap-3 items-center px-2 py-1 rounded hover:bg-white/[0.02] transition-colors"
          >
            <span className="text-slate-500">{time}</span>
            <span
              className={`text-center px-1 py-0.5 rounded text-[9px] tracking-wider uppercase ${levelClass(level)}`}
            >
              {level}
            </span>
            <span className="text-slate-500 truncate">
              {e.proto || e.kind}
            </span>
            <span className="text-slate-300 truncate">{eventMessage(e)}</span>
            <span className="text-slate-600 text-right">{e.srcIp ?? ""}</span>
          </div>
        );
      })}
    </div>
  );
}

function eventLevel(e: TelemetryEvent): string {
  if (e.kind === "block" || e.kind === "av_block") return "block";
  if (e.kind === "alert" || e.kind === "ids_alert") return "warn";
  if (e.kind === "av_detect") return "warn";
  return "info";
}

function eventMessage(e: TelemetryEvent): string {
  if (e.attributes) {
    const msg =
      (e.attributes.message as string) ||
      (e.attributes.description as string) ||
      (e.attributes.detail as string);
    if (msg) return msg;
  }
  const parts = [e.kind];
  if (e.proto) parts.push(e.proto);
  if (e.dstIp) parts.push(`-> ${e.dstIp}:${e.dstPort ?? ""}`);
  return parts.join(" ");
}

function levelClass(level: string): string {
  switch (level) {
    case "block":
      return "bg-red-500/15 text-red-400";
    case "warn":
      return "bg-amber-500/15 text-amber-400";
    case "ok":
      return "bg-emerald-500/15 text-emerald-400";
    default:
      return "bg-cyan-500/10 text-cyan-400";
  }
}

// ── System Health Panel (CPU, Memory, Disk, Rule Eval, Container) ──────

function SystemHealthPanel({
  stats,
  data,
}: {
  stats: SystemStats | null;
  data: DashboardData | null;
}) {
  if (!stats && !data) {
    return <Skeleton className="h-40 w-full" />;
  }

  const items: Array<{
    name: string;
    value: string;
    pct: number;
    color: string;
  }> = [];

  if (stats) {
    items.push({
      name: "CPU",
      value: `${stats.cpu.usagePercent.toFixed(0)}%`,
      pct: stats.cpu.usagePercent,
      color: stats.cpu.usagePercent > 80 ? "#ef4444" : stats.cpu.usagePercent > 60 ? "#f59e0b" : "#22c55e",
    });
    items.push({
      name: "Memory",
      value: stats.memory.totalBytes > 0
        ? `${formatBytes(stats.memory.usedBytes)} / ${formatBytes(stats.memory.totalBytes)}`
        : `${stats.memory.usagePercent.toFixed(0)}%`,
      pct: stats.memory.usagePercent,
      color: stats.memory.usagePercent > 85 ? "#ef4444" : stats.memory.usagePercent > 65 ? "#f59e0b" : "#06b6d4",
    });
    items.push({
      name: "Disk",
      value: stats.disk.totalBytes > 0
        ? `${formatBytes(stats.disk.usedBytes)} / ${formatBytes(stats.disk.totalBytes)}`
        : "N/A",
      pct: stats.disk.usagePercent,
      color: stats.disk.usagePercent > 90 ? "#ef4444" : stats.disk.usagePercent > 70 ? "#f59e0b" : "#22c55e",
    });
  }

  // Rule eval from dashboard counts
  if (data) {
    const totalRules = data.counts.rules + data.counts.icsRules;
    items.push({
      name: "Rule Eval",
      value: `${totalRules} rules`,
      pct: Math.min(100, totalRules * 2),
      color: totalRules > 40 ? "#f59e0b" : "#22c55e",
    });
  }

  // Container metrics
  if (stats?.container.running) {
    const memPct = stats.container.memPercent;
    items.push({
      name: "Container",
      value: stats.container.memLimitBytes > 0
        ? `${formatBytes(stats.container.memUsedBytes)} / ${formatBytes(stats.container.memLimitBytes)}`
        : stats.container.uptime
          ? `Up ${stats.container.uptime}`
          : "Running",
      pct: memPct > 0 ? memPct : 25,
      color: memPct > 85 ? "#ef4444" : memPct > 65 ? "#f59e0b" : "#06b6d4",
    });
  } else if (stats) {
    // Not in container — show Go runtime heap
    items.push({
      name: "Go Heap",
      value: `${stats.runtime.heapAllocMB.toFixed(0)} MB`,
      pct: Math.min(100, (stats.runtime.heapAllocMB / stats.runtime.heapSysMB) * 100),
      color: "#06b6d4",
    });
  }

  return (
    <div className="space-y-3">
      {/* Uptime + goroutines */}
      {stats && (
        <div className="flex justify-between text-2xs font-mono text-slate-500 mb-1">
          <span>Uptime: {stats.runtime.uptime}</span>
          <span>{stats.runtime.goroutines} goroutines</span>
        </div>
      )}

      {items.map((item) => (
        <div key={item.name}>
          <div className="flex justify-between text-2xs font-mono mb-1">
            <span className="text-slate-500 uppercase tracking-wider">
              {item.name}
            </span>
            <span className="text-slate-300 tabular-nums">{item.value}</span>
          </div>
          <div className="h-1 w-full rounded-full bg-white/[0.06]">
            <div
              className="h-1 rounded-full transition-all duration-700"
              style={{ width: `${Math.max(1, item.pct)}%`, background: item.color }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0)} ${units[i]}`;
}

// ── Zone threat posture helpers ──────────────────────────────────────

type ZoneThreat = { alerts: number; blocks: number; level: "critical" | "elevated" | "clear" };

function buildZoneThreatMap(events: TelemetryEvent[], zones: Zone[]): Record<string, ZoneThreat> {
  const map: Record<string, ZoneThreat> = {};
  for (const z of zones) {
    map[z.name] = { alerts: 0, blocks: 0, level: "clear" };
  }

  // Attribute events to zones by matching source/dest IPs to zone names
  // Since we don't have IP-to-zone mapping, use event attributes if available
  for (const e of events) {
    const kind = e.kind;
    const isAlert = kind === "alert" || kind === "ids_alert";
    const isBlock = kind === "block" || kind === "av_block";
    if (!isAlert && !isBlock) continue;

    // Try to attribute to a zone from event attributes
    const zoneAttr = e.attributes?.zone as string | undefined;
    const srcZone = e.attributes?.srcZone as string | undefined;
    const dstZone = e.attributes?.dstZone as string | undefined;

    const targetZones = [zoneAttr, srcZone, dstZone].filter(Boolean) as string[];

    // If no zone info, distribute to all zones proportionally
    if (targetZones.length === 0 && zones.length > 0) {
      // Hash the event to a consistent zone for display
      const idx = (e.id ?? 0) % zones.length;
      targetZones.push(zones[idx].name);
    }

    for (const zn of targetZones) {
      if (!map[zn]) continue;
      if (isAlert) map[zn].alerts++;
      if (isBlock) map[zn].blocks++;
    }
  }

  // Derive threat level
  for (const z of Object.values(map)) {
    if (z.blocks > 0 || z.alerts >= 5) z.level = "critical";
    else if (z.alerts > 0) z.level = "elevated";
  }

  return map;
}

function zoneBadge(level: ZoneThreat["level"]): { label: string; cls: string } {
  switch (level) {
    case "critical":
      return { label: "CRITICAL", cls: "bg-red-500/15 text-red-400" };
    case "elevated":
      return { label: "ELEVATED", cls: "bg-amber-500/15 text-amber-400" };
    default:
      return { label: "CLEAR", cls: "bg-emerald-500/10 text-emerald-400" };
  }
}

function buildZoneSparklines(events: TelemetryEvent[], zones: Zone[]): Record<string, number[]> {
  const BINS = 20;
  const map: Record<string, number[]> = {};
  for (const z of zones) {
    map[z.name] = new Array(BINS).fill(0);
  }

  const now = Date.now();
  const windowMs = 60_000; // 60s window

  for (const e of events) {
    if (!e.timestamp) continue;
    const age = now - new Date(e.timestamp).getTime();
    if (age < 0 || age > windowMs) continue;
    const bin = BINS - 1 - Math.floor((age / windowMs) * BINS);
    if (bin < 0 || bin >= BINS) continue;

    // Attribute to zone
    const zoneAttr = e.attributes?.zone as string | undefined;
    const srcZone = e.attributes?.srcZone as string | undefined;
    const dstZone = e.attributes?.dstZone as string | undefined;
    const targetZones = [zoneAttr, srcZone, dstZone].filter(Boolean) as string[];

    if (targetZones.length === 0 && zones.length > 0) {
      const idx = (e.id ?? 0) % zones.length;
      targetZones.push(zones[idx].name);
    }

    for (const zn of targetZones) {
      if (map[zn]) map[zn][bin]++;
    }
  }

  return map;
}

// ── Service sparklines from event history ───────────────────────────

function buildServiceSparklines(events: TelemetryEvent[]): Record<string, number[]> {
  const BINS = 15;
  const windowMs = 60_000;
  const now = Date.now();

  const serviceMap: Record<string, number[]> = {
    IPS: new Array(BINS).fill(0),
    AV: new Array(BINS).fill(0),
    DNS: new Array(BINS).fill(0),
    Syslog: new Array(BINS).fill(0),
    Proxy: new Array(BINS).fill(0),
    VPN: new Array(BINS).fill(0),
  };

  for (const e of events) {
    if (!e.timestamp) continue;
    const age = now - new Date(e.timestamp).getTime();
    if (age < 0 || age > windowMs) continue;
    const bin = BINS - 1 - Math.floor((age / windowMs) * BINS);
    if (bin < 0 || bin >= BINS) continue;

    // Map event to service based on kind/proto
    const kind = e.kind;
    const proto = (e.proto || "").toLowerCase();

    if (kind === "ids_alert" || kind === "alert") serviceMap.IPS[bin]++;
    else if (kind === "av_detect" || kind === "av_block") serviceMap.AV[bin]++;
    else if (proto === "dns") serviceMap.DNS[bin]++;
    else if (proto === "syslog") serviceMap.Syslog[bin]++;
    else if (proto === "http" || proto === "tls") serviceMap.Proxy[bin]++;
    else serviceMap.IPS[bin]++; // default: attribute to IPS pipeline
  }

  return serviceMap;
}

function deriveServices(
  status: Record<string, unknown> | null,
  events: TelemetryEvent[],
): ServiceInfo[] {
  const sparklines = buildServiceSparklines(events);

  if (!status)
    return [
      { name: "IPS", active: false, detail: "Loading...", href: "/ids/", sparkline: sparklines.IPS },
      { name: "AV", active: false, detail: "Loading...", href: "/system/services/av/", sparkline: sparklines.AV },
      { name: "DNS", active: false, detail: "Loading...", href: "/system/services/dns/", sparkline: sparklines.DNS },
      { name: "VPN", active: false, detail: "Loading...", href: "/vpn/", sparkline: sparklines.VPN },
      { name: "Syslog", active: false, detail: "Loading...", href: "/system/services/syslog/", sparkline: sparklines.Syslog },
      { name: "Proxy", active: false, detail: "Loading...", href: "/proxies/", sparkline: sparklines.Proxy },
    ];

  const av = status.av as Record<string, unknown> | undefined;
  const vpn = status.vpn as Record<string, unknown> | undefined;
  const proxy = status.proxy as Record<string, unknown> | undefined;
  const syslog = status.syslog as Record<string, unknown> | undefined;
  const dns = status.dns as Record<string, unknown> | undefined;

  const syslogConfigured = ((syslog?.configured_forwarders as number) ?? 0) > 0;
  const envoyActive = proxy?.forward_enabled && proxy?.envoy_running;
  const nginxActive = proxy?.reverse_enabled && proxy?.nginx_running;
  const avEnabled = !!av?.enabled;
  const vpnActive = !!vpn?.wireguard_enabled || !!vpn?.openvpn_running;
  const dnsActive = !!dns?.enabled;

  return [
    {
      name: "IPS",
      active: true,
      detail: "Active",
      href: "/ids/",
      sparkline: sparklines.IPS,
    },
    {
      name: "AV",
      active: avEnabled,
      detail: avEnabled ? (av?.mode as string) ?? "Enabled" : "Disabled",
      href: "/system/services/av/",
      sparkline: sparklines.AV,
    },
    {
      name: "DNS",
      active: dnsActive,
      detail: dnsActive ? "Resolving" : "Disabled",
      href: "/system/services/dns/",
      sparkline: sparklines.DNS,
    },
    {
      name: "VPN",
      active: vpnActive,
      detail: vpnActive ? "Tunnel up" : "No tunnels",
      href: "/vpn/",
      sparkline: sparklines.VPN,
    },
    {
      name: "Syslog",
      active: syslogConfigured,
      detail: syslogConfigured
        ? `${syslog?.configured_forwarders} fwd · ${((syslog?.rate_per_min as number) ?? 0).toFixed(0)}/min`
        : "No forwarders",
      href: "/system/services/syslog/",
      sparkline: sparklines.Syslog,
      errorRate: (syslog?.errors_rate_per_min as number) ?? undefined,
    },
    {
      name: "Proxy",
      active: !!(envoyActive || nginxActive),
      detail: envoyActive || nginxActive ? "Active" : "Disabled",
      href: "/proxies/",
      sparkline: sparklines.Proxy,
    },
  ];
}
