"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";

import {
  type DashboardData,
  type TelemetryEvent,
  type Zone,
  type FlowSummary,
  api,
} from "../lib/api";
import { Shell } from "../components/Shell";
import { Console } from "../components/Console";
import { Skeleton } from "../components/Skeleton";

// ── Types ──────────────────────────────────────────────────────────────

type ServiceInfo = {
  name: string;
  active: boolean;
  detail: string;
};

// ── Main Dashboard ─────────────────────────────────────────────────────

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [zones, setZones] = useState<Zone[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [clock, setClock] = useState("");

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
    let alive = true;
    const load = () => {
      api.getDashboard().then((r) => alive && r && setData(r));
      api.listZones().then((r) => alive && r && setZones(r));
      api.listEvents(50).then((r) => alive && r && setEvents(r));
      api.listFlows(100).then((r) => alive && r && setFlows(r));
    };
    load();
    const id = setInterval(load, 10_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const health = data?.health ?? null;
  const eventStats = data?.eventStats ?? null;
  const servicesStatus = data?.services ?? null;
  const hasAlerts =
    eventStats &&
    (eventStats.idsAlerts > 0 || eventStats.avDetections > 0);

  // Derive services list
  const services = deriveServices(servicesStatus);

  // Traffic counters from flows
  const totalFlows = flows.length;
  const activeFlows = flows.filter((f) => {
    if (!f.lastSeen) return false;
    const age = Date.now() - new Date(f.lastSeen).getTime();
    return age < 120_000;
  }).length;

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
            <span className="hidden sm:inline text-2xs text-slate-600 font-mono">
              Build {health.build}
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 text-2xs font-mono text-slate-500">
          {services.slice(0, 4).map((s) => (
            <span key={s.name} className="flex items-center gap-1.5">
              {s.name}
              <span
                className={`inline-block h-1.5 w-1.5 rounded-full ${
                  s.active ? "bg-emerald-400" : "bg-slate-600"
                }`}
              />
            </span>
          ))}
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
            <NetworkPulseCanvas zones={zones} />
          </div>
        </div>

        {/* Zone Status — right column, spans 2 rows */}
        <div className="lg:row-span-2 rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4 overflow-y-auto max-h-[520px]">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Zone Status
          </h3>
          {zones.length > 0 ? (
            <ZoneList zones={zones} />
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
            Traffic &mdash; 60s Window
          </h3>
          <div className="h-[120px] mb-3">
            <TrafficChart />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <TrafficCounter
              label="Total Events"
              value={eventStats?.total ?? 0}
              color="text-amber-400"
            />
            <TrafficCounter
              label="Active Flows"
              value={activeFlows}
              color="text-cyan-400"
            />
            <TrafficCounter
              label="Total Flows"
              value={totalFlows}
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

        {/* System Health */}
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card p-4">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
            System Health
          </h3>
          {data ? (
            <SystemHealth data={data} />
          ) : (
            <Skeleton className="h-32 w-full" />
          )}
        </div>
      </div>

      {/* ── Stats row ───────────────────────────────────────── */}
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-5">
        <StatCard
          label="Zones"
          value={data?.counts?.zones ?? null}
          href="/zones/"
        />
        <StatCard
          label="Interfaces"
          value={data?.counts?.interfaces ?? null}
          href="/interfaces/"
        />
        <StatCard
          label="FW Rules"
          value={data?.counts?.rules ?? null}
          href="/firewall/"
        />
        <StatCard
          label="ICS Rules"
          value={data?.counts?.icsRules ?? null}
          href="/ics/"
        />
        <StatCard
          label="Assets"
          value={data?.counts?.assets ?? null}
          href="/assets/"
        />
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

// ── Network Pulse Canvas ───────────────────────────────────────────────

function NetworkPulseCanvas({ zones }: { zones: Zone[] }) {
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

  // Build nodes from real zones + a CORE FW node + WAN node
  const nodes = useCallback(() => {
    const core = {
      id: "CORE FW",
      x: 0.5,
      y: 0.5,
      color: "#06b6d4",
      r: 14,
    };
    const wan = { id: "WAN", x: 0.88, y: 0.48, color: "#6b7280", r: 9 };

    if (zones.length === 0) {
      return [
        { id: "OT-FIELD", x: 0.15, y: 0.55, color: "#22c55e", r: 10 },
        { id: "SCADA", x: 0.32, y: 0.3, color: "#f59e0b", r: 9 },
        core,
        { id: "CORP", x: 0.68, y: 0.3, color: "#22c55e", r: 11 },
        { id: "DMZ", x: 0.72, y: 0.65, color: "#22c55e", r: 8 },
        wan,
      ];
    }

    // Distribute zone nodes around the core
    const zoneNodes = zones.slice(0, 8).map((z, i) => {
      const angle = (i / Math.min(zones.length, 8)) * Math.PI * 2 - Math.PI / 2;
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

    const n = nodes();
    const coreIdx = n.findIndex((nd) => nd.id === "CORE FW");
    const wanIdx = n.findIndex((nd) => nd.id === "WAN");

    // Build edges: all zones connect to core, core connects to WAN
    const edges: Array<{ from: number; to: number }> = [];
    n.forEach((_, i) => {
      if (i !== coreIdx && i !== wanIdx) edges.push({ from: i, to: coreIdx });
    });
    if (wanIdx >= 0 && coreIdx >= 0) edges.push({ from: coreIdx, to: wanIdx });

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
      const edge = edges[Math.floor(Math.random() * edges.length)];
      const reverse = Math.random() > 0.5;
      const types = ["allow", "allow", "allow", "block", "inspect"];
      const type = types[Math.floor(Math.random() * types.length)];
      packets.push({
        fromIdx: reverse ? edge.to : edge.from,
        toIdx: reverse ? edge.from : edge.to,
        t: 0,
        speed: 0.008 + Math.random() * 0.012,
        color:
          type === "allow"
            ? "#22c55e"
            : type === "block"
              ? "#ef4444"
              : "#f59e0b",
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

      // Spawn packets
      if (frame % 20 === 0) spawnPacket();

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

      animRef.current = requestAnimationFrame(draw);
    }

    animRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animRef.current);
    };
  }, [nodes]);

  return <canvas ref={canvasRef} className="w-full h-full" />;
}

// ── Zone List ──────────────────────────────────────────────────────────

function ZoneList({ zones }: { zones: Zone[] }) {
  return (
    <div className="space-y-2">
      {zones.map((z) => (
        <Link
          key={z.name}
          href={`/zones/`}
          className="block rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 transition-colors hover:border-white/[0.12] hover:bg-white/[0.04]"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
              {z.alias || z.name}
            </span>
            <span className="text-2xs font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
              ACTIVE
            </span>
          </div>
          {z.description && (
            <div className="text-2xs text-slate-500 truncate">
              {z.description}
            </div>
          )}
          <ZoneMiniSparkline />
        </Link>
      ))}
    </div>
  );
}

function ZoneMiniSparkline() {
  // Simple CSS sparkline bars
  const bars = 12;
  return (
    <div className="flex items-end gap-0.5 h-4 mt-2">
      {Array.from({ length: bars }).map((_, i) => {
        const h = Math.max(3, Math.floor(Math.random() * 16));
        return (
          <div
            key={i}
            className="flex-1 rounded-t-sm bg-emerald-500/30"
            style={{ height: `${h}px` }}
          />
        );
      })}
    </div>
  );
}

// ── Service Grid ───────────────────────────────────────────────────────

function ServiceGrid({ services }: { services: ServiceInfo[] }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {services.map((s) => (
        <div
          key={s.name}
          className={`rounded-lg border p-3 transition-colors ${
            s.active
              ? "border-emerald-500/20 bg-emerald-500/[0.04]"
              : "border-white/[0.06] bg-white/[0.02] opacity-50"
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
          <ServiceSparkline active={s.active} />
        </div>
      ))}
    </div>
  );
}

function ServiceSparkline({ active }: { active: boolean }) {
  return (
    <div className="flex items-end gap-0.5 h-5 mt-2">
      {Array.from({ length: 14 }).map((_, i) => {
        const h = active ? Math.floor(Math.random() * 14 + 4) : 3;
        return (
          <div
            key={i}
            className="flex-1 rounded-t-sm"
            style={{
              height: `${h}px`,
              background: active
                ? "rgba(34,197,94,0.5)"
                : "rgba(55,65,81,0.4)",
            }}
          />
        );
      })}
    </div>
  );
}

// ── Traffic Chart (Canvas) ─────────────────────────────────────────────

function TrafficChart() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const dataRef = useRef<number[]>(
    Array.from({ length: 60 }, () => Math.floor(Math.random() * 80 + 20)),
  );
  const animRef = useRef<number>(0);

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

    let frame = 0;

    function draw() {
      frame++;
      const w = canvas!.offsetWidth;
      const h = canvas!.offsetHeight;
      const data = dataRef.current;

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
      ctx!.strokeStyle = "#f59e0b";
      ctx!.lineWidth = 1.5;
      ctx!.stroke();

      // Advance data every ~30 frames (~500ms at 60fps)
      if (frame % 30 === 0) {
        data.shift();
        data.push(Math.floor(Math.random() * 120 + 30));
      }

      animRef.current = requestAnimationFrame(draw);
    }

    animRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener("resize", resize);
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
            <span className="text-slate-300 truncate">
              {eventMessage(e)}
            </span>
            <span className="text-slate-600 text-right">
              {e.srcIp ?? ""}
            </span>
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

// ── System Health ──────────────────────────────────────────────────────

function SystemHealth({ data }: { data: DashboardData }) {
  const me = data.user;
  const lastActivity = data.lastActivity;

  // We don't have real CPU/memory from the backend, so show what we can
  const items: Array<{ name: string; value: string; pct: number; color: string }> =
    [
      {
        name: "Zones",
        value: `${data.counts.zones}`,
        pct: Math.min(100, data.counts.zones * 15),
        color: "#22c55e",
      },
      {
        name: "FW Rules",
        value: `${data.counts.rules}`,
        pct: Math.min(100, data.counts.rules * 5),
        color: "#06b6d4",
      },
      {
        name: "ICS Rules",
        value: `${data.counts.icsRules}`,
        pct: Math.min(100, data.counts.icsRules * 5),
        color: "#22c55e",
      },
      {
        name: "Events",
        value: `${data.eventStats.total}`,
        pct: Math.min(100, Math.round((data.eventStats.total / 500) * 100)),
        color: "#f59e0b",
      },
      {
        name: "Assets",
        value: `${data.counts.assets}`,
        pct: Math.min(100, data.counts.assets * 10),
        color: "#22c55e",
      },
    ];

  return (
    <div className="space-y-3">
      {/* User / last activity */}
      <div className="text-2xs space-y-1 mb-3">
        <div className="flex justify-between">
          <span className="text-slate-500">User</span>
          <span className="text-slate-300">{me?.username ?? "---"}</span>
        </div>
        {lastActivity && (
          <div className="flex justify-between">
            <span className="text-slate-500">Last change</span>
            <span className="text-slate-300 truncate ml-2">
              {new Date(lastActivity.timestamp).toLocaleString()}
            </span>
          </div>
        )}
      </div>

      {/* Health bars */}
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
              style={{
                width: `${item.pct}%`,
                background: item.color,
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Stat Card ──────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  href,
}: {
  label: string;
  value: number | null;
  href: string;
}) {
  return (
    <Link
      href={href}
      className="rounded-xl border border-white/[0.08] bg-white/[0.03] p-3 shadow-card transition-colors hover:bg-white/[0.06] hover:border-white/[0.12]"
    >
      <div className="text-2xl font-semibold tabular-nums text-white">
        {value ?? "---"}
      </div>
      <div className="mt-0.5 text-xs text-slate-500">{label}</div>
    </Link>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────

function deriveServices(
  status: Record<string, unknown> | null,
): ServiceInfo[] {
  if (!status)
    return [
      { name: "IPS", active: false, detail: "Loading..." },
      { name: "AV", active: false, detail: "Loading..." },
      { name: "DNS", active: false, detail: "Loading..." },
      { name: "VPN", active: false, detail: "Loading..." },
      { name: "Syslog", active: false, detail: "Loading..." },
      { name: "Proxy", active: false, detail: "Loading..." },
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
    { name: "IPS", active: true, detail: "Active" },
    {
      name: "AV",
      active: avEnabled,
      detail: avEnabled ? (av?.mode as string) ?? "Enabled" : "Disabled",
    },
    { name: "DNS", active: dnsActive, detail: dnsActive ? "Resolving" : "Disabled" },
    {
      name: "VPN",
      active: vpnActive,
      detail: vpnActive ? "Tunnel up" : "No tunnels",
    },
    {
      name: "Syslog",
      active: syslogConfigured,
      detail: syslogConfigured
        ? `${syslog?.configured_forwarders} fwd`
        : "No forwarders",
    },
    {
      name: "Proxy",
      active: !!(envoyActive || nginxActive),
      detail: envoyActive || nginxActive ? "Active" : "Disabled",
    },
  ];
}
