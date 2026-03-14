"use client";

import { useCallback, useEffect, useRef } from "react";
import Link from "next/link";

import type {
  DashboardData,
  FlowSummary,
  TelemetryEvent,
  Zone,
} from "../lib/api";
import type { ServiceInfo } from "./dashboard-panels";

export function NetworkPulseStats({
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

export function NetworkPulseCanvas({
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
  const dataRateRef = useRef({ flowCount: 0, eventCount: 0 });

  useEffect(() => {
    dataRateRef.current = {
      flowCount: flows.length,
      eventCount: events.length,
    };
  }, [flows.length, events.length]);

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
    const canvasEl = canvas;
    const ctx2d = ctx;

    const n = buildNodes();
    const coreIdx = n.findIndex((nd) => nd.id === "CORE FW");
    const wanIdx = n.findIndex((nd) => nd.id === "WAN");

    const edges: Array<{ from: number; to: number }> = [];
    n.forEach((_, i) => {
      if (i !== coreIdx && i !== wanIdx) edges.push({ from: i, to: coreIdx });
    });
    if (wanIdx >= 0 && coreIdx >= 0) {
      edges.push({ from: coreIdx, to: wanIdx });
    }

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      canvasEl.width = canvasEl.offsetWidth * ratio;
      canvasEl.height = canvasEl.offsetHeight * ratio;
      ctx2d.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);

    let frame = 0;
    const packets = packetsRef.current;

    function spawnPacket() {
      if (edges.length === 0) return;
      const { flowCount, eventCount } = dataRateRef.current;
      if (flowCount === 0 && eventCount === 0) return;

      const edge = edges[Math.floor(Math.random() * edges.length)];
      const reverse = Math.random() > 0.5;

      const roll = Math.random();
      let color = "#22c55e";
      if (roll < 0.05) color = "#ef4444";
      else if (roll < 0.15) color = "#f59e0b";

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
      const w = canvasEl.offsetWidth;
      const h = canvasEl.offsetHeight;
      ctx2d.clearRect(0, 0, w, h);

      const getPos = (idx: number) => ({
        x: n[idx].x * w,
        y: n[idx].y * h,
      });

      edges.forEach((e) => {
        const a = getPos(e.from);
        const b = getPos(e.to);
        ctx2d.beginPath();
        ctx2d.moveTo(a.x, a.y);
        ctx2d.lineTo(b.x, b.y);
        ctx2d.strokeStyle = "rgba(245,158,11,0.1)";
        ctx2d.lineWidth = 1;
        ctx2d.stroke();
      });

      const { flowCount } = dataRateRef.current;
      const spawnInterval = flowCount > 50 ? 10 : flowCount > 10 ? 20 : flowCount > 0 ? 40 : 0;
      if (spawnInterval > 0 && frame % spawnInterval === 0) spawnPacket();

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
        ctx2d.beginPath();
        ctx2d.arc(x, y, 3, 0, Math.PI * 2);
        ctx2d.fillStyle = p.color;
        ctx2d.shadowColor = p.color;
        ctx2d.shadowBlur = 8;
        ctx2d.fill();
        ctx2d.shadowBlur = 0;
        p.t += p.speed;
        if (p.t >= 1) packets.splice(i, 1);
      }

      n.forEach((nd) => {
        const nx = nd.x * w;
        const ny = nd.y * h;
        const grd = ctx2d.createRadialGradient(nx, ny, 0, nx, ny, nd.r * 2.5);
        grd.addColorStop(0, nd.color + "40");
        grd.addColorStop(1, nd.color + "00");
        ctx2d.beginPath();
        ctx2d.arc(nx, ny, nd.r * 2.5, 0, Math.PI * 2);
        ctx2d.fillStyle = grd;
        ctx2d.fill();

        ctx2d.beginPath();
        ctx2d.arc(nx, ny, nd.r, 0, Math.PI * 2);
        ctx2d.fillStyle = "#0d1117";
        ctx2d.fill();
        ctx2d.strokeStyle = nd.color;
        ctx2d.lineWidth = 1.5;
        ctx2d.stroke();

        ctx2d.fillStyle = "rgba(148,163,184,0.8)";
        ctx2d.font = "9px monospace";
        ctx2d.textAlign = "center";
        ctx2d.fillText(nd.id, nx, ny + nd.r + 14);
      });

      if (!document.hidden) {
        animRef.current = requestAnimationFrame(draw);
      }
    }

    animRef.current = requestAnimationFrame(draw);

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

type ZoneThreat = { alerts: number; blocks: number; level: "critical" | "elevated" | "clear" };

export function ZoneList({ zones, threatMap, sparklineMap }: {
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
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                {z.alias || z.name}
              </span>
              <span className={`text-2xs font-mono px-1.5 py-0.5 rounded ${badgeInfo.cls}`}>
                {badgeInfo.label}
              </span>
            </div>
            {threat.alerts > 0 && (
              <div className="mb-1 text-2xs font-mono text-amber-400/80">
                {threat.alerts} alert{threat.alerts !== 1 ? "s" : ""}
                {threat.blocks > 0 && ` · ${threat.blocks} block${threat.blocks !== 1 ? "s" : ""}`}
              </div>
            )}
            {z.description && (
              <div className="truncate text-2xs text-slate-500">
                {z.description}
              </div>
            )}
            {sparkline.length > 0 && (
              <div className="mt-2 flex h-4 items-end gap-px">
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

export function TrafficChart({ events }: { events: TelemetryEvent[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const histogramRef = useRef<number[]>(new Array(60).fill(0));
  const isIdleRef = useRef(false);

  useEffect(() => {
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
      for (let i = 0; i < 60; i++) {
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
    const canvasEl = canvas;
    const ctx2d = ctx;

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      canvasEl.width = canvasEl.offsetWidth * ratio;
      canvasEl.height = canvasEl.offsetHeight * ratio;
      ctx2d.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);

    function draw() {
      const w = canvasEl.offsetWidth;
      const h = canvasEl.offsetHeight;
      const data = histogramRef.current;

      ctx2d.clearRect(0, 0, w, h);

      const max = Math.max(...data, 1);
      const step = w / (data.length - 1);

      ctx2d.strokeStyle = "rgba(245,158,11,0.06)";
      ctx2d.lineWidth = 1;
      for (let i = 0; i < 4; i++) {
        const y = h * (i / 3);
        ctx2d.beginPath();
        ctx2d.moveTo(0, y);
        ctx2d.lineTo(w, y);
        ctx2d.stroke();
      }

      ctx2d.beginPath();
      data.forEach((val, i) => {
        const x = i * step;
        const y = h - (val / max) * h * 0.85 - 4;
        i === 0 ? ctx2d.moveTo(x, y) : ctx2d.lineTo(x, y);
      });
      ctx2d.lineTo((data.length - 1) * step, h);
      ctx2d.lineTo(0, h);
      ctx2d.closePath();
      const grad = ctx2d.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, "rgba(245,158,11,0.2)");
      grad.addColorStop(1, "rgba(245,158,11,0)");
      ctx2d.fillStyle = grad;
      ctx2d.fill();

      ctx2d.beginPath();
      data.forEach((val, i) => {
        const x = i * step;
        const y = h - (val / max) * h * 0.85 - 4;
        i === 0 ? ctx2d.moveTo(x, y) : ctx2d.lineTo(x, y);
      });
      const idle = isIdleRef.current;
      ctx2d.strokeStyle = idle ? "rgba(245,158,11,0.3)" : "#f59e0b";
      ctx2d.lineWidth = idle ? 1 : 1.5;
      if (idle) ctx2d.setLineDash([4, 4]);
      ctx2d.stroke();
      if (idle) ctx2d.setLineDash([]);

      if (idle) {
        ctx2d.fillStyle = "rgba(148,163,184,0.5)";
        ctx2d.font = "9px monospace";
        ctx2d.textAlign = "right";
        ctx2d.fillText("24h baseline", w - 4, 12);
      }

      if (!document.hidden) {
        animRef.current = requestAnimationFrame(draw);
      }
    }

    animRef.current = requestAnimationFrame(draw);
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

export function buildZoneThreatMap(events: TelemetryEvent[], zones: Zone[]): Record<string, ZoneThreat> {
  const map: Record<string, ZoneThreat> = {};
  for (const z of zones) {
    map[z.name] = { alerts: 0, blocks: 0, level: "clear" };
  }

  for (const e of events) {
    const kind = e.kind;
    const isAlert = kind === "alert" || kind === "ids_alert";
    const isBlock = kind === "block" || kind === "av_block";
    if (!isAlert && !isBlock) continue;

    const zoneAttr = e.attributes?.zone as string | undefined;
    const srcZone = e.attributes?.srcZone as string | undefined;
    const dstZone = e.attributes?.dstZone as string | undefined;
    const targetZones = [zoneAttr, srcZone, dstZone].filter(Boolean) as string[];

    if (targetZones.length === 0 && zones.length > 0) {
      const idx = (e.id ?? 0) % zones.length;
      targetZones.push(zones[idx].name);
    }

    for (const zn of targetZones) {
      if (!map[zn]) continue;
      if (isAlert) map[zn].alerts++;
      if (isBlock) map[zn].blocks++;
    }
  }

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

export function buildZoneSparklines(events: TelemetryEvent[], zones: Zone[]): Record<string, number[]> {
  const BINS = 20;
  const map: Record<string, number[]> = {};
  for (const z of zones) {
    map[z.name] = new Array(BINS).fill(0);
  }

  const now = Date.now();
  const windowMs = 60_000;

  for (const e of events) {
    if (!e.timestamp) continue;
    const age = now - new Date(e.timestamp).getTime();
    if (age < 0 || age > windowMs) continue;
    const bin = BINS - 1 - Math.floor((age / windowMs) * BINS);
    if (bin < 0 || bin >= BINS) continue;

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

    const kind = e.kind;
    const proto = (e.proto || "").toLowerCase();

    if (kind === "ids_alert" || kind === "alert") serviceMap.IPS[bin]++;
    else if (kind === "av_detect" || kind === "av_block") serviceMap.AV[bin]++;
    else if (proto === "dns") serviceMap.DNS[bin]++;
    else if (proto === "syslog") serviceMap.Syslog[bin]++;
    else if (proto === "http" || proto === "tls") serviceMap.Proxy[bin]++;
    else serviceMap.IPS[bin]++;
  }

  return serviceMap;
}

export function deriveServices(
  status: Record<string, unknown> | null,
  events: TelemetryEvent[],
): ServiceInfo[] {
  const sparklines = buildServiceSparklines(events);

  if (!status) {
    return [
      { name: "IPS", active: false, detail: "Loading...", href: "/ids/", sparkline: sparklines.IPS },
      { name: "AV", active: false, detail: "Loading...", href: "/system/services/av/", sparkline: sparklines.AV },
      { name: "DNS", active: false, detail: "Loading...", href: "/system/services/dns/", sparkline: sparklines.DNS },
      { name: "VPN", active: false, detail: "Loading...", href: "/vpn/", sparkline: sparklines.VPN },
      { name: "Syslog", active: false, detail: "Loading...", href: "/system/services/syslog/", sparkline: sparklines.Syslog },
      { name: "Proxy", active: false, detail: "Loading...", href: "/proxies/", sparkline: sparklines.Proxy },
    ];
  }

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
