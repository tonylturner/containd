"use client";

import { useEffect, useRef } from "react";
import Link from "next/link";

import type {
  DashboardData,
  FlowSummary,
  ServicesStatus,
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
        <span className="h-2 w-2 rounded-full" />
        <span className="text-slate-500">INSPECT</span>
        <span className="tabular-nums">{inspected}</span>
      </span>
    </div>
  );
}

const zoneLevelColor: Record<ZoneThreat["level"], string> = {
  critical: "#ef4444",
  elevated: "#f59e0b",
  clear: "#22c55e",
};

/**
 * Zone topology around the firewall. Each zone node takes the colour of its
 * threat level from zone-attributed IDS alerts; nothing is animated, because
 * no event stream carries per-edge traffic to show.
 */
export function NetworkPulseCanvas({
  zones,
  threatMap,
}: {
  zones: Zone[];
  threatMap: Record<string, ZoneThreat>;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const canvasEl = canvas;
    const ctx2d = ctx;

    const core = { id: "CORE FW", x: 0.5, y: 0.5, color: "#06b6d4", r: 14 };
    const wan = { id: "WAN", x: 0.88, y: 0.48, color: "#6b7280", r: 9 };
    const shown = zones.slice(0, 8);
    const zoneNodes = shown.map((z, i) => {
      const angle = (i / shown.length) * Math.PI * 2 - Math.PI / 2;
      return {
        id: (z.alias || z.name).toUpperCase().slice(0, 10),
        x: 0.5 + Math.cos(angle) * 0.32,
        y: 0.5 + Math.sin(angle) * 0.35,
        color: zoneLevelColor[threatMap[z.name]?.level ?? "clear"],
        r: 9,
      };
    });
    const nodes = [...zoneNodes, core, wan];
    const edges = [...zoneNodes, wan].map((node) => ({ from: node, to: core }));

    const draw = () => {
      const ratio = window.devicePixelRatio || 1;
      const w = canvasEl.offsetWidth;
      const h = canvasEl.offsetHeight;
      canvasEl.width = w * ratio;
      canvasEl.height = h * ratio;
      ctx2d.setTransform(ratio, 0, 0, ratio, 0, 0);
      ctx2d.clearRect(0, 0, w, h);

      edges.forEach(({ from, to }) => {
        ctx2d.beginPath();
        ctx2d.moveTo(from.x * w, from.y * h);
        ctx2d.lineTo(to.x * w, to.y * h);
        ctx2d.strokeStyle = "rgba(245,158,11,0.1)";
        ctx2d.lineWidth = 1;
        ctx2d.stroke();
      });

      nodes.forEach((nd) => {
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
    };
    draw();
    window.addEventListener("resize", draw);
    return () => window.removeEventListener("resize", draw);
  }, [zones, threatMap]);

  return <canvas ref={canvasRef} className="w-full h-full" />;
}

/** Zone-attributed IDS alerts among the recent events. */
type ZoneThreat = { alerts: number; level: "critical" | "elevated" | "clear" };

export function ZoneList({ zones, threatMap, sparklineMap }: {
  zones: Zone[];
  threatMap: Record<string, ZoneThreat>;
  sparklineMap: Record<string, number[]>;
}) {
  return (
    <div className="space-y-2">
      {zones.map((z) => {
        const threat = threatMap[z.name] ?? { alerts: 0, level: "clear" as const };
        const sparkline = sparklineMap[z.name] ?? [];
        const badgeInfo = zoneBadge(threat.level);

        return (
          <Link
            key={z.name}
            href="/zones/"
            className="block rounded-lg border border-white/6 bg-white/2 p-3 transition-colors hover:border-white/12 hover:bg-white/4"
          >
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                {z.alias || z.name}
              </span>
              <span className={`text-2xs font-mono px-1.5 py-0.5 rounded-sm ${badgeInfo.cls}`}>
                {badgeInfo.label}
              </span>
            </div>
            {threat.alerts > 0 && (
              <div className="mb-1 text-2xs font-mono">
                {threat.alerts} alert{threat.alerts !== 1 ? "s" : ""}
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
                      className="flex-1 rounded-t-xs"
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

/**
 * Events per second over the last 60 seconds of the loaded events. A quiet
 * window draws a flat zero line rather than an invented baseline.
 */
export function TrafficChart({ events }: { events: TelemetryEvent[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const canvasEl = canvas;
    const ctx2d = ctx;

    const now = Date.now();
    const data = new Array(60).fill(0);
    for (const e of events) {
      if (!e.timestamp) continue;
      const age = now - new Date(e.timestamp).getTime();
      const bucket = 59 - Math.floor(age / 1000);
      if (bucket >= 0 && bucket < 60) data[bucket]++;
    }
    const idle = !data.some((v) => v > 0);

    const draw = () => {
      const ratio = window.devicePixelRatio || 1;
      const w = canvasEl.offsetWidth;
      const h = canvasEl.offsetHeight;
      canvasEl.width = w * ratio;
      canvasEl.height = h * ratio;
      ctx2d.setTransform(ratio, 0, 0, ratio, 0, 0);
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

      const trace = () => {
        ctx2d.beginPath();
        data.forEach((val, i) => {
          const x = i * step;
          const y = h - (val / max) * h * 0.85 - 4;
          if (i === 0) ctx2d.moveTo(x, y);
          else ctx2d.lineTo(x, y);
        });
      };

      if (idle) {
        trace();
        ctx2d.strokeStyle = "rgba(245,158,11,0.3)";
        ctx2d.lineWidth = 1;
        ctx2d.stroke();
        ctx2d.fillStyle = "rgba(148,163,184,0.5)";
        ctx2d.font = "9px monospace";
        ctx2d.textAlign = "right";
        ctx2d.fillText("no events", w - 4, 12);
        return;
      }

      trace();
      ctx2d.lineTo((data.length - 1) * step, h);
      ctx2d.lineTo(0, h);
      ctx2d.closePath();
      const grad = ctx2d.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, "rgba(245,158,11,0.2)");
      grad.addColorStop(1, "rgba(245,158,11,0)");
      ctx2d.fillStyle = grad;
      ctx2d.fill();

      trace();
      ctx2d.strokeStyle = "#f59e0b";
      ctx2d.lineWidth = 1.5;
      ctx2d.stroke();
    };
    draw();
    window.addEventListener("resize", draw);
    return () => window.removeEventListener("resize", draw);
  }, [events]);

  return <canvas ref={canvasRef} className="w-full h-full" />;
}

function isIDSAlert(e: TelemetryEvent): boolean {
  return e.proto === "ids" && e.kind === "alert";
}

function zoneNames(attrs: Record<string, unknown> | undefined): string[] {
  if (!attrs) return [];
  return [attrs.zone, attrs.srcZone, attrs.dstZone].filter(
    (z): z is string => typeof z === "string" && z !== "",
  );
}

/**
 * The zones an event names: its own zone attributes, or for an IDS alert
 * those of the event that triggered it. Events without zones belong to none.
 */
function eventZones(e: TelemetryEvent): string[] {
  const own = zoneNames(e.attributes);
  if (own.length > 0) return own;
  const source = e.attributes?.event_attrs;
  if (source && typeof source === "object") {
    return zoneNames(source as Record<string, unknown>);
  }
  return [];
}

export function buildZoneThreatMap(events: TelemetryEvent[], zones: Zone[]): Record<string, ZoneThreat> {
  const map: Record<string, ZoneThreat> = {};
  for (const z of zones) {
    map[z.name] = { alerts: 0, level: "clear" };
  }

  for (const e of events) {
    if (!isIDSAlert(e)) continue;
    for (const zn of new Set(eventZones(e))) {
      if (map[zn]) map[zn].alerts++;
    }
  }

  for (const z of Object.values(map)) {
    if (z.alerts >= 5) z.level = "critical";
    else if (z.alerts > 0) z.level = "elevated";
  }

  return map;
}

function zoneBadge(level: ZoneThreat["level"]): { label: string; cls: string } {
  switch (level) {
    case "critical":
      return { label: "CRITICAL", cls: "bg-red-500/15 text-red-400" };
    case "elevated":
      return { label: "ELEVATED", cls: "" };
    default:
      return { label: "CLEAR", cls: "bg-emerald-500/10 text-emerald-400" };
  }
}

function recentBin(e: TelemetryEvent, now: number, bins: number, windowMs: number): number | null {
  if (!e.timestamp) return null;
  const age = now - new Date(e.timestamp).getTime();
  if (age < 0 || age > windowMs) return null;
  const bin = bins - 1 - Math.floor((age / windowMs) * bins);
  return bin >= 0 && bin < bins ? bin : null;
}

/** Per-zone event counts over the last 60 seconds, zone-attributed only. */
export function buildZoneSparklines(events: TelemetryEvent[], zones: Zone[]): Record<string, number[]> {
  const BINS = 20;
  const map: Record<string, number[]> = {};
  for (const z of zones) {
    map[z.name] = new Array(BINS).fill(0);
  }

  const now = Date.now();
  for (const e of events) {
    const bin = recentBin(e, now, BINS, 60_000);
    if (bin === null) continue;
    for (const zn of new Set(eventZones(e))) {
      if (map[zn]) map[zn][bin]++;
    }
  }

  return map;
}

/** IDS alerts over the last 60 seconds of the loaded events. */
function buildIDSSparkline(events: TelemetryEvent[]): number[] {
  const BINS = 15;
  const series = new Array(BINS).fill(0);
  const now = Date.now();
  for (const e of events) {
    if (!isIDSAlert(e)) continue;
    const bin = recentBin(e, now, BINS, 60_000);
    if (bin !== null) series[bin]++;
  }
  return series;
}

/**
 * Service cards from the services status. Sparklines are each service's own
 * per-minute meter; IPS, which has no meter, counts IDS alert events.
 */
export function deriveServices(
  status: ServicesStatus | null,
  events: TelemetryEvent[],
): ServiceInfo[] {
  const ips = buildIDSSparkline(events);

  if (!status) {
    return [
      { name: "IPS", active: null, detail: "Unknown — protection not reported", href: "/ids/", sparkline: ips },
      { name: "AV", active: null, detail: "Unknown", href: "/system/services/av/" },
      { name: "DNS", active: null, detail: "Unknown", href: "/system/services/dns/" },
      { name: "VPN", active: null, detail: "Unknown", href: "/vpn/" },
      { name: "Syslog", active: null, detail: "Unknown", href: "/system/services/syslog/" },
      { name: "Proxy", active: null, detail: "Unknown", href: "/proxies/" },
    ];
  }

  const { av, vpn, proxy, syslog, dns } = status;
  const syslogKnown = typeof syslog?.configured_forwarders === "number";
  const syslogConfigured = syslogKnown && syslog!.configured_forwarders > 0;
  const envoyActive = !!(proxy?.forward_enabled && proxy.envoy_running);
  const nginxActive = !!(proxy?.reverse_enabled && proxy.nginx_running);
  const avEnabled = av.available && av.enabled;
  const avKnown = av.available && typeof av.enabled === "boolean";
  const vpnActive = !!vpn?.wireguard_enabled || !!vpn?.openvpn_running;
  const vpnKnown = vpnActive || (typeof vpn?.wireguard_enabled === "boolean" && typeof vpn?.openvpn_running === "boolean");
  const proxyActive = envoyActive || nginxActive;
  const proxyKnown = proxyActive || (typeof proxy?.envoy_running === "boolean" && typeof proxy?.nginx_running === "boolean" && typeof proxy?.forward_enabled === "boolean" && typeof proxy?.reverse_enabled === "boolean");
  const dnsKnown = typeof dns?.enabled === "boolean" && typeof dns?.running === "boolean";
  const dnsActive = !!(dns?.enabled && dns.running);

  return [
    {
      name: "IPS",
      active: null,
      detail: "Unknown — protection not reported",
      href: "/ids/",
      sparkline: ips,
    },
    {
      name: "AV",
      active: avKnown ? avEnabled : null,
      detail: !av.available ? "Scanner unavailable" : !avKnown ? "Unknown" : avEnabled ? av.mode || "Enabled" : "Disabled",
      href: "/system/services/av/",
      sparkline: av.available ? av.sparkline : undefined,
    },
    {
      name: "DNS",
      active: dnsKnown ? dnsActive : null,
      detail: !dnsKnown ? "Unknown" : dnsActive ? "Resolving" : dns!.enabled ? "Stopped" : "Disabled",
      href: "/system/services/dns/",
      sparkline: dns?.sparkline,
    },
    {
      name: "VPN",
      active: vpnKnown ? vpnActive : null,
      detail: !vpnKnown ? "Unknown" : vpn!.openvpn_running ? "OpenVPN running" : vpn!.wireguard_enabled ? "WireGuard enabled" : "No tunnels",
      href: "/vpn/",
      sparkline: vpn?.sparkline,
    },
    {
      name: "Syslog",
      active: syslogKnown ? syslogConfigured : null,
      detail: !syslogKnown ? "Unknown" : syslogConfigured
        ? `${syslog?.configured_forwarders} fwd · ${typeof syslog?.rate_per_min === "number" ? syslog.rate_per_min.toFixed(0) : "Unknown"}/min`
        : "No forwarders",
      href: "/system/services/syslog/",
      sparkline: syslog?.sparkline,
      errorRate: syslog?.errors_rate_per_min,
    },
    {
      name: "Proxy",
      active: proxyKnown ? proxyActive : null,
      detail: !proxyKnown ? "Unknown" : proxyActive ? "Active" : "Stopped",
      href: "/proxies/",
      sparkline: proxy?.sparkline,
    },
  ];
}
