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
import { Console } from "../components/Console";
import { Skeleton } from "../components/Skeleton";
import { Card } from "../components/Card";
import { StatusBadge, StatusIndicator } from "../components/StatusBadge";

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
  const [consoleOpen, setConsoleOpen] = useState(false);

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
      api.getSystemStats().then((r) => alive && r && setStats(r));
      api.getSimulationStatus().then((r) => alive && r && setSimRunning(r.running));
    };
    load();
    const id = setInterval(load, 10_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  // Derive overall system health
  const systemHealth = health ? "healthy" : "unknown";
  const hasAlerts = eventStats && (eventStats.idsAlerts > 0 || eventStats.avDetections > 0);

  return (
    <Shell title="Dashboard">
      {/* ── Health summary row ──────────────────────────────── */}
      <div className="mb-5 flex flex-wrap items-center gap-4">
        {health ? (
          <StatusIndicator
            status={hasAlerts ? "degraded" : systemHealth as any}
            label={health.hostname ?? "containd"}
            sublabel={hasAlerts ? "Alerts require attention" : "All systems operational"}
          />
        ) : (
          <Skeleton className="h-5 w-48" />
        )}
        {health && (
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span>Build {health.build ?? "dev"}</span>
            <span>&middot;</span>
            <span>{health.time ? new Date(health.time).toLocaleString() : ""}</span>
          </div>
        )}
      </div>

      {/* ── Needs attention ────────────────────────────────── */}
      {hasAlerts && (
        <div className="mb-5 rounded-xl border border-amber-500/20 bg-amber-500/[0.06] p-4 animate-fade-in">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-amber-400">Needs Attention</h2>
          <div className="flex flex-wrap gap-3">
            {eventStats!.idsAlerts > 0 && (
              <Link href="/alerts/" className="flex items-center gap-2 rounded-lg bg-amber-500/10 px-3 py-2 text-sm text-amber-300 transition-ui hover:bg-amber-500/15">
                <StatusBadge variant="warning" dot>{eventStats!.idsAlerts} IDS alerts</StatusBadge>
              </Link>
            )}
            {eventStats!.avDetections > 0 && (
              <Link href="/events/?av=1" className="flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-300 transition-ui hover:bg-red-500/15">
                <StatusBadge variant="error" dot>{eventStats!.avDetections} AV detections</StatusBadge>
              </Link>
            )}
          </div>
        </div>
      )}

      {/* ── Stats row ──────────────────────────────────────── */}
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-5">
        <StatCard label="Zones" value={zoneCount} href="/zones/" />
        <StatCard label="Interfaces" value={ifaceCount} href="/interfaces/" />
        <StatCard label="FW Rules" value={ruleCount} href="/firewall/" />
        <StatCard label="ICS Rules" value={icsRuleCount} href="/ics/" />
        <StatCard label="Assets" value={assetCount} href="/assets/" />
      </div>

      {/* ── Main grid ──────────────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* Services */}
        <Card title="Services">
          {servicesStatus ? <ServicesWidget status={servicesStatus} /> : <Skeleton className="h-32 w-full" />}
        </Card>

        {/* Traffic */}
        <Card title="Traffic">
          {eventStats ? (
            <div className="space-y-3">
              <TrafficMeter label="Total events" value={eventStats.totalEvents} color="var(--primary)" />
              <TrafficMeter label="IDS alerts" value={eventStats.idsAlerts} color="var(--warning)" />
              <TrafficMeter label="AV detections" value={eventStats.avDetections} color="var(--error)" />
              {eventStats.modbusWrites > 0 && (
                <TrafficMeter label="Modbus writes" value={eventStats.modbusWrites} color="var(--orange)" />
              )}
            </div>
          ) : (
            <Skeleton className="h-32 w-full" />
          )}
        </Card>

        {/* System info */}
        <Card title="System">
          {health ? (
            <div className="space-y-2 text-sm">
              <KV label="User" value={me?.username ?? "—"} />
              <KV label="Role" value={me?.role ?? "—"} />
              <KV
                label="Last change"
                value={
                  lastAdminChange
                    ? `${new Date(lastAdminChange.timestamp).toLocaleString()}`
                    : "—"
                }
              />
              {lastAdminChange && (
                <div className="text-xs text-slate-500 pl-0">{lastAdminChange.action}</div>
              )}
            </div>
          ) : (
            <Skeleton className="h-32 w-full" />
          )}
        </Card>
      </div>

      {/* ── Quick start ────────────────────────────────────── */}
      <div className="mt-5">
        <Card title="Quick Start">
          <div className="grid gap-2 sm:grid-cols-3">
            <QuickStartRow
              href="/interfaces/"
              icon="/icons/docker.svg"
              title="Interfaces"
              desc="Assign ports and zones"
            />
            <TrafficCounter
              label="IDS Alerts"
              value={eventStats?.idsAlerts ?? 0}
              color="text-red-400"
            />
            <QuickStartRow
              href="/system/services/"
              icon="/icons/nginx.svg"
              title="Services"
              desc="Enable DNS, VPN, Proxy"
            />
          </div>
        </Card>
      </div>

      {/* ── Console (collapsible) ──────────────────────────── */}
      <div className="mt-5">
        <button
          type="button"
          onClick={() => setConsoleOpen((v) => !v)}
          className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-slate-500 transition-ui hover:text-slate-300"
        >
          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2}>
            <polyline points="4,17 10,11 4,5" /><line x1="12" y1="19" x2="20" y2="19" />
          </svg>
          CLI Console
          <svg viewBox="0 0 24 24" className={`h-3 w-3 transition-transform duration-200 ${consoleOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" strokeWidth={2}>
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

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200">{value}</span>
    </div>
  );
}

function StatCard({ label, value, href }: { label: string; value: number | null; href: string }) {
  return (
    <Link
      href={href}
      className="rounded-xl border border-white/[0.08] bg-white/[0.03] p-3 shadow-card transition-ui hover:bg-white/[0.06] hover:border-white/[0.12]"
    >
      <div className="text-2xl font-semibold tabular-nums text-white">{value ?? "—"}</div>
      <div className="mt-0.5 text-xs text-slate-500">{label}</div>
    </Link>
  );
}

function ServicesWidget({ status }: { status: Record<string, unknown> | null }) {
  const syslogConfigured = (status?.["syslog"] as any)?.configured_forwarders > 0;
  const proxy = status?.["proxy"] as any;
  const envoyActive = proxy?.forward_enabled && proxy?.envoy_running;
  const nginxActive = proxy?.reverse_enabled && proxy?.nginx_running;
  const avEnabled = (status?.["av"] as any)?.enabled;
  const vpnActive = (status?.["vpn"] as any)?.wireguard_enabled || (status?.["vpn"] as any)?.openvpn_running;

  const chips: Array<{ label: string; ok: boolean; icon?: string; href: string }> = [
    { label: "IPS", ok: true, href: "/ids/" },
    { label: "AV", ok: !!avEnabled, href: "/system/services/av/" },
    { label: "VPN", ok: !!vpnActive, icon: "/icons/wireguard.svg", href: "/vpn/" },
    { label: "Proxy", ok: envoyActive || nginxActive, icon: "/icons/envoyproxy.svg", href: "/proxies/" },
    { label: "Syslog", ok: !!syslogConfigured, href: "/system/services/syslog/" },
  ];

  return (
    <div className="grid grid-cols-3 gap-2 text-xs">
      {chips.map((c) => (
        <Link
          key={c.label}
          href={c.href}
          className={`flex min-h-[52px] flex-col items-center justify-center rounded-lg px-2 py-2 text-center transition-ui ${
            c.ok
              ? "bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/15"
              : "bg-white/[0.04] text-slate-500 hover:bg-white/[0.06]"
          }`}
        >
          {c.icon && (
            <Image src={c.icon} alt="" width={14} height={14} className="mx-auto mb-1 h-3.5 w-3.5 opacity-60" />
          )}
          <span className="font-medium">{c.label}</span>
          <span className={`mt-0.5 text-2xs ${c.ok ? "text-emerald-500" : "text-slate-600"}`}>
            {c.ok ? "Active" : "Off"}
          </span>
        </Link>
      ))}
    </div>
  );
}

function QuickStartRow({ href, icon, title, desc }: { href: string; icon: string; title: string; desc: string }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2.5 transition-ui hover:bg-white/[0.05] hover:border-white/[0.1]"
    >
      <Image src={icon} alt="" width={16} height={16} className="h-4 w-4 opacity-50" />
      <div>
        <div className="text-sm font-medium text-slate-200">{title}</div>
        <div className="text-xs text-slate-500">{desc}</div>
      </div>
    </Link>
  );
}

function TrafficMeter({ label, value, color }: { label: string; value: number; color: string }) {
  const width = Math.min(100, Math.max(4, Math.round((value / 200) * 100)));
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-500">{label}</span>
        <span className="tabular-nums text-slate-300">{value}</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-white/[0.06]">
        <div className="h-1.5 rounded-full transition-all duration-500" style={{ width: `${width}%`, background: color }} />
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
