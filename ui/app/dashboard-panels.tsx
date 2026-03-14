"use client";

import Link from "next/link";

import type {
  DashboardData,
  SystemStats,
  TelemetryEvent,
} from "../lib/api";

import { Skeleton } from "../components/Skeleton";

export type ServiceInfo = {
  name: string;
  active: boolean;
  detail: string;
  href: string;
  sparkline?: number[];
  errorRate?: number;
};

export function SetupChecklist({
  counts,
  configDirty,
  isAdmin,
}: {
  counts: DashboardData["counts"] | null | undefined;
  configDirty: boolean | null;
  isAdmin: boolean;
}) {
  const steps = [
    {
      title: "Create zones",
      detail: counts && counts.zones > 0 ? `${counts.zones} configured` : "Start with WAN, DMZ, and LAN/OT zones.",
      complete: !!counts && counts.zones > 0,
      href: "/zones/",
      cta: (counts?.zones ?? 0) > 0 ? "Review zones" : "Create zones",
    },
    {
      title: "Bind interfaces",
      detail: counts && counts.interfaces > 0 ? `${counts.interfaces} configured` : "Assign zones to interfaces so policy can attach to ports.",
      complete: !!counts && counts.interfaces > 0,
      href: "/interfaces/",
      cta: (counts?.interfaces ?? 0) > 0 ? "Review interfaces" : "Bind interfaces",
    },
    {
      title: "Create policy",
      detail: counts && (counts.rules + counts.icsRules) > 0
        ? `${counts.rules + counts.icsRules} rules ready`
        : "Use the wizard for a first pass, then tighten with explicit rules.",
      complete: !!counts && (counts.rules + counts.icsRules) > 0,
      href: (counts?.rules ?? 0) + (counts?.icsRules ?? 0) > 0 ? "/firewall/" : "/wizard/",
      cta: (counts?.rules ?? 0) + (counts?.icsRules ?? 0) > 0 ? "Review policy" : "Open wizard",
    },
    {
      title: "Commit runtime changes",
      detail: configDirty === null
        ? "Checking running and candidate config state."
        : configDirty
          ? "Candidate config differs from running. Review and commit to apply."
          : "No pending candidate changes.",
      complete: configDirty === false,
      href: "/config/?tab=diff",
      cta: configDirty ? (isAdmin ? "Review & commit" : "Review diff") : "Open config",
    },
  ];

  return (
    <div className="mb-5 rounded-xl border border-white/[0.08] bg-white/[0.03] p-4 shadow-card">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            First-Run Checklist
          </h3>
          <p className="mt-1 text-sm text-slate-500">
            Use Dashboard for setup and config state. Use Monitoring for live telemetry.
          </p>
        </div>
        <Link
          href="/monitoring/"
          className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300 transition-ui hover:bg-white/[0.08] hover:text-white"
        >
          Open Monitoring
        </Link>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {steps.map((step) => (
          <div
            key={step.title}
            className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3"
          >
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="text-sm font-semibold text-slate-100">{step.title}</span>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider ${
                  step.complete
                    ? "bg-emerald-500/15 text-emerald-400"
                    : "bg-amber-500/15 text-amber-400"
                }`}
              >
                {step.complete ? "Ready" : "Action"}
              </span>
            </div>
            <p className="mb-3 text-xs text-slate-500">{step.detail}</p>
            <Link
              href={step.href}
              className="text-xs font-semibold text-amber-300 transition-colors hover:text-amber-200"
            >
              {step.cta} →
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ServiceGrid({ services }: { services: ServiceInfo[] }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {services.map((service) => (
        <Link
          key={service.name}
          href={service.href}
          className={`block rounded-lg border p-3 transition-colors hover:border-white/[0.12] ${
            service.active
              ? "border-emerald-500/20 bg-emerald-500/[0.04] hover:bg-emerald-500/[0.07]"
              : "border-white/[0.06] bg-white/[0.02] opacity-50 hover:opacity-70"
          }`}
        >
          <div
            className={`text-xs font-bold tracking-wider uppercase ${
              service.active ? "text-emerald-400" : "text-slate-500"
            }`}
          >
            {service.name}
          </div>
          <div className="text-2xs text-slate-500 mt-0.5 truncate">
            {service.detail}
          </div>
          {service.sparkline && service.sparkline.length > 0 && (
            <div className="flex items-end gap-0.5 h-5 mt-2">
              {service.sparkline.map((value, index) => {
                const max = Math.max(...service.sparkline!, 1);
                const height = Math.max(2, Math.round((value / max) * 20));
                return (
                  <div
                    key={index}
                    className="flex-1 rounded-t-sm transition-all duration-300"
                    style={{
                      height: `${height}px`,
                      background: service.active
                        ? `rgba(34,197,94,${0.3 + (value / max) * 0.5})`
                        : "rgba(55,65,81,0.4)",
                    }}
                  />
                );
              })}
            </div>
          )}
          {service.errorRate !== undefined && service.errorRate > 0 && (
            <div className="text-2xs text-red-400/70 mt-1 font-mono">
              {service.errorRate.toFixed(1)} err/min
            </div>
          )}
        </Link>
      ))}
    </div>
  );
}

export function TrafficCounter({
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

export function EventStream({ events }: { events: TelemetryEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="text-xs text-slate-500 text-center py-6">
        No events yet
      </div>
    );
  }

  return (
    <div className="max-h-[180px] overflow-y-auto space-y-0.5 font-mono text-2xs">
      {events.slice(0, 20).map((event) => {
        const level = eventLevel(event);
        const time = event.timestamp
          ? new Date(event.timestamp).toLocaleTimeString("en-US", {
              hour12: false,
            })
          : "--:--:--";

        return (
          <div
            key={event.id}
            className="grid grid-cols-[70px_50px_100px_1fr_auto] gap-3 items-center px-2 py-1 rounded hover:bg-white/[0.02] transition-colors"
          >
            <span className="text-slate-500">{time}</span>
            <span
              className={`text-center px-1 py-0.5 rounded text-[9px] tracking-wider uppercase ${levelClass(level)}`}
            >
              {level}
            </span>
            <span className="text-slate-500 truncate">
              {event.proto || event.kind}
            </span>
            <span className="text-slate-300 truncate">{eventMessage(event)}</span>
            <span className="text-slate-600 text-right">{event.srcIp ?? ""}</span>
          </div>
        );
      })}
    </div>
  );
}

function eventLevel(event: TelemetryEvent): string {
  if (event.kind === "block" || event.kind === "av_block") return "block";
  if (event.kind === "alert" || event.kind === "ids_alert") return "warn";
  if (event.kind === "av_detect") return "warn";
  return "info";
}

function eventMessage(event: TelemetryEvent): string {
  if (event.attributes) {
    const message =
      (event.attributes.message as string) ||
      (event.attributes.description as string) ||
      (event.attributes.detail as string);
    if (message) return message;
  }
  const parts = [event.kind];
  if (event.proto) parts.push(event.proto);
  if (event.dstIp) parts.push(`-> ${event.dstIp}:${event.dstPort ?? ""}`);
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

export function SystemHealthPanel({
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

  if (data) {
    const totalRules = data.counts.rules + data.counts.icsRules;
    items.push({
      name: "Rule Eval",
      value: `${totalRules} rules`,
      pct: Math.min(100, totalRules * 2),
      color: totalRules > 40 ? "#f59e0b" : "#22c55e",
    });
  }

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
    items.push({
      name: "Go Heap",
      value: `${stats.runtime.heapAllocMB.toFixed(0)} MB`,
      pct: Math.min(100, (stats.runtime.heapAllocMB / stats.runtime.heapSysMB) * 100),
      color: "#06b6d4",
    });
  }

  return (
    <div className="space-y-3">
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

function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}
