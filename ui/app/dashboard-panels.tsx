"use client";

import Link from "next/link";
import { useState } from "react";

import type {
  DashboardData,
  Interface,
  InterfaceState,
  SystemStats,
  TelemetryEvent,
} from "../lib/api";

import { Skeleton } from "../components/Skeleton";
import { formatEndpoint } from "../lib/endpoint";
import { formatBytes } from "../lib/utils";
import { runtimeFor } from "../lib/interface-addresses";

export type InterfaceBindings = {
  configured: Interface[];
  runtime: InterfaceState[];
};

export type ServiceInfo = {
  name: string;
  active: boolean | null;
  detail: string;
  href: string;
  sparkline?: number[];
  errorRate?: number;
};

export function SetupChecklist({
  counts,
  interfaceBindings,
  configDirty,
  isAdmin,
}: {
  counts: DashboardData["counts"] | null | undefined;
  interfaceBindings: InterfaceBindings | null;
  configDirty: boolean | null;
  isAdmin: boolean;
}) {
  const interfaceCount = interfaceBindings?.configured.length ?? 0;
  const missingBindings = interfaceBindings?.configured.filter((iface) => !runtimeFor(iface, interfaceBindings.runtime)).length ?? 0;
  const steps = [
    {
      title: "Create zones",
      detail: counts && counts.zones > 0 ? `${counts.zones} configured` : "Start with WAN, DMZ, and LAN/OT zones.",
      complete: counts ? counts.zones > 0 : null,
      href: "/zones/",
      cta: (counts?.zones ?? 0) > 0 ? "Review zones" : "Create zones",
    },
    {
      title: "Bind interfaces",
      detail: interfaceBindings === null
        ? "Interface bindings unknown. Check configured interfaces and live devices."
        : interfaceCount === 0
          ? "Assign zones to interfaces so policy can attach to ports."
          : missingBindings > 0
            ? `${missingBindings} of ${interfaceCount} configured interfaces not connected to network devices.`
            : `${interfaceCount} of ${interfaceCount} bound to network devices.`,
      complete: interfaceBindings === null ? null : interfaceCount > 0 && missingBindings === 0,
      href: "/interfaces/",
      cta: (counts?.interfaces ?? 0) > 0 ? "Review interfaces" : "Bind interfaces",
    },
    {
      title: "Create policy",
      detail: counts && (counts.rules + counts.icsRules) > 0
        ? `${counts.rules + counts.icsRules} rules ready`
        : "Use the wizard for a first pass, then tighten with explicit rules.",
      complete: counts ? (counts.rules + counts.icsRules) > 0 : null,
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
      complete: configDirty === null ? null : configDirty === false,
      href: "/config/?tab=diff",
      cta: configDirty ? (isAdmin ? "Review & commit" : "Review diff") : "Open config",
    },
  ];

  const complete = steps.every(step => step.complete === true);
  const [disclosure, setDisclosure] = useState<{ complete: boolean; open: boolean } | null>(null);
  const open = disclosure?.complete === complete ? disclosure.open : !complete;
  const next = steps.find(step => step.complete !== true);

  return (
    <div className="mb-5 rounded-xl border border-white/8 bg-white/3 p-4 shadow-card">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold text-slate-400">
            <button type="button" aria-expanded={open} aria-controls="setup-checklist"
              onClick={() => setDisclosure({ complete, open: !open })}>
              First-Run Checklist {complete ? "— complete" : "— setup needs attention"}
            </button>
          </h3>
          {next && <p className="mt-2 text-sm text-(--text)">Next: <Link href={next.href} className="underline">{next.title}</Link> — {next.detail}</p>}
          <p className="mt-1 text-sm text-slate-500">
            Use Dashboard for setup and config state. Use Monitoring for live telemetry.
          </p>
        </div>
        <Link
          href="/monitoring/"
          className="rounded-lg border border-white/8 bg-white/4 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-ui hover:bg-white/8 hover:text-white"
        >
          Open Monitoring
        </Link>
      </div>
      <div id="setup-checklist" hidden={!open} className={open ? "grid gap-3 md:grid-cols-2 xl:grid-cols-4" : "hidden"}>
        {steps.map((step) => (
          <div
            key={step.title}
            className="rounded-lg border border-white/6 bg-white/2 p-3"
          >
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="text-sm font-semibold text-slate-100">{step.title}</span>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider ${
                  step.complete
                    ? "bg-emerald-500/15 text-emerald-400"
                    : ""
                }`}
              >
                {step.complete === null ? "Unknown" : step.complete ? "Ready" : "Action"}
              </span>
            </div>
            <p className="mb-3 text-xs text-slate-500">{step.detail}</p>
            <Link
              href={step.href}
              className="text-xs font-semibold transition-colors"
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
          className={`block rounded-lg border p-3 transition-colors hover:border-white/12 ${
            service.active === null
              ? "border-slate-500/30 bg-white/2 hover:bg-white/4"
              : service.active
                ? "border-emerald-500/20 bg-emerald-500/4 hover:bg-emerald-500/[0.07]"
                : "border-white/6 bg-white/2 opacity-50 hover:opacity-70"
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
                    className="flex-1 rounded-t-xs transition-all duration-300"
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
  value: number | null;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-white/6 bg-white/2 p-2.5">
      <div className={`text-lg font-bold tabular-nums leading-none ${color}`}>
        {value !== null && Number.isFinite(value) ? value.toLocaleString() : "Unknown"}
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
    <div className="max-h-[180px] overflow-auto space-y-0.5 font-mono text-2xs">
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
            className="grid min-w-[480px] grid-cols-[70px_50px_100px_1fr_auto] gap-3 items-center px-2 py-1 rounded-sm hover:bg-white/2 transition-colors"
          >
            <span className="text-slate-500">{time}</span>
            <span
              className={`text-center px-1 py-0.5 rounded-sm text-[9px] tracking-wider uppercase ${levelClass(level)}`}
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
  if (event.dstIp) parts.push(`-> ${formatEndpoint(event.dstIp, event.dstPort)}`);
  return parts.join(" ");
}

function levelClass(level: string): string {
  switch (level) {
    case "block":
      return "bg-red-500/15 text-red-400";
    case "warn":
      return "";
    case "ok":
      return "bg-emerald-500/15 text-emerald-400";
    default:
      return "";
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
    pct: number | null;
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
      pct: null,
      color: "#94a3b8",
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
      pct: stats.container.memLimitBytes > 0 && Number.isFinite(memPct) ? memPct : null,
      color: memPct > 85 ? "#ef4444" : memPct > 65 ? "#f59e0b" : "#06b6d4",
    });
  } else if (stats) {
    items.push({
      name: "Go Heap",
      value: `${stats.runtime.heapAllocMB.toFixed(0)} MB`,
      pct: stats.runtime.heapSysMB > 0 ? Math.min(100, (stats.runtime.heapAllocMB / stats.runtime.heapSysMB) * 100) : null,
      color: "#06b6d4",
    });
  }

  return (
    <div className="grid gap-3">
      {stats && (
        <div className="flex justify-between text-2xs font-mono text-slate-500">
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
          {item.pct !== null && Number.isFinite(item.pct) && <div className="h-1 w-full rounded-full bg-white/6">
            <div
              className="h-1 rounded-full transition-all duration-700"
              style={{ width: `${Math.min(100, Math.max(0, item.pct))}%`, background: item.color }}
            />
          </div>}
        </div>
      ))}
    </div>
  );
}
