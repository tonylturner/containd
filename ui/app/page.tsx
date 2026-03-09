"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import Link from "next/link";

import { type AuditRecord, type DashboardData, type HealthResponse, type User, api } from "../lib/api";
import { Shell } from "../components/Shell";
import { Console } from "../components/Console";
import { Skeleton } from "../components/Skeleton";
import { Card } from "../components/Card";
import { StatusBadge, StatusIndicator } from "../components/StatusBadge";

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [consoleOpen, setConsoleOpen] = useState(false);

  const health = data?.health ?? null;
  const me = data?.user ?? null;
  const lastAdminChange = data?.lastActivity ?? null;
  const assetCount = data?.counts?.assets ?? null;
  const zoneCount = data?.counts?.zones ?? null;
  const ifaceCount = data?.counts?.interfaces ?? null;
  const ruleCount = data?.counts?.rules ?? null;
  const icsRuleCount = data?.counts?.icsRules ?? null;
  const eventStats = data ? {
    idsAlerts: data.eventStats.idsAlerts,
    modbusWrites: data.eventStats.modbusWrites,
    avDetections: data.eventStats.avDetections,
    avBlocks: data.eventStats.avBlocks,
    totalEvents: data.eventStats.total,
  } : null;
  const servicesStatus = data?.services ?? null;

  useEffect(() => {
    let alive = true;
    api.getDashboard().then((res) => {
      if (alive && res) setData(res);
    });
    return () => { alive = false; };
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
            <QuickStartRow
              href="/firewall/"
              icon="/icons/firewall.svg"
              title="Policies"
              desc="Add allow/deny rules"
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
