 "use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import Link from "next/link";

import { fetchHealth, type AuditRecord, type HealthResponse, type User, api } from "../lib/api";
import { Shell } from "../components/Shell";
import { Console } from "../components/Console";
import { Skeleton } from "../components/Skeleton";

export default function Home() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [me, setMe] = useState<User | null>(null);
  const [lastAdminChange, setLastAdminChange] = useState<AuditRecord | null>(null);
  const [assetCount, setAssetCount] = useState<number | null>(null);
  const [zoneCount, setZoneCount] = useState<number | null>(null);
  const [ifaceCount, setIfaceCount] = useState<number | null>(null);
  const [ruleCount, setRuleCount] = useState<number | null>(null);
  const [eventStats, setEventStats] = useState<{
    idsAlerts: number;
    modbusWrites: number;
    avDetections: number;
    avBlocks: number;
    totalEvents: number;
  } | null>(null);
  const [servicesStatus, setServicesStatus] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    let alive = true;
    fetchHealth().then((res) => alive && setHealth(res));
    Promise.all([
      api.listAssets(),
      api.listZones(),
      api.listInterfaces(),
      api.listFirewallRules(),
      api.listEvents(500),
      api.getServicesStatus(),
      api.me(),
      api.listAudit(),
    ]).then(([assets, zones, ifaces, rules, events, services, meUser, audit]) => {
      if (!alive) return;
      setAssetCount(assets?.length ?? 0);
      setZoneCount(zones?.length ?? 0);
      setIfaceCount(ifaces?.length ?? 0);
      setRuleCount(rules?.length ?? 0);
      setMe(meUser ?? null);
      const evs = events ?? [];
      const idsAlerts = evs.filter((e) => e.proto === "ids" && e.kind === "alert").length;
      const avDetections = evs.filter((e) => e.kind === "service.av.detected").length;
      const avBlocks = evs.filter((e) => e.kind === "service.av.block_flow").length;
      const modbusWrites = evs.filter(
        (e) =>
          e.proto === "modbus" &&
          e.kind === "request" &&
          (e.attributes as any)?.is_write === true,
      ).length;
      setEventStats({ idsAlerts, modbusWrites, avDetections, avBlocks, totalEvents: evs.length });
      setServicesStatus(services);
      const lastChange = (audit ?? []).find((rec) => rec.actor && rec.actor !== "system") ?? null;
      setLastAdminChange(lastChange);
    });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <Shell title="Dashboard">
      <div className="grid gap-4 md:grid-cols-3">
        <DashboardCard title="System information">
          {health ? (
            <div className="space-y-1 text-sm">
              <KeyValue label="Hostname" value="containd" />
              <KeyValue label="Build" value={health?.build ?? "dev"} />
              <KeyValue label="Component" value={health?.component ?? "mgmt"} />
              <KeyValue
                label="Updated"
                value={
                  health?.time
                    ? new Date(health.time).toLocaleString()
                    : "—"
                }
              />
              <KeyValue label="User" value={me?.username ?? "—"} />
              <KeyValue label="Role" value={me?.role ?? "—"} />
              <KeyValue
                label="Last admin change"
                value={
                  lastAdminChange
                    ? `${new Date(lastAdminChange.timestamp).toLocaleString()} · ${lastAdminChange.action}`
                    : "—"
                }
              />
            </div>
          ) : (
            <Skeleton className="h-20 w-full" />
          )}
        </DashboardCard>

        <DashboardCard title="Services">
          {servicesStatus ? <ServicesWidget status={servicesStatus} /> : <Skeleton className="h-20 w-full" />}
        </DashboardCard>

        <DashboardCard title="Traffic Mix">
          {eventStats ? (
            <div className="space-y-2 text-xs text-slate-300">
              <TrafficMeter label="Total events" value={eventStats.totalEvents} color="var(--primary)" />
              <TrafficMeter label="IDS alerts" value={eventStats.idsAlerts} color="var(--warning)" />
              <TrafficMeter label="AV detections" value={eventStats.avDetections} color="var(--error)" />
            </div>
          ) : (
            <Skeleton className="h-20 w-full" />
          )}
        </DashboardCard>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <DashboardCard title="Quick Start">
          <div className="grid gap-2 text-xs text-slate-300">
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
              desc="Enable DNS/VPN/Proxy"
            />
          </div>
        </DashboardCard>
        <DashboardCard title="Policy summary">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Stat label="Zones" value={zoneCount} href="/zones/" />
            <Stat label="Interfaces" value={ifaceCount} href="/interfaces/" />
            <Stat label="FW rules" value={ruleCount} href="/firewall/" />
            <Stat label="ICS rules" value={0} href="/firewall/" />
          </div>
        </DashboardCard>
      </div>

      <div className="mt-6">
        <Console />
      </div>
    </Shell>
  );
}

function DashboardCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-300">
        {title}
      </p>
      <div className="mt-3">{children}</div>
    </div>
  );
}

function KeyValue({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-300">{label}</span>
      <span className="text-slate-100">{value}</span>
    </div>
  );
}

function Stat({
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
      className="rounded-lg border border-white/10 bg-black/30 p-3 hover:bg-black/40"
    >
      <div className="text-2xl font-bold text-white">{value ?? "—"}</div>
      <div className="text-xs uppercase tracking-wide text-slate-300">
        {label}
      </div>
    </Link>
  );
}

function ServicesWidget({ status }: { status: Record<string, unknown> | null }) {
  const syslogConfigured =
    (status?.["syslog"] as any)?.configured_forwarders > 0;
  const proxy = status?.["proxy"] as any;
  const envoyActive = proxy?.forward_enabled && proxy?.envoy_running;
  const nginxActive = proxy?.reverse_enabled && proxy?.nginx_running;
  const envoyRate =
    typeof (status?.["envoy"] as any)?.rate_per_min === "number"
      ? (status?.["envoy"] as any).rate_per_min
      : null;
  const nginxRate =
    typeof (status?.["nginx"] as any)?.rate_per_min === "number"
      ? (status?.["nginx"] as any).rate_per_min
      : null;
  const avEnabled = (status?.["av"] as any)?.enabled;
  const chips: Array<{ label: string; ok: boolean; hint?: string; icon?: string }> = [
    { label: "IPS", ok: true, hint: "native IDS/IPS" },
    { label: "Web Filter", ok: false },
    { label: "AV", ok: !!avEnabled },
    { label: "VPN", ok: (status?.["vpn"] as any)?.wireguard_enabled || (status?.["vpn"] as any)?.openvpn_running, icon: "/icons/wireguard.svg" },
    { label: "Updates", ok: true },
    { label: "Proxy", ok: envoyActive || nginxActive, icon: "/icons/envoyproxy.svg" },
    { label: "Syslog", ok: !!syslogConfigured },
  ];
  return (
    <div>
      <div className="grid grid-cols-3 gap-2 text-xs">
        {chips.map((c) => (
          <div
            key={c.label}
            className={
              c.ok
                ? "flex min-h-[64px] flex-col items-center justify-center rounded-lg bg-mint/15 px-2 py-2 text-center text-mint"
                : "flex min-h-[64px] flex-col items-center justify-center rounded-lg bg-amber/15 px-2 py-2 text-center text-amber"
            }
            title={c.hint}
          >
            {c.icon && (
              <Image src={c.icon} alt="" width={16} height={16} className="mx-auto mb-1 h-4 w-4" />
            )}
            {c.label}
          </div>
        ))}
      </div>
      <p className="mt-2 text-xs text-slate-400">
        Green = configured/active, red = off/unconfigured.
      </p>
      {(envoyRate !== null || nginxRate !== null) && (
        <p className="mt-2 text-xs text-slate-400">
          Proxy rates: Envoy {envoyRate !== null ? envoyRate.toFixed(1) : "0.0"} /min, Nginx{" "}
          {nginxRate !== null ? nginxRate.toFixed(1) : "0.0"} /min.
        </p>
      )}
    </div>
  );
}

function QuickStartRow({
  href,
  icon,
  title,
  desc,
}: {
  href: string;
  icon: string;
  title: string;
  desc: string;
}) {
  return (
    <Link
      href={href}
      className="flex items-center gap-3 rounded-lg border border-white/10 bg-black/30 px-3 py-2 hover:bg-black/40"
    >
      <Image src={icon} alt="" width={16} height={16} className="h-4 w-4" />
      <div>
        <div className="text-xs uppercase tracking-wide text-slate-300">{title}</div>
        <div className="text-xs text-slate-400">{desc}</div>
      </div>
    </Link>
  );
}

function TrafficMeter({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  const width = Math.min(100, Math.max(6, Math.round((value / 200) * 100)));
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="uppercase text-slate-400">{label}</span>
        <span>{value}</span>
      </div>
      <div className="h-2 w-full rounded-full bg-white/5">
        <div className="h-2 rounded-full" style={{ width: `${width}%`, background: color }} />
      </div>
    </div>
  );
}
