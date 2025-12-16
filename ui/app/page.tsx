 "use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { fetchHealth, type HealthResponse, api } from "../lib/api";
import { Shell } from "../components/Shell";
import { Console } from "../components/Console";
import { Skeleton } from "../components/Skeleton";
import { KPI } from "../components/KPI";

export default function Home() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [assetCount, setAssetCount] = useState<number | null>(null);
  const [zoneCount, setZoneCount] = useState<number | null>(null);
  const [ifaceCount, setIfaceCount] = useState<number | null>(null);
  const [ruleCount, setRuleCount] = useState<number | null>(null);
  const [flowCount, setFlowCount] = useState<number | null>(null);
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
      api.listFlows(200),
      api.listEvents(500),
      api.getServicesStatus(),
    ]).then(([assets, zones, ifaces, rules, flows, events, services]) => {
      if (!alive) return;
      setAssetCount(assets?.length ?? 0);
      setZoneCount(zones?.length ?? 0);
      setIfaceCount(ifaces?.length ?? 0);
      setRuleCount(rules?.length ?? 0);
      setFlowCount(flows?.length ?? 0);
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
            </div>
          ) : (
            <Skeleton className="h-20 w-full" />
          )}
        </DashboardCard>

        <DashboardCard title="Services">
          {servicesStatus ? <ServicesWidget status={servicesStatus} /> : <Skeleton className="h-20 w-full" />}
        </DashboardCard>

        <DashboardCard title="Traffic">
          {eventStats ? (
            <TrafficWidget flowCount={flowCount} totalEvents={eventStats?.totalEvents ?? 0} />
          ) : (
            <Skeleton className="h-20 w-full" />
          )}
        </DashboardCard>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-4">
        <KPI label="Flows" value={flowCount ?? "—"} hint="Active flows" />
        <KPI label="Events" value={eventStats?.totalEvents ?? "—"} hint="Recent telemetry" accent="primary" />
        <KPI label="AV detections" value={eventStats?.avDetections ?? 0} accent="error" />
        <KPI label="IDS alerts" value={eventStats?.idsAlerts ?? 0} accent="warning" />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <DashboardCard title="Policy summary">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Stat label="Zones" value={zoneCount} href="/zones/" />
            <Stat label="Interfaces" value={ifaceCount} href="/interfaces/" />
            <Stat label="FW rules" value={ruleCount} href="/firewall/" />
            <Stat label="ICS rules" value={0} href="/firewall/" />
          </div>
        </DashboardCard>

        <DashboardCard title="Rule Violations">
          <ViolationsWidget stats={eventStats} />
        </DashboardCard>

        <DashboardCard title="Operations">
          <div className="flex flex-col gap-2 text-sm">
            <Link
              href="/config/"
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 hover:bg-white/10"
            >
              Candidate / Commit
            </Link>
            <Link
              href="/dataplane/"
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 hover:bg-white/10"
            >
              Dataplane settings
            </Link>
            <Link
              href="/audit/"
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 hover:bg-white/10"
            >
              Audit log
            </Link>
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
  const avEnabled = (status?.["av"] as any)?.enabled;
  const chips: Array<{ label: string; ok: boolean; hint?: string }> = [
    { label: "IPS", ok: true, hint: "native IDS/IPS" },
    { label: "Web Filter", ok: false },
    { label: "AV", ok: !!avEnabled },
    { label: "VPN", ok: (status?.["vpn"] as any)?.wireguard_enabled || (status?.["vpn"] as any)?.openvpn_running },
    { label: "Updates", ok: true },
    { label: "Proxy", ok: envoyActive || nginxActive },
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
                ? "rounded-lg bg-mint/15 px-2 py-2 text-center text-mint"
                : "rounded-lg bg-amber/15 px-2 py-2 text-center text-amber"
            }
            title={c.hint}
          >
            {c.label}
          </div>
        ))}
      </div>
      <p className="mt-2 text-xs text-slate-400">
        Green = configured/active, red = off/unconfigured.
      </p>
    </div>
  );
}

function TrafficWidget({
  flowCount,
  totalEvents,
}: {
  flowCount: number | null;
  totalEvents: number;
}) {
  return (
    <div className="flex items-center justify-between rounded-xl bg-black/30 p-4">
      <div>
        <div className="text-xs uppercase tracking-wide text-slate-300">
          Active flows
        </div>
        <div className="text-4xl font-bold text-white">
          {flowCount ?? "—"}
        </div>
      </div>
      <div className="text-right">
        <div className="text-xs uppercase tracking-wide text-slate-300">
          Recent events
        </div>
        <div className="text-2xl font-semibold text-slate-100">
          {totalEvents}
        </div>
        <Link
          href="/monitoring/"
          className="mt-1 block text-xs text-slate-300 hover:text-white"
        >
          Monitoring →
        </Link>
      </div>
    </div>
  );
}

function ViolationsWidget({
  stats,
}: {
  stats: { idsAlerts: number; modbusWrites: number; avDetections: number; avBlocks: number; totalEvents: number } | null;
}) {
  const idsAlerts = stats?.idsAlerts ?? 0;
  const modbusWrites = stats?.modbusWrites ?? 0;
  const avDetections = stats?.avDetections ?? 0;
  const avBlocks = stats?.avBlocks ?? 0;
  return (
    <div className="grid grid-cols-2 gap-3 text-sm">
      <div className="rounded-xl bg-black/30 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-300">
          IDS alerts
        </div>
        <div className="text-3xl font-bold text-amber">{idsAlerts}</div>
        <Link href="/alerts/" className="text-xs text-slate-300 hover:text-white">
          View →
        </Link>
      </div>
      <div className="rounded-xl bg-black/30 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-300">
          Modbus writes
        </div>
        <div className="text-3xl font-bold text-white">{modbusWrites}</div>
        <Link href="/events/" className="text-xs text-slate-300 hover:text-white">
          Events →
        </Link>
      </div>
      <div className="rounded-xl bg-black/30 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-300">
          AV detections
        </div>
        <div className="text-3xl font-bold text-red">{avDetections}</div>
        <Link href="/events/?filter=service&av=1" className="text-xs text-blue-300 hover:text-blue-200">
          Events →
        </Link>
      </div>
      <div className="rounded-xl bg-black/30 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-300">
          AV blocks
        </div>
        <div className="text-3xl font-bold text-red">{avBlocks}</div>
        <Link href="/flows/?av=1" className="text-xs text-blue-300 hover:text-blue-200">
          Flows →
        </Link>
      </div>
    </div>
  );
}
