"use client";

import { useAsyncRefresh } from "../../../hooks/useAsyncRefresh";

import Image from "next/image";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { api, type ServicesStatus } from "../../../lib/api";
import { staticAssetURL } from "../../../lib/api-core";
import { ServiceFaultBanner } from "../../../components/ServiceFaultBanner";
import { Shell } from "../../../components/Shell";
import { Card as BaseCard } from "../../../components/Card";
import { Skeleton } from "../../../components/Skeleton";
import { useToast } from "../../../components/ToastProvider";
import { ServiceHistory, TelemetryRate } from "../../../components/TelemetryChart";
import { InfoTip } from "../../../components/InfoTip";
import { Disclosure } from "../../../components/Disclosure";

type MeteredService = "syslog" | "proxy" | "envoy" | "nginx" | "dns" | "ntp" | "dhcp" | "vpn" | "av";

export default function ServicesOverviewPage() {
  const toast = useToast();
  const [status, setStatus] = useState<ServicesStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async () => {
    try {
      const s = await api.getServicesStatus();
      setError(null);
      setStatus(s);
      setLastUpdated(new Date());
      toast("Service status refreshed", "success");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to load services.";
      setError(msg);
      toast("Failed to load services", "error");
    }
  }, [toast]));

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const dnsFaulted = status?.dns?.state === "faulted";
  const dhcpFaulted = status?.dhcp?.state === "faulted";
  const vpnFaulted = status?.wireguard?.state === "faulted" || status?.openvpn?.state === "faulted";
  const dnsRunning = !dnsFaulted && status?.dns?.running;
  const dhcpEnabled = !dhcpFaulted && status?.dhcp?.enabled;
  const vpnActive = !vpnFaulted && (status?.vpn?.wireguard_enabled || status?.vpn?.openvpn_running);
  const av = status?.av;

  return (
    <Shell
      title="Services"
      actions={
        <div className="flex items-center gap-3">
          <button
            onClick={() => refresh()}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-(--text)">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)"
            />
            Auto-refresh
          </label>
        </div>
      }
    >
      <ServiceFaultBanner status={status} loading={loading} repairLinks />
      {!loading && error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"} {autoRefresh ? "(auto)" : ""}
      </p>
      <BaseCard className="mb-4" padding="md">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-(--text)">LAN Services</div>
            <div className="mt-1 text-sm text-(--text)">Core connectivity helpers</div>
          </div>
          <Link href="/monitoring/" className="text-xs text-(--text) hover:text-(--text)">
            View Ops →
          </Link>
        </div>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2 text-sm">
            <span className="text-(--text)">DNS</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${dnsFaulted ? "text-amber" : dnsRunning ? "bg-emerald-400/20 text-emerald-400" : "text-(--text)"}`}>
              {typeof status?.dns?.running !== "boolean" ? "Unknown" : dnsFaulted ? "faulted" : dnsRunning ? "running" : "stopped"}
            </span>
          </div>
          <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2 text-sm">
            <span className="text-(--text)">DHCP</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${dhcpFaulted ? "text-amber" : dhcpEnabled ? "bg-emerald-400/20 text-emerald-400" : "text-(--text)"}`}>
              {typeof status?.dhcp?.enabled !== "boolean" ? "Unknown" : dhcpFaulted ? "faulted" : dhcpEnabled ? "enabled" : "off"}
            </span>
          </div>
          <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2 text-sm">
            <span className="text-(--text)">VPN</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${vpnFaulted ? "text-amber" : vpnActive ? "bg-emerald-400/20 text-emerald-400" : "text-(--text)"}`}>
              {!status?.vpn || typeof status.vpn.wireguard_enabled !== "boolean" || typeof status.vpn.openvpn_running !== "boolean" ? "Unknown" : vpnFaulted ? "faulted" : vpnActive ? "active" : "off"}
            </span>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-xs text-(--text)">
          <Link href="/system/services/dns/" className="rounded-full border bg-(--surface2) px-3 py-1 transition-ui">
            Configure DNS
          </Link>
          <Link href="/dhcp/" className="rounded-full border bg-(--surface2) px-3 py-1 transition-ui">
            Configure DHCP
          </Link>
          <Link href="/vpn/" className="rounded-full border bg-(--surface2) px-3 py-1 transition-ui">
            Configure VPN
          </Link>
        </div>
      </BaseCard>
      <section aria-label="Connectivity" className="mt-6"><h2 className="mb-3 text-lg font-semibold">Connectivity</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <ServiceCard
          title="DNS"
          software="Unbound"
          loading={loading}
          service="dns"
          historyTitle="DNS events per minute"
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>DNS resolver</span>
            <InfoTip label="Embedded resolver with upstream forwarding and caching." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Enabled: {typeof status?.dns?.enabled === "boolean" ? (status.dns.enabled ? "yes" : "no") : "Unknown"}, running:{" "}
            {typeof status?.dns?.running === "boolean" ? (status.dns.running ? "yes" : "no") : "Unknown"}
            <br />
            Upstreams: {status?.dns?.configured_upstreams ?? "Unknown"}{" "}
            {status?.dns?.last_error && `(error=${status?.dns?.last_error})`}

          </p>
          <Link href="/system/services/dns/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
        <ServiceCard
          title="NTP"
          software="chrony"
          loading={loading}
          service="ntp"
          historyTitle="NTP events per minute"
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>Time synchronization</span>
            <InfoTip label="Keeps system time in sync using configured NTP servers." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Enabled: {typeof status?.ntp?.enabled === "boolean" ? (status.ntp.enabled ? "yes" : "no") : "Unknown"}, running:{" "}
            {typeof status?.ntp?.running === "boolean" ? (status.ntp.running ? "yes" : "no") : "Unknown"}
            <br />
            Servers: {status?.ntp?.servers_count ?? "Unknown"}{" "}
            {status?.ntp?.last_error && `(error=${status?.ntp?.last_error})`}

          </p>
          <Link href="/system/services/ntp/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
        <ServiceCard
          title="DHCP"
          loading={loading}
          service="dhcp"
          historyTitle="DHCP events per minute"
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>LAN DHCP server</span>
            <InfoTip label="Assigns IPs to LAN clients and tracks leases." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Enabled: {typeof status?.dhcp?.enabled === "boolean" ? (status.dhcp.enabled ? "yes" : "no") : "Unknown"}{" "}
            {(status?.dhcp?.listen_ifaces ?? 0) > 0 &&
              `(ifaces=${status?.dhcp?.listen_ifaces ?? 0})`}

          </p>
          <Link href="/dhcp/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
      </div></section>
      <section aria-label="Access" className="mt-6"><h2 className="mb-3 text-lg font-semibold">Access</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <ServiceCard
          title="Proxies"
          software="Envoy + Nginx"
          loading={loading}
          service="proxy"
          historyTitle="Proxy events per minute"
        >
          <div className="flex items-center gap-2 text-xs text-(--text)">
            <Image src={staticAssetURL("/icons/envoyproxy.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <Image src={staticAssetURL("/icons/nginx.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <span>Web proxies</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>Outbound and published web apps</span>
            <InfoTip label="Forward proxy for outbound traffic and reverse proxy for published apps." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Forward proxy: {typeof status?.proxy?.envoy_running === "boolean" ? (status.proxy.envoy_running ? "running" : "stopped") : "Unknown"}{" "}
            {status?.proxy?.envoy_last_error && `(error=${status?.proxy?.envoy_last_error})`}
            <br />
            Reverse proxy: {typeof status?.proxy?.nginx_running === "boolean" ? (status.proxy.nginx_running ? "running" : "stopped") : "Unknown"}{" "}
            {status?.proxy?.nginx_last_error && `(error=${status?.proxy?.nginx_last_error})`}

            <br />
            Forward proxy activity: <TelemetryRate queries={[{ metric: "service.events", service: "envoy" }]} />
            · errors <TelemetryRate queries={[{ metric: "service.errors", service: "envoy" }]} />
            <br />Reverse proxy activity: <TelemetryRate queries={[{ metric: "service.events", service: "nginx" }]} />
            · errors <TelemetryRate queries={[{ metric: "service.errors", service: "nginx" }]} />
            <br />Telemetry: access logs when enabled.
          </p>
          <Link href="/proxies/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
        <ServiceCard
          title="VPN"
          loading={loading}
          service="vpn"
          historyTitle="VPN events per minute"
        >
          <div className="flex items-center gap-2 text-xs text-(--text)">
            <Image src={staticAssetURL("/icons/wireguard.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <Image src={staticAssetURL("/icons/openvpn.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <span>WireGuard + OpenVPN</span>
            <InfoTip label="Secure remote access tunnels (WireGuard preferred; OpenVPN optional)." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            WireGuard: {typeof status?.vpn?.wireguard_enabled === "boolean" ? (status.vpn.wireguard_enabled ? "on" : "off") : "Unknown"}{" "}
            {(status?.vpn?.wg_peers ?? 0) > 0 &&
              `(peers=${status?.vpn?.wg_peers ?? 0})`}

          </p>
          <Link href="/vpn/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
      </div></section>
      <section aria-label="Inspection" className="mt-6"><h2 className="mb-3 text-lg font-semibold">Inspection</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <ServiceCard
          title="Antivirus / ICAP"
          loading={loading}
          service="av"
          historyTitle="AV scans per minute"
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>AV scanning</span>
            <InfoTip label="Optional ICAP or embedded ClamAV scanning of complete HTTP objects." />
          </div>
          {av?.available === false ? (
            <p className="mt-2 text-xs text-(--text-muted)">
              Scanner status unavailable: {av.error || "no reason reported"}
            </p>
          ) : av ? (
            <div className="mt-2 text-xs text-(--text-muted)">
              Mode: {av.mode || "Unknown"}, Enabled: {typeof av.enabled === "boolean" ? (av.enabled ? "yes" : "no") : "Unknown"}
              <details className="mt-2 rounded-xs border p-3">
                <summary className="cursor-pointer">Service details</summary>
              {av.freshclam_last && (
                <>
                  <br />
                  Definition updater {av.freshclam_last}
                </>
              )}
              {av.clamav_custom_defs && (
                <>
                  <br />
                  Custom definitions: {av.clamav_custom_defs}
                </>
              )}
              {av.last_render && (
                <>
                  <br />
                  Last update: {av.last_render}
                </>
              )}
              </details>
              <br />
              Rate: <TelemetryRate queries={[{ metric: "av.scans" }]} />
            </div>
          ) : null}
          <Link href="/system/services/av/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
      </div></section>
      <section aria-label="Logs" className="mt-6"><h2 className="mb-3 text-lg font-semibold">Logs</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <ServiceCard
          title="Syslog"
          loading={loading}
          service="syslog"
          historyTitle="Syslog events per minute"
        >
          <p className="text-sm text-(--text)">
            Forward unified events to external collectors.
          </p>
          <p className="mt-2 text-xs text-(--text-muted)">
            Forwarders: {status?.syslog?.configured_forwarders ?? "Unknown"}

          </p>
          <Link href="/system/services/syslog/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
      </div></section>

    </Shell>
  );
}

function ServiceCard({ title, children, loading = false, service, historyTitle, software }: {
  title: string; children: React.ReactNode; loading?: boolean;
  service: MeteredService; historyTitle: string; software?: string;
}) {
  return (
    <div className="min-w-0 rounded-xs border bg-(--surface) p-5 shadow-card">
      <p className="text-xs uppercase tracking-[0.2em] text-(--text)">{title}</p>
      <div className="mt-3">{loading ? <Skeleton className="h-14 w-full" /> : children}</div>
      {!loading && <div className="mt-3"><ServiceHistory service={service} title={historyTitle} ranges={false} /></div>}
      {!loading && software && <div className="mt-3">
        <h3 className="mb-2 text-sm">Troubleshooting</h3>
        <Disclosure title="Service details"><p className="text-xs text-(--text-muted)">Software: {software}</p></Disclosure>
      </div>}
    </div>
  );
}
