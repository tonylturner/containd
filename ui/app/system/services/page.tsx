"use client";

import Image from "next/image";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { api, type ServiceMeter, type ServicesStatus } from "../../../lib/api";
import { staticAssetURL } from "../../../lib/api-core";
import { Shell } from "../../../components/Shell";
import { Card as BaseCard } from "../../../components/Card";
import { Skeleton } from "../../../components/Skeleton";
import { useToast } from "../../../components/ToastProvider";
import { Sparkline } from "../../../components/Sparkline";
import { InfoTip } from "../../../components/InfoTip";

type MeteredService = "syslog" | "proxy" | "envoy" | "nginx" | "dns" | "ntp" | "dhcp" | "vpn" | "av";

// The engine reports antivirus scans only while it answers.
function meterOf(status: ServicesStatus | null, svc: MeteredService): ServiceMeter | undefined {
  if (svc === "av") return status?.av?.available ? status.av : undefined;
  return status?.[svc];
}

export default function ServicesOverviewPage() {
  const toast = useToast();
  const [status, setStatus] = useState<ServicesStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  // A card charts only the per-minute series the API reports; without one it
  // shows no chart.
  const spark = useCallback(
    (svc: MeteredService, title: string, color: string, background: string) => {
      const values = meterOf(status, svc)?.sparkline;
      if (!values?.length) return undefined;
      return { values, title, color, background };
    },
    [status],
  );

  const rate = useCallback(
    (svc: MeteredService) => meterOf(status, svc)?.rate_per_min ?? null,
    [status],
  );
  const errRate = useCallback(
    (svc: MeteredService) => meterOf(status, svc)?.errors_rate_per_min ?? null,
    [status],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const s = await api.getServicesStatus();
      setStatus(s);
       setLastUpdated(new Date());
      toast("Service status refreshed", "success");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to load services.";
      setError(msg);
      toast("Failed to load services", "error");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const dnsRunning = status?.dns?.running;
  const dhcpEnabled = status?.dhcp?.enabled;
  const vpnActive = status?.vpn?.wireguard_enabled || status?.vpn?.openvpn_running;
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
      {error && (
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
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${dnsRunning ? "bg-emerald-400/20 text-emerald-400" : "text-(--text)"}`}>
              {dnsRunning ? "running" : "stopped"}
            </span>
          </div>
          <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2 text-sm">
            <span className="text-(--text)">DHCP</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${dhcpEnabled ? "bg-emerald-400/20 text-emerald-400" : "text-(--text)"}`}>
              {dhcpEnabled ? "enabled" : "off"}
            </span>
          </div>
          <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2 text-sm">
            <span className="text-(--text)">VPN</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${vpnActive ? "bg-emerald-400/20 text-emerald-400" : "text-(--text)"}`}>
              {vpnActive ? "active" : "off"}
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
      <div className="grid gap-4 md:grid-cols-2">
        <ServiceCard
          title="Syslog"
          loading={loading}
          spark={spark(
            "syslog",
            "Syslog events per minute",
            "var(--primary)",
            "linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.05))",
          )}
          rate={rate("syslog")}
          errorsRate={errRate("syslog")}
        >
          <p className="text-sm text-(--text)">
            Forward unified events to external collectors.
          </p>
          <p className="mt-2 text-xs text-(--text-muted)">
            Forwarders: {status?.syslog?.configured_forwarders ?? 0}
            {rate("syslog") !== null && (
              <> · Rate: {(rate("syslog") ?? 0).toFixed(1)} /min</>
            )}
          </p>
          <Link href="/system/services/syslog/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="Proxies"
          loading={loading}
          spark={spark(
            "proxy",
            "Proxy events per minute",
            "var(--purple)",
            "linear-gradient(180deg, rgba(139,92,246,0.08), rgba(6,182,212,0.05))",
          )}
          rate={rate("proxy")}
          errorsRate={errRate("proxy")}
        >
          <div className="flex items-center gap-2 text-xs text-(--text)">
            <Image src={staticAssetURL("/icons/envoyproxy.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <Image src={staticAssetURL("/icons/nginx.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <span>Envoy + Nginx</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>Envoy + Nginx proxies</span>
            <InfoTip label="Forward proxy for outbound traffic and reverse proxy for published apps." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Envoy: {status?.proxy?.envoy_running ? "running" : "stopped"}{" "}
            {status?.proxy?.envoy_last_error && `(error=${status?.proxy?.envoy_last_error})`}
            <br />
            Nginx: {status?.proxy?.nginx_running ? "running" : "stopped"}{" "}
            {status?.proxy?.nginx_last_error && `(error=${status?.proxy?.nginx_last_error})`}
            {rate("proxy") !== null && (
              <>
                <br />
                Rate: {(rate("proxy") ?? 0).toFixed(1)} /min
              </>
            )}
            {rate("envoy") !== null && (
              <>
                <br />
                Envoy rate: {(rate("envoy") ?? 0).toFixed(1)} /min
                {errRate("envoy") !== null && <> · errors {(errRate("envoy") ?? 0).toFixed(1)}/min</>}
              </>
            )}
            {rate("nginx") !== null && (
              <>
                <br />
                Nginx rate: {(rate("nginx") ?? 0).toFixed(1)} /min
                {errRate("nginx") !== null && <> · errors {(errRate("nginx") ?? 0).toFixed(1)}/min</>}
              </>
            )}
            <br />
            Telemetry: access logs when enabled.
          </p>
          <Link href="/proxies/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="DNS"
          loading={loading}
          spark={spark(
            "dns",
            "DNS events per minute",
            "var(--primary)",
            "linear-gradient(180deg, rgba(37,99,235,0.08), rgba(139,92,246,0.05))",
          )}
          rate={rate("dns")}
          errorsRate={errRate("dns")}
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>Unbound DNS resolver</span>
            <InfoTip label="Embedded resolver with upstream forwarding and caching." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Enabled: {status?.dns?.enabled ? "yes" : "no"}, running:{" "}
            {status?.dns?.running ? "yes" : "no"}
            <br />
            Upstreams: {status?.dns?.configured_upstreams ?? 0}{" "}
            {status?.dns?.last_error && `(error=${status?.dns?.last_error})`}
            {rate("dns") !== null && (
              <>
                <br />
                Rate: {(rate("dns") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/system/services/dns/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="NTP"
          loading={loading}
          spark={spark(
            "ntp",
            "NTP events per minute",
            "var(--teal)",
            "linear-gradient(180deg, rgba(6,182,212,0.08), rgba(37,99,235,0.04))",
          )}
          rate={rate("ntp")}
          errorsRate={errRate("ntp")}
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>chrony NTP client</span>
            <InfoTip label="Keeps system time in sync using configured NTP servers." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Enabled: {status?.ntp?.enabled ? "yes" : "no"}, running:{" "}
            {status?.ntp?.running ? "yes" : "no"}
            <br />
            Servers: {status?.ntp?.servers_count ?? 0}{" "}
            {status?.ntp?.last_error && `(error=${status?.ntp?.last_error})`}
            {rate("ntp") !== null && (
              <>
                <br />
                Rate: {(rate("ntp") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/system/services/ntp/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="DHCP"
          loading={loading}
          spark={spark(
            "dhcp",
            "DHCP events per minute",
            "var(--teal)",
            "linear-gradient(180deg, rgba(6,182,212,0.08), rgba(59,130,246,0.04))",
          )}
          rate={rate("dhcp")}
          errorsRate={errRate("dhcp")}
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>LAN DHCP server</span>
            <InfoTip label="Assigns IPs to LAN clients and tracks leases." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            Enabled: {status?.dhcp?.enabled ? "yes" : "no"}{" "}
            {(status?.dhcp?.listen_ifaces ?? 0) > 0 &&
              `(ifaces=${status?.dhcp?.listen_ifaces ?? 0})`}
            {rate("dhcp") !== null && (
              <>
                <br />
                Rate: {(rate("dhcp") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/dhcp/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="VPN"
          loading={loading}
          spark={spark(
            "vpn",
            "VPN events per minute",
            "var(--primary)",
            "linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.05))",
          )}
          rate={rate("vpn")}
          errorsRate={errRate("vpn")}
        >
          <div className="flex items-center gap-2 text-xs text-(--text)">
            <Image src={staticAssetURL("/icons/wireguard.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <Image src={staticAssetURL("/icons/openvpn.svg")} alt="" width={16} height={16} className="h-4 w-4" />
            <span>WireGuard + OpenVPN</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>WireGuard + OpenVPN</span>
            <InfoTip label="Secure remote access tunnels (WireGuard preferred; OpenVPN optional)." />
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            WireGuard: {status?.vpn?.wireguard_enabled ? "on" : "off"}{" "}
            {(status?.vpn?.wg_peers ?? 0) > 0 &&
              `(peers=${status?.vpn?.wg_peers ?? 0})`}
            {rate("vpn") !== null && (
              <>
                <br />
                Rate: {(rate("vpn") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/vpn/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="Antivirus / ICAP"
          loading={loading}
          spark={spark(
            "av",
            "AV scans per minute",
            "var(--purple)",
            "linear-gradient(180deg, rgba(139,92,246,0.08), rgba(37,99,235,0.04))",
          )}
          rate={rate("av")}
          errorsRate={errRate("av")}
        >
          <div className="flex items-center gap-2 text-sm text-(--text)">
            <span>AV scanning</span>
            <InfoTip label="Optional ICAP or embedded ClamAV scanning of complete HTTP objects." />
          </div>
          {av?.available === false ? (
            <p className="mt-2 text-xs text-(--text-muted)">
              Engine status unavailable: {av.error || "no reason reported"}
            </p>
          ) : av ? (
            <p className="mt-2 text-xs text-(--text-muted)">
              Mode: {av.mode}, Enabled: {av.enabled ? "yes" : "no"}
              {av.freshclam_last && (
                <>
                  <br />
                  freshclam {av.freshclam_last}
                </>
              )}
              {av.clamav_custom_defs && (
                <>
                  <br />
                  Custom defs: {av.clamav_custom_defs}
                </>
              )}
              {av.last_render && (
                <>
                  <br />
                  Last update: {av.last_render}
                </>
              )}
              <br />
              Rate: {av.rate_per_min.toFixed(1)} /min
            </p>
          ) : null}
          <Link href="/system/services/av/" className="mt-3 inline-block text-xs text-(--text) hover:text-(--text)">
            Configure →
          </Link>
        </ServiceCard>
      </div>
    </Shell>
  );
}

function ServiceCard({
  title,
  children,
  loading = false,
  spark,
  rate,
  errorsRate,
}: {
  title: string;
  children: React.ReactNode;
  loading?: boolean;
  spark?: { values: number[]; color: string; background: string; title?: string };
  rate?: number | null;
  errorsRate?: number | null;
}) {
  const trend =
    spark && spark.values.length > 1
      ? spark.values[spark.values.length - 1] - spark.values[0]
      : 0;
  return (
    <div className="rounded-xs border bg-(--surface) p-5 shadow-card">
      <p className="text-xs uppercase tracking-[0.2em] text-(--text)">
        {title}
      </p>
      <div className="mt-3">
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-4 w-36" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : (
          children
        )}
      </div>
      {!loading && spark ? (
        <div className="mt-3 space-y-2">
          <Sparkline
            values={spark.values}
            color={spark.color}
            background={spark.background}
            title={spark.title}
          />
          <div className="text-xs text-(--text-muted)">
            Trend:{" "}
            <span className={trend > 0 ? "text-emerald-400" : trend < 0 ? "" : "text-(--text)"}>
              {trend > 0 ? "▲" : trend < 0 ? "▼" : "•"} {trend}
            </span>
            {typeof rate === "number" ? (
              <span className="ml-2 text-(--text-muted)">
                Rate: <span className="text-(--text)">{rate.toFixed(1)}/min</span>
              </span>
            ) : null}
            {typeof errorsRate === "number" ? (
              <span className="ml-2">
                Errors: {errorsRate.toFixed(1)}/min
              </span>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
