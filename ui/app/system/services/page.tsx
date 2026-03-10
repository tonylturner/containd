"use client";

import Image from "next/image";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { api, type ServicesStatus } from "../../../lib/api";
import { Shell } from "../../../components/Shell";
import { Card as BaseCard } from "../../../components/Card";
import { Skeleton } from "../../../components/Skeleton";
import { useToast } from "../../../components/ToastProvider";
import { Sparkline } from "../../../components/Sparkline";
import { InfoTip } from "../../../components/InfoTip";

export default function ServicesOverviewPage() {
  const toast = useToast();
  const [status, setStatus] = useState<ServicesStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const series = useCallback(
    (svc: string, fallback: number[]) => {
      const s = (status as any)?.[svc];
      if (Array.isArray(s?.sparkline) && s.sparkline.length) return s.sparkline as number[];
      if (typeof s?.count === "number") {
        return [s.count, Math.max(1, Math.round((s.count as number) * 1.1)), s.count];
      }
      return fallback;
    },
    [status],
  );

  const rate = useCallback(
    (svc: string) => {
      const s = (status as any)?.[svc];
      if (typeof s?.rate_per_min === "number") return s.rate_per_min as number;
      return null;
    },
    [status],
  );
  const errRate = useCallback(
    (svc: string) => {
      const s = (status as any)?.[svc];
      if (typeof s?.errors_rate_per_min === "number") return s.errors_rate_per_min as number;
      return null;
    },
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

  const dnsRunning = (status as any)?.dns?.running;
  const dhcpEnabled = (status as any)?.dhcp?.enabled;
  const vpnActive =
    (status as any)?.vpn?.wireguard_enabled || (status as any)?.vpn?.openvpn_running;

  return (
    <Shell
      title="Services"
      actions={
        <div className="flex items-center gap-3">
          <button
            onClick={() => refresh()}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-[var(--text)]">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
            />
            Auto-refresh
          </label>
        </div>
      }
    >
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-[var(--text-muted)]">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"} {autoRefresh ? "(auto)" : ""}
      </p>
      <BaseCard className="mb-4" padding="md">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-[var(--text)]">LAN Services</div>
            <div className="mt-1 text-sm text-[var(--text)]">Core connectivity helpers</div>
          </div>
          <Link href="/monitoring/" className="text-xs text-[var(--text)] hover:text-[var(--text)]">
            View Ops →
          </Link>
        </div>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm">
            <span className="text-[var(--text)]">DNS</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${dnsRunning ? "bg-emerald-400/20 text-emerald-400" : "bg-amber-500/[0.1] text-[var(--text)]"}`}>
              {dnsRunning ? "running" : "stopped"}
            </span>
          </div>
          <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm">
            <span className="text-[var(--text)]">DHCP</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${dhcpEnabled ? "bg-emerald-400/20 text-emerald-400" : "bg-amber-500/[0.1] text-[var(--text)]"}`}>
              {dhcpEnabled ? "enabled" : "off"}
            </span>
          </div>
          <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm">
            <span className="text-[var(--text)]">VPN</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] ${vpnActive ? "bg-emerald-400/20 text-emerald-400" : "bg-amber-500/[0.1] text-[var(--text)]"}`}>
              {vpnActive ? "active" : "off"}
            </span>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-xs text-[var(--text)]">
          <Link href="/system/services/dns/" className="rounded-full border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1 transition-ui hover:bg-amber-500/[0.08]">
            Configure DNS
          </Link>
          <Link href="/dhcp/" className="rounded-full border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1 transition-ui hover:bg-amber-500/[0.08]">
            Configure DHCP
          </Link>
          <Link href="/vpn/" className="rounded-full border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1 transition-ui hover:bg-amber-500/[0.08]">
            Configure VPN
          </Link>
        </div>
      </BaseCard>
      <div className="grid gap-4 md:grid-cols-2">
        <ServiceCard
          title="Syslog"
          loading={loading}
          spark={{
            values: series("syslog", [2, 4, (status as any)?.syslog?.configured_forwarders ?? 3, 6, 5, 7]),
            color: "var(--primary)",
            background: "linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.05))",
            title: "Forwarding volume (simulated)",
          }}
          rate={rate("syslog")}
          errorsRate={errRate("syslog")}
        >
          <p className="text-sm text-[var(--text)]">
            Forward unified events to external collectors.
          </p>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            Forwarders: {(status?.syslog as any)?.configured_forwarders ?? 0}
            {rate("syslog") !== null && (
              <> · Rate: {(rate("syslog") ?? 0).toFixed(1)} /min</>
            )}
          </p>
          <Link href="/system/services/syslog/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="Proxies"
          loading={loading}
          spark={{
            values: series("proxy", [5, 7, (status as any)?.proxy?.envoy_running ? 9 : 6, 8, 10, 7]),
            color: "var(--purple)",
            background: "linear-gradient(180deg, rgba(139,92,246,0.08), rgba(6,182,212,0.05))",
            title: "Proxy request volume",
          }}
          rate={rate("proxy")}
          errorsRate={errRate("proxy")}
        >
          <div className="flex items-center gap-2 text-xs text-[var(--text)]">
            <Image src="/icons/envoyproxy.svg" alt="" width={16} height={16} className="h-4 w-4" />
            <Image src="/icons/nginx.svg" alt="" width={16} height={16} className="h-4 w-4" />
            <span>Envoy + Nginx</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-[var(--text)]">
            <span>Envoy + Nginx proxies</span>
            <InfoTip label="Forward proxy for outbound traffic and reverse proxy for published apps." />
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            Envoy: {(status?.proxy as any)?.envoy_running ? "running" : "stopped"}{" "}
            {(status?.proxy as any)?.envoy_last_error && `(error=${(status?.proxy as any)?.envoy_last_error})`}
            <br />
            Nginx: {(status?.proxy as any)?.nginx_running ? "running" : "stopped"}{" "}
            {(status?.proxy as any)?.nginx_last_error && `(error=${(status?.proxy as any)?.nginx_last_error})`}
            {rate("proxy") !== null && (
              <>
                <br />
                Rate: {(rate("proxy") ?? 0).toFixed(1)} /min
              </>
            )}
            <br />
            Envoy rate: {typeof (status as any)?.envoy?.rate_per_min === "number" ? (status as any).envoy.rate_per_min.toFixed(1) : "0.0"} /min
            {typeof (status as any)?.envoy?.errors_rate_per_min === "number" && (
              <> · errors {(status as any).envoy.errors_rate_per_min.toFixed(1)}/min</>
            )}
            <br />
            Nginx rate: {typeof (status as any)?.nginx?.rate_per_min === "number" ? (status as any).nginx.rate_per_min.toFixed(1) : "0.0"} /min
            {typeof (status as any)?.nginx?.errors_rate_per_min === "number" && (
              <> · errors {(status as any).nginx.errors_rate_per_min.toFixed(1)}/min</>
            )}
            <br />
            Telemetry: access logs when enabled.
          </p>
          <Link href="/proxies/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="DNS"
          loading={loading}
          spark={{
            values: series("dns", [4, 6, (status as any)?.dns?.running ? 9 : 5, 7, 10, 8]),
            color: "var(--primary)",
            background: "linear-gradient(180deg, rgba(37,99,235,0.08), rgba(139,92,246,0.05))",
            title: "Resolver queries (simulated)",
          }}
          rate={rate("dns")}
          errorsRate={errRate("dns")}
        >
          <div className="flex items-center gap-2 text-sm text-[var(--text)]">
            <span>Unbound DNS resolver</span>
            <InfoTip label="Embedded resolver with upstream forwarding and caching." />
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            Enabled: {(status?.dns as any)?.enabled ? "yes" : "no"}, running:{" "}
            {(status?.dns as any)?.running ? "yes" : "no"}
            <br />
            Upstreams: {(status?.dns as any)?.configured_upstreams ?? 0}{" "}
            {(status?.dns as any)?.last_error && `(error=${(status?.dns as any)?.last_error})`}
            {rate("dns") !== null && (
              <>
                <br />
                Rate: {(rate("dns") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/system/services/dns/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="NTP"
          loading={loading}
          spark={{
            values: series("ntp", [2, 3, (status as any)?.ntp?.running ? 5 : 3, 6, 5, 7]),
            color: "var(--teal)",
            background: "linear-gradient(180deg, rgba(6,182,212,0.08), rgba(37,99,235,0.04))",
            title: "Sync stability (simulated)",
          }}
          rate={rate("ntp")}
          errorsRate={errRate("ntp")}
        >
          <div className="flex items-center gap-2 text-sm text-[var(--text)]">
            <span>OpenNTPD client</span>
            <InfoTip label="Keeps system time in sync using configured NTP servers." />
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            Enabled: {(status?.ntp as any)?.enabled ? "yes" : "no"}, running:{" "}
            {(status?.ntp as any)?.running ? "yes" : "no"}
            <br />
            Servers: {(status?.ntp as any)?.servers_count ?? 0}{" "}
            {(status?.ntp as any)?.last_error && `(error=${(status?.ntp as any)?.last_error})`}
            {rate("ntp") !== null && (
              <>
                <br />
                Rate: {(rate("ntp") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/system/services/ntp/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="DHCP"
          loading={loading}
          spark={{
            values: series("dhcp", [3, 5, (status as any)?.dhcp?.listen_ifaces ?? 4, 6, 8, 7]),
            color: "var(--teal)",
            background: "linear-gradient(180deg, rgba(6,182,212,0.08), rgba(59,130,246,0.04))",
            title: "Lease churn (simulated)",
          }}
          rate={rate("dhcp")}
          errorsRate={errRate("dhcp")}
        >
          <div className="flex items-center gap-2 text-sm text-[var(--text)]">
            <span>LAN DHCP server</span>
            <InfoTip label="Assigns IPs to LAN clients and tracks leases." />
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            Enabled: {(status?.dhcp as any)?.enabled ? "yes" : "no"}{" "}
            {((status?.dhcp as any)?.listen_ifaces ?? 0) > 0 &&
              `(ifaces=${(status?.dhcp as any)?.listen_ifaces ?? 0})`}
            {rate("dhcp") !== null && (
              <>
                <br />
                Rate: {(rate("dhcp") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/dhcp/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="VPN"
          loading={loading}
          spark={{
            values: series("vpn", [3, 4, (status as any)?.vpn?.wg_peers ?? 2, 6, 8, 7]),
            color: "var(--primary)",
            background: "linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.05))",
            title: "Tunnel activity (simulated)",
          }}
          rate={rate("vpn")}
          errorsRate={errRate("vpn")}
        >
          <div className="flex items-center gap-2 text-xs text-[var(--text)]">
            <Image src="/icons/wireguard.svg" alt="" width={16} height={16} className="h-4 w-4" />
            <Image src="/icons/openvpn.svg" alt="" width={16} height={16} className="h-4 w-4" />
            <span>WireGuard + OpenVPN</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-[var(--text)]">
            <span>WireGuard + OpenVPN</span>
            <InfoTip label="Secure remote access tunnels (WireGuard preferred; OpenVPN optional)." />
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            WireGuard: {(status?.vpn as any)?.wireguard_enabled ? "on" : "off"}{" "}
            {((status?.vpn as any)?.wg_peers ?? 0) > 0 &&
              `(peers=${(status?.vpn as any)?.wg_peers ?? 0})`}
            {rate("vpn") !== null && (
              <>
                <br />
                Rate: {(rate("vpn") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/vpn/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
            Configure →
          </Link>
        </ServiceCard>

        <ServiceCard
          title="Antivirus / ICAP"
          loading={loading}
          spark={{
            values: series("av", [2, 4, (status as any)?.av?.clamav_custom_defs ?? 3, 5, 7, 6]),
            color: "var(--purple)",
            background: "linear-gradient(180deg, rgba(139,92,246,0.08), rgba(37,99,235,0.04))",
            title: "AV detections (simulated)",
          }}
          rate={rate("av")}
          errorsRate={errRate("av")}
        >
          <div className="flex items-center gap-2 text-sm text-[var(--text)]">
            <span>Async AV scanning</span>
            <InfoTip label="Optional ICAP or embedded ClamAV scanning without inline latency spikes." />
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">
            Mode: {(status?.av as any)?.mode ?? "icap"}, Enabled: {(status?.av as any)?.enabled ? "yes" : "no"}
            <br />
            Block TTL: {(status?.av as any)?.block_ttl ?? "600"}s{" "}
            {(status?.av as any)?.freshclam_last && `freshclam ${ (status?.av as any)?.freshclam_last }`}
            {(status?.av as any)?.clamav_custom_defs && (
              <>
                <br />
                Custom defs: {(status?.av as any)?.clamav_custom_defs}
              </>
            )}
            {(status?.av as any)?.last_render && (
              <>
                <br />
                Last update: {(status?.av as any)?.last_render}
              </>
            )}
            {rate("av") !== null && (
              <>
                <br />
                Rate: {(rate("av") ?? 0).toFixed(1)} /min
              </>
            )}
          </p>
          <Link href="/system/services/av/" className="mt-3 inline-block text-xs text-[var(--text)] hover:text-[var(--text)]">
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
    <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card">
      <p className="text-xs uppercase tracking-[0.2em] text-[var(--text)]">
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
          <div className="text-xs text-[var(--text-muted)]">
            Trend:{" "}
            <span className={trend > 0 ? "text-emerald-400" : trend < 0 ? "text-amber-400" : "text-[var(--text)]"}>
              {trend > 0 ? "▲" : trend < 0 ? "▼" : "•"} {trend}
            </span>
            {typeof rate === "number" ? (
              <span className="ml-2 text-[var(--text-muted)]">
                Rate: <span className="text-[var(--text)]">{rate.toFixed(1)}/min</span>
              </span>
            ) : null}
            {typeof errorsRate === "number" ? (
              <span className="ml-2 text-amber-400">
                Errors: {errorsRate.toFixed(1)}/min
              </span>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
