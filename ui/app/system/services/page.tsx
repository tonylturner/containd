"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { api, type ServicesStatus } from "../../../lib/api";
import { Shell } from "../../../components/Shell";
import { Skeleton } from "../../../components/Skeleton";
import { useToast } from "../../../components/ToastProvider";
import { Sparkline } from "../../../components/Sparkline";

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

  return (
    <Shell
      title="Services"
      actions={
        <div className="flex items-center gap-3">
          <button
            onClick={() => refresh()}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 transition hover:bg-white/10"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            Auto-refresh
          </label>
        </div>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-slate-400">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"} {autoRefresh ? "(auto)" : ""}
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <Card
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
          <p className="text-sm text-slate-200">
            Forward unified events to external collectors.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Forwarders: {(status?.syslog as any)?.configured_forwarders ?? 0}
            {rate("syslog") !== null && (
              <> · Rate: {(rate("syslog") ?? 0).toFixed(1)} /min</>
            )}
          </p>
          <Link href="/system/services/syslog/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card
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
          <div className="flex items-center gap-2 text-xs text-slate-300">
            <img src="/icons/envoyproxy.svg" alt="" className="h-4 w-4" />
            <img src="/icons/nginx.svg" alt="" className="h-4 w-4" />
            <span>Envoy + Nginx</span>
          </div>
          <p className="text-sm text-slate-200">
            Envoy forward proxy and Nginx reverse proxy.
          </p>
          <p className="mt-2 text-xs text-slate-400">
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
          <Link href="/proxies/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card
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
          <p className="text-sm text-slate-200">
            Unbound resolver managed by containd.
          </p>
          <p className="mt-2 text-xs text-slate-400">
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
          <Link href="/system/services/dns/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card
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
          <p className="text-sm text-slate-200">
            OpenNTPD client managed by containd.
          </p>
          <p className="mt-2 text-xs text-slate-400">
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
          <Link href="/system/services/ntp/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card
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
          <p className="text-sm text-slate-200">
            LAN DHCP server configuration.
          </p>
          <p className="mt-2 text-xs text-slate-400">
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
          <Link href="/dhcp/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card
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
          <div className="flex items-center gap-2 text-xs text-slate-300">
            <img src="/icons/wireguard.svg" alt="" className="h-4 w-4" />
            <img src="/icons/openvpn.svg" alt="" className="h-4 w-4" />
            <span>WireGuard + OpenVPN</span>
          </div>
          <p className="text-sm text-slate-200">
            WireGuard (preferred) and OpenVPN (optional).
          </p>
          <p className="mt-2 text-xs text-slate-400">
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
          <Link href="/vpn/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card
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
          <p className="text-sm text-slate-200">
            Optional async AV via ICAP or embedded ClamAV (non-blocking).
          </p>
          <p className="mt-2 text-xs text-slate-400">
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
          <Link href="/system/services/av/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>
      </div>
    </Shell>
  );
}

function Card({
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
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-300">
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
          <div className="text-xs text-slate-400">
            Trend:{" "}
            <span className={trend > 0 ? "text-mint" : trend < 0 ? "text-amber" : "text-slate-300"}>
              {trend > 0 ? "▲" : trend < 0 ? "▼" : "•"} {trend}
            </span>
            {typeof rate === "number" ? (
              <span className="ml-2 text-slate-400">
                Rate: <span className="text-slate-100">{rate.toFixed(1)}/min</span>
              </span>
            ) : null}
            {typeof errorsRate === "number" ? (
              <span className="ml-2 text-amber-300">
                Errors: {errorsRate.toFixed(1)}/min
              </span>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
