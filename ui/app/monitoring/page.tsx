"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, type FlowSummary, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function MonitoringOverviewPage() {
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [services, setServices] = useState<Record<string, unknown> | null>(null);

  async function refresh() {
    const [f, e, s] = await Promise.all([
      api.listFlows(200),
      api.listEvents(500),
      api.getServicesStatus(),
    ]);
    setFlows(f ?? []);
    setEvents(e ?? []);
    setServices(s);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);

  const alertCount = events.filter(
    (ev) => ev.proto === "ids" && ev.kind === "alert",
  ).length;
  const dpiCount = events.filter((ev) => ev.proto !== "ids").length;

  const envoyRate =
    typeof (services as any)?.envoy?.rate_per_min === "number"
      ? (services as any).envoy.rate_per_min
      : null;
  const envoyErrors =
    typeof (services as any)?.envoy?.errors_rate_per_min === "number"
      ? (services as any).envoy.errors_rate_per_min
      : null;
  const nginxRate =
    typeof (services as any)?.nginx?.rate_per_min === "number"
      ? (services as any).nginx.rate_per_min
      : null;
  const nginxErrors =
    typeof (services as any)?.nginx?.errors_rate_per_min === "number"
      ? (services as any).nginx.errors_rate_per_min
      : null;

  return (
    <Shell title="Monitoring Overview">
      <div className="grid gap-4 md:grid-cols-3">
        <Card title="Flows">
          <div className="text-3xl font-bold text-white">{flows.length}</div>
          <Link href="/flows/" className="text-xs text-slate-300 hover:text-white">
            View flows →
          </Link>
        </Card>
        <Card title="DPI Events">
          <div className="text-3xl font-bold text-white">{dpiCount}</div>
          <Link href="/events/" className="text-xs text-slate-300 hover:text-white">
            View events →
          </Link>
        </Card>
        <Card title="IDS Alerts">
          <div className="text-3xl font-bold text-white">{alertCount}</div>
          <Link href="/alerts/" className="text-xs text-slate-300 hover:text-white">
            View alerts →
          </Link>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card title="Proxy Telemetry">
          <div className="space-y-2 text-xs text-slate-300">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-slate-400">
                <img src="/icons/envoyproxy.svg" alt="" className="h-4 w-4" />
                Envoy
              </span>
              <span>
                {envoyRate !== null ? envoyRate.toFixed(1) : "0.0"} /min
                {envoyErrors !== null && (
                  <span className="text-amber-300"> · {envoyErrors.toFixed(1)} err/min</span>
                )}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-slate-400">
                <img src="/icons/nginx.svg" alt="" className="h-4 w-4" />
                Nginx
              </span>
              <span>
                {nginxRate !== null ? nginxRate.toFixed(1) : "0.0"} /min
                {nginxErrors !== null && (
                  <span className="text-amber-300"> · {nginxErrors.toFixed(1)} err/min</span>
                )}
              </span>
            </div>
            <div className="text-[11px] text-slate-500">
              Counts derived from access logs when enabled.
            </div>
          </div>
        </Card>
        <Card title="Services Summary">
          {!services && (
            <div className="text-sm text-slate-400">Unavailable.</div>
          )}
          {services && (
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">DNS</span>
                <span>
                  {(services as any)?.dns?.running ? "running" : "stopped"}
                  {(services as any)?.dns?.enabled ? " · enabled" : ""}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">NTP</span>
                <span>
                  {(services as any)?.ntp?.running ? "running" : "stopped"}
                  {(services as any)?.ntp?.enabled ? " · enabled" : ""}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">DHCP</span>
                <span>
                  {(services as any)?.dhcp?.enabled ? "enabled" : "off"}
                  {typeof (services as any)?.dhcp?.listen_ifaces === "number" &&
                    (services as any).dhcp.listen_ifaces > 0 &&
                    ` · ifaces ${(services as any).dhcp.listen_ifaces}`}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">VPN</span>
                <span>
                  {(services as any)?.vpn?.wireguard_enabled ? "wg on" : "wg off"}
                  {(services as any)?.vpn?.openvpn_running ? " · ovpn running" : ""}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">AV</span>
                <span>
                  {(services as any)?.av?.enabled ? "enabled" : "off"}
                  {(services as any)?.av?.mode ? ` · ${(services as any).av.mode}` : ""}
                </span>
              </div>
              <div className="text-[11px] text-slate-500">
                Detail pages provide full configuration and runtime state.
              </div>
            </div>
          )}
        </Card>
        <Card title="Recent Alerts">
          {alertCount === 0 && (
            <div className="text-sm text-slate-400">No alerts.</div>
          )}
          {events
            .filter((ev) => ev.proto === "ids" && ev.kind === "alert")
            .slice(0, 5)
            .map((ev) => (
              <div key={ev.id} className="mb-2 rounded-lg bg-black/30 p-2 text-xs">
                <div className="text-slate-100">
                  {(ev.attributes?.["message"] as string) ?? "IDS alert"}
                </div>
                <div className="text-slate-400">
                  {new Date(ev.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
        </Card>
      </div>
    </Shell>
  );
}

function Card({
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
