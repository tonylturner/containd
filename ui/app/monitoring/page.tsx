"use client";

import { useEffect, useMemo, useState } from "react";
import Image from "next/image";
import Link from "next/link";

import { api, type FlowSummary, type ServicesStatus, type TelemetryEvent } from "../../lib/api";
import { staticAssetURL } from "../../lib/api-core";
import { Shell } from "../../components/Shell";
import { DemoBadge, TelemetryChart, TelemetryRate } from "../../components/TelemetryChart";
import { TelemetryProtocols } from "../../components/TelemetryProtocols";
import { Card } from "../../components/Card";

export default function MonitoringOverviewPage() {
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [flowStatus, setFlowStatus] = useState<"loading" | "ready" | "unavailable">("loading");
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [eventsStatus, setEventsStatus] = useState<"loading" | "ready" | "unavailable">("loading");
  const [services, setServices] = useState<ServicesStatus | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    async function refresh() {
      try {
        const [f, e, s] = await Promise.all([
          api.listFlows(200, controller.signal),
          api.listEvents(500, controller.signal),
          api.getServicesStatus(controller.signal),
        ]);
        setFlows(f ?? []);
        setFlowStatus(f === null ? "unavailable" : "ready");
        setEvents(e ?? []);
        setEventsStatus(e === null ? "unavailable" : "ready");
        setServices(s);
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setEvents([]);
        setEventsStatus("unavailable");
      }
    }

    refresh();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, 10000);
    const onVisible = () => { if (!document.hidden) refresh(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  async function retryFlows() {
    const result = await api.listFlows(200);
    setFlows(result ?? []);
    setFlowStatus(result === null ? "unavailable" : "ready");
  }

  const alertCount = events.filter(
    (ev) => ev.proto === "ids" && ev.kind === "alert",
  ).length;
  const dpiCount = events.filter((ev) => ev.proto !== "ids").length;
  const appSeries = useMemo(() => {
    const counts = new Map<string, number>();
    for (const flow of flows) {
      const key = (flow.application || flow.transport || "unknown").toLowerCase();
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const max = Math.max(1, ...entries.map(([, c]) => c));
    const colorFor = (app: string) => {
      switch (app) {
        case "modbus":
          return "var(--orange)";
        case "ssh":
          return "var(--teal)";
        case "rdp":
          return "var(--warning)";
        case "http":
        case "https":
        case "tls":
          return "var(--primary)";
        default:
          return "var(--primary-hover)";
      }
    };
    return entries.map(([app, count]) => ({
      app,
      count,
      pct: Math.round((count / max) * 100),
      color: colorFor(app),
    }));
  }, [flows]);
  const endpointStats = useMemo(() => {
    const src = new Set<string>();
    const dst = new Set<string>();
    for (const f of flows) {
      if (f.srcIp) src.add(f.srcIp);
      if (f.dstIp) dst.add(f.dstIp);
    }
    const total = Math.max(1, src.size + dst.size);
    return {
      srcCount: src.size,
      dstCount: dst.size,
      srcPct: Math.round((src.size / total) * 100),
      dstPct: Math.round((dst.size / total) * 100),
    };
  }, [flows]);

  const serviceCards = services
    ? [
        {
          key: "dns",
          label: "DNS",
          icon: staticAssetURL("/icons/envoyproxy.svg"),
          status: typeof services.dns?.running === "boolean" ? (services.dns.running ? "running" : "stopped") : "Unknown",
          hint: "DNS resolution",
        },
        {
          key: "ntp",
          label: "NTP",
          icon: staticAssetURL("/icons/envoyproxy.svg"),
          status: typeof services.ntp?.running === "boolean" ? (services.ntp.running ? "running" : "stopped") : "Unknown",
          hint: "Time synchronization",
        },
        {
          key: "dhcp",
          label: "DHCP",
          icon: staticAssetURL("/icons/envoyproxy.svg"),
          status: typeof services.dhcp?.enabled === "boolean" ? (services.dhcp.enabled ? "enabled" : "off") : "Unknown",
          hint: "LAN leases",
        },
        {
          key: "vpn",
          label: "VPN",
          icon: staticAssetURL("/icons/wireguard.svg"),
          status: services.vpn?.wireguard_enabled || services.vpn?.openvpn_running ? "enabled" : typeof services.vpn?.wireguard_enabled === "boolean" && typeof services.vpn?.openvpn_running === "boolean" ? "off" : "Unknown",
          hint: "WireGuard/OpenVPN",
        },
        {
          key: "proxy",
          label: "Proxies",
          icon: staticAssetURL("/icons/nginx.svg"),
          status: services.proxy?.envoy_running || services.proxy?.nginx_running ? "running" : "stopped",
          hint: "Envoy + Nginx",
        },
        {
          key: "av",
          label: "AV",
          icon: staticAssetURL("/icons/envoyproxy.svg"),
          status: !services.av.available ? "unavailable" : services.av.enabled ? "enabled" : "off",
          hint: "ICAP/ClamAV",
        },
      ]
    : [];

  return (
    <Shell title="Monitoring Overview">
      <div className="mb-4 rounded-xl border border-white/8 bg-white/3 px-4 py-3 text-sm text-(--text-muted)">
        Live traffic records and service activity.
        {" "}
        <Link href="/" className="text-(--text) hover:text-white">
          Use Dashboard
        </Link>
        {" "}
        for setup, policy workflow, and config state.
      </div>
      {flowStatus === "unavailable" && <div role="status" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
        Flows unavailable — live traffic monitoring could not be reached.
        <button onClick={retryFlows} className="ml-2 rounded-xs border border-red-500/30 px-3 py-1">Retry</button>
      </div>}
      <div className="grid gap-4 md:grid-cols-3">
        <Card title="Flows">
          <div className="text-3xl font-bold text-(--text)">{flowStatus === "ready" ? flows.length : flowStatus === "loading" ? "Loading…" : "Unavailable"}</div>
          <Link href="/flows/" className="text-xs text-(--text) hover:text-(--text)">
            View flows →
          </Link>
        </Card>
        <Card title="DPI Events">
          <div className="text-3xl font-bold text-(--text)">{eventsStatus === "ready" ? dpiCount : eventsStatus === "loading" ? "Loading…" : "Unavailable"}</div>
          <Link href="/events/" className="text-xs text-(--text) hover:text-(--text)">
            View events →
          </Link>
        </Card>
        <Card title="IDS Alerts">
          <div className="text-3xl font-bold text-(--text)">{eventsStatus === "ready" ? alertCount : eventsStatus === "loading" ? "Loading…" : "Unavailable"}</div>
          <Link href="/alerts/" className="text-xs text-(--text) hover:text-(--text)">
            View alerts →
          </Link>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <Card title="Services Health">
          <div className="space-y-3 text-xs text-(--text)">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-(--text-muted)">
                <Image src={staticAssetURL("/icons/nginx.svg")} alt="" width={16} height={16} className="h-4 w-4" />
                Proxies
              </span>
              <span>
                <TelemetryRate queries={[{ metric: "service.events", service: "envoy" }]} />
                <span> · reverse proxy <TelemetryRate queries={[{ metric: "service.events", service: "nginx" }]} /></span>
                <span> · errors <TelemetryRate queries={[{ metric: "service.errors", service: "envoy" }]} /></span>
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {serviceCards.slice(0, 4).map((svc) => (
                <div
                  key={svc.key}
                  className="flex items-center justify-between rounded-lg border bg-(--surface) px-3 py-2 transition-ui"
                >
                  <span className="flex items-center gap-2 text-(--text)">
                    <Image src={svc.icon} alt="" width={16} height={16} className="h-4 w-4" />
                    {svc.label}
                  </span>
                  <span className="rounded-full px-2 py-1 text-[10px] text-(--text)">
                    {svc.status}
                  </span>
                </div>
              ))}
            </div>
            <Link href="/system/services/" className="text-xs text-(--text) hover:text-(--text)">
              Configure services →
            </Link>
          </div>
        </Card>
        <Card title="Top Protocols">
          <TelemetryProtocols />
        </Card>
        <Card title="Recent Alerts">
          {eventsStatus !== "ready" && <div role="status" className="text-sm text-amber">{eventsStatus === "loading" ? "Loading recent events…" : "Recent events unavailable — alert counts unknown."}</div>}
          {eventsStatus === "ready" && alertCount === 0 && (
            <div className="text-sm text-(--text-muted)">No alerts.</div>
          )}
          {events
            .filter((ev) => ev.proto === "ids" && ev.kind === "alert")
            .slice(0, 5)
            .map((ev) => (
              <div key={ev.id} className="mb-2 rounded-lg bg-(--surface) p-2 text-xs">
                <div className="text-slate-100">
                  {(ev.attributes?.["message"] as string) ?? "IDS alert"}<DemoBadge origin={ev.origin} />
                </div>
                <div className="text-(--text-muted)">
                  {new Date(ev.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <Card title="Traffic Pulse">
          <p className="text-xs text-(--text-muted)">Last 60 min · bytes/s</p>
          <TelemetryChart title="Traffic Pulse" queries={[{ metric: "iface.rx_bytes", role: "leaf", group: "role" }]} />
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-(--text)">
            <div>DPI {eventsStatus === "ready" ? dpiCount.toLocaleString() : "Unknown"}</div>
            <div>Alerts {eventsStatus === "ready" ? alertCount.toLocaleString() : "Unknown"}</div>
          </div>
        </Card>
        <Card title="Top Applications">
          {flowStatus === "ready" && appSeries.length === 0 && (
            <div className="text-sm text-(--text-muted)">No flow apps yet.</div>
          )}
          {flowStatus === "ready" && appSeries.length > 0 && (
            <div className="space-y-2 text-xs text-(--text)">
              {appSeries.map((row) => (
                <div key={row.app} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="uppercase text-(--text-muted)">{row.app}</span>
                    <span>{row.count}</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-(--surface)">
                    <div
                      className="h-2 rounded-full"
                      style={{ width: `${row.pct}%`, background: row.color }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card title="Endpoints">
          <div className="space-y-3 text-xs text-(--text)">
            <div className="flex items-center justify-between">
              <span className="text-(--text-muted)">Sources</span>
              <span className="text-(--text)">{flowStatus === "ready" ? endpointStats.srcCount : "Unknown"}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-(--surface)">
              <div
                className="h-2 rounded-full"
                style={{ width: `${flowStatus === "ready" ? endpointStats.srcPct : 0}%`, background: "var(--teal)" }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-(--text-muted)">Destinations</span>
              <span className="text-(--text)">{flowStatus === "ready" ? endpointStats.dstCount : "Unknown"}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-(--surface)">
              <div
                className="h-2 rounded-full"
                style={{ width: `${flowStatus === "ready" ? endpointStats.dstPct : 0}%`, background: "var(--orange)" }}
              />
            </div>
          </div>
        </Card>
      </div>
    </Shell>
  );
}
