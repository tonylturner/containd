"use client";

import { useEffect, useMemo, useState } from "react";
import Image from "next/image";
import Link from "next/link";

import { api, type FlowSummary, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Sparkline } from "../../components/Sparkline";
import { Card } from "../../components/Card";

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
  const protoSeries = useMemo(() => {
    const counts = new Map<string, number>();
    for (const ev of events) {
      const key = (ev.proto || "unknown").toLowerCase();
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const max = Math.max(1, ...entries.map(([, c]) => c));
    const colorFor = (proto: string) => {
      switch (proto) {
        case "ids":
          return "var(--warning)";
        case "firewall":
          return "var(--primary)";
        case "dns":
          return "var(--teal)";
        case "modbus":
          return "var(--orange)";
        case "http":
          return "var(--purple)";
        case "tls":
          return "var(--primary-hover)";
        default:
          return "var(--pink)";
      }
    };
    return entries.map(([proto, count]) => ({
      proto,
      count,
      pct: Math.round((count / max) * 100),
      color: colorFor(proto),
    }));
  }, [events]);
  const activitySeries = useMemo(() => {
    const buckets = 12;
    const windowMs = 60 * 60 * 1000;
    const now = Date.now();
    const start = now - windowMs;
    const bucketMs = windowMs / buckets;
    const values = Array.from({ length: buckets }, () => 0);
    for (const ev of events) {
      const ts = new Date(ev.timestamp).getTime();
      if (!Number.isFinite(ts) || ts < start || ts > now) continue;
      const idx = Math.min(buckets - 1, Math.max(0, Math.floor((ts - start) / bucketMs)));
      values[idx] += 1;
    }
    return values;
  }, [events]);
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

  const serviceCards = services
    ? [
        {
          key: "dns",
          label: "DNS",
          icon: "/icons/envoyproxy.svg",
          status: (services as any)?.dns?.running ? "running" : "stopped",
          hint: "Unbound resolver",
        },
        {
          key: "ntp",
          label: "NTP",
          icon: "/icons/envoyproxy.svg",
          status: (services as any)?.ntp?.running ? "running" : "stopped",
          hint: "OpenNTPD client",
        },
        {
          key: "dhcp",
          label: "DHCP",
          icon: "/icons/envoyproxy.svg",
          status: (services as any)?.dhcp?.enabled ? "enabled" : "off",
          hint: "LAN leases",
        },
        {
          key: "vpn",
          label: "VPN",
          icon: "/icons/wireguard.svg",
          status:
            (services as any)?.vpn?.wireguard_enabled || (services as any)?.vpn?.openvpn_running
              ? "active"
              : "off",
          hint: "WireGuard/OpenVPN",
        },
        {
          key: "proxy",
          label: "Proxies",
          icon: "/icons/nginx.svg",
          status: (services as any)?.proxy?.envoy_running || (services as any)?.proxy?.nginx_running ? "running" : "stopped",
          hint: "Envoy + Nginx",
        },
        {
          key: "av",
          label: "AV",
          icon: "/icons/envoyproxy.svg",
          status: (services as any)?.av?.enabled ? "enabled" : "off",
          hint: "ICAP/ClamAV",
        },
      ]
    : [];

  return (
    <Shell title="Operations Center">
      <div className="grid gap-4 md:grid-cols-3">
        <Card title="Flows">
          <div className="text-3xl font-bold text-[var(--text)]">{flows.length}</div>
          <Link href="/flows/" className="text-xs text-[var(--text)] hover:text-[var(--text)]">
            View flows →
          </Link>
        </Card>
        <Card title="DPI Events">
          <div className="text-3xl font-bold text-[var(--text)]">{dpiCount}</div>
          <Link href="/events/" className="text-xs text-[var(--text)] hover:text-[var(--text)]">
            View events →
          </Link>
        </Card>
        <Card title="IDS Alerts">
          <div className="text-3xl font-bold text-[var(--text)]">{alertCount}</div>
          <Link href="/alerts/" className="text-xs text-[var(--text)] hover:text-[var(--text)]">
            View alerts →
          </Link>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <Card title="Services Health">
          <div className="space-y-3 text-xs text-[var(--text)]">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-[var(--text-muted)]">
                <Image src="/icons/nginx.svg" alt="" width={16} height={16} className="h-4 w-4" />
                Proxies
              </span>
              <span>
                {envoyRate !== null ? envoyRate.toFixed(1) : "0.0"} /min
                {nginxRate !== null && (
                  <span className="text-[var(--text-dim)]"> · nginx {nginxRate.toFixed(1)}/min</span>
                )}
                {envoyErrors !== null && (
                  <span className="text-amber-400"> · {envoyErrors.toFixed(1)} err/min</span>
                )}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {serviceCards.slice(0, 4).map((svc) => (
                <div
                  key={svc.key}
                  className="flex items-center justify-between rounded-lg border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 transition-ui"
                >
                  <span className="flex items-center gap-2 text-[var(--text)]">
                    <Image src={svc.icon} alt="" width={16} height={16} className="h-4 w-4" />
                    {svc.label}
                  </span>
                  <span className="rounded-full bg-amber-500/[0.1] px-2 py-1 text-[10px] text-[var(--text)]">
                    {svc.status}
                  </span>
                </div>
              ))}
            </div>
            <Link href="/system/services/" className="text-xs text-[var(--text)] hover:text-[var(--text)]">
              Configure services →
            </Link>
          </div>
        </Card>
        <Card title="Top Protocols">
          {protoSeries.length === 0 && (
            <div className="text-sm text-[var(--text-muted)]">No telemetry yet.</div>
          )}
          {protoSeries.length > 0 && (
            <div className="space-y-2 text-xs text-[var(--text)]">
              {protoSeries.map((row) => (
                <div key={row.proto} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="uppercase text-[var(--text-muted)]">{row.proto}</span>
                    <span>{row.count}</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-[var(--surface)]">
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
        <Card title="Recent Alerts">
          {alertCount === 0 && (
            <div className="text-sm text-[var(--text-muted)]">No alerts.</div>
          )}
          {events
            .filter((ev) => ev.proto === "ids" && ev.kind === "alert")
            .slice(0, 5)
            .map((ev) => (
              <div key={ev.id} className="mb-2 rounded-lg bg-[var(--surface)] p-2 text-xs">
                <div className="text-slate-100">
                  {(ev.attributes?.["message"] as string) ?? "IDS alert"}
                </div>
                <div className="text-[var(--text-muted)]">
                  {new Date(ev.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <Card title="Traffic Pulse">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)]">
            <span>Last 60 min</span>
            <span className="text-[var(--text)]">{events.length.toLocaleString()} events</span>
          </div>
          <div className="mt-3">
            <Sparkline values={activitySeries} color="var(--primary)" />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-[var(--text)]">
            <div className="rounded-lg border border-amber-500/[0.15] bg-black/20 px-2 py-1">
              DPI {dpiCount.toLocaleString()}
            </div>
            <div className="rounded-lg border border-amber-500/[0.15] bg-black/20 px-2 py-1">
              Alerts {alertCount.toLocaleString()}
            </div>
          </div>
        </Card>
        <Card title="Top Applications">
          {appSeries.length === 0 && (
            <div className="text-sm text-[var(--text-muted)]">No flow apps yet.</div>
          )}
          {appSeries.length > 0 && (
            <div className="space-y-2 text-xs text-[var(--text)]">
              {appSeries.map((row) => (
                <div key={row.app} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="uppercase text-[var(--text-muted)]">{row.app}</span>
                    <span>{row.count}</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-[var(--surface)]">
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
          <div className="space-y-3 text-xs text-[var(--text)]">
            <div className="flex items-center justify-between">
              <span className="text-[var(--text-muted)]">Sources</span>
              <span className="text-[var(--text)]">{endpointStats.srcCount}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-[var(--surface)]">
              <div
                className="h-2 rounded-full"
                style={{ width: `${endpointStats.srcPct}%`, background: "var(--teal)" }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--text-muted)]">Destinations</span>
              <span className="text-[var(--text)]">{endpointStats.dstCount}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-[var(--surface)]">
              <div
                className="h-2 rounded-full"
                style={{ width: `${endpointStats.dstPct}%`, background: "var(--orange)" }}
              />
            </div>
          </div>
        </Card>
      </div>
    </Shell>
  );
}
