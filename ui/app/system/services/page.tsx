"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api, type ServicesStatus } from "../../../lib/api";
import { Shell } from "../../../components/Shell";
import { Skeleton } from "../../../components/Skeleton";

export default function ServicesOverviewPage() {
  const [status, setStatus] = useState<ServicesStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getServicesStatus().then((s) => {
      setStatus(s);
      setLoading(false);
    });
  }, []);

  return (
    <Shell title="Services">
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Syslog" loading={loading}>
          <p className="text-sm text-slate-200">
            Forward unified events to external collectors.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Forwarders: {(status?.syslog as any)?.configured_forwarders ?? 0}
          </p>
          <Link href="/system/services/syslog/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="Proxies" loading={loading}>
          <p className="text-sm text-slate-200">
            Envoy forward proxy and Nginx reverse proxy.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Envoy: {(status?.proxy as any)?.envoy_running ? "running" : "stopped"}{" "}
            {(status?.proxy as any)?.envoy_last_error && `(error=${(status?.proxy as any)?.envoy_last_error})`}
            <br />
            Nginx: {(status?.proxy as any)?.nginx_running ? "running" : "stopped"}{" "}
            {(status?.proxy as any)?.nginx_last_error && `(error=${(status?.proxy as any)?.nginx_last_error})`}
          </p>
          <Link href="/proxies/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="DNS" loading={loading}>
          <p className="text-sm text-slate-200">
            Unbound resolver managed by containd.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Enabled: {(status?.dns as any)?.enabled ? "yes" : "no"}, running:{" "}
            {(status?.dns as any)?.running ? "yes" : "no"}
            <br />
            Upstreams: {(status?.dns as any)?.configured_upstreams ?? 0}{" "}
            {(status?.dns as any)?.last_error && `(error=${(status?.dns as any)?.last_error})`}
          </p>
          <Link href="/system/services/dns/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="NTP" loading={loading}>
          <p className="text-sm text-slate-200">
            OpenNTPD client managed by containd.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Enabled: {(status?.ntp as any)?.enabled ? "yes" : "no"}, running:{" "}
            {(status?.ntp as any)?.running ? "yes" : "no"}
            <br />
            Servers: {(status?.ntp as any)?.servers_count ?? 0}{" "}
            {(status?.ntp as any)?.last_error && `(error=${(status?.ntp as any)?.last_error})`}
          </p>
          <Link href="/system/services/ntp/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="DHCP" loading={loading}>
          <p className="text-sm text-slate-200">
            LAN DHCP server configuration.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Enabled: {(status?.dhcp as any)?.enabled ? "yes" : "no"}{" "}
            {((status?.dhcp as any)?.listen_ifaces ?? 0) > 0 &&
              `(ifaces=${(status?.dhcp as any)?.listen_ifaces ?? 0})`}
          </p>
          <Link href="/dhcp/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="VPN" loading={loading}>
          <p className="text-sm text-slate-200">
            WireGuard (preferred) and OpenVPN (optional).
          </p>
          <p className="mt-2 text-xs text-slate-400">
            WireGuard: {(status?.vpn as any)?.wireguard_enabled ? "on" : "off"}{" "}
            {((status?.vpn as any)?.wg_peers ?? 0) > 0 &&
              `(peers=${(status?.vpn as any)?.wg_peers ?? 0})`}
          </p>
          <Link href="/vpn/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="Antivirus / ICAP" loading={loading}>
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
}: {
  title: string;
  children: React.ReactNode;
  loading?: boolean;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-300">
        {title}
      </p>
      <div className="mt-3">{loading ? <Skeleton className="h-16 w-full" /> : children}</div>
    </div>
  );
}
