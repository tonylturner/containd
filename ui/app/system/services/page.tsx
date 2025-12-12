"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api, type ServicesStatus } from "../../../lib/api";
import { Shell } from "../../../components/Shell";

export default function ServicesOverviewPage() {
  const [status, setStatus] = useState<ServicesStatus | null>(null);

  useEffect(() => {
    api.getServicesStatus().then((s) => setStatus(s));
  }, []);

  return (
    <Shell title="Services">
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Syslog">
          <p className="text-sm text-slate-200">
            Forward unified events to external collectors.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Configured forwarders:{" "}
            {(status?.syslog as any)?.configured_forwarders ?? 0}
          </p>
          <Link href="/system/services/syslog/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="Proxies">
          <p className="text-sm text-slate-200">
            Envoy forward proxy and Nginx reverse proxy.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Status available via Monitoring and CLI.
          </p>
          <Link href="/proxies/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="DNS">
          <p className="text-sm text-slate-200">
            Unbound resolver managed by containd.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Enabled: {(status?.dns as any)?.enabled ? "yes" : "no"}{" "}
            {((status?.dns as any)?.configured_upstreams ?? 0) > 0 &&
              `(upstreams=${(status?.dns as any)?.configured_upstreams ?? 0})`}
          </p>
          <Link href="/system/services/dns/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
            Configure →
          </Link>
        </Card>

        <Card title="NTP">
          <p className="text-sm text-slate-200">
            OpenNTPD client managed by containd.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Enabled: {(status?.ntp as any)?.enabled ? "yes" : "no"}{" "}
            {((status?.ntp as any)?.servers_count ?? 0) > 0 &&
              `(servers=${(status?.ntp as any)?.servers_count ?? 0})`}
          </p>
          <Link href="/system/services/ntp/" className="mt-3 inline-block text-xs text-slate-300 hover:text-white">
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
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-300">
        {title}
      </p>
      <div className="mt-3">{children}</div>
    </div>
  );
}
