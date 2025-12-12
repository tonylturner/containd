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
        <Card title="Services Status">
          {!services && (
            <div className="text-sm text-slate-400">Unavailable.</div>
          )}
          {services && (
            <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-slate-200">
              {JSON.stringify(services, null, 2)}
            </pre>
          )}
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

