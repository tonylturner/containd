 "use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { fetchHealth, type HealthResponse, api } from "../lib/api";
import { Shell } from "../components/Shell";
import { Console } from "../components/Console";

export default function Home() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [assetCount, setAssetCount] = useState<number | null>(null);
  const [zoneCount, setZoneCount] = useState<number | null>(null);
  const [ifaceCount, setIfaceCount] = useState<number | null>(null);
  const [ruleCount, setRuleCount] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    fetchHealth().then((res) => alive && setHealth(res));
    Promise.all([
      api.listAssets(),
      api.listZones(),
      api.listInterfaces(),
      api.listFirewallRules(),
    ]).then(([assets, zones, ifaces, rules]) => {
      if (!alive) return;
      setAssetCount(assets?.length ?? 0);
      setZoneCount(zones?.length ?? 0);
      setIfaceCount(ifaces?.length ?? 0);
      setRuleCount(rules?.length ?? 0);
    });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <Shell title="Dashboard">
      <div className="grid gap-4 md:grid-cols-3">
        <DashboardCard title="System information">
          <div className="space-y-1 text-sm">
            <KeyValue label="Hostname" value="containd" />
            <KeyValue label="Build" value={health?.build ?? "dev"} />
            <KeyValue label="Component" value={health?.component ?? "mgmt"} />
            <KeyValue
              label="Updated"
              value={
                health?.time
                  ? new Date(health.time).toLocaleString()
                  : "—"
              }
            />
          </div>
        </DashboardCard>

        <DashboardCard title="Licenses / Services">
          <div className="grid grid-cols-3 gap-2 text-xs">
            {["IPS", "Web Filter", "AV", "Support", "Updates", "Proxy"].map(
              (label) => (
                <div
                  key={label}
                  className="rounded-lg bg-mint/10 px-2 py-2 text-center text-mint"
                >
                  {label}
                </div>
              ),
            )}
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Placeholders until service manager lands.
          </p>
        </DashboardCard>

        <DashboardCard title="Assets">
          <div className="flex items-center justify-center py-6">
            <div className="text-center">
              <div className="text-4xl font-bold text-white">
                {assetCount ?? "—"}
              </div>
              <div className="text-xs uppercase tracking-wide text-slate-300">
                Devices
              </div>
            </div>
          </div>
          <Link href="/assets/" className="text-xs text-slate-300 hover:text-white">
            View assets →
          </Link>
        </DashboardCard>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <DashboardCard title="Policy summary">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Stat label="Zones" value={zoneCount} href="/zones/" />
            <Stat label="Interfaces" value={ifaceCount} href="/interfaces/" />
            <Stat label="FW rules" value={ruleCount} href="/firewall/" />
            <Stat label="ICS rules" value={0} href="/firewall/" />
          </div>
        </DashboardCard>

        <DashboardCard title="DPI / IDS">
          <div className="space-y-2 text-sm text-slate-200">
            <KeyValue label="Modbus events (lab)" value="streaming" />
            <KeyValue label="IT DPI" value="pending" />
            <KeyValue label="IDS engine" value="pending" />
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Populates once selective DPI + IDS land.
          </p>
        </DashboardCard>

        <DashboardCard title="Operations">
          <div className="flex flex-col gap-2 text-sm">
            <Link
              href="/config/"
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 hover:bg-white/10"
            >
              Candidate / Commit
            </Link>
            <Link
              href="/dataplane/"
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 hover:bg-white/10"
            >
              Dataplane settings
            </Link>
            <Link
              href="/audit/"
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 hover:bg-white/10"
            >
              Audit log
            </Link>
          </div>
        </DashboardCard>
      </div>

      <div className="mt-6">
        <Console />
      </div>
    </Shell>
  );
}

function DashboardCard({
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

function KeyValue({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-300">{label}</span>
      <span className="text-slate-100">{value}</span>
    </div>
  );
}

function Stat({
  label,
  value,
  href,
}: {
  label: string;
  value: number | null;
  href: string;
}) {
  return (
    <Link
      href={href}
      className="rounded-lg border border-white/10 bg-black/30 p-3 hover:bg-black/40"
    >
      <div className="text-2xl font-bold text-white">{value ?? "—"}</div>
      <div className="text-xs uppercase tracking-wide text-slate-300">
        {label}
      </div>
    </Link>
  );
}
