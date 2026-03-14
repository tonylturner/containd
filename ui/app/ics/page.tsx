"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

import {
  api,
  fetchDataPlane,
  isAdmin,
  type DataPlaneConfig,
  type FirewallRule,
  type ICSPredicate,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { EditICSModal } from "./ics-edit-modal";
import { PROTOCOL_KEYS, PROTOCOLS, protoMeta } from "./ics-shared";

/* -- Page ----------------------------------------------------------------- */

export default function ICSPolicyPage() {
  const canEdit = isAdmin();
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [filterProto, setFilterProto] = useState<string>("all");
  const [dpiConfig, setDpiConfig] = useState<DataPlaneConfig>({
    captureInterfaces: [],
    dpiMock: false,
  });

  async function refresh() {
    setError(null);
    const list = await api.listFirewallRules();
    if (!list) {
      setError("Failed to load firewall rules.");
      return;
    }
    setRules(list);
  }

  useEffect(() => {
    refresh();
  }, []);
  useEffect(() => {
    fetchDataPlane().then((dp) => {
      if (dp) setDpiConfig(dp);
    });
  }, []);

  const icsRules = useMemo(
    () =>
      rules
        .filter((r) => !!r.ics?.protocol)
        .filter(
          (r) => filterProto === "all" || r.ics?.protocol === filterProto,
        ),
    [rules, filterProto],
  );

  const protoCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of rules) {
      if (r.ics?.protocol) m[r.ics.protocol] = (m[r.ics.protocol] ?? 0) + 1;
    }
    return m;
  }, [rules]);

  async function onSave(id: string, ics: ICSPredicate | undefined) {
    setError(null);
    const result = await api.updateFirewallRule(id, { ics });
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setEditing(null);
    refresh();
  }

  return (
    <Shell
      title="ICS / OT Protocol Filters"
      actions={
        <button
          onClick={refresh}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* -- DPI status --------------------------------------------------- */}
      <Card title="DPI Status" className="mb-4">
        <div className="flex items-center justify-between">
          <div className="text-sm text-[var(--text)]">
            ICS protocol filters require DPI to be enabled with at least one capture interface configured.
          </div>
          <StatusBadge variant={(dpiConfig.dpiEnabled ?? false) ? "success" : "neutral"} dot>
            {(dpiConfig.dpiEnabled ?? false) ? "DPI Enabled" : "DPI Disabled"}
          </StatusBadge>
        </div>
        {(dpiConfig.captureInterfaces ?? []).length > 0 && (
          <div className="mt-2 text-xs text-[var(--text-muted)]">
            Capture interfaces: {(dpiConfig.captureInterfaces ?? []).join(", ")}
          </div>
        )}
        <div className="mt-2">
          <Link href="/firewall/" className="text-xs font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
            Configure DPI in Firewall Rules &rarr;
          </Link>
        </div>
      </Card>

      {/* -- Protocol summary cards -------------------------------------- */}
      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <Card title="Supported Protocols">
          <div className="flex flex-wrap gap-2">
            {PROTOCOL_KEYS.map((k) => (
              <StatusBadge key={k} variant="neutral">
                {PROTOCOLS[k].label}
              </StatusBadge>
            ))}
          </div>
        </Card>
        <Card title="Quick Start">
          <ol className="space-y-1 text-xs text-[var(--text-muted)]">
            <li>1. Create a firewall rule matching your PLC/RTU zone.</li>
            <li>2. Select the protocol and define criteria here.</li>
            <li>3. Start with Safe Learning, then switch to Enforce.</li>
          </ol>
          <Link
            href="/firewall/"
            className="mt-3 inline-block text-xs text-[var(--amber)] hover:text-[var(--amber)]"
          >
            Go to Firewall Rules &rarr;
          </Link>
        </Card>
        <Card title="Active Filters">
          {Object.keys(protoCounts).length === 0 ? (
            <div className="text-xs text-[var(--text-muted)]">
              No ICS filters configured yet.
            </div>
          ) : (
            <div className="space-y-1">
              {Object.entries(protoCounts).map(([p, n]) => (
                <div
                  key={p}
                  className="flex items-center justify-between text-sm text-[var(--text)]"
                >
                  <span>{protoMeta(p).label}</span>
                  <StatusBadge variant="neutral">{n}</StatusBadge>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* -- Protocol filter tabs ---------------------------------------- */}
      <div className="mb-3 flex gap-2 overflow-x-auto">
        <button
          onClick={() => setFilterProto("all")}
          className={`rounded-sm px-3 py-1.5 text-xs transition-ui ${filterProto === "all" ? "bg-[var(--amber)] text-white font-medium" : "bg-[var(--surface2)] text-[var(--text)] hover:bg-amber-500/[0.08]"}`}
        >
          All
        </button>
        {PROTOCOL_KEYS.map((k) => (
          <button
            key={k}
            onClick={() => setFilterProto(k)}
            className={`rounded-sm px-3 py-1.5 text-xs transition-ui ${filterProto === k ? "bg-[var(--amber)] text-white font-medium" : "bg-[var(--surface2)] text-[var(--text)] hover:bg-amber-500/[0.08]"}`}
          >
            {PROTOCOLS[k].label}
            {protoCounts[k] ? ` (${protoCounts[k]})` : ""}
          </button>
        ))}
      </div>

      {/* -- Rules table ------------------------------------------------- */}
      <div className="overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
            <tr>
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">
                {filterProto !== "all"
                  ? protoMeta(filterProto).fcLabel
                  : "Codes"}
              </th>
              <th className="px-4 py-3">
                {filterProto !== "all"
                  ? protoMeta(filterProto).addrLabel
                  : "Addresses"}
              </th>
              <th className="px-4 py-3">R/W</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {icsRules.length === 0 && (
              <tr>
                <td className="px-4 py-8" colSpan={8}>
                  <EmptyState
                    title={`No ICS filters${filterProto !== "all" ? ` for ${protoMeta(filterProto).label}` : ""} configured`}
                    description="Create firewall rules with ICS protocol filters to monitor and control industrial traffic."
                    action={
                      <Link
                        href="/firewall/"
                        className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
                      >
                        Open Firewall Rules
                      </Link>
                    }
                  />
                </td>
              </tr>
            )}
            {icsRules.map((r) => (
              <tr key={r.id} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {(r.sourceZones ?? []).join(", ") || "any"} &rarr;{" "}
                  {(r.destZones ?? []).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  <StatusBadge variant="neutral">
                    {protoMeta(r.ics?.protocol ?? "").label}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {(r.ics?.functionCode ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {(r.ics?.addresses ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 text-xs text-[var(--text)]">
                  {r.ics?.readOnly
                    ? "R"
                    : r.ics?.writeOnly
                      ? "W"
                      : "R/W"}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  <StatusBadge
                    variant={r.ics?.mode === "learn" ? "warning" : "success"}
                    dot
                  >
                    {r.ics?.mode === "learn" ? "learning" : "enforce"}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => setEditing(r)}
                    className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
                  >
                    Edit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && (
        <EditICSModal
          rule={editing}
          onClose={() => setEditing(null)}
          onSave={(ics) => onSave(editing.id, ics)}
        />
      )}
    </Shell>
  );
}
