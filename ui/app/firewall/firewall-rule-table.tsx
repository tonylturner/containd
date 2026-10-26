"use client";

import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { isAdmin, type FirewallRule, type Zone } from "../../lib/api";
import { summarizeIEC104 } from "../ics/iec104";
import { ICSCoverageCell } from "../ics/ics-coverage";
import type { ICSCoverageView } from "../ics/ics-coverage-model";
import { formatICSMode } from "../ics/ics-shared";
import { zoneName } from "./firewall-utils";

/** The firewall page's rule list. */
export function FirewallRuleTable({
  rules,
  zones,
  dpiMode,
  coverage,
  onEdit,
  onDelete,
}: {
  rules: FirewallRule[];
  zones: Zone[];
  dpiMode: string | undefined;
  coverage: ICSCoverageView;
  onEdit: (rule: FirewallRule) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <div className="overflow-hidden rounded-xs border bg-(--surface) shadow-card">
      <table className="w-full text-sm">
        <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
          <tr>
            <th className="px-4 py-3">ID</th>
            <th className="px-4 py-3">Description</th>
            <th className="px-4 py-3">Zones</th>
            <th className="px-4 py-3">Protocols</th>
            <th className="px-4 py-3">ICS Filter</th>
            <th className="px-4 py-3">Action</th>
            <th className="px-4 py-3">Log</th>
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 && (
            <tr>
              <td className="px-4 py-4" colSpan={8}>
                <EmptyState
                  title="No firewall rules configured"
                  description="Create rules below to control traffic between zones."
                />
              </td>
            </tr>
          )}
          {rules.map((r) => (
            <tr key={r.id} className="border-t table-row-hover transition-ui">
              <td className="px-4 py-3 font-mono text-xs text-(--text)">{r.id}</td>
              <td className="px-4 py-3 text-(--text)">{r.description || "\u2014"}</td>
              <td className="px-4 py-3 text-(--text)">
                {(r.sourceZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}{" \u2192 "}
                {(r.destZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}
              </td>
              <td className="px-4 py-3 text-(--text)">
                {(r.protocols ?? []).map((p) => `${p.name}${p.port ? ":" + p.port : ""}`).join(", ") || "any"}
              </td>
              <td className="px-4 py-3 text-(--text)">
                {r.ics?.protocol ? (
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge variant="neutral">
                        {formatICSMode(r.ics.mode, dpiMode).label}
                      </StatusBadge>
                      <span className="text-xs text-(--text)">
                        {r.ics.protocol === "iec104"
                          ? `iec104 ${summarizeIEC104(r.ics).types} ${summarizeIEC104(r.ics).addresses}`
                          : `${r.ics.protocol} fc=${(r.ics.functionCode ?? []).join(",") || "*"}`}
                      </span>
                    </div>
                    <ICSCoverageCell view={coverage} ruleId={r.id} />
                  </div>
                ) : "\u2014"}
              </td>
              <td className="px-4 py-3">
                <StatusBadge variant={r.action === "ALLOW" ? "success" : "error"}>
                  {r.action}
                </StatusBadge>
              </td>
              <td className="px-4 py-3">
                {r.log ? (
                  <StatusBadge variant="info">log</StatusBadge>
                ) : (
                  <span className="text-xs text-(--text-muted)">&mdash;</span>
                )}
              </td>
              <td className="px-4 py-3 text-right">
                {isAdmin() && (
                  <>
                    <button onClick={() => onEdit(r)} className="mr-2 rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui">Edit</button>
                    <button
                      onClick={() => onDelete(r.id)}
                      className="rounded-md px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                    >
                      Delete
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
