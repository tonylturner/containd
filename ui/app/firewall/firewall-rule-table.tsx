"use client";

import type { ShadowCounters } from "../../lib/api-shadow-counters";
import { ShadowCountersCell, ShadowCountersNote } from "../ics/ics-shadow-counters";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { isAdmin, type FirewallRule, type Position, type Zone } from "../../lib/api";
import { MoveRuleDialog } from "./firewall-rule-position";
import { useState } from "react";
import { summarizeIEC104 } from "../ics/iec104";
import { ICSCoverageCell } from "../ics/ics-coverage";
import type { ICSCoverageView } from "../ics/ics-coverage-model";
import { summarizeGenericICS, formatICSMode, isSupportedICSProtocol } from "../ics/ics-shared";
import { zoneName } from "../../lib/zones";
import { RuleCountersCell, RuleCountersNote, type CountersState } from "./firewall-rule-counters";
import {
  actionInfo,
  actionVariant,
  formatRateLimit,
  formatSchedule,
} from "./firewall-rule-policy";

/** States how ordered enforcing rules decide. */
export function RulePrecedenceNote() {
  return (
    <p className="mb-2 text-xs text-(--text-muted)">
      Among enforcing rules, the first matching terminal rule in list order decides, then the default
      action. Monitor ICS rules never decide. RATE_LIMIT and TAG are effects and never admit traffic.
    </p>
  );
}

function ActionCell({ rule }: { rule: FirewallRule }) {
  return (
    <div className="space-y-1">
      <StatusBadge variant={actionVariant(rule.action)}>{rule.action}</StatusBadge>
      {!actionInfo(rule.action).decides && (
        <div className="text-[10px] uppercase tracking-wider text-(--text-dim)">effect</div>
      )}
      {rule.action === "RATE_LIMIT" && rule.rateLimit && (
        <div className="whitespace-nowrap text-xs text-(--text-muted)">{formatRateLimit(rule.rateLimit)}</div>
      )}
      {rule.action === "TAG" && rule.tag && (
        <div className="font-mono text-xs text-(--text-muted)">{rule.tag}</div>
      )}
    </div>
  );
}

function ConditionsCell({ rule }: { rule: FirewallRule }) {
  if (!rule.identities?.length && !rule.schedule && !rule.viaForwards?.length) return <>{"\u2014"}</>;
  return (
    <div className="space-y-1 text-xs">
      {!!rule.viaForwards?.length && <div>via <span className="font-mono">{rule.viaForwards.join(", ")}</span></div>}
      {!!rule.identities?.length && (
        <div title="Opener bound to any of these identities">
          <span className="text-(--text-dim)">identity </span>
          <span className="font-mono">{rule.identities.join(", ")}</span>
        </div>
      )}
      {rule.schedule && (
        <div title="Recurring window">
          <span className="text-(--text-dim)">schedule </span>
          {formatSchedule(rule.schedule)}
        </div>
      )}
    </div>
  );
}

/** The firewall page's rule list. */
export function FirewallRuleTable({
  rules,
  zones,
  dpiMode,
  coverage,
  counters,
  shadowCounters,
  onEdit,
  onDelete,
  onMove,
  moving,
}: {
  rules: FirewallRule[];
  zones: Zone[];
  dpiMode: string | undefined;
  coverage: ICSCoverageView;
  counters: CountersState;
  shadowCounters: ShadowCounters | null;
  onEdit: (rule: FirewallRule) => void;
  onDelete: (id: string) => void;
  onMove: (id: string, position: Position) => void;
  moving: boolean;
}) {
  const [moveTarget, setMoveTarget] = useState<FirewallRule | null>(null);
  return (
    <section aria-label="Firewall rules">
      <RulePrecedenceNote />
      <RuleCountersNote counters={counters} />
      <ShadowCountersNote counters={shadowCounters} />
      <div className="overflow-x-auto rounded-xs border bg-(--surface) shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
            <tr>
              <th className="px-3 py-3">Order</th>
              <th className="px-3 py-3">ID</th>
              <th className="px-3 py-3">Description</th>
              <th className="px-3 py-3">Zones</th>
              <th className="px-3 py-3">Protocols</th>
              <th className="px-3 py-3">Conditions</th>
              <th className="px-3 py-3">ICS Filter</th>
              <th className="px-3 py-3">Action</th>
              <th className="px-3 py-3">Hits</th>
              <th className="px-3 py-3">Shadow matches</th>
              <th className="px-3 py-3">Log</th>
              <th className="px-3 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4" colSpan={12}>
                  <EmptyState
                    title="No firewall rules configured"
                    description="Create rules below to control traffic between zones."
                  />
                </td>
              </tr>
            )}
            {rules.map((r, index) => (
              <tr key={r.id} id={`rule-${r.id}`} className="border-t table-row-hover transition-ui">
                <td className="px-3 py-3 font-mono">{index + 1}</td>
                <td className="px-3 py-3 font-mono text-xs text-(--text)">{r.id}</td>
                <td className="px-3 py-3 text-(--text)">{r.description || "\u2014"}</td>
                <td className="px-3 py-3 text-(--text)">
                  {(r.sourceZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}{" \u2192 "}
                  {(r.destZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}
                </td>
                <td className="px-3 py-3 text-(--text)">
                  {(r.protocols ?? []).map((p) => `${p.name}${p.port ? ":" + p.port : ""}`).join(", ") || "any"}
                </td>
                <td className="px-3 py-3 text-(--text)">
                  <ConditionsCell rule={r} />
                </td>
                <td className="px-3 py-3 text-(--text)">
                  {r.ics?.protocol ? (
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <StatusBadge variant="neutral">
                          {formatICSMode(r.ics.mode, dpiMode).label}
                        </StatusBadge>
                        <span className="text-xs text-(--text)">
                          {r.ics.protocol === "iec104"
                            ? `iec104 ${summarizeIEC104(r.ics).types} ${summarizeIEC104(r.ics).addresses}`
                            : `${r.ics.protocol} ${summarizeGenericICS(r.ics)}`}
                        </span>
                        {!isSupportedICSProtocol(r.ics.protocol) && (
                          <StatusBadge variant="warning">unsupported</StatusBadge>
                        )}
                      </div>
                      <ICSCoverageCell view={coverage} ruleId={r.id} />
                    </div>
                  ) : "\u2014"}
                </td>
                <td className="px-3 py-3">
                  <ActionCell rule={r} />
                </td>
                <td className="px-3 py-3">
                  <RuleCountersCell rule={r} counters={counters} />
                </td>
                <td className="px-3 py-3">
                  <ShadowCountersCell rule={r} globalMode={dpiMode} counters={shadowCounters} />
                </td>
                <td className="px-3 py-3">
                  {r.log ? (
                    <StatusBadge variant="info">log</StatusBadge>
                  ) : (
                    <span className="text-xs text-(--text-muted)">&mdash;</span>
                  )}
                </td>
                <td className="px-3 py-3 text-right">
                  {isAdmin() && (
                    <>
                      <div className="mb-2 flex items-center justify-end gap-2">
                        <button disabled={moving || index === 0} aria-label={`Move ${r.id} up`} onClick={() => onMove(r.id, { before: rules[index - 1].id })} className="rounded-md border bg-(--surface2) px-2 py-1 text-xs disabled:opacity-50">↑</button>
                        <button disabled={moving || index === rules.length - 1} aria-label={`Move ${r.id} down`} onClick={() => onMove(r.id, { after: rules[index + 1].id })} className="rounded-md border bg-(--surface2) px-2 py-1 text-xs disabled:opacity-50">↓</button>
                        <button disabled={moving} onClick={() => setMoveTarget(r)} className="rounded-md border bg-(--surface2) px-2 py-1 text-xs disabled:opacity-50">Move to…</button>
                      </div>
                      {(!r.ics?.protocol || isSupportedICSProtocol(r.ics.protocol)) ? (
                        <button onClick={() => onEdit(r)} className="mr-2 rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui">Edit</button>
                      ) : (
                        <span className="mr-2 text-xs text-(--text-muted)" title="Unsupported ICS rules are read-only; delete this rule to remove it.">Read-only</span>
                      )}
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
      {moveTarget && <MoveRuleDialog rule={moveTarget} rules={rules} onClose={() => setMoveTarget(null)} onMove={(position) => { onMove(moveTarget.id, position); setMoveTarget(null); }} />}
    </section>
  );
}
