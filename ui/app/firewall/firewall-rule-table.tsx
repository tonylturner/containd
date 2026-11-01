"use client";

import type { ShadowCounters } from "../../lib/api-shadow-counters";
import { ShadowCountersNote } from "../ics/ics-shadow-counters";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { isAdmin, type FirewallRule, type Position, type Zone } from "../../lib/api";
import { MoveRuleDialog } from "./firewall-rule-position";
import { Fragment, useLayoutEffect, useRef, useState } from "react";
import { FirewallDefaultRow, type DefaultAction } from "./firewall-default-row";
import { ICSCoverageCell } from "../ics/ics-coverage";
import type { ICSCoverageView } from "../ics/ics-coverage-model";
import { formatICSMode, isSupportedICSProtocol } from "../ics/ics-shared";
import { zoneName } from "../../lib/zones";
import { RuleCountersCell, RuleCountersNote, type CountersState } from "./firewall-rule-counters";
import { FirewallRuleDetail } from "./firewall-rule-detail";
import {
  actionInfo,
  actionVariant,
  formatRateLimit,
} from "./firewall-rule-policy";

/** States how ordered enforcing rules decide. */
export function RulePrecedenceNote() {
  return (
    <p className="mb-2 text-xs text-(--text-muted)">
      Among enforcing rules, the first matching rule that allows or blocks traffic decides, then the default
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

/** Keep hidden matching constraints and monitor telemetry discoverable. */
function RuleIndicators({ rule, dpiMode, shadowCounters }: {
  rule: FirewallRule; dpiMode?: string; shadowCounters: ShadowCounters | null;
}) {
  const count = shadowCounters?.available ? shadowCounters.rules.find(c => c.ruleId === rule.id) : undefined;
  const monitor = !!rule.ics?.protocol && formatICSMode(rule.ics.mode, dpiMode).effectiveMode === "monitor";
  return <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
    {(rule.sources?.length || rule.destinations?.length || rule.identities?.length || rule.schedule || rule.viaForwards?.length)
      ? <StatusBadge variant="neutral">has conditions</StatusBadge> : null}
    {rule.ics?.protocol && <>
      <StatusBadge variant="neutral">ICS Filter: {rule.ics.protocol}</StatusBadge>
      <StatusBadge variant="neutral">{formatICSMode(rule.ics.mode, dpiMode).label}</StatusBadge>
      {!isSupportedICSProtocol(rule.ics.protocol) && <StatusBadge variant="warning">unsupported</StatusBadge>}
    </>}
    {rule.log && <StatusBadge variant="info">Log: on</StatusBadge>}
    {count && count.shadowMatches > 0 && <StatusBadge variant="warning">Shadow matches: {count.shadowMatches.toLocaleString()} messages</StatusBadge>}
    {monitor && !count && <StatusBadge variant="neutral">Shadow matches: {!shadowCounters ? "checking" : !shadowCounters.available ? "unavailable" : "not applied yet"}</StatusBadge>}
  </div>;
}

/** The firewall page's rule list. */
export function FirewallRuleTable({
  rules,
  defaultAction,
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
  defaultAction: DefaultAction;
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
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [moveTarget, setMoveTarget] = useState<FirewallRule | null>(null);
  const moveControl = useRef<HTMLButtonElement | null>(null);
  useLayoutEffect(() => {
    if (moving || !moveControl.current) return;
    const control = moveControl.current;
    // At an end, keep focus on the same rule's remaining enabled direction.
    const target = control.disabled
      ? control.parentElement?.querySelector<HTMLButtonElement>("button:not(:disabled)")
      : control;
    target?.focus({ preventScroll: true });
    moveControl.current = null;
  }, [moving, rules]);
  return (
    <section aria-label="Firewall rules" className="min-w-0">
      <RulePrecedenceNote />
      <RuleCountersNote counters={counters} />
      {shadowCounters && !shadowCounters.available
        ? <div role="status" aria-label="Shadow counters" className="mb-2 text-xs text-(--text-muted)">
          Monitor counts unavailable.<p className="break-words">{shadowCounters.reason}</p>
        </div>
        : <ShadowCountersNote counters={shadowCounters} />}
      <div className="overflow-x-auto rounded-xs border bg-(--surface) shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
            <tr>
              <th className="px-3 py-3">Order</th>
              <th className="px-3 py-3">Description</th>
              <th className="px-3 py-3">Zones</th>
              <th className="px-3 py-3">Protocols</th>
              <th className="px-3 py-3">Action</th>
              <th className="px-3 py-3">Hits</th>
              <th className="px-3 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4" colSpan={7}>
                  <EmptyState
                    title="No firewall rules configured"
                    description="Use Create rule below to control traffic between zones."
                  />
                </td>
              </tr>
            )}
            {rules.map((r, index) => (
              <Fragment key={r.id}>
                <tr id={`rule-${r.id}`} className="border-t table-row-hover transition-ui">
                  <td className="px-3 py-3 font-mono">
                    <div className="flex items-center gap-1 whitespace-nowrap">
                      <span aria-label={`Position ${index + 1}`} className="mr-1">{index + 1}</span>
                      {isAdmin() && (
                        <>
                          <button disabled={moving || index === 0} aria-label={`Move ${r.id} up`} onClick={(event) => { moveControl.current = event.currentTarget; onMove(r.id, { before: rules[index - 1].id }); }} className="rounded-md border bg-(--surface2) px-2 py-1 text-xs disabled:opacity-50">↑</button>
                          <button disabled={moving || index === rules.length - 1} aria-label={`Move ${r.id} down`} onClick={(event) => { moveControl.current = event.currentTarget; onMove(r.id, { after: rules[index + 1].id }); }} className="rounded-md border bg-(--surface2) px-2 py-1 text-xs disabled:opacity-50">↓</button>
                        </>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-3 text-(--text)">
                    <div className="max-w-72 break-words">{r.description || "\u2014"}</div>
                    <div className="mt-1 font-mono text-xs break-all"><span className="text-(--text-dim)">ID: </span><span data-rule-id>{r.id}</span></div>
                    <RuleIndicators rule={r} dpiMode={dpiMode} shadowCounters={shadowCounters} />
                    {r.ics?.protocol && <div className="mt-2"><ICSCoverageCell view={coverage} ruleId={r.id} /></div>}
                    <button type="button" aria-expanded={expanded.has(r.id)} aria-controls={`rule-detail-${r.id}`}
                      onClick={() => setExpanded(current => { const next = new Set(current); if (next.has(r.id)) next.delete(r.id); else next.add(r.id); return next; })}
                      className="mt-2 rounded-xs border bg-(--surface2) px-2 py-1 text-xs">
                      Details for {r.id}
                    </button>
                  </td>
                  <td className="px-3 py-3 text-(--text)">
                    {(r.sourceZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}{" \u2192 "}
                    {(r.destZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}
                  </td>
                  <td className="px-3 py-3 text-(--text)">
                    {(r.protocols ?? []).map((p) => `${p.name}${p.port ? ":" + p.port : ""}`).join(", ") || "any"}
                  </td>
                  <td className="px-3 py-3">
                    <ActionCell rule={r} />
                  </td>
                  <td className="px-3 py-3">
                    <RuleCountersCell rule={r} counters={counters} compact />
                  </td>
                  <td className="px-3 py-3 text-right">
                    {isAdmin() && (
                      <>
                        <div className="mb-2 flex items-center justify-end gap-2">
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
                <tr hidden={!expanded.has(r.id)} className="border-t bg-(--surface2)">
                  <td colSpan={7} className="px-4 py-4">
                    <div id={`rule-detail-${r.id}`}>
                      {expanded.has(r.id) && <FirewallRuleDetail rule={r} dpiMode={dpiMode} counters={counters} shadowCounters={shadowCounters} />}
                    </div>
                  </td>
                </tr>
              </Fragment>
            ))}
            <FirewallDefaultRow action={defaultAction} />
          </tbody>
        </table>
      </div>
      {moveTarget && <MoveRuleDialog rule={moveTarget} rules={rules} onClose={() => setMoveTarget(null)} onMove={(position) => { onMove(moveTarget.id, position); setMoveTarget(null); }} />}
    </section>
  );
}
