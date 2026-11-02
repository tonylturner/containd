"use client";

import { revisionError } from "../../lib/config-revision";

import type { ConfigBase } from "../../lib/config-boundary";
import { useConfigView, matchingRevisions } from "../../lib/use-config-revision";

import { useConfigLoad } from "../../lib/use-config-editor";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useMemo, useState } from "react";
import Link from "next/link";

import {
  api,
  fetchDataPlane,
  isAdmin,
  type DataPlaneConfig,
  type FirewallRule,
  type ICSPredicatePatch,
} from "../../lib/api";
import { useToast } from "../../components/ToastProvider";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { EditICSModal } from "./ics-edit-modal";
import { RulePrecedenceNote } from "../firewall/firewall-rule-table";
import {
  formatICSMode,
  PROTOCOL_KEYS,
  PROTOCOLS,
  isSupportedICSProtocol,
  protoMeta,
} from "./ics-shared";
import { ICSRuleDetails } from "./ics-rule-details";
import { useHealth } from "../../hooks/useHealth";
import { useInstalledRuleset } from "../../hooks/useInstalledRuleset";
import { ICSCoverageCell } from "./ics-coverage";
import { Disclosure } from "../../components/Disclosure";
import { ICSInspectionStatus } from "./ics-inspection-status";
import { ShadowCountersCell, ShadowCountersNote, useShadowCounters } from "./ics-shadow-counters";
import styles from "./ics-rule-table.module.css";
import { useICSCoverage } from "./use-ics-coverage";

/* -- Page ----------------------------------------------------------------- */

export default function ICSPolicyPage() {
  const toast = useToast();
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const view = useConfigView({ rules: [] as FirewallRule[], dpiConfig: { captureInterfaces: [], dpiMock: false } as DataPlaneConfig });
  const { readConfig } = view;
  const { rules, dpiConfig } = view.data;
  const viewRevision = view.state.baseRevision ?? "";
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [filterProto, setFilterProto] = useState<string>("all");
  const coverage = useICSCoverage();
  const shadow = useShadowCounters();
  const health = useHealth();
  const installed = useInstalledRuleset();
  const queueGroup = dpiConfig.nfqueueGroup ?? 0;

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [listSnapshot, dpSnapshot] = await Promise.all([api.listFirewallRules(), fetchDataPlane()]);
    if (!matchingRevisions(listSnapshot, dpSnapshot)) { checkLoaded(null); return; }
    const list = (listSnapshot?.data ?? null);
    const dp = (dpSnapshot?.data ?? null);
    if (!checkLoaded(list)) return;
    setError(null);
    readConfig({ data: { rules: list, dpiConfig: dp! }, revision: listSnapshot!.revision }, keepEdits);
    if (!keepEdits) setEditing(null);
  }, [checkLoaded, readConfig]));

  useConfigRefresh(refresh);

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

  // The editor reports a disabled filter as no predicate; null clears the
  // stored one, where an omitted key would keep it.
  async function onSave(id: string, ics: ICSPredicatePatch | undefined, revision: ConfigBase) {
    setError(null);
    if (!canSave) return null;
    const result = await view.writer((base, predicate: ICSPredicatePatch | undefined) => api.updateFirewallRule(base, id, { ics: predicate ?? null }),
      (view, saved) => ({ ...view, rules: view.rules.map(row => row.id === saved.id ? saved : row) }))(revision, ics);
    if (!result.ok) {
      setError(revisionError(result));
      return result;
    }
    toast(
      ics ? "ICS filter staged — commit to apply." : "ICS filter removal staged — commit to apply.",
      "success",
    );
    refresh();
    return result;
  }

  return (
    <Shell
      title="ICS / OT Protocol Filters"
      actions={
        <button
          onClick={() => {
            void refresh({ keepEdits: false });
            void coverage.reload();
            void shadow.reload();
          }}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
        >
          Refresh
        </button>
      }
    >
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      {!loading && error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <ICSInspectionStatus coverage={coverage.view} health={health} installed={installed} />

      <section aria-label="Candidate Filters" className="mb-3 text-xs text-(--text-muted)">
        <h2 className="font-medium">Candidate Filters</h2>
        {Object.keys(protoCounts).length === 0 ? (
          <div className="text-xs text-(--text-muted)">
            No ICS filters configured yet.
          </div>
        ) : (
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {Object.entries(protoCounts).map(([p, n]) => (
              <div
                key={p}
                className="flex items-center gap-2 text-xs text-(--text)"
              >
                <span className="flex items-center gap-2">
                  {protoMeta(p).label}
                  {!isSupportedICSProtocol(p) && (
                    <StatusBadge variant="warning">unsupported</StatusBadge>
                  )}
                </span>
                <StatusBadge variant="neutral">{n}</StatusBadge>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* -- Protocol filter tabs ---------------------------------------- */}
      <div className="mb-3 flex gap-2 overflow-x-auto">
        <button
          onClick={() => setFilterProto("all")}
          className={`rounded-xs px-3 py-1.5 text-xs transition-ui ${filterProto === "all" ? "bg-(--amber) text-white font-medium" : "bg-(--surface2) text-(--text) "}`}
        >
          All
        </button>
        {PROTOCOL_KEYS.map((k) => (
          <button
            key={k}
            onClick={() => setFilterProto(k)}
            className={`rounded-xs px-3 py-1.5 text-xs transition-ui ${filterProto === k ? "bg-(--amber) text-white font-medium" : "bg-(--surface2) text-(--text) "}`}
          >
            {PROTOCOLS[k].label}
            {protoCounts[k] ? ` (${protoCounts[k]})` : ""}
          </button>
        ))}
      </div>

      {/* -- Rules table ------------------------------------------------- */}
      <RulePrecedenceNote />
      <ShadowCountersNote counters={shadow.counters} />
      <div className="overflow-x-auto rounded-xs border bg-(--surface) shadow-card">
        <table role="table" className={`${styles.table} w-full text-sm`}>
          <thead role="rowgroup" className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
            <tr role="row">
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3">Coverage</th>
              <th className="px-4 py-3">Shadow matches</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody role="rowgroup">
            {icsRules.length === 0 && (
              <tr role="row">
                <td className="px-4 py-8" colSpan={7}>
                  <EmptyState
                    title={`No ICS filters${filterProto !== "all" ? ` for ${protoMeta(filterProto).label}` : ""} configured`}
                    description="Create firewall rules with ICS protocol filters to monitor and control industrial traffic."
                    action={
                      <Link
                        href="/firewall/"
                        className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
                      >
                        Open Firewall Rules
                      </Link>
                    }
                  />
                </td>
              </tr>
            )}
            {icsRules.map((r) => (
              <tr role="row" key={r.id} className={`${styles.ruleRow} border-t table-row-hover transition-ui`}>
                <td role="cell" data-label="Rule" aria-label={r.id} className="px-4 py-3 font-mono text-xs text-(--text)">
                  {r.id}
                  {r.ics && <ICSRuleDetails ics={r.ics} filterProto={filterProto} />}
                </td>
                <td role="cell" data-label="Zones" className="px-4 py-3 text-(--text)">
                  {(r.sourceZones ?? []).join(", ") || "any"} &rarr;{" "}
                  {(r.destZones ?? []).join(", ") || "any"}
                </td>
                <td role="cell" data-label="Protocol" className="px-4 py-3 text-(--text)">
                  <StatusBadge variant="neutral">
                    {protoMeta(r.ics?.protocol ?? "").label}
                  </StatusBadge>
                  {!isSupportedICSProtocol(r.ics?.protocol ?? "") && (
                    <span className="ml-2">
                      <StatusBadge variant="warning">unsupported</StatusBadge>
                    </span>
                  )}
                </td>
                <td role="cell" data-label="Mode" className="px-4 py-3 text-(--text)">
                  <StatusBadge variant="neutral">
                    {formatICSMode(r.ics?.mode, dpiConfig.dpiMode).label}
                  </StatusBadge>
                  {formatICSMode(r.ics?.mode, dpiConfig.dpiMode).effectiveMode === "monitor" && (
                    <p className="mt-1 text-xs text-(--text-muted)">Observation only — non-blocking</p>
                  )}
                </td>
                <td role="cell" data-label="Coverage" className="px-4 py-3 text-(--text)">
                  <ICSCoverageCell view={coverage.view} ruleId={r.id} compact />
                </td>
                <td role="cell" data-label="Shadow matches" className="px-4 py-3"><ShadowCountersCell rule={r} globalMode={dpiConfig.dpiMode} counters={shadow.counters} /></td>
                <td role="cell" data-label="Actions" className="px-4 py-3 text-right">
                  {canEdit && (
                    isSupportedICSProtocol(r.ics?.protocol ?? "") ? (
                      <button
                        onClick={() => setEditing(r)}
                        className="rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui"
                      >
                        Edit
                      </button>
                    ) : (
                      <Link
                        href="/firewall/"
                        className="text-xs font-medium text-(--amber) hover:underline"
                        title="Unsupported ICS rules are read-only; delete the rule from Firewall Rules."
                      >
                        Delete in Firewall Rules
                      </Link>
                    )
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* -- Candidate settings, separate from active inspection ---------- */}
      <Card title="Candidate DPI Settings" className="my-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm text-(--text)">
            Industrial protocol filters need traffic inspection enabled. Blocking also requires
            inline inspection of routed traffic and needs no capture interface; capture interfaces only observe.
          </div>
          <StatusBadge variant={canSave && dpiConfig.dpiEnabled ? "success" : "neutral"} dot>
            {!canSave ? "DPI status unknown" : dpiConfig.dpiEnabled ? "DPI Enabled" : "DPI Disabled"}
          </StatusBadge>
        </div>
        <div className="mt-2 text-xs text-(--text-muted)">
          {!canSave ? "Inline inspection status unknown" : queueGroup > 0
            ? "Inline inspection configured"
            : "Monitor only \u2014 inline inspection is not configured"}
        </div>
        {canSave && !queueGroup && <Link href="/firewall/#inline-inspection" className="mt-2 inline-block text-xs font-semibold text-(--amber) underline">Set up inline inspection</Link>}
        {canSave && <div className="mt-2">
          <Disclosure title="Technical details"
            defaultOpen={queueGroup > 0 || (dpiConfig.captureInterfaces ?? []).length > 0}
            indicator={queueGroup > 0 || (dpiConfig.captureInterfaces ?? []).length > 0 ? "Inline queue or capture interfaces configured" : undefined}>
            <p>Inline inspection queue (NFQUEUE): {queueGroup}</p>
            {(dpiConfig.captureInterfaces ?? []).length > 0 && (
              <div>
                Capture interfaces: {(dpiConfig.captureInterfaces ?? []).join(", ")}
              </div>
            )}
          </Disclosure>
        </div>}
        <div className="mt-2">
          <Link href="/firewall/#inline-inspection" className="text-xs font-semibold text-(--amber) hover:text-(--amber)">
            Configure DPI in Firewall Rules &rarr;
          </Link>
        </div>
      </Card>

      <div className="mt-4 rounded-xs border bg-(--surface) p-4">
        <Disclosure title="Inspection setup" defaultOpen={canSave && Object.keys(protoCounts).length === 0}>
          <section aria-label="Supported Protocols"><h2 className="mb-2 text-sm font-medium text-(--text)">Supported Protocols</h2>
            <div className="flex flex-wrap gap-2">
              {PROTOCOL_KEYS.map((k) => (
                <StatusBadge key={k} variant="neutral">
                  {PROTOCOLS[k].label}
                </StatusBadge>
              ))}
            </div>
          </section>
          <section aria-label="Quick Start"><h2 className="mb-2 text-sm font-medium text-(--text)">Quick Start</h2>
            <ol className="space-y-1 text-xs text-(--text-muted)">
              <li>1. Create a firewall rule matching your PLC/RTU zone.</li>
              <li>2. Select the protocol and define criteria here.</li>
              <li>3. Optionally monitor matches, or select Enforce directly.</li>
            </ol>
            <Link
              href="/firewall/"
              className="mt-3 inline-block text-xs text-(--amber) hover:text-(--amber)"
            >
              Go to Firewall Rules &rarr;
            </Link>
          </section>

        </Disclosure>
      </div>

      {editing && canEdit && (
        <EditICSModal
          revision={viewRevision}
          available={canSave}
          rule={rules.find((r) => r.id === editing.id) ?? editing}
          context={rules}
          globalMode={dpiConfig.dpiMode}
          inlineConfigured={canSave ? queueGroup > 0 : undefined}
          onClose={() => setEditing(null)}
          onSave={(ics, revision) => onSave(editing.id, ics, revision)}
        />
      )}
    </Shell>
  );
}
