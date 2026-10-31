"use client";

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
  summarizeGenericICS,
  PROTOCOL_KEYS,
  PROTOCOLS,
  isSupportedICSProtocol,
  protoMeta,
} from "./ics-shared";
import { summarizeIEC104 } from "./iec104";
import { IEC104HealthIndicator } from "./iec104-health";
import { useHealth } from "../../hooks/useHealth";
import { useInstalledRuleset } from "../../hooks/useInstalledRuleset";
import { InstalledRulesetUnavailable, RulesetFaults } from "../firewall/firewall-ruleset-status";
import { EnforcementHealthIndicator } from "../../components/EnforcementHealthIndicator";
import { ICSCoverageCell, ICSCoverageNotice, ICSEnforcementIndicator } from "./ics-coverage";
import { ShadowCountersCell, ShadowCountersNote, useShadowCounters } from "./ics-shadow-counters";
import { useICSCoverage } from "./use-ics-coverage";

/* -- Page ----------------------------------------------------------------- */

export default function ICSPolicyPage() {
  const toast = useToast();
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [filterProto, setFilterProto] = useState<string>("all");
  const [dpiConfig, setDpiConfig] = useState<DataPlaneConfig>({
    captureInterfaces: [],
    dpiMock: false,
  });
  const coverage = useICSCoverage();
  const shadow = useShadowCounters();
  const health = useHealth();
  const installed = useInstalledRuleset();
  const queueGroup = dpiConfig.nfqueueGroup ?? 0;

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [list, dp] = await Promise.all([api.listFirewallRules(), fetchDataPlane()]);
    if (!checkLoaded(list)) return;
    setError(null);
    if (dp) setDpiConfig(dp);
    setRules(list);
    if (!keepEdits) setEditing(null);
  }, [checkLoaded]));

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
  async function onSave(id: string, ics: ICSPredicatePatch | undefined) {
    setError(null);
    if (!canSave) return null;
    const result = await api.updateFirewallRule(id, { ics: ics ?? null });
    if (!result.ok) {
      setError(result.error);
      return null;
    }
    toast(
      ics ? "ICS filter staged — commit to apply." : "ICS filter removal staged — commit to apply.",
      "success",
    );
    refresh();
    return result.data;
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

      {/* -- DPI status --------------------------------------------------- */}
      <Card title="Candidate DPI Settings" className="mb-4">
        <div className="flex items-center justify-between">
          <div className="text-sm text-(--text)">
            ICS protocol filters need DPI enabled. Enforce needs an NFQUEUE group, which inspects
            routed traffic inline and needs no capture interface; capture interfaces only observe.
          </div>
          <StatusBadge variant={(dpiConfig.dpiEnabled ?? false) ? "success" : "neutral"} dot>
            {(dpiConfig.dpiEnabled ?? false) ? "DPI Enabled" : "DPI Disabled"}
          </StatusBadge>
        </div>
        <div className="mt-2 text-xs text-(--text-muted)">
          {queueGroup > 0
            ? `Inline inspection: NFQUEUE group ${queueGroup}`
            : "Inline inspection: off \u2014 no NFQUEUE group, so ICS rules can only monitor"}
        </div>
        {(dpiConfig.captureInterfaces ?? []).length > 0 && (
          <div className="mt-2 text-xs text-(--text-muted)">
            Capture interfaces: {(dpiConfig.captureInterfaces ?? []).join(", ")}
          </div>
        )}
        <div className="mt-3 space-y-2">
          <EnforcementHealthIndicator health={health?.enforcement} />
          <ICSEnforcementIndicator health={health?.icsEnforcement} />
          <IEC104HealthIndicator health={health?.iec104Enforcement} />
          {installed.state === "loaded" && <RulesetFaults status={installed.status} />}
          <InstalledRulesetUnavailable view={installed} />
        </div>
        <div className="mt-2">
          <Link href="/firewall/" className="text-xs font-semibold text-(--amber) hover:text-(--amber)">
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
        </Card>
        <Card title="Candidate Filters">
          {Object.keys(protoCounts).length === 0 ? (
            <div className="text-xs text-(--text-muted)">
              No ICS filters configured yet.
            </div>
          ) : (
            <div className="space-y-1">
              {Object.entries(protoCounts).map(([p, n]) => (
                <div
                  key={p}
                  className="flex items-center justify-between text-sm text-(--text)"
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
        </Card>
      </div>

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
      {Object.keys(protoCounts).length > 0 && <ICSCoverageNotice view={coverage.view} />}
      <RulePrecedenceNote />
      <ShadowCountersNote counters={shadow.counters} />
      <div className="overflow-x-auto rounded-xs border bg-(--surface) shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
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
              <th className="px-4 py-3">Coverage</th>
              <th className="px-4 py-3">Shadow matches</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {icsRules.length === 0 && (
              <tr>
                <td className="px-4 py-8" colSpan={10}>
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
              <tr key={r.id} className="border-t table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-(--text)">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-(--text)">
                  {(r.sourceZones ?? []).join(", ") || "any"} &rarr;{" "}
                  {(r.destZones ?? []).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-(--text)">
                  <StatusBadge variant="neutral">
                    {protoMeta(r.ics?.protocol ?? "").label}
                  </StatusBadge>
                  {!isSupportedICSProtocol(r.ics?.protocol ?? "") && (
                    <span className="ml-2">
                      <StatusBadge variant="warning">unsupported</StatusBadge>
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-(--text)">
                  {r.ics?.protocol === "iec104"
                    ? summarizeIEC104(r.ics).types
                    : r.ics ? summarizeGenericICS(r.ics) : "*"}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-(--text)">
                  {r.ics?.protocol === "iec104"
                    ? summarizeIEC104(r.ics).addresses
                    : (r.ics?.addresses ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 text-xs text-(--text)">
                  {r.ics?.readOnly
                    ? "R"
                    : r.ics?.writeOnly
                      ? "W"
                      : "R/W"}
                </td>
                <td className="px-4 py-3 text-(--text)">
                  <StatusBadge variant="neutral">
                    {formatICSMode(r.ics?.mode, dpiConfig.dpiMode).label}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3 text-(--text)">
                  <ICSCoverageCell view={coverage.view} ruleId={r.id} />
                </td>
                <td className="px-4 py-3"><ShadowCountersCell rule={r} globalMode={dpiConfig.dpiMode} counters={shadow.counters} /></td>
                <td className="px-4 py-3 text-right">
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

      {editing && canEdit && (
        <EditICSModal
          available={canSave}
          rule={rules.find((r) => r.id === editing.id) ?? editing}
          context={rules}
          globalMode={dpiConfig.dpiMode}
          onClose={() => setEditing(null)}
          onSave={(ics) => onSave(editing.id, ics)}
        />
      )}
    </Shell>
  );
}
