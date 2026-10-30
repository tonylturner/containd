"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useState } from "react";
import Link from "next/link";

import {
  api,
  isAdmin,
  fetchDataPlane,
  getRulesetPreview,
  type DataPlaneConfig,
  type FirewallRule,
  type FirewallRulePatch,
  type RoutingConfig,
  type Zone,
  type NATConfig,
  type RulesetPreview,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { StatusBadge } from "../../components/StatusBadge";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";
import { inferWanGateway, WAN_GATEWAY_NAME, wanGateway, withDefaultRoute } from "../../lib/wan-gateway";
import { DPIConfigSection } from "./firewall-dpi-config";
import { CreateRuleForm, EditRuleModal } from "./firewall-rule-forms";
import { RuleWarningList } from "./firewall-rule-warnings";
import { AppliedRulesetStatus, InstalledRulesetUnavailable } from "./firewall-ruleset-status";
import { EnforcementHealthIndicator } from "../../components/EnforcementHealthIndicator";
import { ICSCoverageNotice } from "../ics/ics-coverage";
import { FirewallRuleTable } from "./firewall-rule-table";
import { tagsInUse } from "./firewall-rule-policy";
import type { CountersState } from "./firewall-rule-counters";
import { useICSCoverage } from "../ics/use-ics-coverage";
import { useHealth } from "../../hooks/useHealth";
import { useInstalledRuleset } from "../../hooks/useInstalledRuleset";

// This page should own firewall page orchestration and top-level state.
// Large forms, modals, and static protocol metadata belong in sibling modules
// under ui/app/firewall/ as they become non-trivial.

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [nat, setNat] = useState<NATConfig>({ enabled: false });
  const [routing, setRouting] = useState<RoutingConfig | null>(null);
  const [dpiConfig, setDpiConfig] = useState<DataPlaneConfig>({ captureInterfaces: [], dpiMock: false });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [counters, setCounters] = useState<CountersState>(null);
  const [rulesetPreview, setRulesetPreview] = useState<RulesetPreview | null>(null);
  const [rulesetState, setRulesetState] = useState<"idle" | "loading" | "error">("idle");
  const [rulesetError, setRulesetError] = useState("");
  const coverage = useICSCoverage();
  const health = useHealth();
  const installed = useInstalledRuleset();
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [quickStarting, setQuickStarting] = useState(false);
  const confirm = useConfirm();
  const tips: Tip[] = [
    {
      id: "firewall:zones",
      title: "Create zones first",
      body: (
        <>
          Define zones in{" "}
          <Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">
            Zones
          </Link>{" "}
          so you can target them in rules.
        </>
      ),
      when: () => zones.length === 0,
    },
    {
      id: "firewall:first-rule",
      title: "Add your first rule",
      body: "Start with a simple allow rule between LAN and WAN, then tighten later.",
      when: () => zones.length > 0 && rules.length === 0,
    },
    {
      id: "firewall:nat",
      title: "Enable NAT for outbound access",
      body: (
        <>
          Turn on SNAT in{" "}
          <Link href="/nat/" className="font-semibold text-(--amber) hover:text-(--amber)">
            NAT
          </Link>{" "}
          to allow LAN hosts to reach the Internet.
        </>
      ),
      when: () => zones.length > 0 && rules.length > 0 && !nat.enabled,
    },
    {
      id: "firewall:ics",
      title: "Advance to ICS policies",
      body: "Add ICS rules to safely control protocol-specific behavior.",
      when: () => rules.length > 0,
    },
  ];

  const { refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [r, z, n, rt, dp, c] = await Promise.all([
      api.listFirewallRules(),
      api.listZones(),
      api.getNAT(),
      api.getRouting(),
      fetchDataPlane(),
      api.getRuleCounters(),
    ]);
    setRules(r ?? []);
    setCounters(c);
    setZones(z ?? []);
    setNat(n ?? { enabled: false });
    setRouting(rt);
    if (dp) {
      setDpiConfig(dp);
    }
    if (!keepEdits) {
      setEditing(null);
      setRefreshKey((key) => key + 1);
    }
  }, []));

  useConfigRefresh(refresh);

  async function loadRulesetPreview() {
    if (!isAdmin()) return;
    setRulesetPreview(null);
    setRulesetState("loading");
    const preview = await getRulesetPreview();
    if (!preview.ok) {
      setRulesetError(preview.error);
      setRulesetState("error");
      return;
    }
    setRulesetPreview(preview.data);
    setRulesetState("idle");
  }

  async function onDelete(id: string) {
    setError(null);
    setNotice(null);
    const result = await api.deleteFirewallRule(id);
    if (!result.ok) {
      setError(result.error || "Failed to delete rule.");
      return;
    }
    setNotice(result.warning ? `Rule staged — commit to apply. Warning: ${result.warning}` : "Rule staged — commit to apply.");
    refresh();
  }

  async function onCreate(rule: FirewallRule) {
    setError(null);
    setNotice(null);
    const created = await api.createFirewallRule(rule);
    if (!created.ok) {
      setError(created.error || "Failed to create rule (check zones/CIDRs).");
      return false;
    }
    setNotice(created.warning ? `Rule staged — commit to apply. Warning: ${created.warning}` : "Rule staged — commit to apply.");
    refresh();
    return true;
  }

  async function onUpdate(id: string, patch: FirewallRulePatch) {
    setError(null);
    setNotice(null);
    const updated = await api.updateFirewallRule(id, patch);
    if (!updated.ok) {
      setError(updated.error || "Failed to update rule.");
      return null;
    }
    setNotice(updated.warning ? `Rule staged — commit to apply. Warning: ${updated.warning}` : "Rule staged — commit to apply.");
    refresh();
    return updated.data;
  }
  const outboundStatus = (() => {
    const isDefaultDst = (dst: string) => {
      const d = dst.trim().toLowerCase();
      return d === "default" || d === "0.0.0.0/0";
    };
    const hasDefaultRoute = !!(routing?.routes ?? []).find((r) => isDefaultDst(r.dst) && (r.table ?? 0) === 0);

    const natEnabled = !!nat.enabled;
    const natEgress = (nat.egressZone || "wan").trim() === "wan";
    const natSources = new Set((nat.sourceZones ?? []).map((z) => z.trim()).filter(Boolean));
    const natHasLan = natSources.has("lan") || natSources.has("mgmt");

    const hasAllowLanWan = rules.some((r) => {
      if (r.action !== "ALLOW") return false;
      const src = new Set((r.sourceZones ?? []).map((z) => z.trim()).filter(Boolean));
      const dst = new Set((r.destZones ?? []).map((z) => z.trim()).filter(Boolean));
      return (src.has("lan") || src.has("mgmt")) && dst.has("wan");
    });

    return {
      hasDefaultRoute,
      natEnabled,
      natEgress,
      natHasLan,
      hasAllowLanWan,
      ok: hasDefaultRoute && natEnabled && natEgress && natHasLan && hasAllowLanWan,
    };
  })();

  async function quickStartLanWanOutbound() {
    if (!isAdmin()) return;
    setError(null);
    setNotice(null);
    confirm.open({
      title: "Enable outbound Internet?",
      message: "This will attempt to enable outbound Internet for LAN/MGMT \u2192 WAN by:\n\n\u2022 creating/updating a WAN gateway + default route (best-effort)\n\u2022 enabling SNAT (masquerade) for LAN+MGMT out WAN\n\u2022 creating an ALLOW firewall rule for LAN+MGMT \u2192 WAN\n\nNote: NAT settings will also be configured (see the NAT page).",
      confirmLabel: "Continue",
      variant: "warning",
      onConfirm: () => doQuickStart(),
    });
  }

  async function doQuickStart() {
    setQuickStarting(true);
    try {
      const warnings: string[] = [];
      const [ifs, states, curRouting] = await Promise.all([
        api.listInterfaces(),
        api.listInterfaceState(),
        api.getRouting(),
      ]);
      if (states === null) throw new Error("Interface state unavailable — WAN address discovery failed; no quick-start changes were staged.");
      if (ifs === null) throw new Error("Interface configuration unavailable — WAN discovery failed; no quick-start changes were staged.");
      const inferred = inferWanGateway(ifs, states);
      if (!inferred.ok) throw new Error(inferred.error);
      const nextRouting = withDefaultRoute(curRouting, wanGateway(inferred.wan));

      const routingUpdated = await api.setRouting(nextRouting);
      if (!routingUpdated.ok) throw new Error(routingUpdated.error || "Failed to update routing configuration.");
      if (routingUpdated.warning) warnings.push(`routing: ${routingUpdated.warning}`);

      const sourceZones = new Set([...(nat.sourceZones ?? []), "lan", "mgmt"]);
      const natNext: NATConfig = {
        ...nat,
        enabled: true,
        egressZone: nat.egressZone || "wan",
        sourceZones: Array.from(sourceZones),
      };
      const natUpdated = await api.setNAT(natNext);
      if (!natUpdated.ok) throw new Error(natUpdated.error || "Failed to update NAT configuration.");
      if (natUpdated.warning) warnings.push(`nat: ${natUpdated.warning}`);

      const allowID = "allow-lan-wan";
      const existing = rules.find((r) => r.id === allowID) ?? null;
      const allowRule: FirewallRule = {
        id: allowID,
        description: "Quick start: allow LAN/MGMT to WAN",
        sourceZones: ["lan", "mgmt"],
        destZones: ["wan"],
        action: "ALLOW",
      };
      if (!existing) {
        const created = await api.createFirewallRule(allowRule);
        if (!created.ok) throw new Error(created.error || "Failed to create the LAN\u2192WAN allow rule.");
        if (created.warning) warnings.push(`firewall rule: ${created.warning}`);
      } else {
        const updated = await api.updateFirewallRule(allowID, allowRule);
        if (!updated.ok) throw new Error(updated.error || "Failed to update the LAN\u2192WAN allow rule.");
        if (updated.warning) warnings.push(`firewall rule: ${updated.warning}`);
      }

      setNotice(
        warnings.length > 0
          ? `Outbound quick start staged — commit to apply. Warnings: ${warnings.join(" | ")}`
          : `Outbound quick start staged — commit to apply: default route via ${WAN_GATEWAY_NAME}, SNAT (LAN+MGMT \u2192 WAN), and firewall allow rule '${allowID}'.`,
      );
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setQuickStarting(false);
    }
  }

  return (
    <Shell
      title="Firewall Rules"
      actions={
        <div className="flex items-center gap-2">
          {isAdmin() && (
            <button
              onClick={quickStartLanWanOutbound}
              disabled={quickStarting}
              className="rounded-xs border px-3 py-1.5 text-sm text-(--amber) transition-ui disabled:opacity-50"
              title="Best-effort: default route + SNAT + allow rule for LAN/MGMT \u2192 WAN"
            >
              {quickStarting ? "Enabling..." : "Quick start (LAN\u2192WAN)"}
            </button>
          )}
          <button
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <Card padding="md" className="mb-4">
        <EnforcementHealthIndicator health={health?.enforcement} />
        {installed.state === "loaded" && (
          <>
            <AppliedRulesetStatus status={installed.status} />
            <RuleWarningList scope="applied" warnings={installed.status.warnings} />
          </>
        )}
        <InstalledRulesetUnavailable view={installed} />
      </Card>
      <Card padding="md" className="mb-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="font-semibold text-(--text)">Outbound readiness</div>
          <div className="flex flex-wrap gap-2 text-xs">
            <StatusBadge variant={outboundStatus.hasDefaultRoute ? "success" : "warning"} dot>
              default route
            </StatusBadge>
            <StatusBadge variant={outboundStatus.natEnabled ? "success" : "warning"} dot>
              <Link href="/nat/" className="hover:underline">snat enabled</Link>
            </StatusBadge>
            <StatusBadge variant={outboundStatus.natEgress ? "success" : "warning"} dot>
              egress=wan
            </StatusBadge>
            <StatusBadge variant={outboundStatus.natHasLan ? "success" : "warning"} dot>
              src includes lan/mgmt
            </StatusBadge>
            <StatusBadge variant={outboundStatus.hasAllowLanWan ? "success" : "warning"} dot>
              {"allow lan\u2192wan"}
            </StatusBadge>
          </div>
        </div>
        {!outboundStatus.ok && (
          <div className="mt-2 text-xs text-(--text-muted)">
            {"To reach the Internet from LAN, you typically need a default route, a LAN\u2192WAN allow rule, and "}
            <Link href="/nat/" className="font-semibold text-(--text) hover:text-(--text)">SNAT</Link>
            {" out WAN. Use "}
            <span className="font-semibold text-(--text)">{"Quick start (LAN\u2192WAN)"}</span>
            {" to auto-configure these (including NAT)."}
          </div>
        )}
      </Card>
      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-4 rounded-xs border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {notice}
        </div>
      )}

      <Card padding="lg" className="mt-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-(--text)">nftables ruleset preview</h2>
            <p className="mt-1 text-xs text-(--text-muted)">
              Compile the candidate using the engine&apos;s current queue ownership, without applying it.
            </p>
          </div>
          {isAdmin() && (
            <button
              onClick={loadRulesetPreview}
              disabled={rulesetState === "loading"}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              {rulesetState === "loading" ? "Loading..." : "Preview"}
            </button>
          )}
        </div>
        {!isAdmin() && (
          <div className="mt-3 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
            View-only mode: ruleset preview requires admin access.
          </div>
        )}
        {rulesetState === "error" && (
          <div className="mt-3 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            Ruleset preview unavailable: {rulesetError}. A live engine must be reachable and able to compile the candidate. Try again after checking engine health and candidate settings.
          </div>
        )}
        {rulesetPreview?.runtime && (
          <p className="mt-3 text-xs text-(--text-muted)">
            {rulesetPreview.runtime.reason}.
            {rulesetPreview.ruleset && " Queue ownership is sampled at preview time; changes before commit can change IEC 104 steering."}
          </p>
        )}
        <RuleWarningList scope="candidate" warnings={rulesetPreview?.warnings} />
        {rulesetPreview?.ruleset && (
          <pre className="mt-4 max-h-[360px] overflow-auto rounded-xs border bg-(--surface) p-4 text-xs text-(--text)">
            {rulesetPreview.ruleset}
          </pre>
        )}
      </Card>

      <DPIConfigSection key={`dpi-${refreshKey}`} config={dpiConfig} health={health} onChange={setDpiConfig} />

      {isAdmin() && (
        <CreateRuleForm
          key={`create-${refreshKey}`}
          context={rules}
          zones={zones}
          globalMode={dpiConfig.dpiMode}
          tagsInUse={tagsInUse(rules)}
          onCreate={onCreate}
        />
      )}

      <div className="mt-6">
        {rules.some((r) => r.ics?.protocol) && <ICSCoverageNotice view={coverage.view} />}
      </div>
      <FirewallRuleTable
        rules={rules}
        zones={zones}
        dpiMode={dpiConfig.dpiMode}
        coverage={coverage.view}
        counters={counters}
        onEdit={setEditing}
        onDelete={(id) => {
          confirm.open({
            title: "Delete rule?",
            message: `Are you sure you want to delete rule "${id}"? This action cannot be undone.`,
            confirmLabel: "Delete",
            variant: "danger",
            onConfirm: () => onDelete(id),
          });
        }}
      />

      {editing && isAdmin() && (
        <EditRuleModal
          zones={zones}
          rule={rules.find((r) => r.id === editing.id) ?? editing}
          context={rules}
          globalMode={dpiConfig.dpiMode}
          tagsInUse={tagsInUse(rules, editing.id)}
          onClose={() => setEditing(null)}
          onSave={(patch) => onUpdate(editing.id, patch)}
        />
      )}
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
