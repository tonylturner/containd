"use client";

import { revisionError } from "../../lib/config-revision";

import type { ConfigBase } from "../../lib/config-boundary";

import { matchingRevisions, useConfigView } from "../../lib/use-config-revision";

import { useConfigLoad } from "../../lib/use-config-editor";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  isAdmin,
  fetchDataPlane,
  setDataPlane,
  getRulesetPreview,
  type DataPlaneConfig,
  type FirewallRule,
  type FirewallRuleCreate,
  type Position,
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
import { effectiveDefaultAction, type DefaultAction } from "./firewall-default-row";
import { tagsInUse } from "./firewall-rule-policy";
import type { CountersState } from "./firewall-rule-counters";
import { useICSCoverage } from "../ics/use-ics-coverage";
import { useShadowCounters } from "../ics/ics-shadow-counters";
import { useHealth } from "../../hooks/useHealth";
import { useInstalledRuleset } from "../../hooks/useInstalledRuleset";

// This page should own firewall page orchestration and top-level state.
// Large forms, modals, and static protocol metadata belong in sibling modules
// under ui/app/firewall/ as they become non-trivial.

function insertCreatedRule(rows: FirewallRule[], saved: FirewallRule & { index: number }): FirewallRule[] {
  const { index, ...rule } = saved;
  const next = rows.filter(row => row.id !== rule.id);
  next.splice(index, 0, rule);
  return next;
}

export default function FirewallPage() {
  const configView = useConfigView({ rules: [] as FirewallRule[], zones: [] as Zone[],
    defaultAction: "unknown" as DefaultAction,
    nat: { enabled: false } as NATConfig, routing: null as RoutingConfig | null,
    dpiConfig: { captureInterfaces: [], dpiMock: false } as DataPlaneConfig });
  const { readConfig, write, revisionNotice } = configView;
  const { rules, defaultAction, zones, nat, routing, dpiConfig } = configView.data;
  const viewRevision = configView.state.baseRevision ?? "";
  const { canSave, canSaveNow, loadError, checkLoaded } = useConfigLoad();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [counters, setCounters] = useState<CountersState>(null);
  const [rulesetPreview, setRulesetPreview] = useState<RulesetPreview | null>(null);
  const [rulesetState, setRulesetState] = useState<"idle" | "loading" | "error">("idle");
  const [rulesetError, setRulesetError] = useState("");
  const coverage = useICSCoverage();
  const shadow = useShadowCounters();
  const health = useHealth();
  const installed = useInstalledRuleset();
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [quickStarting, setQuickStarting] = useState(false);
  const [moving, setMoving] = useState(false);
  // Forward links may arrive before the asynchronously loaded row exists.
  useEffect(() => {
    const target = rules.find((r) => `#${encodeURIComponent(`rule-${r.id}`)}` === window.location.hash);
    if (target) document.getElementById(`rule-${target.id}`)?.scrollIntoView({ block: "center" });
  }, [rules]);
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
    const [rSnapshot, zSnapshot, nSnapshot, rtSnapshot, dpSnapshot, c, candidate] = await Promise.all([api.listFirewallRules(), api.listZones(), api.getNAT(), api.getRouting(), fetchDataPlane(), api.getRuleCounters(), api.getCandidateConfig()]);
    if (!matchingRevisions(rSnapshot, zSnapshot, nSnapshot, rtSnapshot, dpSnapshot)) { checkLoaded(null); return; }
    if (!checkLoaded(rSnapshot && zSnapshot && nSnapshot && rtSnapshot && dpSnapshot)) return;
    readConfig({ data: { rules: rSnapshot!.data,
      defaultAction: matchingRevisions(rSnapshot, candidate) ? effectiveDefaultAction(candidate!.data) : "unknown",
      zones: zSnapshot!.data, nat: nSnapshot!.data,
      routing: rtSnapshot!.data, dpiConfig: dpSnapshot!.data }, revision: rSnapshot!.revision }, keepEdits);
    setCounters(c);
    if (!keepEdits) {
      setEditing(null);
      setRefreshKey((key) => key + 1);
    }
  }, [checkLoaded, readConfig]));

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
    if (!canSaveNow()) return;
    setError(null);
    setNotice(null);
    const result = await write(base => api.deleteFirewallRule(base, id), { patch: view => ({ ...view, rules: view.rules.filter(row => row.id !== id) }) });
    if (!result.ok) {
      setError(revisionError(result));
      return;
    }
    setNotice(result.warning ? `Rule staged — commit to apply. Warning: ${result.warning}` : "Rule staged — commit to apply.");
    refresh();
  }

  async function onMove(id: string, position: Position) {
    if (!canSaveNow() || moving) return;
    setMoving(true);
    setError(null);
    setNotice(null);
    const result = await write(base => api.moveFirewallRule(base, id, position), { patch: (view, data) => ({ ...view, rules: data.rules }) });
    setMoving(false);
    if (!result.ok) {
      setError(revisionError(result));
      return;
    }
    setRulesetPreview(null);
    setNotice(`Rule moved to position ${result.data.index + 1} — commit to apply.${result.warning ? ` Warning: ${result.warning}` : ""}`);
  }

  async function onCreate(rule: FirewallRuleCreate, revision: ConfigBase) {
    if (!canSaveNow()) return null;
    setError(null);
    setNotice(null);
    const created = await configView.writer((base, input: FirewallRuleCreate) => api.createFirewallRule(base, input),
      (view, saved) => ({ ...view, rules: insertCreatedRule(view.rules, saved) }))(revision, rule);
    if (!created.ok) {
      setError(revisionError(created));
      return created;
    }
    setNotice(created.warning ? `Rule staged — commit to apply. Warning: ${created.warning}` : "Rule staged — commit to apply.");
    refresh();
    return created;
  }

  async function onUpdate(id: string, patch: FirewallRulePatch, revision: ConfigBase) {
    if (!canSaveNow()) return null;
    setError(null);
    setNotice(null);
    const updated = await configView.writer((base, input: FirewallRulePatch) => api.updateFirewallRule(base, id, input),
      (view, saved) => ({ ...view, rules: view.rules.map(row => row.id === saved.id ? saved : row) }))(revision, patch);
    if (!updated.ok) {
      setError(revisionError(updated));
      return updated;
    }
    setNotice(updated.warning ? `Rule staged — commit to apply. Warning: ${updated.warning}` : "Rule staged — commit to apply.");
    refresh();
    return updated;
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
    if (!canSaveNow()) return;
    setQuickStarting(true);
    try {
      const warnings: string[] = [];
      const [ifsSnapshot, states, curRoutingSnapshot] = await Promise.all([api.listInterfaces(), api.listInterfaceState(), api.getRouting()]);
      const ifs = ifsSnapshot?.data ?? null;
      const curRouting = curRoutingSnapshot?.data ?? null;
      if (curRouting === null) {
        checkLoaded(null);
        throw new Error("Routing configuration unavailable; no quick-start changes were staged.");
      }
      if (states === null) throw new Error("Interface state unavailable — WAN address discovery failed; no quick-start changes were staged.");
      if (ifs === null) throw new Error("Interface configuration unavailable — WAN discovery failed; no quick-start changes were staged.");
      if (!matchingRevisions(ifsSnapshot, curRoutingSnapshot) || curRoutingSnapshot?.revision !== viewRevision) throw new Error("Configuration changed since you loaded it. Refresh and review before quick start.");
      const inferred = inferWanGateway(ifs, states);
      if (!inferred.ok) throw new Error(inferred.error);
      const nextRouting = withDefaultRoute(curRouting, wanGateway(inferred.wan));

      const routingUpdated = await write(base => base === curRoutingSnapshot?.revision
        ? api.setRouting(base, nextRouting) : Promise.resolve({ ok: false as const, error: "Configuration changed during discovery. Refresh and review before quick start." }),
        { patch: (view, data) => ({ ...view, routing: data }) });
      if (!routingUpdated.ok) { setError(revisionError(routingUpdated)); return; }
      if (!routingUpdated.adopted) return;
      if (routingUpdated.warning) warnings.push(`routing: ${routingUpdated.warning}`);

      const natUpdated = await write((base, view) => api.setNAT(base, {
        ...view.nat, enabled: true, egressZone: view.nat.egressZone || "wan",
        sourceZones: Array.from(new Set([...(view.nat.sourceZones ?? []), "lan", "mgmt"])),
      }), { patch: (view, data) => ({ ...view, nat: data }) });
      if (!natUpdated.ok) { setError(revisionError(natUpdated)); return; }
      if (!natUpdated.adopted) return;
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
        const created = await write(base => api.createFirewallRule(base, allowRule), { patch: (view, data) => ({ ...view, rules: insertCreatedRule(view.rules, data) }) });
        if (!created.ok) { setError(revisionError(created)); return; }
        if (created.warning) warnings.push(`firewall rule: ${created.warning}`);
      } else {
        const updated = await write(base => api.updateFirewallRule(base, allowID, allowRule), { patch: (view, data) => ({ ...view, rules: view.rules.map(row => row.id === data.id ? data : row) }) });
        if (!updated.ok) { setError(revisionError(updated)); return; }
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
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin() && (
            <button
              onClick={quickStartLanWanOutbound}
              disabled={quickStarting || !canSave}
              className="rounded-xs border px-3 py-1.5 text-sm text-(--amber) transition-ui disabled:opacity-50"
              title="Best-effort: default route + SNAT + allow rule for LAN/MGMT \u2192 WAN"
            >
              {quickStarting ? "Enabling..." : "Quick start (LAN\u2192WAN)"}
            </button>
          )}
          <button
            onClick={() => { void refresh({ keepEdits: false }); void shadow.reload(); }}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
        </div>
      }
    >
      {revisionNotice(() => refresh({ keepEdits: false }))}
      {!isAdmin() && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <Card padding="md" className="mb-4">
        <div className="flex flex-wrap items-start gap-x-4 gap-y-2">
          <EnforcementHealthIndicator health={health?.enforcement} />
          {installed.state === "loaded" && (
            <>
              <AppliedRulesetStatus status={installed.status} />
              <RuleWarningList scope="applied" warnings={installed.status.warnings} />
            </>
          )}
          <InstalledRulesetUnavailable view={installed} />
        </div>
        {health?.enforcement?.state !== "enforcing" && health?.enforcement?.reason && <p className="mt-2 break-words text-xs text-amber">{health.enforcement.reason}</p>}
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
              Source zones include lan/mgmt
            </StatusBadge>
            <StatusBadge variant={outboundStatus.hasAllowLanWan ? "success" : "warning"} dot>
              {"allow lan\u2192wan present"}
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
            {" Rule presence does not guarantee delivery: an earlier enforcing rule can shadow an allow."}
          </div>
        )}
      </Card>
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
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

      <div className="min-w-0">
        <div className="mt-6">
          {rules.some((r) => r.ics?.protocol) && <ICSCoverageNotice view={coverage.view} />}
        </div>
        <FirewallRuleTable
          available={canSave}
          rules={rules}
          defaultAction={canSave ? defaultAction : "unknown"}
          zones={zones}
          shadowCounters={shadow.counters}
          dpiMode={dpiConfig.dpiMode}
          coverage={coverage.view}
          counters={counters}
          onMove={onMove}
          moving={moving}
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

        {isAdmin() && (
          <div className="mt-4">
            <button type="button" disabled={!canSave} aria-expanded={showCreate} aria-controls="create-rule-panel" onClick={() => setShowCreate(!showCreate)}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text)">Create rule</button>
            <div id="create-rule-panel" hidden={!showCreate}>
              <CreateRuleForm
                available={canSave}
                revision={viewRevision}
                key={`create-${refreshKey}`}
                context={rules}
                zones={zones}
                forwards={nat.portForwards ?? []}
                globalMode={dpiConfig.dpiMode}
                tagsInUse={tagsInUse(rules)}
                onCreate={onCreate}
              />
            </div>
          </div>
        )}

        {editing && isAdmin() && (
          <EditRuleModal
            available={canSave}
            revision={viewRevision}
            zones={zones}
            forwards={nat.portForwards ?? []}
            rule={rules.find((r) => r.id === editing.id) ?? editing}
            context={rules}
            globalMode={dpiConfig.dpiMode}
            tagsInUse={tagsInUse(rules, editing.id)}
            onClose={() => setEditing(null)}
            onSave={(patch, revision) => onUpdate(editing.id, patch, revision)}
          />
        )}
      </div>
      <DPIConfigSection key={`dpi-${refreshKey}`} config={dpiConfig} revision={viewRevision} available={canSave} health={health} onSave={update => write((base, view) => setDataPlane(base, update(view.dpiConfig)), { patch: (view, data) => ({ ...view, dpiConfig: data }) })}
        onSaveDraft={configView.writer((base, updated: DataPlaneConfig) => setDataPlane(base, updated), (view, data) => ({ ...view, dpiConfig: data }))} />

      <Card padding="lg" className="mt-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-(--text)">Generated firewall configuration (nftables)</h2>
            <p className="mt-1 text-xs text-(--text-muted)">
              Preview the low-level configuration for your saved changes without activating it.
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
            Preview unavailable. Check appliance health and saved settings.
            <p className="mt-2 break-words text-xs">{rulesetError}</p>
          </div>
        )}
        {rulesetPreview?.runtime && (
          <div className="mt-3 text-xs text-(--text-muted)">
            <p className="break-words">{rulesetPreview.runtime.reason}.</p>
            {rulesetPreview.ruleset && <p>Queue ownership is sampled at preview time; changes before commit can change IEC 104 steering.</p>}
          </div>
        )}
        <RuleWarningList scope="candidate" warnings={rulesetPreview?.warnings} />
        {rulesetPreview?.ruleset && (
          <section aria-label="Advanced" className="mt-4 text-xs text-(--text)">
            <h3 className="mb-2 font-semibold">Advanced</h3>
            <details>
              <summary className="cursor-pointer">Generated ruleset</summary>
              <pre className="mt-2 max-h-[360px] overflow-auto rounded-xs border bg-(--surface) p-4">
                {rulesetPreview.ruleset}
              </pre>
            </details>
          </section>
        )}
      </Card>

      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
