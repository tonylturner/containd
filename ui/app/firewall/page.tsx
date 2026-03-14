"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  isAdmin,
  fetchDataPlane,
  setDataPlane,
  getRulesetPreview,
  type DataPlaneConfig,
  type DPIExclusion,
  type FirewallRule,
  type Gateway,
  type Interface,
  type InterfaceState,
  type RoutingConfig,
  type StaticRoute,
  type Zone,
  type NATConfig,
  type RulesetPreview,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";
import {
  firstHostInCIDR,
  pickWanCIDR,
  pickWanIface,
  zoneName,
} from "./firewall-utils";
import { DPIConfigSection } from "./firewall-dpi-config";
import { CreateRuleForm, EditRuleModal } from "./firewall-rule-forms";

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
  const [rulesetPreview, setRulesetPreview] = useState<RulesetPreview | null>(null);
  const [rulesetState, setRulesetState] = useState<"idle" | "loading" | "error">("idle");
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [quickStarting, setQuickStarting] = useState(false);
  const confirm = useConfirm();
  const tips: Tip[] = [
    {
      id: "firewall:zones",
      title: "Create zones first",
      body: (
        <>
          Define zones in{" "}
          <Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
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
          <Link href="/nat/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
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

  async function refresh() {
    const [r, z, n, rt, dp] = await Promise.all([
      api.listFirewallRules(),
      api.listZones(),
      api.getNAT(),
      api.getRouting(),
      fetchDataPlane(),
    ]);
    setRules(r ?? []);
    setZones(z ?? []);
    setNat(n ?? { enabled: false });
    setRouting(rt);
    if (dp) {
      setDpiConfig(dp);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function loadRulesetPreview() {
    if (!isAdmin()) return;
    setRulesetState("loading");
    const preview = await getRulesetPreview();
    if (!preview) {
      setRulesetState("error");
      return;
    }
    setRulesetPreview(preview);
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
    setNotice(result.warning ? `Rule deleted with warning: ${result.warning}` : "Rule deleted.");
    refresh();
  }

  async function onCreate(rule: FirewallRule) {
    setError(null);
    setNotice(null);
    const created = await api.createFirewallRule(rule);
    if (!created.ok) {
      setError(created.error || "Failed to create rule (check zones/CIDRs).");
      return;
    }
    setNotice(created.warning ? `Rule created with warning: ${created.warning}` : "Rule created.");
    refresh();
  }

  async function onUpdate(id: string, patch: Partial<FirewallRule>) {
    setError(null);
    setNotice(null);
    const updated = await api.updateFirewallRule(id, patch);
    if (!updated.ok) {
      setError(updated.error || "Failed to update rule.");
      return;
    }
    setEditing(null);
    setNotice(updated.warning ? `Rule updated with warning: ${updated.warning}` : "Rule updated.");
    refresh();
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
      const wanIface = pickWanIface(ifs ?? []);
      if (!wanIface) throw new Error("Could not determine WAN interface (expected an interface named 'wan' or in zone 'wan').");
      const wanState = (states ?? []).find((s) => s.name === wanIface.name) ?? null;
      const wanCIDR = pickWanCIDR(wanState);
      if (!wanCIDR) {
        throw new Error(
          `Could not determine WAN IPv4 address for '${wanIface.name}'. If you're using DHCP in Docker, restart the container so Docker assigns an IP at startup.`,
        );
      }
      const inferredGw = firstHostInCIDR(wanCIDR);
      if (!inferredGw) throw new Error(`Could not infer a WAN gateway from '${wanCIDR}'.`);

      const gwName = "wan-gw";
      const nextGateway: Gateway = {
        name: gwName,
        address: inferredGw,
        iface: wanIface.name,
        description: "Auto (WAN) from OS address",
      };

      const nextRouting: RoutingConfig = {
        gateways: curRouting?.gateways ?? [],
        routes: curRouting?.routes ?? [],
        rules: curRouting?.rules ?? [],
      };

      const existingGwIdx = (nextRouting.gateways ?? []).findIndex((g) => g.name === gwName);
      nextRouting.gateways =
        existingGwIdx >= 0
          ? (nextRouting.gateways ?? []).map((g, i) => (i === existingGwIdx ? nextGateway : g))
          : [...(nextRouting.gateways ?? []), nextGateway];

      const isDefaultDst = (dst: string) => {
        const d = dst.trim().toLowerCase();
        return d === "default" || d === "0.0.0.0/0";
      };
      const routes = nextRouting.routes ?? [];
      const existingDefaultIdx = routes.findIndex((r) => isDefaultDst(r.dst) && (r.table ?? 0) === 0);
      const nextDefault: StaticRoute = { dst: "default", gateway: gwName, iface: wanIface.name, table: 0 };
      nextRouting.routes =
        existingDefaultIdx >= 0 ? routes.map((r, i) => (i === existingDefaultIdx ? nextDefault : r)) : [...routes, nextDefault];

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
          ? `Enabled outbound quick start with warnings: ${warnings.join(" | ")}`
          : `Enabled outbound quick start: default route via ${gwName}, SNAT (LAN+MGMT \u2192 WAN), and firewall allow rule '${allowID}'.`,
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
              className="rounded-sm border border-amber-500/30 bg-amber-500/[0.1] px-3 py-1.5 text-sm text-[var(--amber)] transition-ui hover:brightness-110/15 disabled:opacity-50"
              title="Best-effort: default route + SNAT + allow rule for LAN/MGMT \u2192 WAN"
            >
              {quickStarting ? "Enabling..." : "Quick start (LAN\u2192WAN)"}
            </button>
          )}
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <Card padding="md" className="mb-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="font-semibold text-[var(--text)]">Outbound readiness</div>
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
          <div className="mt-2 text-xs text-[var(--text-muted)]">
            {"To reach the Internet from LAN, you typically need a default route, a LAN\u2192WAN allow rule, and "}
            <Link href="/nat/" className="font-semibold text-[var(--text)] hover:text-[var(--text)]">SNAT</Link>
            {" out WAN. Use "}
            <span className="font-semibold text-[var(--text)]">{"Quick start (LAN\u2192WAN)"}</span>
            {" to auto-configure these (including NAT)."}
          </div>
        )}
      </Card>
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-4 rounded-sm border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {notice}
        </div>
      )}

      <Card padding="lg" className="mt-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">nftables ruleset preview</h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Preview the compiled ruleset before it is applied to the dataplane.
            </p>
          </div>
          {isAdmin() && (
            <button
              onClick={loadRulesetPreview}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
            >
              {rulesetState === "loading" ? "Loading..." : "Preview"}
            </button>
          )}
        </div>
        {!isAdmin() && (
          <div className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
            View-only mode: ruleset preview requires admin access.
          </div>
        )}
        {rulesetState === "error" && (
          <div className="mt-3 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            Failed to load ruleset preview.
          </div>
        )}
        {rulesetPreview?.engineStatusError && (
          <div className="mt-3 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            Engine status unavailable: {rulesetPreview.engineStatusError}
          </div>
        )}
        {rulesetPreview?.ruleset && (
          <pre className="mt-4 max-h-[360px] overflow-auto rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 text-xs text-[var(--text)]">
            {rulesetPreview.ruleset}
          </pre>
        )}
      </Card>

      <DPIConfigSection config={dpiConfig} onChange={setDpiConfig} />

      {isAdmin() && <CreateRuleForm zones={zones} onCreate={onCreate} />}

      <div className="mt-6 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
              <tr key={r.id} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">{r.id}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.description || "\u2014"}</td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {(r.sourceZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}{" \u2192 "}
                  {(r.destZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {(r.protocols ?? []).map((p) => `${p.name}${p.port ? ":" + p.port : ""}`).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {r.ics?.protocol ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge variant="neutral">
                        {r.ics.mode === "learn" ? "safe learning" : "enforce"}
                      </StatusBadge>
                      <span className="text-xs text-[var(--text)]">
                        {r.ics.protocol} fc={(r.ics.functionCode ?? []).join(",") || "*"}
                      </span>
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
                    <span className="text-xs text-[var(--text-muted)]">&mdash;</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  {isAdmin() && (
                    <>
                      <button onClick={() => setEditing(r)} className="mr-2 rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]">Edit</button>
                      <button
                        onClick={() => {
                          confirm.open({
                            title: "Delete rule?",
                            message: `Are you sure you want to delete rule "${r.id}"? This action cannot be undone.`,
                            confirmLabel: "Delete",
                            variant: "danger",
                            onConfirm: () => onDelete(r.id),
                          });
                        }}
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

      {editing && isAdmin() && (
        <EditRuleModal
          zones={zones}
          rule={editing}
          onClose={() => setEditing(null)}
          onSave={(patch) => onUpdate(editing.id, patch)}
        />
      )}
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
