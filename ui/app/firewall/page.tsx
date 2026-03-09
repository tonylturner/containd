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
  type FirewallRule,
  type Gateway,
  type Interface,
  type InterfaceState,
  type Protocol,
  type RoutingConfig,
  type StaticRoute,
  type Zone,
  type ICSPredicate,
  type NATConfig,
  type RulesetPreview,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { InfoTip } from "../../components/InfoTip";
import { validateIPOrCIDRList } from "../../lib/validate";

/* ── ICS protocol metadata for firewall rule modals ───────────── */

const ICS_PROTOCOLS: Record<string, { label: string; fcLabel: string; fcPlaceholder: string; addrLabel: string; addrPlaceholder: string; showUnitId?: boolean; showObjectClasses?: boolean }> = {
  modbus: { label: "Modbus/TCP", fcLabel: "Function codes", fcPlaceholder: "3, 16", addrLabel: "Register addresses", addrPlaceholder: "0-100", showUnitId: true },
  dnp3: { label: "DNP3", fcLabel: "Function codes", fcPlaceholder: "1, 2, 3", addrLabel: "Addresses", addrPlaceholder: "1-10" },
  cip: { label: "CIP / EtherNet/IP", fcLabel: "Service codes", fcPlaceholder: "76, 77", addrLabel: "CIP path addresses", addrPlaceholder: "", showObjectClasses: true },
  s7comm: { label: "S7comm (Siemens)", fcLabel: "Function codes", fcPlaceholder: "4, 5", addrLabel: "DB / variable addresses", addrPlaceholder: "" },
  mms: { label: "IEC 61850 MMS", fcLabel: "Service codes", fcPlaceholder: "", addrLabel: "Variable names", addrPlaceholder: "" },
  bacnet: { label: "BACnet/IP", fcLabel: "Service choices", fcPlaceholder: "12, 15", addrLabel: "Object instance", addrPlaceholder: "" },
  opcua: { label: "OPC UA", fcLabel: "Service node IDs", fcPlaceholder: "", addrLabel: "Node IDs", addrPlaceholder: "" },
};

const ICS_PROTOCOL_KEYS = Object.keys(ICS_PROTOCOLS);

function icsProtoMeta(name: string) {
  return ICS_PROTOCOLS[name] ?? { label: name, fcLabel: "Function codes", fcPlaceholder: "", addrLabel: "Addresses", addrPlaceholder: "" };
}

function zoneLabel(zone: Zone): string {
  return zone.alias ? `${zone.alias} (${zone.name})` : zone.name;
}

function zoneName(zones: Zone[], name: string): string {
  const match = zones.find((z) => z.name === name);
  return match ? zoneLabel(match) : name;
}

function ip4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

function intToIP4(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

function maskFromPrefix(prefix: number): number | null {
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function firstHostInCIDR(cidr: string): string | null {
  const raw = cidr.trim();
  const slash = raw.lastIndexOf("/");
  if (slash <= 0) return null;
  const ip = raw.slice(0, slash);
  const pfx = Number(raw.slice(slash + 1));
  const ipInt = ip4ToInt(ip);
  const mask = maskFromPrefix(pfx);
  if (ipInt == null || mask == null) return null;
  const net = ipInt & mask;
  const first = (net + 1) >>> 0;
  return intToIP4(first);
}

function pickWanIface(ifs: Interface[]): Interface | null {
  const byName = ifs.find((i) => i.name === "wan");
  if (byName) return byName;
  const byZone = ifs.find((i) => (i.zone || "").toLowerCase() === "wan");
  return byZone ?? null;
}

function pickWanCIDR(state: InterfaceState | null): string | null {
  if (!state) return null;
  for (const addr of state.addrs || []) {
    const s = String(addr);
    if (!s.includes("/")) continue;
    if (s.includes(":")) continue;
    if (s.startsWith("169.254.")) continue;
    return s;
  }
  return null;
}

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [nat, setNat] = useState<NATConfig>({ enabled: false });
  const [routing, setRouting] = useState<RoutingConfig | null>(null);
  const [dpiConfig, setDpiConfig] = useState<DataPlaneConfig>({ captureInterfaces: [], dpiMock: false });
  const [dpiSaveState, setDpiSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [rulesetPreview, setRulesetPreview] = useState<RulesetPreview | null>(null);
  const [rulesetState, setRulesetState] = useState<"idle" | "loading" | "error">("idle");
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [quickStarting, setQuickStarting] = useState(false);
  const tips: Tip[] = [
    {
      id: "firewall:zones",
      title: "Create zones first",
      body: (
        <>
          Define zones in{" "}
          <Link href="/zones/" className="font-semibold text-mint hover:text-mint/80">
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
          <Link href="/nat/" className="font-semibold text-mint hover:text-mint/80">
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
      setDpiConfig({
        captureInterfaces: dp.captureInterfaces ?? [],
        dpiMock: dp.dpiMock ?? false,
      });
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
    const ok = await api.deleteFirewallRule(id);
    if (!ok) {
      setError("Failed to delete rule.");
      return;
    }
    refresh();
  }

  async function onCreate(rule: FirewallRule) {
    setError(null);
    const created = await api.createFirewallRule(rule);
    if (!created) {
      setError("Failed to create rule (check zones/CIDRs).");
      return;
    }
    refresh();
  }

  async function onUpdate(id: string, patch: Partial<FirewallRule>) {
    setError(null);
    const updated = await api.updateFirewallRule(id, patch);
    if (!updated) {
      setError("Failed to update rule.");
      return;
    }
    setEditing(null);
    refresh();
  }
  async function saveDpiConfig() {
    if (!isAdmin()) return;
    setDpiSaveState("saving");
    const saved = await setDataPlane({
      captureInterfaces: dpiConfig.captureInterfaces ?? [],
      dpiMock: dpiConfig.dpiMock ?? false,
    });
    setDpiSaveState(saved ? "saved" : "error");
    setTimeout(() => setDpiSaveState("idle"), 1500);
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
    if (
      typeof window !== "undefined" &&
      !window.confirm(
        "This will attempt to enable outbound Internet for LAN/MGMT \u2192 WAN by:\n\n\u2022 creating/updating a WAN gateway + default route (best-effort)\n\u2022 enabling SNAT (masquerade) for LAN+MGMT out WAN\n\u2022 creating an ALLOW firewall rule for LAN+MGMT \u2192 WAN\n\nNote: NAT settings will also be configured (see the NAT page).\n\nContinue?",
      )
    ) {
      return;
    }
    setQuickStarting(true);
    try {
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
      if (!routingUpdated) throw new Error("Failed to update routing configuration.");

      const sourceZones = new Set([...(nat.sourceZones ?? []), "lan", "mgmt"]);
      const natNext: NATConfig = {
        ...nat,
        enabled: true,
        egressZone: nat.egressZone || "wan",
        sourceZones: Array.from(sourceZones),
      };
      const natUpdated = await api.setNAT(natNext);
      if (!natUpdated) throw new Error("Failed to update NAT configuration.");

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
        if (!created) throw new Error("Failed to create the LAN\u2192WAN allow rule.");
      } else {
        const updated = await api.updateFirewallRule(allowID, allowRule);
        if (!updated) throw new Error("Failed to update the LAN\u2192WAN allow rule.");
      }

      setNotice(`Enabled outbound quick start: default route via ${gwName}, SNAT (LAN+MGMT \u2192 WAN), and firewall allow rule '${allowID}'.`);
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
              className="rounded-lg border border-mint/30 bg-mint/10 px-3 py-1.5 text-sm text-mint hover:bg-mint/15 disabled:opacity-50"
              title="Best-effort: default route + SNAT + allow rule for LAN/MGMT \u2192 WAN"
            >
              {quickStarting ? "Enabling..." : "Quick start (LAN\u2192WAN)"}
            </button>
          )}
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <div className="mb-4 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="font-semibold text-white">Outbound readiness</div>
          <div className="flex flex-wrap gap-2 text-xs">
            <span className={outboundStatus.hasDefaultRoute ? "rounded-md bg-mint/15 px-2 py-1 text-mint" : "rounded-md bg-amber/15 px-2 py-1 text-amber"}>
              default route
            </span>
            <span className={outboundStatus.natEnabled ? "rounded-md bg-mint/15 px-2 py-1 text-mint" : "rounded-md bg-amber/15 px-2 py-1 text-amber"}>
              <Link href="/nat/" className="hover:underline">snat enabled</Link>
            </span>
            <span className={outboundStatus.natEgress ? "rounded-md bg-mint/15 px-2 py-1 text-mint" : "rounded-md bg-amber/15 px-2 py-1 text-amber"}>
              egress=wan
            </span>
            <span className={outboundStatus.natHasLan ? "rounded-md bg-mint/15 px-2 py-1 text-mint" : "rounded-md bg-amber/15 px-2 py-1 text-amber"}>
              src includes lan/mgmt
            </span>
            <span className={outboundStatus.hasAllowLanWan ? "rounded-md bg-mint/15 px-2 py-1 text-mint" : "rounded-md bg-amber/15 px-2 py-1 text-amber"}>
              {"allow lan\u2192wan"}
            </span>
          </div>
        </div>
        {!outboundStatus.ok && (
          <div className="mt-2 text-xs text-slate-400">
            {"To reach the Internet from LAN, you typically need a default route, a LAN\u2192WAN allow rule, and "}
            <Link href="/nat/" className="font-semibold text-slate-200 hover:text-white">SNAT</Link>
            {" out WAN. Use "}
            <span className="font-semibold text-slate-200">{"Quick start (LAN\u2192WAN)"}</span>
            {" to auto-configure these (including NAT)."}
          </div>
        )}
      </div>
      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-4 rounded-xl border border-mint/30 bg-mint/10 px-4 py-3 text-sm text-mint">
          {notice}
        </div>
      )}

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">nftables ruleset preview</h2>
            <p className="mt-1 text-xs text-slate-400">
              Preview the compiled ruleset before it is applied to the dataplane.
            </p>
          </div>
          {isAdmin() && (
            <button
              onClick={loadRulesetPreview}
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
            >
              {rulesetState === "loading" ? "Loading..." : "Preview"}
            </button>
          )}
        </div>
        {!isAdmin() && (
          <div className="mt-3 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
            View-only mode: ruleset preview requires admin access.
          </div>
        )}
        {rulesetState === "error" && (
          <div className="mt-3 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
            Failed to load ruleset preview.
          </div>
        )}
        {rulesetPreview?.engineStatusError && (
          <div className="mt-3 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
            Engine status unavailable: {rulesetPreview.engineStatusError}
          </div>
        )}
        {rulesetPreview?.ruleset && (
          <pre className="mt-4 max-h-[360px] overflow-auto rounded-xl border border-white/10 bg-black/60 p-4 text-xs text-slate-200">
            {rulesetPreview.ruleset}
          </pre>
        )}
      </div>

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">DPI capture (required for ICS filters)</h2>
            <p className="mt-1 text-xs text-slate-400">
              DPI capture is configured here; PCAP storage is managed separately.
            </p>
          </div>
          {isAdmin() && (
            <button
              onClick={saveDpiConfig}
              className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
            >
              {dpiSaveState === "saving" ? "Saving..." : "Save"}
            </button>
          )}
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-400">
              Capture interfaces
              <InfoTip label="Comma-separated interfaces to inspect for DPI (e.g., lan2, lan3)." />
            </label>
            <input
              value={(dpiConfig.captureInterfaces ?? []).join(", ")}
              disabled={!isAdmin()}
              onChange={(e) =>
                setDpiConfig((c) => ({
                  ...c,
                  captureInterfaces: e.target.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="lan2, lan3"
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={dpiConfig.dpiMock ?? false}
              disabled={!isAdmin()}
              onChange={(e) => setDpiConfig((c) => ({ ...c, dpiMock: e.target.checked }))}
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            Safe learning lab mode (DPI inspect-all)
            <InfoTip label="Lab-only: emit synthetic Modbus events for learning and UI visibility." />
          </label>
        </div>
        {!isAdmin() && (
          <div className="mt-2 text-xs text-slate-400">View-only mode: DPI capture settings are read-only.</div>
        )}
      </div>

      {isAdmin() && <CreateRuleForm zones={zones} onCreate={onCreate} />}

      <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocols</th>
              <th className="px-4 py-3">ICS Filter</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={7}>
                  No firewall rules configured. Create rules below to control traffic between zones.
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id} className="border-t border-white/5">
                <td className="px-4 py-3 font-mono text-xs text-white">{r.id}</td>
                <td className="px-4 py-3 text-slate-200">{r.description || "\u2014"}</td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.sourceZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}{" \u2192 "}
                  {(r.destZones ?? []).map((z) => zoneName(zones, z)).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.protocols ?? []).map((p) => `${p.name}${p.port ? ":" + p.port : ""}`).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {r.ics?.protocol ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs">
                        {r.ics.mode === "learn" ? "safe learning" : "enforce"}
                      </span>
                      <span className="text-xs text-slate-300">
                        {r.ics.protocol} fc={(r.ics.functionCode ?? []).join(",") || "*"}
                      </span>
                    </div>
                  ) : "\u2014"}
                </td>
                <td className="px-4 py-3">
                  <span className={r.action === "ALLOW" ? "rounded-full bg-mint/20 px-2 py-0.5 text-xs text-mint" : "rounded-full bg-amber/20 px-2 py-0.5 text-xs text-amber"}>
                    {r.action}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  {isAdmin() && (
                    <>
                      <button onClick={() => setEditing(r)} className="mr-2 rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10">Edit</button>
                      <button onClick={() => onDelete(r.id)} className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30">Delete</button>
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
    </Shell>
  );
}

function EditRuleModal({
  zones,
  rule,
  onClose,
  onSave,
}: {
  zones: Zone[];
  rule: FirewallRule;
  onClose: () => void;
  onSave: (patch: Partial<FirewallRule>) => void;
}) {
  const [description, setDescription] = useState(rule.description ?? "");
  const [action, setAction] = useState<"ALLOW" | "DENY">(rule.action);
  const [srcZone, setSrcZone] = useState((rule.sourceZones ?? [])[0] ?? "");
  const [dstZone, setDstZone] = useState((rule.destZones ?? [])[0] ?? "");
  const [sources, setSources] = useState((rule.sources ?? []).join(", "));
  const [destinations, setDestinations] = useState((rule.destinations ?? []).join(", "));
  const [proto, setProto] = useState((rule.protocols ?? [])[0]?.name ?? "tcp");
  const [port, setPort] = useState((rule.protocols ?? [])[0]?.port ?? "");
  const [icsEnabled, setIcsEnabled] = useState(!!rule.ics?.protocol);
  const [icsProtocol, setIcsProtocol] = useState(rule.ics?.protocol ?? "modbus");
  const [functionCodes, setFunctionCodes] = useState((rule.ics?.functionCode ?? []).join(", ") || "3,16");
  const [addresses, setAddresses] = useState((rule.ics?.addresses ?? []).join(", ") || "0-100");
  const [icsUnitId, setIcsUnitId] = useState(rule.ics?.unitId?.toString() ?? "");
  const [objectClasses, setObjectClasses] = useState((rule.ics?.objectClasses ?? []).map((v) => "0x" + v.toString(16)).join(", "));
  const [readOnly, setReadOnly] = useState(rule.ics?.readOnly ?? false);
  const [writeOnly, setWriteOnly] = useState(rule.ics?.writeOnly ?? false);
  const [mode, setMode] = useState<"enforce" | "learn">(rule.ics?.mode ?? "learn");

  const icsMeta = icsProtoMeta(icsProtocol);

  function save() {
    const protocols: Protocol[] = proto ? [{ name: proto, port: port.trim() || undefined }] : [];
    let ics: ICSPredicate | undefined;
    if (icsEnabled) {
      ics = {
        protocol: icsProtocol,
        functionCode: functionCodes.split(",").map((v) => Number(v.trim())).filter((n) => Number.isFinite(n)).map((n) => Math.max(0, Math.min(255, n))),
        addresses: addresses.split(",").map((s) => s.trim()).filter(Boolean),
        readOnly,
        writeOnly,
        mode,
      };
      if (icsMeta.showUnitId && icsUnitId.trim()) {
        const uid = Number(icsUnitId.trim());
        if (Number.isFinite(uid) && uid >= 0 && uid <= 255) ics.unitId = uid;
      }
      if (icsMeta.showObjectClasses && objectClasses.trim()) {
        ics.objectClasses = objectClasses.split(",").map((s) => s.trim()).filter(Boolean).map((s) => parseInt(s, s.startsWith("0x") ? 16 : 10)).filter((n) => Number.isFinite(n) && n >= 0);
      }
      if ((ics.functionCode?.length ?? 0) === 0) delete ics.functionCode;
      if ((ics.addresses?.length ?? 0) === 0) delete ics.addresses;
      if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;
    }
    onSave({
      description: description.trim() || undefined,
      action,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols,
      ics,
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-2xl rounded-2xl border border-white/10 bg-ink p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Edit rule {rule.id}</h2>
          <button onClick={onClose} className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10">Close</button>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-3" />
          <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
            <option value="">Source zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          {zones.length === 0 && (
            <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-300 md:col-span-2">
              No zones yet.{" "}<Link href="/zones/" className="font-semibold text-mint hover:text-mint/80">Create a zone</Link> to target policies.
            </div>
          )}
          <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
            <option value="">Dest zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          <select value={action} onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
          </select>
          <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2" />
          <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2" />
          <select value={proto} onChange={(e) => setProto(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
          <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white" />
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-black/30" />
            ICS Protocol Filter
            <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
          </label>
          <span className="text-xs text-slate-400 md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
          <span className="text-xs text-slate-400 md:col-span-4">Requires DPI capture to see ICS traffic (configure above).</span>
        </div>

        {icsEnabled && (
          <div className="mt-3 grid gap-3 rounded-xl border border-white/10 bg-black/30 p-4 md:grid-cols-4">
            <select value={icsProtocol} onChange={(e) => setIcsProtocol(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
              {ICS_PROTOCOL_KEYS.map((k) => (<option key={k} value={k}>{ICS_PROTOCOLS[k].label}</option>))}
            </select>
            <select value={mode} onChange={(e) => setMode(e.target.value as "enforce" | "learn")} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-1">
              <option value="learn">safe learning</option>
              <option value="enforce">enforce</option>
            </select>
            <input value={functionCodes} onChange={(e) => setFunctionCodes(e.target.value)} placeholder={icsMeta.fcPlaceholder || `${icsMeta.fcLabel} (csv)`} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white" />
            <input value={addresses} onChange={(e) => setAddresses(e.target.value)} placeholder={icsMeta.addrPlaceholder || `${icsMeta.addrLabel} (csv)`} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white" />
            {icsMeta.showUnitId && (
              <input value={icsUnitId} onChange={(e) => setIcsUnitId(e.target.value)} placeholder="Unit ID (0-255)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white" />
            )}
            {icsMeta.showObjectClasses && (
              <input value={objectClasses} onChange={(e) => setObjectClasses(e.target.value)} placeholder="Object classes (hex csv, e.g. 0x02, 0x04)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2" />
            )}
            <div className="flex items-center gap-4 text-sm text-slate-200">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={readOnly} onChange={(e) => setReadOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-black/30" />
                Read-only
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={writeOnly} onChange={(e) => setWriteOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-black/30" />
                Write-only
              </label>
            </div>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10">Cancel</button>
          <button onClick={save} className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30">Save changes</button>
        </div>
      </div>
    </div>
  );
}

function CreateRuleForm({ zones, onCreate }: { zones: Zone[]; onCreate: (rule: FirewallRule) => void }) {
  const [id, setId] = useState("");
  const [description, setDescription] = useState("");
  const [action, setAction] = useState<"ALLOW" | "DENY">("ALLOW");
  const [srcZone, setSrcZone] = useState("");
  const [dstZone, setDstZone] = useState("");
  const [sources, setSources] = useState("");
  const [destinations, setDestinations] = useState("");
  const [proto, setProto] = useState("tcp");
  const [port, setPort] = useState("502");
  const [icsEnabled, setIcsEnabled] = useState(false);
  const [icsProtocol, setIcsProtocol] = useState("modbus");
  const [functionCodes, setFunctionCodes] = useState("3,16");
  const [addresses, setAddresses] = useState("0-100");
  const [icsUnitId, setIcsUnitId] = useState("");
  const [objectClasses, setObjectClasses] = useState("");
  const [readOnly, setReadOnly] = useState(false);
  const [writeOnly, setWriteOnly] = useState(false);
  const [mode, setMode] = useState<"enforce" | "learn">("learn");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const icsMeta = icsProtoMeta(icsProtocol);

  async function submit() {
    setError(null);
    if (!id.trim()) { setError("Rule ID is required."); return; }
    if (sources.trim()) {
      const srcErr = validateIPOrCIDRList(sources);
      if (srcErr) { setError("Source: " + srcErr); return; }
    }
    if (destinations.trim()) {
      const dstErr = validateIPOrCIDRList(destinations);
      if (dstErr) { setError("Destination: " + dstErr); return; }
    }
    const protocols: Protocol[] = proto ? [{ name: proto, port: port.trim() || undefined }] : [];
    let ics: ICSPredicate | undefined;
    if (icsEnabled) {
      ics = {
        protocol: icsProtocol,
        functionCode: functionCodes.split(",").map((v) => Number(v.trim())).filter((n) => Number.isFinite(n)).map((n) => Math.max(0, Math.min(255, n))),
        addresses: addresses.split(",").map((s) => s.trim()).filter(Boolean),
        readOnly,
        writeOnly,
        mode,
      };
      if (icsMeta.showUnitId && icsUnitId.trim()) {
        const uid = Number(icsUnitId.trim());
        if (Number.isFinite(uid) && uid >= 0 && uid <= 255) ics.unitId = uid;
      }
      if (icsMeta.showObjectClasses && objectClasses.trim()) {
        ics.objectClasses = objectClasses.split(",").map((s) => s.trim()).filter(Boolean).map((s) => parseInt(s, s.startsWith("0x") ? 16 : 10)).filter((n) => Number.isFinite(n) && n >= 0);
      }
      if ((ics.functionCode?.length ?? 0) === 0) delete ics.functionCode;
      if ((ics.addresses?.length ?? 0) === 0) delete ics.addresses;
      if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;
    }
    const rule: FirewallRule = {
      id: id.trim(),
      description: description.trim() || undefined,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols,
      ics,
      action,
    };
    setSaving(true);
    await onCreate(rule);
    setSaving(false);
    setId("");
    setDescription("");
    setSources("");
    setDestinations("");
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
      <h2 className="text-sm font-semibold text-white">Create rule</h2>
      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder="id (e.g. mb-allow)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2" />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
          <option value="">Source zone (any)</option>
          {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
        </select>
        {zones.length === 0 && (
          <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-300 md:col-span-2">
            No zones yet.{" "}<Link href="/zones/" className="font-semibold text-mint hover:text-mint/80">Create a zone</Link> to target policies.
          </div>
        )}
        <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
          <option value="">Dest zone (any)</option>
          {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
        </select>
        <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
        <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select value={proto} onChange={(e) => setProto(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
        </select>
        <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
        <select value={action} onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-slate-200">
          <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-black/30" />
          ICS Protocol Filter
          <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
        </label>
        <span className="text-xs text-slate-400 md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
        <span className="text-xs text-slate-400 md:col-span-4">Requires DPI capture to see ICS traffic (configure above).</span>
      </div>

      {icsEnabled && (
        <div className="mt-3 grid gap-3 rounded-xl border border-white/10 bg-black/30 p-4 md:grid-cols-4">
          <select value={icsProtocol} onChange={(e) => setIcsProtocol(e.target.value)} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
            {ICS_PROTOCOL_KEYS.map((k) => (<option key={k} value={k}>{ICS_PROTOCOLS[k].label}</option>))}
          </select>
          <select value={mode} onChange={(e) => setMode(e.target.value as "enforce" | "learn")} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-1">
            <option value="learn">safe learning</option>
            <option value="enforce">enforce</option>
          </select>
          <input value={functionCodes} onChange={(e) => setFunctionCodes(e.target.value)} placeholder={icsMeta.fcPlaceholder || `${icsMeta.fcLabel} (csv)`} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
          <input value={addresses} onChange={(e) => setAddresses(e.target.value)} placeholder={icsMeta.addrPlaceholder || `${icsMeta.addrLabel} (csv)`} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
          {icsMeta.showUnitId && (
            <input value={icsUnitId} onChange={(e) => setIcsUnitId(e.target.value)} placeholder="Unit ID (0-255)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500" />
          )}
          {icsMeta.showObjectClasses && (
            <input value={objectClasses} onChange={(e) => setObjectClasses(e.target.value)} placeholder="Object classes (hex csv, e.g. 0x02, 0x04)" className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2" />
          )}
          <div className="flex items-center gap-4 text-sm text-slate-200">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={readOnly} onChange={(e) => setReadOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-black/30" />
              Read-only
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={writeOnly} onChange={(e) => setWriteOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-black/30" />
              Write-only
            </label>
          </div>
        </div>
      )}

      <div className="mt-3 flex items-center justify-between">
        {error && <p className="text-sm text-amber">{error}</p>}
        <button onClick={submit} disabled={saving} className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50">
          {saving ? "Creating..." : "Create rule"}
        </button>
      </div>
    </div>
  );
}

function splitCSV(v: string): string[] | undefined {
  const out = v.split(",").map((s) => s.trim()).filter(Boolean);
  return out.length > 0 ? out : undefined;
}
