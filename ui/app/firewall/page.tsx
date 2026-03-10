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
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

/* ── ICS protocol metadata for firewall rule modals ───────────── */

type ICSProtoMeta = {
  label: string;
  port: string;
  fcLabel: string;
  fcPlaceholder: string;
  fcHelp: string;
  addrLabel: string;
  addrPlaceholder: string;
  addrHelp: string;
  showUnitId?: boolean;
  showObjectClasses?: boolean;
  showStationAddrs?: boolean;
  showDbNumber?: boolean;
  showObjectType?: boolean;
  showPropertyId?: boolean;
  notes?: string;
};

const ICS_PROTOCOLS: Record<string, ICSProtoMeta> = {
  modbus: {
    label: "Modbus/TCP", port: "502",
    fcLabel: "Function codes",
    fcPlaceholder: "3, 16",
    fcHelp: "1=Read Coils, 2=Read Discrete Inputs, 3=Read Holding Registers, 4=Read Input Registers, 5=Write Single Coil, 6=Write Single Register, 8=Diagnostics, 15=Write Multiple Coils, 16=Write Multiple Registers, 43=Encapsulated Interface Transport (MEI)",
    addrLabel: "Register / coil addresses",
    addrPlaceholder: "0-100, 40001-40100",
    addrHelp: "Comma-separated ranges. Supports decimal (0-100) or hex (0x0000-0x00FF). Modbus registers are 16-bit (0-65535).",
    showUnitId: true,
    notes: "Unit ID identifies the slave device on a serial-to-TCP gateway (0-255, 0=broadcast).",
  },
  dnp3: {
    label: "DNP3", port: "20000",
    fcLabel: "Function codes",
    fcPlaceholder: "1, 2, 129",
    fcHelp: "1=Read, 2=Write, 3=Select, 4=Operate, 5=Direct Operate, 6=Direct Operate No Ack, 13=Cold Restart, 14=Warm Restart, 129=Response, 130=Unsolicited Response",
    addrLabel: "Point indices",
    addrPlaceholder: "0-10",
    addrHelp: "DNP3 data point indices. Used to restrict which binary/analog points this rule matches.",
    showStationAddrs: true,
    notes: "DNP3 uses source/destination station addresses (0-65534) to identify master and outstation. IIN (Internal Indications) flags are inspected for anomaly detection.",
  },
  cip: {
    label: "CIP / EtherNet/IP", port: "44818",
    fcLabel: "CIP service codes",
    fcPlaceholder: "0x4C, 0x4D, 0x52",
    fcHelp: "0x01=Get Attributes All, 0x02=Set Attributes All, 0x0E=Get Attribute Single, 0x10=Set Attribute Single, 0x4C=Read Tag, 0x4D=Write Tag, 0x4E=Read Modify Write, 0x52=Multiple Service Packet, 0x4F=Read Tag Fragmented, 0x53=Write Tag Fragmented",
    addrLabel: "EPATH (class/instance)",
    addrPlaceholder: "0x02/1, 0x04/1",
    addrHelp: "CIP path segments as class/instance pairs. The EPATH defines the target object in the CIP object model.",
    showObjectClasses: true,
    notes: "CIP uses an object model: Object Class identifies the type (0x01=Identity, 0x02=Message Router, 0x04=Assembly, 0x66=Connection Manager). Multiple Service Packet (0x52) requests are unpacked into individual services for inspection.",
  },
  s7comm: {
    label: "S7comm (Siemens)", port: "102",
    fcLabel: "Function codes",
    fcPlaceholder: "4, 5",
    fcHelp: "0x04=Read Variable, 0x05=Write Variable, 0x1D=Request Download, 0x1E=Download Block, 0x1F=Download Ended, 0x28=PI Service (PLC Control), 0x29=PLC Stop",
    addrLabel: "Variable addresses",
    addrPlaceholder: "DB1.DBX0.0, MW100",
    addrHelp: "S7 addressing: DBx.DBXy.z (data blocks), Mx (merkers), Ix (inputs), Qx (outputs). DB number identifies the data block.",
    showDbNumber: true,
    notes: "S7comm shares TCP port 102 with IEC 61850 MMS (differentiated by COTP protocol ID). Memory areas: 0x81=Inputs, 0x82=Outputs, 0x83=Merkers, 0x84=Data Blocks, 0x1C=Counters, 0x1D=Timers.",
  },
  mms: {
    label: "IEC 61850 MMS", port: "102",
    fcLabel: "MMS service types",
    fcPlaceholder: "",
    fcHelp: "MMS services: Read (confirmed), Write (confirmed), GetNameList, GetVariableAccessAttributes, DefineNamedVariableList, DeleteNamedVariableList, ObtainFile, Report, GOOSE-control. Service codes are ASN.1 context tags.",
    addrLabel: "Named variables",
    addrPlaceholder: "LLN0$BR$brcb01",
    addrHelp: "IEC 61850 variable names follow domain/item naming: LogicalDevice/LogicalNode$FC$DataObject (e.g., XCBR1$ST$Pos). FC = Functional Constraint (ST=Status, MX=Measured, CO=Control).",
    notes: "MMS is the application layer for IEC 61850 substation automation. Uses ISO/ACSE transport over TPKT/COTP on port 102. Shares port with S7comm (differentiated by COTP protocol ID byte).",
  },
  bacnet: {
    label: "BACnet/IP", port: "47808",
    fcLabel: "Service choices",
    fcPlaceholder: "12, 14, 15",
    fcHelp: "Confirmed: 12=ReadProperty, 14=WriteProperty, 15=WritePropertyMultiple, 5=SubscribeCOV, 26=ReadPropertyMultiple. Unconfirmed: 0=I-Am, 1=I-Have, 8=Who-Is, 7=Who-Has, 2=COV-Notification",
    addrLabel: "Object type / instance",
    addrPlaceholder: "analog-input:1, binary-output:5",
    addrHelp: "BACnet objects are type:instance pairs. Common types: analog-input (0), analog-output (1), analog-value (2), binary-input (3), binary-output (4), binary-value (5), device (8).",
    showObjectType: true,
    showPropertyId: true,
    notes: "BACnet/IP uses UDP port 47808 (0xBAC0). BVLC (BACnet Virtual Link Control) encapsulates NPDU and APDU layers. Property IDs: 85=Present Value, 28=Description, 77=Object Name.",
  },
  opcua: {
    label: "OPC UA", port: "4840",
    fcLabel: "Service types",
    fcPlaceholder: "",
    fcHelp: "Services: OpenSecureChannel, CloseSecureChannel, CreateSession, ActivateSession, Read, Write, Browse, BrowseNext, Call, CreateSubscription, Publish, CreateMonitoredItems",
    addrLabel: "Node IDs",
    addrPlaceholder: "ns=2;s=MyVariable",
    addrHelp: "OPC UA node IDs: ns=<namespace>;i=<numeric> or ns=<namespace>;s=<string>. Namespace 0 is the OPC UA standard namespace. Application-specific nodes typically use ns=1 or ns=2.",
    notes: "OPC UA uses a binary protocol over TCP. The decoder identifies message types (HEL, ACK, OPN, CLO, MSG) and extracts service IDs from MSG chunks. Security is negotiated at the secure channel level.",
  },
};

const ICS_PROTOCOL_KEYS = Object.keys(ICS_PROTOCOLS);

function icsProtoMeta(name: string): ICSProtoMeta {
  return ICS_PROTOCOLS[name] ?? { label: name, port: "", fcLabel: "Function codes", fcPlaceholder: "", fcHelp: "", addrLabel: "Addresses", addrPlaceholder: "", addrHelp: "" };
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

      <Card padding="md" className="mt-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">DPI Status</h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Deep packet inspection for ICS protocol filtering.
            </p>
          </div>
          <StatusBadge variant={(dpiConfig.captureInterfaces ?? []).length > 0 ? "success" : "neutral"} dot>
            {(dpiConfig.captureInterfaces ?? []).length > 0 ? "Enabled" : "Disabled"}
          </StatusBadge>
        </div>
        <div className="mt-2 text-xs text-[var(--text)]">
          Monitored interfaces: {(dpiConfig.captureInterfaces ?? []).length > 0 ? (dpiConfig.captureInterfaces ?? []).join(", ") : "none"}
        </div>
        <div className="mt-2">
          <Link href="/dataplane/" className="text-xs font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
            Configure DPI settings &rarr;
          </Link>
        </div>
      </Card>

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
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4" colSpan={7}>
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface)] px-4 animate-fade-in">
      <div className="w-full max-w-2xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[var(--text)]">Edit rule {rule.id}</h2>
          <button onClick={onClose} className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]">Close</button>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="input-industrial md:col-span-3" />
          <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="input-industrial">
            <option value="">Source zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          {zones.length === 0 && (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:col-span-2">
              No zones yet.{" "}<Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">Create a zone</Link> to target policies.
            </div>
          )}
          <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="input-industrial">
            <option value="">Dest zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          <select value={action} onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")} className="input-industrial">
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
          </select>
          <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="input-industrial md:col-span-2" />
          <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="input-industrial md:col-span-2" />
          <select value={proto} onChange={(e) => setProto(e.target.value)} className="input-industrial">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
          <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="input-industrial" />
          <label className="flex items-center gap-2 text-sm text-[var(--text)]">
            <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
            ICS Protocol Filter
            <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
          </label>
          <span className="text-xs text-[var(--text-muted)] md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
          <span className="text-xs text-[var(--text-muted)] md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-[var(--amber)] hover:text-[var(--amber)]">PCAP Capture</a>).</span>
        </div>

        {icsEnabled && (
          <div className="mt-3 grid gap-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 md:grid-cols-4">
            <select value={icsProtocol} onChange={(e) => setIcsProtocol(e.target.value)} className="input-industrial">
              {ICS_PROTOCOL_KEYS.map((k) => (<option key={k} value={k}>{ICS_PROTOCOLS[k].label}</option>))}
            </select>
            <select value={mode} onChange={(e) => setMode(e.target.value as "enforce" | "learn")} className="input-industrial md:col-span-1">
              <option value="learn">safe learning</option>
              <option value="enforce">enforce</option>
            </select>
            <input value={functionCodes} onChange={(e) => setFunctionCodes(e.target.value)} placeholder={icsMeta.fcPlaceholder || `${icsMeta.fcLabel} (csv)`} className="input-industrial" />
            <input value={addresses} onChange={(e) => setAddresses(e.target.value)} placeholder={icsMeta.addrPlaceholder || `${icsMeta.addrLabel} (csv)`} className="input-industrial" />
            {icsMeta.showUnitId && (
              <input value={icsUnitId} onChange={(e) => setIcsUnitId(e.target.value)} placeholder="Unit ID (0-255)" className="input-industrial" />
            )}
            {icsMeta.showObjectClasses && (
              <input value={objectClasses} onChange={(e) => setObjectClasses(e.target.value)} placeholder="Object classes (hex csv, e.g. 0x02, 0x04)" className="input-industrial md:col-span-2" />
            )}
            <div className="flex items-center gap-4 text-sm text-[var(--text)]">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={readOnly} onChange={(e) => setReadOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
                Read-only
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={writeOnly} onChange={(e) => setWriteOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
                Write-only
              </label>
            </div>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">Cancel</button>
          <button onClick={save} className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110">Save changes</button>
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
    <Card padding="lg" className="mt-6">
      <h2 className="text-sm font-semibold text-[var(--text)]">Create rule</h2>
      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder="id (e.g. mb-allow)" className="input-industrial" />
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="input-industrial md:col-span-2" />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="input-industrial">
          <option value="">Source zone (any)</option>
          {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
        </select>
        {zones.length === 0 && (
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:col-span-2">
            No zones yet.{" "}<Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">Create a zone</Link> to target policies.
          </div>
        )}
        <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="input-industrial">
          <option value="">Dest zone (any)</option>
          {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
        </select>
        <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="input-industrial" />
        <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="input-industrial" />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select value={proto} onChange={(e) => setProto(e.target.value)} className="input-industrial">
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
        </select>
        <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="input-industrial" />
        <select value={action} onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")} className="input-industrial">
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-[var(--text)]">
          <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
          ICS Protocol Filter
          <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
        </label>
        <span className="text-xs text-[var(--text-muted)] md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
        <span className="text-xs text-[var(--text-muted)] md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-[var(--amber)] hover:text-[var(--amber)]">PCAP Capture</a>).</span>
      </div>

      {icsEnabled && (
        <div className="mt-3 grid gap-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 md:grid-cols-4">
          <select value={icsProtocol} onChange={(e) => setIcsProtocol(e.target.value)} className="input-industrial">
            {ICS_PROTOCOL_KEYS.map((k) => (<option key={k} value={k}>{ICS_PROTOCOLS[k].label}</option>))}
          </select>
          <select value={mode} onChange={(e) => setMode(e.target.value as "enforce" | "learn")} className="input-industrial md:col-span-1">
            <option value="learn">safe learning</option>
            <option value="enforce">enforce</option>
          </select>
          <input value={functionCodes} onChange={(e) => setFunctionCodes(e.target.value)} placeholder={icsMeta.fcPlaceholder || `${icsMeta.fcLabel} (csv)`} className="input-industrial" />
          <input value={addresses} onChange={(e) => setAddresses(e.target.value)} placeholder={icsMeta.addrPlaceholder || `${icsMeta.addrLabel} (csv)`} className="input-industrial" />
          {icsMeta.showUnitId && (
            <input value={icsUnitId} onChange={(e) => setIcsUnitId(e.target.value)} placeholder="Unit ID (0-255)" className="input-industrial" />
          )}
          {icsMeta.showObjectClasses && (
            <input value={objectClasses} onChange={(e) => setObjectClasses(e.target.value)} placeholder="Object classes (hex csv, e.g. 0x02, 0x04)" className="input-industrial md:col-span-2" />
          )}
          <div className="flex items-center gap-4 text-sm text-[var(--text)]">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={readOnly} onChange={(e) => setReadOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
              Read-only
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={writeOnly} onChange={(e) => setWriteOnly(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
              Write-only
            </label>
          </div>
        </div>
      )}

      <div className="mt-3 flex items-center justify-between">
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button onClick={submit} disabled={saving} className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
          {saving ? "Creating..." : "Create rule"}
        </button>
      </div>
    </Card>
  );
}

function splitCSV(v: string): string[] | undefined {
  const out = v.split(",").map((s) => s.trim()).filter(Boolean);
  return out.length > 0 ? out : undefined;
}

/* ── DPI Configuration Section ───────────────────────────────────── */

const IT_PROTOCOLS: { key: string; label: string; port: string; desc: string }[] = [
  { key: "dns", label: "DNS", port: "53", desc: "Domain name queries and responses" },
  { key: "tls", label: "TLS / SSL", port: "443", desc: "TLS handshake metadata, SNI, JA3 fingerprinting" },
  { key: "http", label: "HTTP", port: "80", desc: "HTTP method, URI, host, status inspection" },
  { key: "ssh", label: "SSH", port: "22", desc: "SSH version exchange and cipher negotiation" },
  { key: "smb", label: "SMB", port: "445", desc: "Windows file sharing commands and shares" },
  { key: "ntp", label: "NTP", port: "123", desc: "Network time protocol mode and stratum" },
  { key: "snmp", label: "SNMP", port: "161", desc: "SNMP community auth, PDU type, OIDs" },
  { key: "rdp", label: "RDP", port: "3389", desc: "Remote desktop protocol negotiation and security" },
];

const ICS_DPI_PROTOCOLS: { key: string; label: string; port: string; desc: string }[] = [
  { key: "modbus", label: "Modbus/TCP", port: "502", desc: "Function codes, register addresses, unit IDs" },
  { key: "dnp3", label: "DNP3", port: "20000", desc: "Function codes, station addresses, IIN flags" },
  { key: "cip", label: "CIP / EtherNet/IP", port: "44818", desc: "Service codes, object classes, CIP paths" },
  { key: "s7comm", label: "S7comm", port: "102", desc: "Memory areas, DB numbers, read/write ops" },
  { key: "mms", label: "IEC 61850 MMS", port: "102", desc: "MMS service requests, named variables" },
  { key: "bacnet", label: "BACnet/IP", port: "47808", desc: "Service types, object types, property IDs" },
  { key: "opcua", label: "OPC UA", port: "4840", desc: "Service types, node IDs, browse/read/write" },
];

const ICS_PROTOCOL_OPTIONS: Record<string, { fcLabel: string; fcHelp: string; addrLabel: string; addrHelp: string; hasUnitId?: boolean; hasObjectClasses?: boolean }> = {
  modbus: { fcLabel: "Function codes", fcHelp: "1=Read Coils, 3=Read Holding, 5=Write Coil, 6=Write Register, 15=Write Coils, 16=Write Registers", addrLabel: "Register/coil addresses", addrHelp: "e.g. 0-100, 40001-40100", hasUnitId: true },
  dnp3: { fcLabel: "Function codes", fcHelp: "1=Read, 2=Write, 3=Select, 4=Operate, 13=Cold Restart, 14=Warm Restart", addrLabel: "Station addresses", addrHelp: "Source and destination addresses (0-65534)" },
  cip: { fcLabel: "Service codes", fcHelp: "0x4C=Read Tag, 0x4D=Write Tag, 0x52=Multiple Service", addrLabel: "CIP path", addrHelp: "Object class / instance path", hasObjectClasses: true },
  s7comm: { fcLabel: "Function codes", fcHelp: "0x04=Read, 0x05=Write, 0x28=Setup Comm, 0x29=PLC Stop", addrLabel: "Memory area / DB", addrHelp: "DB numbers, memory area types" },
  mms: { fcLabel: "Service types", fcHelp: "Read, Write, GetNameList, Define, Report", addrLabel: "Named variables", addrHelp: "Domain/variable name patterns" },
  bacnet: { fcLabel: "Service types", fcHelp: "ReadProperty, WriteProperty, SubscribeCOV, WhoIs", addrLabel: "Object type / instance", addrHelp: "e.g. analog-input:1, binary-output:5" },
  opcua: { fcLabel: "Service types", fcHelp: "Read, Write, Browse, Call, CreateSubscription", addrLabel: "Node IDs", addrHelp: "Namespace and identifier patterns" },
};

function DPIConfigSection({ config: cfg, onChange }: { config: DataPlaneConfig; onChange: (c: DataPlaneConfig) => void }) {
  const [saving, setSaving] = useState(false);
  const [saveState, setSaveState] = useState<"idle" | "saved" | "error">("idle");
  const [showProtoModal, setShowProtoModal] = useState(false);
  const [showExclModal, setShowExclModal] = useState(false);
  const [showICSConfigModal, setShowICSConfigModal] = useState(false);
  const canEdit = isAdmin();
  const dpiOn = cfg.dpiEnabled ?? false;
  const dpiMode = cfg.dpiMode ?? "learn";
  const protos = cfg.dpiProtocols ?? {};
  const icsProtos = cfg.dpiIcsProtocols ?? {};
  const exclusions = cfg.dpiExclusions ?? [];

  const enabledProtoCount = IT_PROTOCOLS.filter((p) => protos[p.key] !== false).length;
  const enabledICSCount = ICS_DPI_PROTOCOLS.filter((p) => icsProtos[p.key] !== false).length;

  async function save(updated: DataPlaneConfig) {
    if (!canEdit) return;
    setSaving(true);
    const result = await setDataPlane(updated);
    setSaving(false);
    setSaveState(result ? "saved" : "error");
    setTimeout(() => setSaveState("idle"), 1500);
  }

  function toggleDPI() {
    const updated = { ...cfg, dpiEnabled: !dpiOn };
    onChange(updated);
    save(updated);
  }

  function setMode(mode: "learn" | "enforce") {
    const updated = { ...cfg, dpiMode: mode };
    onChange(updated);
    save(updated);
  }

  function saveProtos(newProtos: Record<string, boolean>) {
    const updated = { ...cfg, dpiProtocols: newProtos };
    onChange(updated);
    save(updated);
  }

  function saveICSProtos(newICSProtos: Record<string, boolean>) {
    const updated = { ...cfg, dpiIcsProtocols: newICSProtos };
    onChange(updated);
    save(updated);
  }

  function saveExclusions(newExcl: DPIExclusion[]) {
    const updated = { ...cfg, dpiExclusions: newExcl };
    onChange(updated);
    save(updated);
  }

  return (
    <>
      <Card padding="md" className="mt-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">Deep Packet Inspection</h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Inspect ICS and IT protocol traffic for visibility, IDS alerting, and policy enforcement.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {saving && <span className="text-[10px] text-[var(--text-muted)]">Saving...</span>}
            {saveState === "saved" && <span className="text-[10px] text-emerald-400">Saved</span>}
            {saveState === "error" && <span className="text-[10px] text-red-400">Error</span>}
            {canEdit && (
              <button
                onClick={toggleDPI}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  dpiOn ? "bg-emerald-500" : "bg-white/10"
                }`}
              >
                <span className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                  dpiOn ? "translate-x-6" : "translate-x-1"
                }`} />
              </button>
            )}
            <StatusBadge variant={dpiOn ? "success" : "neutral"} dot>
              {dpiOn ? "Enabled" : "Disabled"}
            </StatusBadge>
          </div>
        </div>

        {dpiOn && (
          <div className="mt-4 space-y-3">
            {/* ICS DPI Mode */}
            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">ICS DPI Mode</span>
                  <InfoTip label="Learning mode passively observes traffic to build a baseline. Enforcement mode actively applies DPI policy rules." />
                </div>
                {canEdit && (
                  <div className="flex items-center rounded-sm border border-amber-500/[0.1] overflow-hidden">
                    <button
                      onClick={() => setMode("learn")}
                      className={`px-3 py-1 text-[10px] font-medium transition-ui ${
                        dpiMode === "learn"
                          ? "bg-blue-500/20 text-blue-400 border-r border-amber-500/[0.1]"
                          : "bg-[var(--surface)] text-[var(--text-muted)] hover:bg-white/[0.04] border-r border-amber-500/[0.1]"
                      }`}
                    >
                      Learning
                    </button>
                    <button
                      onClick={() => setMode("enforce")}
                      className={`px-3 py-1 text-[10px] font-medium transition-ui ${
                        dpiMode === "enforce"
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-[var(--surface)] text-[var(--text-muted)] hover:bg-white/[0.04]"
                      }`}
                    >
                      Enforcement
                    </button>
                  </div>
                )}
              </div>
              <p className="mt-1 text-[10px] text-[var(--text-dim)]">
                {dpiMode === "learn"
                  ? "Passively observing ICS traffic to build protocol baseline. No traffic will be blocked."
                  : "Actively enforcing DPI policy rules. Non-conforming traffic may be blocked."}
              </p>
            </div>

            {/* ICS Protocols */}
            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">ICS Protocol Decoders</span>
                  <span className="ml-2 text-[10px] text-[var(--text-muted)]">{enabledICSCount}/{ICS_DPI_PROTOCOLS.length} enabled</span>
                </div>
                <div className="flex items-center gap-2">
                  {canEdit && (
                    <button
                      onClick={() => setShowICSConfigModal(true)}
                      className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-medium text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                    >
                      Configure
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {ICS_DPI_PROTOCOLS.map((p) => {
                  const on = icsProtos[p.key] !== false;
                  return (
                    <span key={p.key} className={`rounded-sm border px-1.5 py-0.5 text-[9px] ${
                      on
                        ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                        : "border-white/[0.06] bg-white/[0.02] text-[var(--text-dim)] line-through"
                    }`}>
                      {p.label}
                    </span>
                  );
                })}
              </div>
            </div>

            {/* IT Protocols */}
            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">IT Protocol Decoders</span>
                  <span className="ml-2 text-[10px] text-[var(--text-muted)]">{enabledProtoCount}/{IT_PROTOCOLS.length} enabled</span>
                </div>
                {canEdit && (
                  <button
                    onClick={() => setShowProtoModal(true)}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-medium text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                  >
                    Configure
                  </button>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {IT_PROTOCOLS.map((p) => {
                  const on = protos[p.key] !== false;
                  return (
                    <span key={p.key} className={`rounded-sm border px-1.5 py-0.5 text-[9px] ${
                      on
                        ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                        : "border-white/[0.06] bg-white/[0.02] text-[var(--text-dim)] line-through"
                    }`}>
                      {p.label}
                    </span>
                  );
                })}
              </div>
            </div>

            {/* DPI Exclusions */}
            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">DPI Exclusions</span>
                  <span className="ml-2 text-[10px] text-[var(--text-muted)]">
                    {exclusions.length === 0 ? "None" : `${exclusions.length} excluded`}
                  </span>
                </div>
                {canEdit && (
                  <button
                    onClick={() => setShowExclModal(true)}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-medium text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                  >
                    {exclusions.length > 0 ? "Manage" : "Add Exclusion"}
                  </button>
                )}
              </div>
              {exclusions.length > 0 && (
                <div className="mt-2 space-y-1">
                  {exclusions.map((e, i) => (
                    <div key={i} className="flex items-center justify-between rounded-sm border border-white/[0.04] bg-[var(--surface)] px-2 py-1 text-[10px]">
                      <div className="flex items-center gap-2">
                        <span className="rounded-sm border border-amber-500/20 bg-amber-500/10 px-1 py-0.5 text-[9px] text-amber-400 uppercase">{e.type}</span>
                        <span className="font-mono text-[var(--text)]">{e.value}</span>
                      </div>
                      {e.reason && <span className="text-[var(--text-muted)] truncate max-w-[180px]">{e.reason}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Info note */}
            <div className="text-[10px] text-[var(--text-dim)]">
              Use Learning mode to passively build a traffic baseline before switching to Enforcement.
              DPI exclusions skip inspection for specific IPs, CIDRs, or domains.
              TLS inspection covers handshake metadata only (SNI, JA3) — full interception is planned.
            </div>
          </div>
        )}
      </Card>

      {showProtoModal && (
        <DPIProtocolModal
          protocols={protos}
          onSave={(p) => { saveProtos(p); setShowProtoModal(false); }}
          onClose={() => setShowProtoModal(false)}
        />
      )}
      {showExclModal && (
        <DPIExclusionModal
          exclusions={exclusions}
          onSave={(e) => { saveExclusions(e); setShowExclModal(false); }}
          onClose={() => setShowExclModal(false)}
        />
      )}
      {showICSConfigModal && (
        <ICSDPIConfigModal
          icsProtocols={icsProtos}
          onSave={(p) => { saveICSProtos(p); setShowICSConfigModal(false); }}
          onClose={() => setShowICSConfigModal(false)}
        />
      )}
    </>
  );
}

/* ── IT Protocol Toggle Modal ── */

function DPIProtocolModal({ protocols, onSave, onClose }: {
  protocols: Record<string, boolean>;
  onSave: (p: Record<string, boolean>) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<Record<string, boolean>>({ ...protocols });

  function toggle(key: string) {
    setDraft((d) => ({ ...d, [key]: d[key] === false ? true : false }));
  }

  function enableAll() {
    const next: Record<string, boolean> = {};
    IT_PROTOCOLS.forEach((p) => { next[p.key] = true; });
    setDraft(next);
  }

  function disableAll() {
    const next: Record<string, boolean> = {};
    IT_PROTOCOLS.forEach((p) => { next[p.key] = false; });
    setDraft(next);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-lg rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-[var(--text)]">IT Protocol DPI Configuration</h2>
          <div className="flex items-center gap-2">
            <button onClick={enableAll} className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-500/20">
              Enable All
            </button>
            <button onClick={disableAll} className="rounded-sm border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20">
              Disable All
            </button>
          </div>
        </div>

        <div className="space-y-1">
          {IT_PROTOCOLS.map((p) => {
            const on = draft[p.key] !== false;
            return (
              <div
                key={p.key}
                onClick={() => toggle(p.key)}
                className={`flex items-center justify-between rounded-sm border px-3 py-2.5 cursor-pointer transition-ui ${
                  on
                    ? "border-emerald-500/20 bg-emerald-500/[0.04] hover:bg-emerald-500/[0.08]"
                    : "border-white/[0.04] bg-white/[0.01] hover:bg-white/[0.03]"
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-medium ${on ? "text-[var(--text)]" : "text-[var(--text-dim)]"}`}>{p.label}</span>
                    <span className="font-mono text-[10px] text-[var(--text-muted)]">:{p.port}</span>
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)] mt-0.5">{p.desc}</div>
                </div>
                <div className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${on ? "bg-emerald-500" : "bg-white/10"}`}>
                  <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${on ? "translate-x-4" : "translate-x-0.5"}`} />
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-4 text-[10px] text-[var(--text-dim)]">
          ICS protocol decoders (Modbus, DNP3, CIP, S7comm, IEC 61850 MMS, BACnet, OPC UA) are always active and cannot be disabled.
          TLS inspection covers handshake metadata only (SNI, JA3, cipher suites) — full TLS interception is planned for a future release.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">Cancel</button>
          <button onClick={() => onSave(draft)} className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110">Save</button>
        </div>
      </div>
    </div>
  );
}

/* ── ICS DPI Configuration Modal ── */

function ICSDPIConfigModal({ icsProtocols, onSave, onClose }: {
  icsProtocols: Record<string, boolean>;
  onSave: (p: Record<string, boolean>) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<Record<string, boolean>>({ ...icsProtocols });
  const [activeProto, setActiveProto] = useState<string | null>(null);

  function toggle(key: string) {
    setDraft((d) => ({ ...d, [key]: d[key] === false ? true : false }));
  }

  function enableAll() {
    const next: Record<string, boolean> = {};
    ICS_DPI_PROTOCOLS.forEach((p) => { next[p.key] = true; });
    setDraft(next);
  }

  function disableAll() {
    const next: Record<string, boolean> = {};
    ICS_DPI_PROTOCOLS.forEach((p) => { next[p.key] = false; });
    setDraft(next);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-2xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">ICS Protocol DPI Configuration</h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">Enable or disable individual ICS protocol decoders and view protocol-specific options.</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={enableAll} className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-500/20">
              Enable All
            </button>
            <button onClick={disableAll} className="rounded-sm border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20">
              Disable All
            </button>
          </div>
        </div>

        <div className="space-y-1">
          {ICS_DPI_PROTOCOLS.map((p) => {
            const on = draft[p.key] !== false;
            const expanded = activeProto === p.key;
            const opts = ICS_PROTOCOL_OPTIONS[p.key];
            return (
              <div key={p.key}>
                <div
                  className={`flex items-center justify-between rounded-sm border px-3 py-2.5 transition-ui ${
                    on
                      ? "border-emerald-500/20 bg-emerald-500/[0.04]"
                      : "border-white/[0.04] bg-white/[0.01]"
                  } ${expanded ? "rounded-b-none" : ""}`}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0 cursor-pointer" onClick={() => setActiveProto(expanded ? null : p.key)}>
                    <svg className={`w-3 h-3 text-[var(--text-muted)] transition-transform ${expanded ? "rotate-90" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`text-sm font-medium ${on ? "text-[var(--text)]" : "text-[var(--text-dim)]"}`}>{p.label}</span>
                        <span className="font-mono text-[10px] text-[var(--text-muted)]">:{p.port}</span>
                      </div>
                      <div className="text-[10px] text-[var(--text-muted)] mt-0.5">{p.desc}</div>
                    </div>
                  </div>
                  <div
                    onClick={() => toggle(p.key)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors cursor-pointer shrink-0 ${on ? "bg-emerald-500" : "bg-white/10"}`}
                  >
                    <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${on ? "translate-x-4" : "translate-x-0.5"}`} />
                  </div>
                </div>

                {expanded && opts && (
                  <div className="border border-t-0 border-amber-500/[0.08] rounded-b-sm bg-[var(--surface2)] px-4 py-3 space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">{opts.fcLabel}</label>
                        <p className="text-[9px] text-[var(--text-dim)] mb-1.5">{opts.fcHelp}</p>
                        <div className="text-[10px] text-[var(--text-dim)] italic">Configured in firewall rules per-entry</div>
                      </div>
                      <div>
                        <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">{opts.addrLabel}</label>
                        <p className="text-[9px] text-[var(--text-dim)] mb-1.5">{opts.addrHelp}</p>
                        <div className="text-[10px] text-[var(--text-dim)] italic">Configured in firewall rules per-entry</div>
                      </div>
                    </div>
                    {opts.hasUnitId && (
                      <div className="text-[10px] text-[var(--text-dim)]">
                        Unit ID filtering available in firewall rules (per-entry ICS predicate).
                      </div>
                    )}
                    {opts.hasObjectClasses && (
                      <div className="text-[10px] text-[var(--text-dim)]">
                        CIP object class filtering available in firewall rules (per-entry ICS predicate).
                      </div>
                    )}
                    <div className="pt-2 border-t border-white/[0.04]">
                      <div className="flex items-center gap-2 text-[10px]">
                        <span className="text-[var(--text-muted)]">Decoder status:</span>
                        {on ? (
                          <span className="text-emerald-400">Active — inspecting traffic on port {p.port}</span>
                        ) : (
                          <span className="text-[var(--text-dim)]">Disabled — traffic on port {p.port} will not be decoded</span>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="mt-4 text-[10px] text-[var(--text-dim)]">
          Protocol-specific DPI parameters (function codes, register addresses, unit IDs) are configured per-rule in firewall entries with ICS predicates.
          This panel controls which ICS decoders are active at the engine level.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">Cancel</button>
          <button onClick={() => onSave(draft)} className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110">Save</button>
        </div>
      </div>
    </div>
  );
}

/* ── DPI Exclusion Modal ── */

function DPIExclusionModal({ exclusions, onSave, onClose }: {
  exclusions: DPIExclusion[];
  onSave: (e: DPIExclusion[]) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<DPIExclusion[]>([...exclusions]);
  const [newValue, setNewValue] = useState("");
  const [newType, setNewType] = useState<"ip" | "cidr" | "domain">("ip");
  const [newReason, setNewReason] = useState("");

  function detectType(v: string): "ip" | "cidr" | "domain" {
    if (v.includes("/")) return "cidr";
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return "ip";
    if (v.includes(":") && !v.includes(".")) return "ip"; // IPv6
    return "domain";
  }

  function add() {
    const val = newValue.trim();
    if (!val) return;
    if (draft.some((e) => e.value === val)) return;
    setDraft([...draft, { value: val, type: detectType(val), reason: newReason.trim() || undefined }]);
    setNewValue("");
    setNewReason("");
  }

  function remove(i: number) {
    setDraft(draft.filter((_, idx) => idx !== i));
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-lg rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <h2 className="text-sm font-semibold text-[var(--text)] mb-4">DPI Exclusions</h2>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          Exclude specific IP addresses, CIDR ranges, or domains from deep packet inspection.
          Traffic to or from excluded targets will bypass DPI entirely.
        </p>

        {/* Add new exclusion */}
        <div className="flex gap-2 mb-4">
          <select
            value={newType}
            onChange={(e) => setNewType(e.target.value as "ip" | "cidr" | "domain")}
            className="rounded-sm border border-amber-500/[0.1] bg-[var(--surface2)] px-2.5 py-2.5 text-sm text-[var(--text)] outline-none"
          >
            <option value="ip">IP</option>
            <option value="cidr">CIDR</option>
            <option value="domain">Domain</option>
          </select>
          <input
            value={newValue}
            onChange={(e) => {
              setNewValue(e.target.value);
              setNewType(detectType(e.target.value));
            }}
            placeholder={newType === "domain" ? "example.com" : newType === "cidr" ? "10.0.0.0/8" : "192.168.1.1"}
            className="flex-1 input-industrial py-2.5 text-sm"
            onKeyDown={(e) => { if (e.key === "Enter") add(); }}
          />
          <input
            value={newReason}
            onChange={(e) => setNewReason(e.target.value)}
            placeholder="Reason (optional)"
            className="w-40 input-industrial py-2.5 text-sm"
            onKeyDown={(e) => { if (e.key === "Enter") add(); }}
          />
          <button onClick={add} className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110">Add</button>
        </div>

        {/* Exclusion list */}
        <div className="max-h-[280px] overflow-y-auto space-y-1">
          {draft.length === 0 ? (
            <div className="text-center py-6 text-xs text-[var(--text-muted)]">No exclusions configured.</div>
          ) : (
            draft.map((e, i) => (
              <div key={i} className="flex items-center justify-between rounded-sm border border-white/[0.04] bg-[var(--surface2)] px-3 py-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="shrink-0 rounded-sm border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[9px] text-amber-400 uppercase">{e.type}</span>
                  <span className="font-mono text-xs text-[var(--text)] truncate">{e.value}</span>
                  {e.reason && <span className="text-[10px] text-[var(--text-muted)] truncate">— {e.reason}</span>}
                </div>
                <button onClick={() => remove(i)} className="shrink-0 ml-2 rounded-sm border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 transition-ui">Remove</button>
              </div>
            ))
          )}
        </div>

        <div className="mt-3 text-[10px] text-[var(--text-dim)]">
          IP and CIDR exclusions take effect immediately. Domain exclusions will be supported when TLS interception is added.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">Cancel</button>
          <button onClick={() => onSave(draft)} className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110">Save</button>
        </div>
      </div>
    </div>
  );
}
