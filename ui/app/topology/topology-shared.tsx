"use client";

import React from "react";
import { Edge, Handle, Node, NodeProps, Position } from "@xyflow/react";

import {
  api,
  type ApiResult,
  type FirewallRule,
  type RuleAction,
  type RuleCounters,
  type Interface,
  type OSRoutingSnapshot,
  type RoutingConfig,
  type SystemStats,
  type TelemetryEvent,
  type Zone,
  type HealthResponse,
} from "../../lib/api";
import s from "./topology.module.css";
import { normalizeFirewallRules } from "../../lib/api-normalize";
import { interfaceAddresses, runtimeFor, type InterfaceAddresses } from "../../lib/interface-addresses";
import { TopologyAddress } from "./topology-address";
import { formatRateLimit } from "../firewall/firewall-rule-policy";

export interface BuiltIface {
  name: string;
  address: InterfaceAddresses;
  fullAddrs: string[];
  state: "up" | "down";
  zone: string;
  rx: string;
  tx: string;
  vlan: number | null;
}

export interface BuiltRoute {
  dst: string;
  gw: string;
  iface: string;
  origin: "static" | "dynamic" | "local";
  metric: number;
}

export interface BuiltRule {
  id: string;
  action: RuleAction;
  /** ALLOW admits; DENY and RESET refuse; RATE_LIMIT and TAG are effects that decide nothing. */
  kind: "allow" | "deny" | "effect";
  desc: string;
  /** Packets since the last apply (connection openers for TAG); null when not counted. */
  hits: number | null;
}

/** The firewall node's rule list, with the applied ruleset's counters. */
export function buildTopologyRules(rules: FirewallRule[], counters: ApiResult<RuleCounters>): BuiltRule[] {
  const counts = new Map(counters.ok ? counters.data.rules.map((c) => [c.ruleId, c.packets]) : []);
  return rules.map((r) => {
    const src = (r.sourceZones || []).join(",") || "*";
    const dst = (r.destZones || []).join(",") || "*";
    const ports = (r.protocols || [])
      .map((p) => (p.port ? `${p.name}/${p.port}` : p.name))
      .join(",");
    const effect =
      r.action === "RATE_LIMIT" && r.rateLimit ? ` \u00b7 ${formatRateLimit(r.rateLimit)}`
        : r.action === "TAG" && r.tag ? ` \u00b7 tag ${r.tag}`
          : "";
    return {
      id: r.id,
      action: r.action,
      kind: r.action === "ALLOW" ? "allow" : r.action === "DENY" || r.action === "RESET" ? "deny" : "effect",
      desc: `${src} \u2192 ${dst}${ports ? " " + ports : ""}${effect}`,
      hits: counts.get(r.id) ?? null,
    };
  });
}

export type TopoNodeData = {
  label: string;
  nodeType: "internet" | "gateway" | "firewall" | "zone";
  status?: "ok" | "warn" | "crit" | "down";
  hostname?: string;
  version?: string;
  uptime?: string;
  cpu?: number;
  mem?: number;
  sessions?: number;
  interfaces?: BuiltIface[];
  routes?: BuiltRoute[];
  rules?: BuiltRule[];
  ip?: string;
  asn?: string;
  latency?: string;
  loss?: string;
  iface?: string;
  subnet?: string;
  address?: InterfaceAddresses;
  fullAddrs?: string[];
  hosts?: number;
  flows?: number;
  rx?: string;
  tx?: string;
  vlan?: number | null;
  desc?: string;
};

export interface TopologyAction {
  href: string;
  label: string;
  detail: string;
}

interface TopoResult {
  nodes: Node<TopoNodeData>[];
  edges: Edge[];
  nodeDataMap: Record<string, TopoNodeData>;
}

export const STATUS_COLORS: Record<string, string> = {
  ok: "#22c55e",
  warn: "#f59e0b",
  crit: "#ef4444",
  down: "#6b7280",
};

const hStyle: React.CSSProperties = {
  opacity: 0,
  width: 1,
  height: 1,
  border: "none",
  pointerEvents: "none",
};

function InternetNode({ data, selected }: NodeProps<Node<TopoNodeData>>) {
  return (
    <div
      className={`${s.nodeCard} ${s.accentGray} ${selected ? s.nodeCardSelected : ""}`}
    >
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${s.nameGray}`}>{data.label}</span>
        <div
          className={s.statusDot}
          style={{ background: "#6b7280", boxShadow: "0 0 5px #6b728080" }}
        />
      </div>
    </div>
  );
}

function GatewayNode({ data, selected }: NodeProps<Node<TopoNodeData>>) {
  const sc = STATUS_COLORS[data.status || "ok"];
  return (
    <div
      className={`${s.nodeCard} ${s.accentCyan} ${selected ? s.nodeCardSelected : ""}`}
    >
      <Handle type="target" position={Position.Top} style={hStyle} />
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${s.nameCyan}`}>{data.label}</span>
        <div
          className={s.statusDot}
          style={{ background: sc, boxShadow: `0 0 5px ${sc}80` }}
        />
      </div>
      <div className={s.nodeBody}>
        <NRow k="ip" v={data.ip || "\u2014"} />
        <NRow k="latency" v={data.latency || "\u2014"} />
      </div>
    </div>
  );
}

function FirewallNode({ data, selected }: NodeProps<Node<TopoNodeData>>) {
  return (
    <div
      className={`${s.nodeCard} ${s.accentAmber} ${selected ? s.nodeCardSelected : ""}`}
      style={{ minWidth: 160 }}
    >
      <Handle type="target" position={Position.Top} style={hStyle} />
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${s.nameAmber}`}>{data.label}</span>
        <div
          className={s.statusDot}
          style={{ background: "#22c55e", boxShadow: "0 0 5px #22c55e80" }}
        />
      </div>
      <div className={s.nodeBody}>
        <NRow k="sessions" v={String(data.sessions ?? 0)} />
        <NRow k="cpu" v={`${data.cpu ?? 0}%`} />
        <NRow k="mem" v={`${data.mem ?? 0}%`} />
      </div>
    </div>
  );
}

function ZoneNode({ data, selected }: NodeProps<Node<TopoNodeData>>) {
  const st = data.status || "ok";
  const sc = STATUS_COLORS[st];
  const accentCls =
    st === "crit" ? s.accentRed : st === "warn" ? s.accentAmber : s.accentGreen;
  const nameCls =
    st === "crit" ? s.nameRed : st === "warn" ? s.nameAmber : s.nameGreen;
  return (
    <div
      className={`${s.nodeCard} ${accentCls} ${selected ? s.nodeCardSelected : ""}`}
    >
      <Handle type="target" position={Position.Top} style={hStyle} />
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${nameCls}`}>{data.label}</span>
        <div
          className={s.statusDot}
          style={{ background: sc, boxShadow: `0 0 5px ${sc}80` }}
        />
      </div>
      <div className={s.nodeBody}>
        <NRow k="subnet" v={<TopologyAddress address={data.address} fullAddrs={data.fullAddrs} />} />
        <NRow k="hosts" v={String(data.hosts ?? 0)} />
        <NRow k="flows" v={String(data.flows ?? 0)} />
      </div>
    </div>
  );
}

function NRow({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className={s.nodeRow}>
      <span className={s.nodeRowKey}>{k}</span>
      <span className={s.nodeRowVal}>{v}</span>
    </div>
  );
}

export const nodeTypes = {
  internet: InternetNode,
  gateway: GatewayNode,
  firewall: FirewallNode,
  zone: ZoneNode,
};

function ip4(str: string): number {
  const p = (str || "").split(".");
  return (((+p[0]) << 24) | ((+p[1]) << 16) | ((+p[2]) << 8) | +p[3]) >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  if (!cidr || !ip) {
    return false;
  }
  const [base, bits] = cidr.split("/");
  if (!bits) {
    return ip === base;
  }
  const mask = (-1 << (32 - parseInt(bits))) >>> 0;
  return (ip4(ip) & mask) === (ip4(base) & mask);
}

function edgeStyle(type: string): Partial<Edge> {
  switch (type) {
    case "wan":
      return {
        type: "straight",
        style: { stroke: "rgba(107,114,128,0.5)", strokeWidth: 1 },
        animated: false,
      };
    case "gw":
      return {
        type: "straight",
        style: { stroke: "rgba(6,182,212,0.5)", strokeWidth: 1.5 },
        animated: false,
      };
    case "zone":
      return {
        type: "straight",
        style: { stroke: "rgba(34,197,94,0.4)", strokeWidth: 1.2 },
        animated: false,
      };
    case "iface":
      return {
        type: "straight",
        style: { stroke: "rgba(168,85,247,0.4)", strokeWidth: 1 },
        animated: false,
      };
    default:
      return {
        type: "straight",
        style: { stroke: "rgba(107,114,128,0.3)", strokeWidth: 1 },
        animated: false,
      };
  }
}

export function nextActionsForNode(data: TopoNodeData): TopologyAction[] {
  switch (data.nodeType) {
    case "firewall":
      return [
        {
          href: "/interfaces/",
          label: "Review interfaces",
          detail: "Check port bindings, IPs, and zone mapping.",
        },
        {
          href: "/routing/",
          label: "Review routing",
          detail: "Inspect gateways and outbound path selection.",
        },
        {
          href: "/firewall/",
          label: "Review policy",
          detail: "Adjust allow/deny rules and ordering.",
        },
        {
          href: "/system/services/",
          label: "Check services",
          detail: "Inspect DNS, DHCP, NTP, proxy, and AV services.",
        },
      ];
    case "zone":
      return [
        {
          href: "/zones/",
          label: "Edit zone",
          detail: "Rename or document this zone and review its purpose.",
        },
        {
          href: "/interfaces/",
          label: "Bind interfaces",
          detail: "Confirm the right interfaces are attached here.",
        },
        {
          href: "/firewall/",
          label: "Review policy",
          detail: "Adjust rules that allow or deny traffic for this zone.",
        },
      ];
    case "gateway":
      return [
        {
          href: "/routing/",
          label: "Review routes",
          detail: "Check default route, metrics, and next hops.",
        },
        {
          href: "/interfaces/",
          label: "Inspect WAN interface",
          detail: "Verify the interface carrying upstream traffic.",
        },
      ];
    case "internet":
      return [
        {
          href: "/monitoring/",
          label: "Open monitoring",
          detail: "Review overall health and traffic telemetry.",
        },
        {
          href: "/flows/",
          label: "Inspect active flows",
          detail: "See which sessions are currently traversing the edge.",
        },
      ];
    default:
      return [];
  }
}

export function nodeOperatorHint(data: TopoNodeData): string {
  switch (data.nodeType) {
    case "firewall":
      return "This node represents the live appliance and its current policy, routes, and interface state.";
    case "zone":
      return "This node represents a policy zone. Use it to confirm subnet placement and decide whether policy or interface mapping needs attention.";
    case "gateway":
      return "This node represents the current upstream path. Use it to validate reachability and routing decisions.";
    case "internet":
      return "This node represents external connectivity beyond the appliance edge.";
    default:
      return "";
  }
}

function uptimeSince(time: string | undefined): string | undefined {
  const ms = time ? Date.now() - new Date(time).getTime() : NaN;
  if (!(ms > 0)) return undefined;
  const d = Math.floor(ms / 86400000);
  const h = Math.floor((ms % 86400000) / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  return `${d}d ${h}h ${m}m`;
}

/**
 * The firewall node's identity from the shared health poll: hostname and
 * version, and uptime when system stats did not report one.
 */
export function withHealth(data: TopoNodeData, health: HealthResponse | undefined): TopoNodeData {
  if (data.nodeType !== "firewall") return data;
  return {
    ...data,
    hostname: health?.component || "containd",
    version: health?.build || "dev-build",
    uptime: data.uptime ?? uptimeSince(health?.time) ?? "\u2014",
  };
}

export async function buildTopology(): Promise<TopoResult | null> {
  const [running, ifaceState, osRouting, flows, events, sysStats, counters] = await Promise.all([
    api.getRunningConfig().then(snapshot => snapshot?.data ?? null),
    api.listInterfaceState(),
    api.getOSRouting(),
    api.listFlows(),
    api.listEvents(),
    api.getSystemStats().catch(() => null),
    api.getRuleCounters(),
  ]);
  if (!running || ifaceState === null || flows === null) return null;
  const zones = running.zones;
  const ifaces = running.interfaces;
  const routing = running.routing;
  const fwRules = normalizeFirewallRules(running.firewall?.rules);

  const zoneSubnet: Record<string, string> = {};
  const zoneAddresses: Record<string, { address: InterfaceAddresses; fullAddrs: string[] }> = {};
  for (const ifc of ifaces || []) {
    const address = interfaceAddresses(ifc, ifaceState);
    if (ifc.zone && address.addrs.length &&
        (!zoneSubnet[ifc.zone] || (address.source === "config" && zoneAddresses[ifc.zone]?.address.source !== "config"))) {
      zoneSubnet[ifc.zone] = address.addrs[0];
      zoneAddresses[ifc.zone] = {
        address,
        fullAddrs: (address.source === "config" ? ifc.addresses : runtimeFor(ifc, ifaceState)?.addrs) || [],
      };
    }
  }

  const zoneHosts: Record<string, Set<string>> = {};
  const zoneFlowIds: Record<string, Set<string>> = {};
  for (const ev of (events as TelemetryEvent[]) || []) {
    const attr = ev.attributes as Record<string, string> | undefined;
    for (const z of [attr?.srcZone, attr?.dstZone]) {
      if (!z) {
        continue;
      }
      (zoneHosts[z] ??= new Set()).add(ev.srcIp || "");
      zoneHosts[z].add(ev.dstIp || "");
      if (ev.srcIp) {
        zoneHosts[z].add(ev.srcIp);
      }
      if (ev.dstIp) {
        zoneHosts[z].add(ev.dstIp);
      }
    }
  }
  for (const fl of flows) {
    for (const ip of [fl.srcIp, fl.dstIp]) {
      if (!ip) {
        continue;
      }
      for (const [zn, sub] of Object.entries(zoneSubnet)) {
        if (ipInCidr(ip, sub)) {
          (zoneHosts[zn] ??= new Set()).add(ip);
          if (fl.flowId) {
            (zoneFlowIds[zn] ??= new Set()).add(fl.flowId);
          }
        }
      }
    }
  }

  const zoneFlowCount: Record<string, { rx: number; tx: number }> = {};
  for (const fl of flows) {
    for (const [zn, sub] of Object.entries(zoneSubnet)) {
      if (fl.srcIp && ipInCidr(fl.srcIp, sub)) {
        (zoneFlowCount[zn] ??= { rx: 0, tx: 0 }).tx += fl.eventCount || 1;
      }
      if (fl.dstIp && ipInCidr(fl.dstIp, sub)) {
        (zoneFlowCount[zn] ??= { rx: 0, tx: 0 }).rx += fl.eventCount || 1;
      }
    }
  }

  const builtIfaces: BuiltIface[] = ((ifaces as Interface[]) || []).map((ifc) => {
    const st = runtimeFor(ifc, ifaceState);
    const address = interfaceAddresses(ifc, ifaceState);
    const zfc = ifc.zone ? zoneFlowCount[ifc.zone] : undefined;
    const rxStr = zfc ? `${zfc.rx} pkts` : "0 pkts";
    const txStr = zfc ? `${zfc.tx} pkts` : "0 pkts";
    return {
      name: ifc.device || ifc.name,
      address,
      fullAddrs: (address.source === "config" ? ifc.addresses : st?.addrs) || [],
      state: st?.up !== false ? "up" : "down",
      zone: ifc.zone || "\u2014",
      rx: rxStr,
      tx: txStr,
      vlan: ifc.vlanId || null,
    };
  });

  const gwByName: Record<string, { address?: string }> = {};
  for (const gw of (routing as RoutingConfig)?.gateways || []) {
    gwByName[gw.name] = gw;
  }
  const builtRoutes: BuiltRoute[] = [];
  for (const r of (routing as RoutingConfig)?.routes || []) {
    const gwName = r.gateway || "";
    const gwObj = gwByName[gwName];
    builtRoutes.push({
      dst: r.dst === "default" ? "0.0.0.0/0" : r.dst || "\u2014",
      gw: gwObj?.address || gwName || "\u2014",
      iface: r.iface || "\u2014",
      origin: "static",
      metric: r.metric ?? 0,
    });
  }
  for (const ifc of (ifaces as Interface[]) || []) {
    if (
      ifc.addresses?.length &&
      !builtRoutes.some((r) => r.dst === ifc.addresses![0])
    ) {
      builtRoutes.push({
        dst: ifc.addresses[0],
        gw: "\u2014",
        iface: ifc.name,
        origin: "local",
        metric: 0,
      });
    }
  }
  const osDflt = (osRouting as OSRoutingSnapshot)?.defaultRoute;
  if (osDflt && !builtRoutes.some((r) => r.dst === "0.0.0.0/0")) {
    builtRoutes.push({
      dst: "0.0.0.0/0",
      gw: osDflt.gateway || "\u2014",
      iface: osDflt.iface || "\u2014",
      origin: "dynamic",
      metric: osDflt.metric ?? 0,
    });
  }

  const builtRules = buildTopologyRules(fwRules, counters);

  const gwCfg = (routing as RoutingConfig)?.gateways?.[0];

  const stats = sysStats as SystemStats | null;

  const zoneAlerts: Record<string, number> = {};
  for (const ev of (events as TelemetryEvent[]) || []) {
    if (ev.kind !== "alert") {
      continue;
    }
    const attr = ev.attributes as Record<string, string> | undefined;
    for (const z of [attr?.srcZone, attr?.dstZone]) {
      if (z) {
        zoneAlerts[z] = (zoneAlerts[z] || 0) + 1;
      }
    }
  }

  const rfNodes: Node<TopoNodeData>[] = [];
  const nodeDataMap: Record<string, TopoNodeData> = {};

  const internetData: TopoNodeData = { label: "INTERNET", nodeType: "internet" };
  rfNodes.push({
    id: "internet",
    type: "internet",
    position: { x: 500, y: 0 },
    data: internetData,
    draggable: true,
  });
  nodeDataMap.internet = internetData;

  const gwData: TopoNodeData = {
    label: gwCfg?.name?.toUpperCase() || "ISP-GW",
    nodeType: "gateway",
    ip: gwCfg?.address || osDflt?.gateway || "\u2014",
    asn: "\u2014",
    latency: "\u2014",
    loss: "\u2014",
  };
  rfNodes.push({
    id: "gw-isp",
    type: "gateway",
    position: { x: 500, y: 140 },
    data: gwData,
    draggable: true,
  });
  nodeDataMap["gw-isp"] = gwData;

  const fwData: TopoNodeData = {
    label: "CONTAIND",
    nodeType: "firewall",
    // Hostname, version and an uptime fallback come from health: withHealth.
    uptime: stats?.runtime?.uptime || undefined,
    cpu: stats?.cpu?.usagePercent != null ? Math.round(stats.cpu.usagePercent) : 0,
    mem: stats?.memory?.usagePercent != null
      ? Math.round(stats.memory.usagePercent)
      : 0,
    sessions: flows.length,
    interfaces: builtIfaces,
    routes: builtRoutes,
    rules: builtRules,
  };
  rfNodes.push({
    id: "fw-main",
    type: "firewall",
    position: { x: 480, y: 310 },
    data: fwData,
    draggable: true,
  });
  nodeDataMap["fw-main"] = fwData;

  const zoneList = (zones as Zone[]) || [];
  const count = zoneList.length;
  const spreadX = Math.min(900, 200 * count);
  const cx = 540;
  const baseY = 520;

  zoneList.forEach((z, i) => {
    const name = z.name;
    const ifc = ((ifaces as Interface[]) || []).find((ii) => ii.zone === name);
    const subnet = zoneSubnet[name] || "\u2014";
    const hosts = zoneHosts[name]?.size || 0;
    const flCount = zoneFlowIds[name]?.size || 0;
    const alerts = zoneAlerts[name] || 0;
    const status: TopoNodeData["status"] =
      alerts >= 5 ? "crit" : alerts >= 1 ? "warn" : "ok";
    const id = "zone-" + name.toLowerCase().replace(/[^a-z0-9]+/g, "_");

    const t = count === 1 ? 0.5 : i / (count - 1);
    const x = cx - spreadX / 2 + t * spreadX;
    const arc = Math.sin(t * Math.PI) * 50;

    const zData: TopoNodeData = {
      label: name.toUpperCase(),
      nodeType: "zone",
      status,
      iface: ifc?.device || ifc?.name || "\u2014",
      subnet,
      ...zoneAddresses[name],
      hosts,
      flows: flCount,
      rx: "\u2014",
      tx: "\u2014",
      vlan: ifc?.vlanId || null,
      desc: z.description || z.alias || "",
    };
    rfNodes.push({
      id,
      type: "zone",
      position: { x, y: baseY + arc },
      data: zData,
      draggable: true,
    });
    nodeDataMap[id] = zData;
  });

  const rfEdges: Edge[] = [];
  rfEdges.push({
    id: "e-internet-gw",
    source: "internet",
    target: "gw-isp",
    ...edgeStyle("wan"),
  });
  rfEdges.push({
    id: "e-gw-fw",
    source: "gw-isp",
    target: "fw-main",
    ...edgeStyle("gw"),
  });
  zoneList.forEach((z) => {
    const zId = "zone-" + z.name.toLowerCase().replace(/[^a-z0-9]+/g, "_");
    const estyle = z.name.toLowerCase() === "wan" ? "iface" : "zone";
    rfEdges.push({
      id: `e-fw-${zId}`,
      source: "fw-main",
      target: zId,
      ...edgeStyle(estyle),
    });
  });

  return { nodes: rfNodes, edges: rfEdges, nodeDataMap };
}
