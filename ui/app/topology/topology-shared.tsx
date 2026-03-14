"use client";

import React, { createContext, useContext } from "react";
import { Edge, Handle, Node, NodeProps, Position } from "reactflow";

import {
  api,
  type FirewallRule,
  type FlowSummary,
  type Interface,
  type InterfaceState,
  type OSRoutingSnapshot,
  type RoutingConfig,
  type SystemStats,
  type TelemetryEvent,
  type Zone,
  fetchHealth,
} from "../../lib/api";
import s from "./topology.module.css";

export interface BuiltIface {
  name: string;
  ip: string;
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
  action: "allow" | "deny";
  desc: string;
  hits: number;
}

export interface TopoNodeData {
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
  hosts?: number;
  flows?: number;
  rx?: string;
  tx?: string;
  vlan?: number | null;
  desc?: string;
  spark?: number[];
  selected?: boolean;
}

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

export const sparkStore: { data: Record<string, number[]>; tick: number } = {
  data: {},
  tick: 0,
};

export const SparkTickContext = createContext(0);

const hStyle: React.CSSProperties = {
  opacity: 0,
  width: 1,
  height: 1,
  border: "none",
  pointerEvents: "none",
};

function InternetNode({ data }: NodeProps<TopoNodeData>) {
  return (
    <div
      className={`${s.nodeCard} ${s.accentGray} ${data.selected ? s.nodeCardSelected : ""}`}
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

function GatewayNode({ id, data }: NodeProps<TopoNodeData>) {
  const sc = STATUS_COLORS[data.status || "ok"];
  return (
    <div
      className={`${s.nodeCard} ${s.accentCyan} ${data.selected ? s.nodeCardSelected : ""}`}
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
        <Spark nodeId={id} color="#06b6d4" />
      </div>
    </div>
  );
}

function FirewallNode({ id, data }: NodeProps<TopoNodeData>) {
  return (
    <div
      className={`${s.nodeCard} ${s.accentAmber} ${data.selected ? s.nodeCardSelected : ""}`}
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
        <Spark nodeId={id} color="#f59e0b" />
      </div>
    </div>
  );
}

function ZoneNode({ id, data }: NodeProps<TopoNodeData>) {
  const st = data.status || "ok";
  const sc = STATUS_COLORS[st];
  const accentCls =
    st === "crit" ? s.accentRed : st === "warn" ? s.accentAmber : s.accentGreen;
  const nameCls =
    st === "crit" ? s.nameRed : st === "warn" ? s.nameAmber : s.nameGreen;
  const sparkColor =
    st === "crit" ? "#ef4444" : st === "warn" ? "#f59e0b" : "#22c55e";
  return (
    <div
      className={`${s.nodeCard} ${accentCls} ${data.selected ? s.nodeCardSelected : ""}`}
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
        <NRow k="subnet" v={data.subnet || "\u2014"} />
        <NRow k="hosts" v={String(data.hosts ?? 0)} />
        <NRow k="flows" v={String(data.flows ?? 0)} />
        <Spark nodeId={id} color={sparkColor} />
      </div>
    </div>
  );
}

function NRow({ k, v }: { k: string; v: string }) {
  return (
    <div className={s.nodeRow}>
      <span className={s.nodeRowKey}>{k}</span>
      <span className={s.nodeRowVal}>{v}</span>
    </div>
  );
}

function Spark({ nodeId, color }: { nodeId?: string; color: string }) {
  useContext(SparkTickContext);
  const data = nodeId ? sparkStore.data[nodeId] : undefined;
  if (!data?.length) {
    return null;
  }
  return (
    <div className={s.sparkline}>
      {data.map((v, i) => (
        <div
          key={i}
          className={s.spark}
          style={{
            height: Math.max(2, Math.floor(v * 16)),
            background: color,
          }}
        />
      ))}
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

export async function buildTopology(): Promise<TopoResult | null> {
  const [
    health,
    zones,
    ifaces,
    ifaceState,
    routing,
    osRouting,
    fwRules,
    flows,
    events,
    sysStats,
  ] = await Promise.all([
    fetchHealth(),
    api.listZones(),
    api.listInterfaces(),
    api.listInterfaceState(),
    api.getRouting(),
    api.getOSRouting(),
    api.listFirewallRules(),
    api.listFlows(),
    api.listEvents(),
    api.getSystemStats().catch(() => null),
  ]);

  const zoneSubnet: Record<string, string> = {};
  for (const ifc of ifaces || []) {
    if (ifc.zone && ifc.addresses?.length && !zoneSubnet[ifc.zone]) {
      zoneSubnet[ifc.zone] = ifc.addresses[0];
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
  for (const fl of (flows as FlowSummary[]) || []) {
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

  const stateMap: Record<string, InterfaceState> = {};
  for (const st of (ifaceState as InterfaceState[]) || []) {
    stateMap[st.name] = st;
  }
  const ifState = (ifc: Interface) =>
    stateMap[ifc.name] || (ifc.device ? stateMap[ifc.device] : undefined);

  const zoneFlowCount: Record<string, { rx: number; tx: number }> = {};
  for (const fl of (flows as FlowSummary[]) || []) {
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
    const st = ifState(ifc);
    const addr = ifc.addresses?.length
      ? ifc.addresses[0]
      : st?.addrs?.find(
          (a: string) => !a.startsWith("::") && !a.startsWith("fe80"),
        ) || "\u2014";
    const zfc = ifc.zone ? zoneFlowCount[ifc.zone] : undefined;
    const rxStr = zfc ? `${zfc.rx} pkts` : "0 pkts";
    const txStr = zfc ? `${zfc.tx} pkts` : "0 pkts";
    return {
      name: ifc.device || ifc.name,
      ip: addr,
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

  const builtRules: BuiltRule[] = ((fwRules as FirewallRule[]) || []).map((r) => {
    const src = (r.sourceZones || []).join(",") || "*";
    const dst = (r.destZones || []).join(",") || "*";
    const ports = (r.protocols || [])
      .map((p) => (p.port ? `${p.name}/${p.port}` : p.name))
      .join(",");
    return {
      action: (r.action || "DENY").toLowerCase() as "allow" | "deny",
      desc: `${src} \u2192 ${dst}${ports ? " " + ports : ""}`,
      hits: 0,
    };
  });

  const gwCfg = (routing as RoutingConfig)?.gateways?.[0];

  const stats = sysStats as SystemStats | null;
  let uptimeStr = "\u2014";
  if (stats?.runtime?.uptime) {
    uptimeStr = stats.runtime.uptime;
  } else if (health?.time) {
    const ms = Date.now() - new Date(health.time).getTime();
    if (ms > 0) {
      const d = Math.floor(ms / 86400000);
      const h = Math.floor((ms % 86400000) / 3600000);
      const m = Math.floor((ms % 3600000) / 60000);
      uptimeStr = `${d}d ${h}h ${m}m`;
    }
  }

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
    hostname: health?.component || "containd",
    version: health?.build || "dev-build",
    uptime: uptimeStr,
    cpu: stats?.cpu?.usagePercent != null ? Math.round(stats.cpu.usagePercent) : 0,
    mem: stats?.memory?.usagePercent != null
      ? Math.round(stats.memory.usagePercent)
      : 0,
    sessions: ((flows as FlowSummary[]) || []).length,
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
    const st = ifc ? ifState(ifc) : undefined;
    const subnet =
      zoneSubnet[name] ||
      st?.addrs?.find((a: string) => !a.startsWith("::") && !a.startsWith("fe80")) ||
      "\u2014";
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
