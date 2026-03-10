"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  applyNodeChanges,
  Background,
  Controls,
  Edge,
  Handle,
  MiniMap,
  Node,
  NodeChange,
  NodeProps,
  Position,
  useReactFlow,
  ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";
import PhysicalView from "./PhysicalView";
import SecurityView from "./SecurityView";
import { Shell } from "../../components/Shell";
import {
  api,
  FirewallRule,
  Interface,
  InterfaceState,
  RoutingConfig,
  OSRoutingSnapshot,
  SystemStats,
  Zone,
  FlowSummary,
  TelemetryEvent,
  fetchHealth,
} from "../../lib/api";
import s from "./topology.module.css";

/* ════════════════════════════════════════════════════════════════════
   TYPES
   ════════════════════════════════════════════════════════════════════ */

interface BuiltIface { name: string; ip: string; state: "up" | "down"; zone: string; rx: string; tx: string; vlan: number | null }
interface BuiltRoute { dst: string; gw: string; iface: string; origin: "static" | "dynamic" | "local"; metric: number }
interface BuiltRule { action: "allow" | "deny"; desc: string; hits: number }

interface TopoNodeData {
  label: string;
  nodeType: "internet" | "gateway" | "firewall" | "zone";
  status?: "ok" | "warn" | "crit" | "down";
  hostname?: string; version?: string; uptime?: string;
  cpu?: number; mem?: number; sessions?: number;
  interfaces?: BuiltIface[]; routes?: BuiltRoute[]; rules?: BuiltRule[];
  ip?: string; asn?: string; latency?: string; loss?: string;
  iface?: string; subnet?: string; hosts?: number; flows?: number;
  rx?: string; tx?: string; vlan?: number | null; desc?: string;
  spark?: number[];
  selected?: boolean;
}

/* ════════════════════════════════════════════════════════════════════
   CONSTANTS
   ════════════════════════════════════════════════════════════════════ */

const STATUS_COLORS: Record<string, string> = {
  ok: "#22c55e", warn: "#f59e0b", crit: "#ef4444", down: "#6b7280",
};

/* Hidden handle style for ReactFlow connection points */
const hStyle: React.CSSProperties = { opacity: 0, width: 1, height: 1, border: "none", pointerEvents: "none" };

/* ════════════════════════════════════════════════════════════════════
   CUSTOM NODE TYPES
   ════════════════════════════════════════════════════════════════════ */

function InternetNode({ data }: NodeProps<TopoNodeData>) {
  return (
    <div className={`${s.nodeCard} ${s.accentGray} ${data.selected ? s.nodeCardSelected : ""}`}>
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${s.nameGray}`}>{data.label}</span>
        <div className={s.statusDot} style={{ background: "#6b7280", boxShadow: "0 0 5px #6b728080" }} />
      </div>
    </div>
  );
}

function GatewayNode({ data }: NodeProps<TopoNodeData>) {
  const sc = STATUS_COLORS[data.status || "ok"];
  return (
    <div className={`${s.nodeCard} ${s.accentCyan} ${data.selected ? s.nodeCardSelected : ""}`}>
      <Handle type="target" position={Position.Top} style={hStyle} />
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${s.nameCyan}`}>{data.label}</span>
        <div className={s.statusDot} style={{ background: sc, boxShadow: `0 0 5px ${sc}80` }} />
      </div>
      <div className={s.nodeBody}>
        <NRow k="ip" v={data.ip || "\u2014"} />
        <NRow k="latency" v={data.latency || "\u2014"} />
        <Spark data={data.spark} color="#06b6d4" />
      </div>
    </div>
  );
}

function FirewallNode({ data }: NodeProps<TopoNodeData>) {
  return (
    <div className={`${s.nodeCard} ${s.accentAmber} ${data.selected ? s.nodeCardSelected : ""}`} style={{ minWidth: 160 }}>
      <Handle type="target" position={Position.Top} style={hStyle} />
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${s.nameAmber}`}>{data.label}</span>
        <div className={s.statusDot} style={{ background: "#22c55e", boxShadow: "0 0 5px #22c55e80" }} />
      </div>
      <div className={s.nodeBody}>
        <NRow k="sessions" v={String(data.sessions ?? 0)} />
        <NRow k="cpu" v={`${data.cpu ?? 0}%`} />
        <NRow k="mem" v={`${data.mem ?? 0}%`} />
        <Spark data={data.spark} color="#f59e0b" />
      </div>
    </div>
  );
}

function ZoneNode({ data }: NodeProps<TopoNodeData>) {
  const st = data.status || "ok";
  const sc = STATUS_COLORS[st];
  const accentCls = st === "crit" ? s.accentRed : st === "warn" ? s.accentAmber : s.accentGreen;
  const nameCls = st === "crit" ? s.nameRed : st === "warn" ? s.nameAmber : s.nameGreen;
  const sparkColor = st === "crit" ? "#ef4444" : st === "warn" ? "#f59e0b" : "#22c55e";
  return (
    <div className={`${s.nodeCard} ${accentCls} ${data.selected ? s.nodeCardSelected : ""}`}>
      <Handle type="target" position={Position.Top} style={hStyle} />
      <Handle type="source" position={Position.Bottom} style={hStyle} />
      <div className={s.nodeHeader}>
        <span className={`${s.nodeName} ${nameCls}`}>{data.label}</span>
        <div className={s.statusDot} style={{ background: sc, boxShadow: `0 0 5px ${sc}80` }} />
      </div>
      <div className={s.nodeBody}>
        <NRow k="subnet" v={data.subnet || "\u2014"} />
        <NRow k="hosts" v={String(data.hosts ?? 0)} />
        <NRow k="flows" v={String(data.flows ?? 0)} />
        <Spark data={data.spark} color={sparkColor} />
      </div>
    </div>
  );
}

function NRow({ k, v }: { k: string; v: string }) {
  return <div className={s.nodeRow}><span className={s.nodeRowKey}>{k}</span><span className={s.nodeRowVal}>{v}</span></div>;
}

function Spark({ data, color }: { data?: number[]; color: string }) {
  if (!data?.length) return null;
  return (
    <div className={s.sparkline}>
      {data.map((v, i) => (
        <div key={i} className={s.spark} style={{ height: Math.max(2, Math.floor(v * 16)), background: color }} />
      ))}
    </div>
  );
}

const nodeTypes = {
  internet: InternetNode,
  gateway: GatewayNode,
  firewall: FirewallNode,
  zone: ZoneNode,
};

/* ════════════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════════════ */

function ip4(str: string): number {
  const p = (str || "").split(".");
  return (((+p[0]) << 24) | ((+p[1]) << 16) | ((+p[2]) << 8) | +p[3]) >>> 0;
}
function ipInCidr(ip: string, cidr: string): boolean {
  if (!cidr || !ip) return false;
  const [base, bits] = cidr.split("/");
  if (!bits) return ip === base;
  const mask = (-1 << (32 - parseInt(bits))) >>> 0;
  return (ip4(ip) & mask) === (ip4(base) & mask);
}

/* Edge style by type */
function edgeStyle(type: string): Partial<Edge> {
  switch (type) {
    case "wan": return { type: "straight", style: { stroke: "rgba(107,114,128,0.5)", strokeWidth: 1 }, animated: false };
    case "gw": return { type: "straight", style: { stroke: "rgba(6,182,212,0.5)", strokeWidth: 1.5 }, animated: false };
    case "zone": return { type: "straight", style: { stroke: "rgba(34,197,94,0.4)", strokeWidth: 1.2 }, animated: false };
    case "iface": return { type: "straight", style: { stroke: "rgba(168,85,247,0.4)", strokeWidth: 1 }, animated: false };
    default: return { type: "straight", style: { stroke: "rgba(107,114,128,0.3)", strokeWidth: 1 }, animated: false };
  }
}

/* ════════════════════════════════════════════════════════════════════
   BUILD TOPOLOGY FROM API
   ════════════════════════════════════════════════════════════════════ */

interface TopoResult {
  nodes: Node<TopoNodeData>[];
  edges: Edge[];
  nodeDataMap: Record<string, TopoNodeData>;
}

async function buildTopology(): Promise<TopoResult | null> {
  const [health, zones, ifaces, ifaceState, routing, osRouting, fwRules, flows, events, sysStats] =
    await Promise.all([
      fetchHealth(), api.listZones(), api.listInterfaces(), api.listInterfaceState(),
      api.getRouting(), api.getOSRouting(), api.listFirewallRules(), api.listFlows(), api.listEvents(),
      api.getSystemStats().catch(() => null),
    ]);

  // Maps
  const zoneSubnet: Record<string, string> = {};
  for (const ifc of ifaces || []) {
    if (ifc.zone && ifc.addresses?.length && !zoneSubnet[ifc.zone]) zoneSubnet[ifc.zone] = ifc.addresses[0];
  }

  const zoneHosts: Record<string, Set<string>> = {};
  const zoneFlowIds: Record<string, Set<string>> = {};
  for (const ev of (events as TelemetryEvent[]) || []) {
    const attr = ev.attributes as Record<string, string> | undefined;
    for (const z of [attr?.srcZone, attr?.dstZone]) {
      if (!z) continue;
      (zoneHosts[z] ??= new Set()).add(ev.srcIp || "");
      (zoneHosts[z]).add(ev.dstIp || "");
      if (ev.srcIp) zoneHosts[z].add(ev.srcIp);
      if (ev.dstIp) zoneHosts[z].add(ev.dstIp);
    }
  }
  for (const fl of (flows as FlowSummary[]) || []) {
    for (const ip of [fl.srcIp, fl.dstIp]) {
      if (!ip) continue;
      for (const [zn, sub] of Object.entries(zoneSubnet)) {
        if (ipInCidr(ip, sub)) {
          (zoneHosts[zn] ??= new Set()).add(ip);
          if (fl.flowId) (zoneFlowIds[zn] ??= new Set()).add(fl.flowId);
        }
      }
    }
  }

  const stateMap: Record<string, InterfaceState> = {};
  for (const st of (ifaceState as InterfaceState[]) || []) stateMap[st.name] = st;
  const ifState = (ifc: Interface) => stateMap[ifc.name] || (ifc.device ? stateMap[ifc.device] : undefined);

  // Count flows per zone for interface traffic estimation
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

  // Build interfaces list
  const builtIfaces: BuiltIface[] = ((ifaces as Interface[]) || []).map((ifc) => {
    const st = ifState(ifc);
    const addr = ifc.addresses?.length ? ifc.addresses[0]
      : st?.addrs?.find((a: string) => !a.startsWith("::") && !a.startsWith("fe80")) || "\u2014";
    const zfc = ifc.zone ? zoneFlowCount[ifc.zone] : undefined;
    const rxStr = zfc ? `${zfc.rx} pkts` : "0 pkts";
    const txStr = zfc ? `${zfc.tx} pkts` : "0 pkts";
    return { name: ifc.device || ifc.name, ip: addr, state: st?.up !== false ? "up" as const : "down" as const, zone: ifc.zone || "\u2014", rx: rxStr, tx: txStr, vlan: ifc.vlanId || null };
  });

  // Build routes
  const gwByName: Record<string, { address?: string }> = {};
  for (const gw of (routing as RoutingConfig)?.gateways || []) gwByName[gw.name] = gw;
  const builtRoutes: BuiltRoute[] = [];
  for (const r of (routing as RoutingConfig)?.routes || []) {
    const gwName = r.gateway || "";
    const gwObj = gwByName[gwName];
    builtRoutes.push({ dst: r.dst === "default" ? "0.0.0.0/0" : r.dst || "\u2014", gw: gwObj?.address || gwName || "\u2014", iface: r.iface || "\u2014", origin: "static", metric: r.metric ?? 0 });
  }
  for (const ifc of (ifaces as Interface[]) || []) {
    if (ifc.addresses?.length && !builtRoutes.some((r) => r.dst === ifc.addresses![0]))
      builtRoutes.push({ dst: ifc.addresses[0], gw: "\u2014", iface: ifc.name, origin: "local", metric: 0 });
  }
  const osDflt = (osRouting as OSRoutingSnapshot)?.defaultRoute;
  if (osDflt && !builtRoutes.some((r) => r.dst === "0.0.0.0/0"))
    builtRoutes.push({ dst: "0.0.0.0/0", gw: osDflt.gateway || "\u2014", iface: osDflt.iface || "\u2014", origin: "dynamic", metric: osDflt.metric ?? 0 });

  // Build rules
  const builtRules: BuiltRule[] = ((fwRules as FirewallRule[]) || []).map((r) => {
    const src = (r.sourceZones || []).join(",") || "*";
    const dst = (r.destZones || []).join(",") || "*";
    const ports = (r.protocols || []).map((p) => (p.port ? `${p.name}/${p.port}` : p.name)).join(",");
    return { action: (r.action || "DENY").toLowerCase() as "allow" | "deny", desc: `${src} \u2192 ${dst}${ports ? " " + ports : ""}`, hits: 0 };
  });

  const gwCfg = (routing as RoutingConfig)?.gateways?.[0];

  // Uptime — prefer runtime.uptime from SystemStats, fall back to health.time
  const stats = sysStats as SystemStats | null;
  let uptimeStr = "\u2014";
  if (stats?.runtime?.uptime) {
    uptimeStr = stats.runtime.uptime;
  } else if (health?.time) {
    const ms = Date.now() - new Date(health.time).getTime();
    if (ms > 0) { const d = Math.floor(ms / 86400000), h = Math.floor((ms % 86400000) / 3600000), m = Math.floor((ms % 3600000) / 60000); uptimeStr = `${d}d ${h}h ${m}m`; }
  }

  // IDS alerts per zone
  const zoneAlerts: Record<string, number> = {};
  for (const ev of (events as TelemetryEvent[]) || []) {
    if (ev.kind !== "alert") continue;
    const attr = ev.attributes as Record<string, string> | undefined;
    for (const z of [attr?.srcZone, attr?.dstZone]) if (z) zoneAlerts[z] = (zoneAlerts[z] || 0) + 1;
  }

  // ── Build ReactFlow nodes ──
  const rfNodes: Node<TopoNodeData>[] = [];
  const nodeDataMap: Record<string, TopoNodeData> = {};

  // Internet
  const internetData: TopoNodeData = { label: "INTERNET", nodeType: "internet" };
  rfNodes.push({ id: "internet", type: "internet", position: { x: 500, y: 0 }, data: internetData, draggable: true });
  nodeDataMap["internet"] = internetData;

  // Gateway
  const gwData: TopoNodeData = {
    label: gwCfg?.name?.toUpperCase() || "ISP-GW", nodeType: "gateway",
    ip: gwCfg?.address || osDflt?.gateway || "\u2014", asn: "\u2014", latency: "\u2014", loss: "\u2014",
  };
  rfNodes.push({ id: "gw-isp", type: "gateway", position: { x: 500, y: 140 }, data: gwData, draggable: true });
  nodeDataMap["gw-isp"] = gwData;

  // Firewall
  const fwData: TopoNodeData = {
    label: "CONTAIND", nodeType: "firewall",
    hostname: health?.component || "containd", version: health?.build || "dev-build",
    uptime: uptimeStr,
    cpu: stats?.cpu?.usagePercent != null ? Math.round(stats.cpu.usagePercent) : 0,
    mem: stats?.memory?.usagePercent != null ? Math.round(stats.memory.usagePercent) : 0,
    sessions: ((flows as FlowSummary[]) || []).length,
    interfaces: builtIfaces, routes: builtRoutes, rules: builtRules,
  };
  rfNodes.push({ id: "fw-main", type: "firewall", position: { x: 480, y: 310 }, data: fwData, draggable: true });
  nodeDataMap["fw-main"] = fwData;

  // Zones — spread in arc below firewall
  const zoneList = (zones as Zone[]) || [];
  const count = zoneList.length;
  const spreadX = Math.min(900, 200 * count);
  const cx = 540;
  const baseY = 520;

  zoneList.forEach((z, i) => {
    const name = z.name;
    const ifc = ((ifaces as Interface[]) || []).find((ii) => ii.zone === name);
    const st = ifc ? ifState(ifc) : undefined;
    const subnet = zoneSubnet[name] || st?.addrs?.find((a: string) => !a.startsWith("::") && !a.startsWith("fe80")) || "\u2014";
    const hosts = zoneHosts[name]?.size || 0;
    const flCount = zoneFlowIds[name]?.size || 0;
    const alerts = zoneAlerts[name] || 0;
    const status: TopoNodeData["status"] = alerts >= 5 ? "crit" : alerts >= 1 ? "warn" : "ok";
    const id = "zone-" + name.toLowerCase().replace(/[^a-z0-9]+/g, "_");

    // Position: evenly spread, slight arc
    const t = count === 1 ? 0.5 : i / (count - 1);
    const x = cx - spreadX / 2 + t * spreadX;
    const arc = Math.sin(t * Math.PI) * 50;

    const zData: TopoNodeData = {
      label: name.toUpperCase(), nodeType: "zone", status,
      iface: ifc?.device || ifc?.name || "\u2014",
      subnet, hosts, flows: flCount, rx: "\u2014", tx: "\u2014",
      vlan: ifc?.vlanId || null, desc: z.description || z.alias || "",
    };
    rfNodes.push({ id, type: "zone", position: { x, y: baseY + arc }, data: zData, draggable: true });
    nodeDataMap[id] = zData;
  });

  // ── Build ReactFlow edges ──
  const rfEdges: Edge[] = [];
  rfEdges.push({ id: "e-internet-gw", source: "internet", target: "gw-isp", ...edgeStyle("wan") });
  rfEdges.push({ id: "e-gw-fw", source: "gw-isp", target: "fw-main", ...edgeStyle("gw") });
  zoneList.forEach((z) => {
    const zId = "zone-" + z.name.toLowerCase().replace(/[^a-z0-9]+/g, "_");
    const estyle = z.name.toLowerCase() === "wan" ? "iface" : "zone";
    rfEdges.push({ id: `e-fw-${zId}`, source: "fw-main", target: zId, ...edgeStyle(estyle) });
  });

  return { nodes: rfNodes, edges: rfEdges, nodeDataMap };
}

/* ════════════════════════════════════════════════════════════════════
   INNER COMPONENT (needs ReactFlowProvider)
   ════════════════════════════════════════════════════════════════════ */

function TopologyInner() {
  const [nodes, setNodes] = useState<Node<TopoNodeData>[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);
  const [syncTime, setSyncTime] = useState("\u2014");
  const [currentView, setCurrentView] = useState("logical");
  const nodeDataRef = useRef<Record<string, TopoNodeData>>({});
  const sparkRef = useRef<Record<string, number[]>>({});
  const { fitView } = useReactFlow();

  // ── Fetch & build ──
  const fetchData = useCallback(async () => {
    const result = await buildTopology();
    if (!result) return;

    // Merge sparkline history
    for (const n of result.nodes) {
      if (!sparkRef.current[n.id]) sparkRef.current[n.id] = Array.from({ length: 14 }, () => Math.random() * 0.6 + 0.1);
      n.data.spark = sparkRef.current[n.id];
    }

    nodeDataRef.current = result.nodeDataMap;
    setNodes(result.nodes);
    setEdges(result.edges);
    setSyncTime(new Date().toLocaleTimeString("en-US", { hour12: false }));
  }, []);

  const initialFitDone = useRef(false);
  useEffect(() => {
    fetchData().then(() => {
      // Delay fitView to let ReactFlow measure nodes
      setTimeout(() => { fitView({ padding: 0.15, duration: 400 }); initialFitDone.current = true; }, 200);
    });
    const iv = setInterval(fetchData, 30000);
    return () => clearInterval(iv);
  }, [fetchData, fitView]);

  // ── Sparkline traffic simulation ──
  useEffect(() => {
    const iv = setInterval(() => {
      const hist = sparkRef.current;
      for (const id of Object.keys(hist)) {
        hist[id].shift();
        hist[id].push(Math.max(0.05, Math.min(1, hist[id][hist[id].length - 1] + (Math.random() - 0.5) * 0.2)));
      }
      // Update node data with new spark values + selection state
      setNodes((prev) =>
        prev.map((n) => ({
          ...n,
          data: { ...n.data, spark: [...(hist[n.id] || [])], selected: n.id === selectedId },
        })),
      );
    }, 2000);
    return () => clearInterval(iv);
  }, [selectedId]);

  // ── Update selection highlight on nodes ──
  useEffect(() => {
    setNodes((prev) =>
      prev.map((n) => (n.data.selected !== (n.id === selectedId) ? { ...n, data: { ...n.data, selected: n.id === selectedId } } : n)),
    );
  }, [selectedId]);

  // ── Handle node click ──
  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedId(node.id);
    setPanelOpen(true);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedId(null);
  }, []);

  // ── Handle all node changes (position, dimensions, selection, etc.) ──
  const onNodesChange = useCallback((changes: NodeChange[]) => {
    setNodes((prev) => applyNodeChanges(changes, prev));
  }, []);

  const selectedData = selectedId ? nodeDataRef.current[selectedId] : null;

  return (
    <div className={s.page}>
      {/* TOPBAR */}
      <div className={s.topbar}>
        <div className={s.topbarLeft}>
          <span className={s.breadcrumb}>MONITORING <span>&rsaquo;</span> TOPOLOGY</span>
        </div>
        <div className={s.viewTabs}>
          {(["logical", "physical", "security"] as const).map((v) => (
            <button key={v} className={`${s.tab} ${currentView === v ? s.tabActive : ""}`} onClick={() => setCurrentView(v)}>{v.toUpperCase()}</button>
          ))}
        </div>
        <div className={s.topbarRight}>
          <div className={s.statusChip}>
            <div className={s.chipDot} style={{ background: "#22c55e", boxShadow: "0 0 6px #22c55e" }} />
            <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: "#22c55e" }}>ALL NOMINAL</span>
          </div>
          <div className={s.statusChip}>
            <span style={{ color: "#4a4030" }}>LAST SYNC</span>
            <span style={{ color: "#f59e0b" }}>{syncTime}</span>
          </div>
          {currentView === "logical" && (
            <button className={s.iconBtn} title="Fit to screen" onClick={() => fitView({ padding: 0.15, duration: 300 })}>&#x2922;</button>
          )}
          <button className={s.iconBtn} title="Refresh" onClick={() => fetchData()}>&#x21bb;</button>
        </div>
      </div>

      {/* WORKSPACE — switches between views */}
      {currentView === "physical" ? (
        <PhysicalView />
      ) : currentView === "security" ? (
        <SecurityView />
      ) : (
        <div className={s.workspace} style={panelOpen ? undefined : { gridTemplateColumns: "1fr" }}>
          <div className={s.flowWrap}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodeClick={onNodeClick}
              onPaneClick={onPaneClick}
              onNodesChange={onNodesChange}
              fitView
              fitViewOptions={{ padding: 0.15 }}
              minZoom={0.2}
              maxZoom={2}
              nodesDraggable
              elementsSelectable
              proOptions={{ hideAttribution: true }}
              defaultEdgeOptions={{ type: "straight" }}
              style={{ background: "#060808" }}
            >
              <Background color="rgba(245,158,11,0.06)" gap={28} size={1} />
              <Controls
                showInteractive={false}
                style={{ background: "#0e130e", border: "1px solid rgba(245,158,11,0.14)", borderRadius: 0 }}
              />
              <MiniMap
                nodeColor={(n) => {
                  const t = (n.data as TopoNodeData)?.nodeType;
                  return t === "firewall" ? "#f59e0b" : t === "gateway" ? "#06b6d4" : t === "zone" ? "#22c55e" : "#6b7280";
                }}
                maskColor="rgba(6,8,8,0.85)"
                style={{ background: "#0a0e0a", border: "1px solid rgba(245,158,11,0.14)", borderRadius: 0 }}
              />
            </ReactFlow>

            {/* Legend overlay */}
            <div className={s.canvasLegend}>
              <div className={s.legendItem}><div className={s.legendLine} style={{ background: "#f59e0b" }} />Firewall / Policy</div>
              <div className={s.legendItem}><div className={s.legendLine} style={{ background: "#06b6d4" }} />Gateway link</div>
              <div className={s.legendItem}><div className={s.legendLine} style={{ background: "#22c55e", opacity: 0.7 }} />Zone interconnect</div>
              <div className={s.legendItem}><div className={s.legendLine} style={{ background: "#a855f7", opacity: 0.7 }} />Interface / VLAN</div>
              <div className={s.legendItem}><div className={s.legendLine} style={{ background: "#6b7280", opacity: 0.7, borderTop: "1px dashed #6b7280", height: 0 }} />External / WAN</div>
            </div>

            {!panelOpen && <button className={s.panelToggle} onClick={() => setPanelOpen(true)} title="Show detail panel">&#x25C0;</button>}
          </div>

          {/* DETAIL PANEL */}
          {panelOpen && (
            <div className={s.detailPanel}>
              <div className={s.panelHeader}>
                <span className={s.panelTitle}>{selectedData?.label || "TOPOLOGY"}</span>
                <button className={s.panelClose} onClick={() => setPanelOpen(false)}>&#x25B6;</button>
              </div>
              <div className={s.panelBody}>
                {selectedData ? <DetailContent data={selectedData} /> : (
                  <div className={s.panelEmpty}>
                    <div className={s.panelEmptyIcon}>&#x2B21;</div>
                    <div>Select any node to inspect its configuration, interfaces, routes, and active rules.</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   PAGE EXPORT (wraps in ReactFlowProvider)
   ════════════════════════════════════════════════════════════════════ */

export default function TopologyPage() {
  return (
    <Shell title="Topology">
      <ReactFlowProvider>
        <TopologyInner />
      </ReactFlowProvider>
    </Shell>
  );
}

/* ════════════════════════════════════════════════════════════════════
   DETAIL PANEL CONTENT
   ════════════════════════════════════════════════════════════════════ */

function DetailContent({ data }: { data: TopoNodeData }) {
  const sc = STATUS_COLORS[data.status || "ok"];
  const sl: Record<string, string> = { ok: "ONLINE", warn: "WARNING", crit: "CRITICAL", down: "OFFLINE" };

  return (
    <>
      <div className={s.panelSection}>
        <div className={s.panelSectionLabel}>Status</div>
        <DRow k="State" v={sl[data.status || "ok"]} color={sc} />
        <DRow k="Type" v={data.nodeType.toUpperCase()} />
        {data.nodeType === "firewall" && <>
          <DRow k="Hostname" v={data.hostname || ""} />
          <DRow k="Version" v={data.version || ""} cls={s.valAmber} />
          <DRow k="Uptime" v={data.uptime || ""} cls={s.valGreen} />
          <DRow k="CPU" v={`${data.cpu ?? 0}%`} />
          <DRow k="Memory" v={`${data.mem ?? 0}%`} />
          <DRow k="Sessions" v={String(data.sessions ?? 0)} cls={s.valCyan} />
        </>}
        {data.nodeType === "zone" && <>
          <DRow k="Subnet" v={data.subnet || ""} cls={s.valCyan} />
          <DRow k="Interface" v={data.iface || ""} />
          <DRow k="Hosts" v={String(data.hosts ?? 0)} />
          <DRow k="Active flows" v={String(data.flows ?? 0)} cls={s.valGreen} />
          {data.vlan ? <DRow k="VLAN" v={String(data.vlan)} cls={s.valAmber} /> : null}
          {data.desc ? <DRow k="Description" v={data.desc} /> : null}
        </>}
        {data.nodeType === "gateway" && <>
          <DRow k="IP" v={data.ip || ""} cls={s.valCyan} />
          <DRow k="ASN" v={data.asn || ""} />
          <DRow k="Latency" v={data.latency || ""} cls={s.valGreen} />
          <DRow k="Packet loss" v={data.loss || ""} cls={s.valGreen} />
        </>}
      </div>

      {data.nodeType === "firewall" && data.interfaces && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Interfaces</div>
          <div className={s.ifaceList}>
            {data.interfaces.map((ifc) => (
              <div key={ifc.name} className={s.ifaceItem}>
                <div className={s.ifaceTop}>
                  <span className={s.ifaceName}>{ifc.name}</span>
                  <span className={`${s.ifaceState} ${ifc.state === "up" ? s.ifaceUp : s.ifaceDown}`}>{ifc.state.toUpperCase()}</span>
                </div>
                <div className={s.ifaceIp}>{ifc.ip} &middot; {ifc.zone}</div>
                <div className={s.ifaceStats}><span>&darr; {ifc.rx}</span><span>&uarr; {ifc.tx}</span></div>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.nodeType === "firewall" && data.routes && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Routing Table</div>
          <table className={s.routeTable}>
            <thead><tr><th>Destination</th><th>Via</th><th>Iface</th><th>Origin</th></tr></thead>
            <tbody>
              {data.routes.map((r, i) => (
                <tr key={i}>
                  <td>{r.dst}</td><td>{r.gw}</td><td>{r.iface}</td>
                  <td><span className={`${s.routeOrigin} ${r.origin === "static" ? s.originStatic : r.origin === "dynamic" ? s.originDynamic : s.originLocal}`}>{r.origin}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.rules && data.rules.length > 0 && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Policy Rules</div>
          <div className={s.ruleList}>
            {data.rules.map((r, i) => (
              <div key={i} className={`${s.ruleItem} ${r.action === "allow" ? s.ruleAllow : s.ruleDeny}`}>
                <span className={s.ruleAction}>{r.action.toUpperCase()}</span>
                <span className={s.ruleDesc}>{r.desc}</span>
                <span className={s.ruleHits}>{r.hits.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function DRow({ k, v, cls, color }: { k: string; v: string; cls?: string; color?: string }) {
  return (
    <div className={s.detailRow}>
      <span className={s.detailKey}>{k}</span>
      <span className={`${s.detailVal} ${cls || ""}`} style={color ? { color } : undefined}>{v}</span>
    </div>
  );
}
