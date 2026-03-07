"use client";

import { useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Edge,
  Handle,
  MarkerType,
  Node,
  NodeProps,
  Position,
} from "reactflow";
import "reactflow/dist/style.css";
import { Shell } from "../../components/Shell";
import {
  api,
  Asset,
  Interface,
  InterfaceState,
  OSRoutingSnapshot,
  RoutingConfig,
  Zone,
} from "../../lib/api";

export default function TopologyPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [ifaceState, setIfaceState] = useState<InterfaceState[]>([]);
  const [routing, setRouting] = useState<RoutingConfig | null>(null);
  const [osRouting, setOsRouting] = useState<OSRoutingSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      setError(null);
      const [zonesRes, ifacesRes, assetsRes, stateRes, routingRes, osRoutingRes] =
        await Promise.all([
        api.listZones(),
        api.listInterfaces(),
        api.listAssets(),
        api.listInterfaceState(),
        api.getRouting(),
        api.getOSRouting(),
      ]);
      if (!mounted) return;
      if (zonesRes) setZones(zonesRes);
      if (ifacesRes) setInterfaces(ifacesRes);
      if (assetsRes) setAssets(assetsRes);
      if (stateRes) setIfaceState(stateRes);
      if (routingRes) setRouting(routingRes);
      if (osRoutingRes) setOsRouting(osRoutingRes);
      if (!zonesRes && !ifacesRes && !assetsRes) {
        setError("Failed to load topology data.");
      }
    };
    void load();
    return () => {
      mounted = false;
    };
  }, []);

  const { nodes, edges } = useMemo(() => {
    return buildTopologyNodes(zones, interfaces, assets, ifaceState, routing, osRouting);
  }, [zones, interfaces, assets, ifaceState, routing, osRouting]);

  return (
    <Shell title="Topology">
      {expanded ? (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm" />
      ) : null}
      <div
        className={`relative min-h-[640px] rounded-2xl border border-white/10 bg-black/40 p-2 shadow-lg backdrop-blur ${
          expanded ? "fixed inset-6 z-[60] h-[calc(100vh-48px)]" : "h-[calc(100vh-160px)]"
        }`}
      >
        {error ? (
          <div className="absolute left-4 top-4 z-10 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
            {error}
          </div>
        ) : null}
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="absolute right-4 top-4 z-10 inline-flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-black/70 text-slate-200 hover:bg-black/60"
          title={expanded ? "Exit full screen" : "Full screen"}
        >
          <svg
            viewBox="0 0 24 24"
            className="h-4 w-4"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden
          >
            {expanded ? (
              <>
                <path d="M8 3H3v5" />
                <path d="M16 21h5v-5" />
                <path d="M3 21h5v-5" />
                <path d="M21 3h-5v5" />
              </>
            ) : (
              <>
                <path d="M8 3H3v5" />
                <path d="M16 21h5v-5" />
                <path d="M3 21h5v-5" />
                <path d="M21 3h-5v5" />
              </>
            )}
          </svg>
        </button>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.5}
          maxZoom={1.5}
          nodesConnectable={false}
          nodesDraggable
          elementsSelectable
          selectionOnDrag
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{
            type: "smoothstep",
            animated: false,
            style: { stroke: "rgba(148, 163, 184, 0.6)", strokeWidth: 1.5 },
          }}
        >
          <Background color="rgba(255,255,255,0.06)" gap={24} />
          <Controls showInteractive={false} className="reactflow-controls" />
        </ReactFlow>
      </div>
    </Shell>
  );
}

const nodeTypes = {
  upstream: UpstreamNode,
  gateway: GatewayNode,
  firewall: FirewallNode,
  zone: ZoneNode,
  iface: InterfaceNode,
  asset: AssetNode,
  routes: RoutesNode,
};

const handleStyle = {
  opacity: 0,
  width: 0,
  height: 0,
  border: "none",
};

type UpstreamNodeData = {
  label: string;
  detail?: string;
};

function UpstreamNode({ data }: NodeProps<UpstreamNodeData>) {
  return (
    <div className="w-[220px] rounded-full border border-white/10 bg-black/60 px-5 py-3 text-sm text-slate-200 shadow-lg">
      <Handle type="source" position={Position.Right} id="right" style={handleStyle} />
      <div className="mb-2 h-1 w-10 rounded-full" style={{ backgroundColor: "var(--primary)" }} />
      <div className="text-xs uppercase tracking-[0.2em] text-slate-400">Upstream</div>
      <div className="mt-2 text-base text-white">{data.label}</div>
      {data.detail ? <div className="text-xs text-slate-400">{data.detail}</div> : null}
    </div>
  );
}

type GatewayNodeData = {
  name: string;
  address?: string;
  iface?: string;
};

function GatewayNode({ data }: NodeProps<GatewayNodeData>) {
  return (
    <div className="flex w-[240px] items-center gap-3 rounded-xl border border-white/10 bg-black/60 px-3 py-2 text-xs text-slate-200">
      <Handle type="target" position={Position.Left} id="left" style={handleStyle} />
      <Handle type="source" position={Position.Right} id="right" style={handleStyle} />
      <div className="h-7 w-7 rotate-45 rounded border border-white/20 bg-black/70" />
      <div>
        <div className="mb-1 h-1 w-8 rounded-full" style={{ backgroundColor: "var(--teal)" }} />
        <div className="text-[10px] uppercase tracking-[0.2em] text-slate-400">
          Gateway
        </div>
        <div className="text-sm text-white">{data.name}</div>
        <div className="text-[11px] text-slate-400">
          {data.address ?? "address unset"}
        </div>
        <div className="text-[11px] text-slate-400">
          {data.iface ? `via ${data.iface}` : "interface unset"}
        </div>
      </div>
    </div>
  );
}

type FirewallNodeData = {
  label: string;
  detail?: string;
};

function FirewallNode({ data }: NodeProps<FirewallNodeData>) {
  return (
    <div className="w-[260px] rounded-2xl border border-white/10 bg-black/70 px-4 py-4 text-sm text-slate-200 shadow-lg backdrop-blur">
      <Handle type="target" position={Position.Left} id="left" style={handleStyle} />
      <Handle type="source" position={Position.Right} id="right" style={handleStyle} />
      <Handle type="source" position={Position.Bottom} id="bottom" style={handleStyle} />
      <div className="mb-2 h-1 w-12 rounded-full" style={{ backgroundColor: "var(--success)" }} />
      <div className="flex items-center gap-3">
        <img
          src="/icons/firewall.svg"
          alt=""
          className="h-10 w-10 opacity-90 grayscale"
        />
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-slate-300">
            Firewall
          </div>
          <div className="mt-1 text-lg text-white">{data.label}</div>
        </div>
      </div>
      {data.detail ? <div className="text-xs text-slate-400">{data.detail}</div> : null}
    </div>
  );
}

type ZoneNodeData = {
  name: string;
  alias?: string;
  count: number;
};

function ZoneNode({ data }: NodeProps<ZoneNodeData>) {
  const accent = zoneAccent(data.name);
  return (
    <div className="rounded-2xl border border-white/10 bg-black/70 px-4 py-3 text-sm text-slate-200 shadow-lg">
      <Handle type="target" position={Position.Left} id="left" style={handleStyle} />
      <Handle type="source" position={Position.Bottom} id="bottom" style={handleStyle} />
      <div className="mb-2 h-1 w-12 rounded-full" style={{ backgroundColor: accent.color }} />
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-slate-300">
            Zone
          </div>
          <div className="text-base text-white">{data.name}</div>
          {data.alias ? (
            <div className="text-xs text-slate-400">{data.alias}</div>
          ) : null}
        </div>
        <div
          className="rounded-full border border-white/10 bg-black/40 px-2 py-1 text-xs text-slate-300"
          style={{ color: accent.color }}
        >
          {data.count} nodes
        </div>
      </div>
    </div>
  );
}

type InterfaceNodeData = {
  name: string;
  device?: string;
  alias?: string;
  addressMode?: string;
  addresses?: string[];
  up?: boolean;
  zone?: string;
};

function InterfaceNode({ data }: NodeProps<InterfaceNodeData>) {
  const accent = zoneAccent(data.zone);
  return (
    <div
      className="w-[230px] rounded-xl border border-white/10 bg-black/70 px-3 py-2 text-xs text-slate-200"
      style={{ borderLeft: `3px solid ${accent.color}` }}
    >
      <Handle type="target" position={Position.Left} id="left" style={handleStyle} />
      <Handle type="source" position={Position.Right} id="right" style={handleStyle} />
      <Handle type="target" position={Position.Top} id="top" style={handleStyle} />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-white">
          <span className="inline-flex h-3 w-3 rounded-sm border border-white/20 bg-black/60" />
          {data.name}
        </div>
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] ${
            data.up ? "bg-mint/15 text-mint" : "bg-amber/15 text-amber"
          }`}
        >
          {data.up ? "up" : "down"}
        </span>
      </div>
      <div className="mt-1 inline-flex items-center rounded-full border border-white/10 px-2 py-0.5 text-[10px] uppercase tracking-[0.2em] text-slate-300">
        {data.zone || "unassigned"}
      </div>
      <div className="mt-1 text-[11px] text-slate-400">
        {data.device ? `dev ${data.device}` : "device unset"}
      </div>
      <div className="mt-1 text-[11px] text-slate-400">
        {data.addressMode ? data.addressMode.toUpperCase() : "static"}
        {data.addresses?.length ? ` • ${data.addresses.join(", ")}` : ""}
      </div>
    </div>
  );
}

type AssetNodeData = {
  name: string;
  type?: string;
  criticality?: string;
  ips?: string[];
};

function AssetNode({ data }: NodeProps<AssetNodeData>) {
  return (
    <div className="w-[230px] rounded-xl border border-white/10 bg-black/60 px-3 py-2 text-xs text-slate-200">
      <Handle type="target" position={Position.Left} id="left" style={handleStyle} />
      <Handle type="target" position={Position.Top} id="top" style={handleStyle} />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-white">
          <span className="inline-flex h-2.5 w-2.5 rounded-full bg-mint/60" />
          {data.name}
        </div>
        <span className="rounded-full border border-white/10 bg-black/40 px-2 py-0.5 text-[10px] text-slate-300">
          {data.criticality ?? "standard"}
        </span>
      </div>
      <div className="mt-1 text-[11px] text-slate-400">
        {data.type ?? "asset"}
      </div>
      <div className="mt-1 text-[11px] text-slate-400">
        {data.ips?.length ? data.ips.join(", ") : "no IPs listed"}
      </div>
    </div>
  );
}

type RoutesNodeData = {
  items: string[];
};

function RoutesNode({ data }: NodeProps<RoutesNodeData>) {
  return (
    <div className="w-[280px] rounded-2xl border border-white/10 bg-black/70 px-4 py-3 text-xs text-slate-200">
      <Handle type="target" position={Position.Top} id="top" style={handleStyle} />
      <div className="mb-2 h-1 w-10 rounded-full" style={{ backgroundColor: "var(--purple)" }} />
      <div className="text-xs uppercase tracking-[0.2em] text-slate-400">Routes</div>
      <ul className="mt-2 space-y-1 text-[11px] text-slate-300">
        {data.items.length === 0 ? (
          <li>no routes configured</li>
        ) : (
          data.items.map((item) => <li key={item}>{item}</li>)
        )}
      </ul>
    </div>
  );
}

function buildTopologyNodes(
  zones: Zone[],
  interfaces: Interface[],
  assets: Asset[],
  ifaceState: InterfaceState[],
  routing: RoutingConfig | null,
  osRouting: OSRoutingSnapshot | null,
): { nodes: Node[]; edges: Edge[] } {
  const zoneOrder = ["wan", "dmz", "lan", "mgmt"];
  const zoneMap = new Map<string, Zone>();
  for (const z of zones) {
    if (z?.name) zoneMap.set(z.name, z);
  }
  const impliedZones = new Set<string>();
  let needsUnassigned = false;
  for (const iface of interfaces) {
    if (iface.zone) impliedZones.add(iface.zone);
    else needsUnassigned = true;
  }
  for (const asset of assets) {
    if (asset.zone) impliedZones.add(asset.zone);
    else needsUnassigned = true;
  }
  for (const name of impliedZones) {
    if (!zoneMap.has(name)) zoneMap.set(name, { name });
  }
  if (needsUnassigned && !zoneMap.has("unassigned")) {
    zoneMap.set("unassigned", { name: "unassigned" });
  }
  const zoneNames = Array.from(
    new Set([...zoneOrder.filter((z) => zoneMap.has(z)), ...zoneMap.keys()]),
  );
  if (zoneNames.length === 0) {
    zoneNames.push(...zoneOrder);
  }
  const stateByName = new Map(ifaceState.map((s) => [s.name, s]));
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const zoneWidth = 280;
  const zoneGap = 48;
  const zoneHeader = 96;
  const rowHeight = 128;
  const zonePadding = 16;
  const columnsStart = 980;
  const firewallX = 620;
  const firewallY = 120;
  const upstreamX = 60;
  const upstreamY = 120;
  const gatewayX = 340;
  const gatewayY = 140;

  nodes.push({
    id: "upstream",
    type: "upstream",
    position: { x: upstreamX, y: upstreamY },
    data: { label: "ISP / Internet", detail: "Primary uplink" },
    draggable: true,
    selectable: true,
  });

  const gateway = pickGateway(routing, osRouting);
  nodes.push({
    id: "gateway",
    type: "gateway",
    position: { x: gatewayX, y: gatewayY },
    data: {
      name: gateway?.name ?? "default-gw",
      address: gateway?.address,
      iface: gateway?.iface,
    },
    draggable: true,
    selectable: true,
  });

  nodes.push({
    id: "firewall",
    type: "firewall",
    position: { x: firewallX, y: firewallY },
    data: { label: "containd", detail: "policy enforcement + DPI" },
    draggable: true,
    selectable: true,
  });

  edges.push({
    id: "edge-upstream-gateway",
    source: "upstream",
    target: "gateway",
    sourceHandle: "right",
    targetHandle: "left",
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
  });
  edges.push({
    id: "edge-gateway-firewall",
    source: "gateway",
    target: "firewall",
    sourceHandle: "right",
    targetHandle: "left",
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
  });

  const routes = summarizeRoutes(routing, osRouting);
  nodes.push({
    id: "routes",
    type: "routes",
    position: { x: firewallX + 40, y: firewallY + 240 },
    data: { items: routes },
    draggable: true,
    selectable: true,
  });
  edges.push({
    id: "edge-firewall-routes",
    source: "firewall",
    target: "routes",
    sourceHandle: "bottom",
    targetHandle: "top",
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
  });

  zoneNames.forEach((zoneName, idx) => {
    const zone = zoneMap.get(zoneName) ?? { name: zoneName };
    const zoneIfaces = interfaces.filter((i) => (i.zone || "unassigned") === zoneName);
    const zoneAssets = assets.filter((a) => (a.zone || "unassigned") === zoneName);
    const childCount = zoneIfaces.length + zoneAssets.length;
    const zoneHeight = Math.max(220, zoneHeader + zonePadding * 2 + childCount * rowHeight);
    const zoneId = `zone-${zoneName}`;
    const zoneX = columnsStart + idx * (zoneWidth + zoneGap);
    nodes.push({
      id: zoneId,
      type: "zone",
      position: { x: zoneX, y: 60 },
      data: { name: zone.name, alias: zone.alias, count: childCount },
      style: { width: zoneWidth, height: zoneHeight },
      draggable: true,
      selectable: true,
    });

    let rowIndex = 0;
    for (const iface of zoneIfaces) {
      const st = stateByName.get(iface.name);
      const ifaceId = `iface-${iface.name}`;
      nodes.push({
        id: ifaceId,
        type: "iface",
      position: { x: zonePadding, y: zoneHeader + zonePadding + rowIndex * rowHeight },
        data: {
          name: iface.name,
          device: iface.device,
          alias: iface.alias,
          addressMode: iface.addressMode,
          addresses: iface.addresses,
          up: st?.up,
          zone: zoneName,
        },
        parentNode: zoneId,
        draggable: true,
        selectable: true,
      });
      edges.push({
        id: `edge-fw-${ifaceId}`,
        source: "firewall",
        target: ifaceId,
        sourceHandle: "right",
        targetHandle: "left",
        style: { stroke: zoneAccent(zoneName).color, strokeWidth: 1.6 },
      });
      rowIndex++;
    }
    for (const asset of zoneAssets) {
      const assetId = `asset-${asset.id}`;
      const parentIface = zoneIfaces[0]?.name;
      nodes.push({
        id: assetId,
        type: "asset",
        position: { x: zonePadding, y: zoneHeader + zonePadding + rowIndex * rowHeight },
        data: {
          name: asset.name || asset.id,
          type: asset.type,
          criticality: asset.criticality,
          ips: asset.ips,
        },
        parentNode: zoneId,
        draggable: true,
        selectable: true,
      });
      if (parentIface) {
        edges.push({
          id: `edge-${parentIface}-${assetId}`,
          source: `iface-${parentIface}`,
          target: assetId,
          sourceHandle: "right",
          targetHandle: "left",
          style: { stroke: zoneAccent(zoneName).color, strokeWidth: 1.2 },
        });
      }
      rowIndex++;
    }
  });
  return { nodes, edges };
}

function pickGateway(
  routing: RoutingConfig | null,
  osRouting: OSRoutingSnapshot | null,
): { name: string; address?: string; iface?: string } | null {
  const fromConfig = routing?.gateways?.[0];
  if (fromConfig) {
    return {
      name: fromConfig.name || "gateway",
      address: fromConfig.address,
      iface: fromConfig.iface,
    };
  }
  const osDefault = osRouting?.defaultRoute;
  if (osDefault) {
    return {
      name: "default",
      address: osDefault.gateway,
      iface: osDefault.iface,
    };
  }
  return null;
}

function summarizeRoutes(
  routing: RoutingConfig | null,
  osRouting: OSRoutingSnapshot | null,
): string[] {
  const out: string[] = [];
  const routes = routing?.routes ?? [];
  for (const r of routes) {
    if (!r?.dst) continue;
    const gw = r.gateway ? ` via ${r.gateway}` : "";
    const iface = r.iface ? ` dev ${r.iface}` : "";
    out.push(`${r.dst}${gw}${iface}`);
  }
  const osDefault = osRouting?.defaultRoute;
  if (osDefault?.gateway) {
    out.push(`default via ${osDefault.gateway}${osDefault.iface ? ` dev ${osDefault.iface}` : ""}`);
  }
  return out.slice(0, 6);
}

function zoneAccent(name?: string): { color: string } {
  switch ((name || "").toLowerCase()) {
    case "wan":
      return { color: "var(--primary)" };
    case "dmz":
      return { color: "var(--warning)" };
    case "mgmt":
      return { color: "var(--teal)" };
    case "lan":
      return { color: "var(--success)" };
    default:
      return { color: "var(--purple)" };
  }
}
