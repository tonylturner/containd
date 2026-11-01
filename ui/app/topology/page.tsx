"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import {
  applyNodeChanges,
  Edge,
  Node,
  NodeChange,
  useNodesInitialized,
  useReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import type { BackgroundProps, ControlProps, MiniMapProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

const ReactFlow = dynamic(
  () => import("@xyflow/react").then((m) => m.ReactFlow<Node<TopoNodeData>>),
  { ssr: false, loading: () => <div style={{ width: "100%", height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 11 }}>Loading topology...</div> },
);
const Background = dynamic(
  () => import("@xyflow/react").then((m) => m.Background as React.ComponentType<BackgroundProps>),
  { ssr: false },
);
const Controls = dynamic(
  () => import("@xyflow/react").then((m) => m.Controls as React.ComponentType<ControlProps>),
  { ssr: false },
);
const MiniMap = dynamic(
  () => import("@xyflow/react").then((m) => m.MiniMap as React.ComponentType<MiniMapProps>),
  { ssr: false },
);
const PhysicalView = dynamic(() => import("./PhysicalView"), {
  ssr: false,
  loading: () => <div style={{ padding: 24, color: "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 11 }}>Loading physical view...</div>,
});
const SecurityView = dynamic(() => import("./SecurityView"), {
  ssr: false,
  loading: () => <div style={{ padding: 24, color: "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 11 }}>Loading security view...</div>,
});
import { Shell } from "../../components/Shell";
import { CONFIG_COMMITTED } from "../../lib/config-events";
import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";
import { useHealth } from "../../hooks/useHealth";
import { useProtection } from "../../hooks/useProtection";
import { ProtectionRetry } from "../../components/ProtectionNotice";
import { isAdmin } from "../../lib/api";
import s from "./topology.module.css";
import { DetailContent } from "./topology-detail";
import {
  buildTopology,
  withHealth,
  nodeTypes,
  type TopoNodeData,
} from "./topology-shared";
import { TONE_COLORS, topologyStatus } from "./topology-status";

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
  const [topoError, setTopoError] = useState<string | null>(null);
  const [nodeData, setNodeData] = useState<Record<string, TopoNodeData>>({});
  const health = useHealth();
  const protection = useProtection();
  const { fitView } = useReactFlow();
  const nodesInitialized = useNodesInitialized();

  // ── Fetch & build ──
  const { refresh: fetchData } = useAsyncRefresh(useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await buildTopology();
      if (signal?.aborted) return;
      if (!result) {
        setTopoError("Logical topology unavailable — running configuration, interface runtime state or flows could not be read.");
        return;
      }

      setTopoError(null);

      setNodeData(result.nodeDataMap);
      setNodes((previous) => {
        const byId = new Map(previous.map((node) => [node.id, node]));
        return result.nodes.map((node) => {
          const existing = byId.get(node.id);
          // Update data without resetting ReactFlow's measured dimensions,
          // selection or the operator's dragged position on every poll.
          return existing && existing.type === node.type ? { ...existing, data: node.data } : node;
        });
      });
      setEdges(result.edges);
      setSyncTime(new Date().toLocaleTimeString("en-US", { hour12: false }));
    } catch (e) {
      if (signal?.aborted) return;
      if (e instanceof DOMException && e.name === "AbortError") return;
      setTopoError("Logical topology unavailable — running configuration, interface runtime state or flows could not be read.");
    }
  }, []), { initialArgs: (signal): [AbortSignal] => [signal] });

  useEffect(() => {
    const refresh = () => { void fetchData(); };
    window.addEventListener(CONFIG_COMMITTED, refresh);
    return () => window.removeEventListener(CONFIG_COMMITTED, refresh);
  }, [fetchData]);

  const inspectedNode = useRef<HTMLElement | null>(null);
  const initialFitDone = useRef(false);
  useEffect(() => {
    if (!nodesInitialized || initialFitDone.current) return;
    void fitView({ padding: 0.15, duration: 400 });
    initialFitDone.current = true;
  }, [nodesInitialized, fitView]);

  useEffect(() => {
    const wrappedFetch = () => { if (!document.hidden) void fetchData(); };
    const iv = setInterval(wrappedFetch, 30000);
    document.addEventListener("visibilitychange", wrappedFetch);
    return () => {
      clearInterval(iv);
      document.removeEventListener("visibilitychange", wrappedFetch);
    };
  }, [fetchData]);

  // ── Handle node click ──
  const onNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    inspectedNode.current = (event.target as HTMLElement).closest<HTMLElement>(".react-flow__node");
    setSelectedId(node.id);
    setPanelOpen(true);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedId(null);
  }, []);

  // ── Handle all node changes (position, dimensions, selection, etc.) ──
  const onNodesChange = useCallback((changes: NodeChange<Node<TopoNodeData>>[]) => {
    setNodes((prev) => applyNodeChanges(changes, prev));
  }, []);

  const selected = selectedId ? nodeData[selectedId] : null;
  const selectedData = selected ? withHealth(selected, health) : null;
  const status = topologyStatus(health, protection.status);
  const statusColor = TONE_COLORS[status.tone];

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
          <div role="status" aria-label="Firewall enforcement" className={s.statusChip} title={status.reason ? `Firewall enforcement: ${status.reason}. ${status.action || ""}` : "Firewall enforcement"}>
            <div className={s.chipDot} style={{ background: statusColor }} />
            <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: statusColor }}>{status.label}</span>
            {status.reason && <span className={s.chipReason}>{status.reason}</span>}
          </div>
          {health?.enforcement?.state !== "enforcing" && <div className="flex flex-wrap items-center gap-2 text-amber">
            {status.action && <span className="text-xs">{status.action}</span>}
            <ProtectionRetry isAdmin={isAdmin()} />
          </div>}
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

      {/* Error banner */}
      {currentView === "logical" && topoError && (
        <div role="alert" style={{ margin: "8px 12px 0", padding: "8px 14px", fontFamily: "var(--mono)", fontSize: 10, color: "#ef4444", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: 2 }}>
          {topoError}
          <button onClick={() => fetchData()} style={{ marginLeft: 12, color: "#f59e0b", background: "transparent", border: "1px solid rgba(245,158,11,0.3)", padding: "2px 10px", cursor: "pointer", fontFamily: "var(--mono)", fontSize: 9 }}>Retry</button>
        </div>
      )}

      <p className="px-4 py-2 text-xs text-(--text-muted)">{currentView === "security" ? "Live · Conduit observations / Saved target · Candidate zone settings" : currentView === "physical" ? "Live · Deployment details" : "Live · Running network and traffic observations"}</p>

      {/* WORKSPACE — switches between views */}
      {currentView === "physical" ? (
        <PhysicalView />
      ) : currentView === "security" ? (
        <SecurityView />
      ) : topoError ? null : (
        <div className={s.workspace} style={panelOpen ? undefined : { gridTemplateColumns: "1fr" }}>
          <div className={s.flowWrap} onKeyDownCapture={event => {
            if (event.key !== "Enter" && event.key !== " ") return;
            const node = (event.target as HTMLElement).closest<HTMLElement>(".react-flow__node[data-id]");
            if (node?.dataset.id) {
              event.preventDefault(); inspectedNode.current = node; setSelectedId(node.dataset.id); setPanelOpen(true);
            }
          }}>
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
                position="top-left"
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

            {!panelOpen && <button className={s.panelToggle} onClick={() => setPanelOpen(true)} title="Show detail panel" aria-expanded={panelOpen} aria-controls="logical-inspector">&#x25C0;</button>}
          </div>

          {/* DETAIL PANEL */}
          {(
            <div className={s.detailPanel} id="logical-inspector" hidden={!panelOpen} style={panelOpen ? undefined : { display: "none" }} role="region" aria-label="Topology inspector">
              <div className={s.panelHeader}>
                <span className={s.panelTitle}>{selectedData?.label || "TOPOLOGY"}</span>
                <button className={s.panelClose} aria-label="Hide detail panel" aria-expanded={panelOpen} aria-controls="logical-inspector" onClick={() => { setPanelOpen(false); inspectedNode.current?.focus(); }}>&#x25B6;</button>
              </div>
              <div className={s.panelBody}>
                {selectedData ? <DetailContent data={selectedData} /> : (
                  <div className={s.panelEmpty}>
                    <div className={s.panelEmptyIcon}>&#x2B21;</div>
                    <div>Select any node to inspect its state and jump to the most relevant config or monitoring page.</div>
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
