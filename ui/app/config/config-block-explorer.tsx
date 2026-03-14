"use client";

import { Card } from "../../components/Card";

export type ViewerSource = "running" | "candidate";
export type BlockKey =
  | "system"
  | "zones"
  | "interfaces"
  | "routing"
  | "firewall"
  | "nat"
  | "portForwards"
  | "assets"
  | "objects"
  | "ids"
  | "services"
  | "dataPlane"
  | "dpi"
  | "export"
  | "pcap";

type BlockItem = {
  id: string;
  label: string;
  meta: string;
};

const VIEWER_SOURCE_LABEL: Record<ViewerSource, string> = {
  running: "Live",
  candidate: "Staged",
};

const BLOCK_OPTIONS: Array<{ key: BlockKey; label: string; help: string }> = [
  { key: "system", label: "System", help: "Appliance identity, management listeners, SSH." },
  { key: "zones", label: "Zones", help: "Security zones used by policies and interfaces." },
  { key: "interfaces", label: "Interfaces", help: "Port bindings, IPs, and zone mapping." },
  { key: "routing", label: "Routing", help: "Gateways, routes, and policy routing rules." },
  { key: "firewall", label: "Firewall rules", help: "Allow/deny policies and zone matches." },
  { key: "nat", label: "NAT", help: "SNAT/DNAT settings for egress and port forwards." },
  { key: "portForwards", label: "Port forwards", help: "Inbound DNAT mappings." },
  { key: "assets", label: "Assets", help: "OT/ICS asset inventory and tags." },
  { key: "objects", label: "Objects", help: "Named address/service objects for reuse in rules." },
  { key: "ids", label: "IDS", help: "Detection rules, Sigma/YARA imports, and settings." },
  { key: "services", label: "Services", help: "DNS, NTP, DHCP, proxy, VPN, AV, and syslog." },
  { key: "dataPlane", label: "Data plane", help: "Enforcement, capture interfaces, nftables." },
  { key: "dpi", label: "DPI", help: "DPI mode (learn/enforce), protocol enable/disable, exclusions." },
  { key: "export", label: "Export", help: "Event export targets (CEF, JSON, Syslog)." },
  { key: "pcap", label: "PCAP", help: "Capture settings and forwarding." },
];

type Props = {
  viewerSource: ViewerSource;
  setViewerSource: (source: ViewerSource) => void;
  selectedBlock: BlockKey;
  setSelectedBlock: (block: BlockKey) => void;
  selectedItemId: string | null;
  setSelectedItemId: (id: string | null) => void;
  blockItems: BlockItem[];
  selectedItem: unknown;
  blockValue: unknown;
  viewerConfig: unknown;
  setSelectedRef: (node: HTMLDivElement | null) => void;
};

export function ConfigBlockExplorer({
  viewerSource,
  setViewerSource,
  selectedBlock,
  setSelectedBlock,
  selectedItemId,
  setSelectedItemId,
  blockItems,
  selectedItem,
  blockValue,
  viewerConfig,
  setSelectedRef,
}: Props) {
  return (
    <Card padding="lg">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
            Config viewer
          </div>
          <h2 className="text-lg font-semibold text-[var(--text)]">Explore config blocks</h2>
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
          <span>Source</span>
          <button
            onClick={() => setViewerSource("running")}
            className={
              viewerSource === "running"
                ? "rounded-md bg-amber-500/[0.1] px-2 py-1 text-[var(--text)] transition-ui"
                : "rounded-md px-2 py-1 text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
            }
          >
            {VIEWER_SOURCE_LABEL.running}
          </button>
          <button
            onClick={() => setViewerSource("candidate")}
            className={
              viewerSource === "candidate"
                ? "rounded-md bg-amber-500/[0.1] px-2 py-1 text-[var(--text)] transition-ui"
                : "rounded-md px-2 py-1 text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
            }
          >
            {VIEWER_SOURCE_LABEL.candidate}
          </button>
        </div>
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-[240px_1fr]">
        <div className="grid gap-2">
          {BLOCK_OPTIONS.map((item) => (
            <button
              key={item.key}
              onClick={() => {
                setSelectedBlock(item.key);
                setSelectedItemId(null);
              }}
              title={item.help}
              className={
                selectedBlock === item.key
                  ? "rounded-sm bg-amber-500/[0.1] px-3 py-2 text-left text-sm text-[var(--text)] transition-ui"
                  : "rounded-sm px-3 py-2 text-left text-sm text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
              }
            >
              {item.label}
            </button>
          ))}
        </div>
        <div className="grid gap-3">
          {blockItems.length > 0 && (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 shadow-card">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  {selectedBlock} entries
                </div>
                <span className="text-xs text-[var(--text-muted)]">{blockItems.length} items</span>
              </div>
              <div className="mt-2 grid gap-1 md:grid-cols-2">
                {blockItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setSelectedItemId(item.id)}
                    className={
                      selectedItemId === item.id
                        ? "rounded-sm border border-amber-500/[0.15] bg-amber-500/[0.1] px-2 py-1 text-left text-xs text-[var(--text)] transition-ui"
                        : "rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-left text-xs text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                    }
                  >
                    <div className="font-semibold">{item.label}</div>
                    <div className="text-[11px] text-[var(--text-muted)]">{item.meta}</div>
                  </button>
                ))}
              </div>
              {selectedItem != null && (
                <div className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 text-xs text-[var(--text)]">
                  <div className="mb-2 flex items-center justify-between">
                    <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Selected
                    </div>
                    {selectedBlock === "zones" && (
                      <a href="/zones/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                        Open Zones
                      </a>
                    )}
                    {selectedBlock === "interfaces" && (
                      <a href="/interfaces/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                        Open Interfaces
                      </a>
                    )}
                    {selectedBlock === "firewall" && (
                      <a href="/firewall/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                        Open Firewall
                      </a>
                    )}
                    {selectedBlock === "assets" && (
                      <a href="/assets/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                        Open Assets
                      </a>
                    )}
                    {selectedBlock === "ids" && (
                      <a href="/ids/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                        Open IDS
                      </a>
                    )}
                  </div>
                  <pre className="whitespace-pre-wrap">
{JSON.stringify(selectedItem, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 text-xs text-[var(--text)]">
            {viewerConfig != null ? (
              Array.isArray(blockValue) ? (
                blockValue.length === 0 ? (
                  <div className="text-[var(--text-muted)]">No entries in this block.</div>
                ) : (
                  <div className="grid gap-2">
                    {blockValue.map((item: any) => {
                      const id = item?.id || item?.name;
                      const isSelected = selectedItemId && id === selectedItemId;
                      return (
                        <div
                          key={id ?? JSON.stringify(item)}
                          role="button"
                          tabIndex={0}
                          onClick={() => {
                            if (id) setSelectedItemId(id);
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && id) setSelectedItemId(id);
                          }}
                          ref={isSelected ? setSelectedRef : undefined}
                          className={
                            isSelected
                              ? "rounded-sm border border-amber-500/40 bg-amber-500/[0.1] p-3 transition-ui"
                              : "rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 hover:border-amber-500/30 transition-ui"
                          }
                        >
                          <pre className="whitespace-pre-wrap">
{JSON.stringify(item, null, 2)}
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                )
              ) : (
                <pre className="whitespace-pre-wrap">
{JSON.stringify(blockValue ?? {}, null, 2)}
                </pre>
              )
            ) : (
              <div className="text-[var(--text-muted)]">No config loaded for this source.</div>
            )}
          </div>
        </div>
      </div>
      <div className="mt-3 text-xs text-[var(--text-muted)]">
        Select a block to jump to its JSON. Use Live for current runtime state and Staged for saved changes waiting to be applied.
      </div>
    </Card>
  );
}
