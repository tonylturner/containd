"use client";

import type { InterfaceState, WireGuardStatus } from "../../lib/api";

export function WireGuardRuntimeCard({
  cfgInterface,
  peerCount,
  peerNameByKey,
  runtime,
  interfaceStateStatus,
  onRetry,
  wgStatus,
}: {
  cfgInterface: string;
  peerCount: number;
  peerNameByKey: Map<string, string>;
  runtime: InterfaceState | null;
  interfaceStateStatus: "loading" | "ready" | "unavailable";
  onRetry: () => void;
  wgStatus: WireGuardStatus | null;
}) {
  return (
    <section aria-label="WireGuard runtime" className="rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
      <h2 className="text-lg font-semibold text-(--text)">Runtime</h2>
      <p className="mt-1 text-sm text-(--text)">Live tunnel status.</p>
      {interfaceStateStatus === "unavailable" && (
        <div role="status" className="mt-3 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <p>Interface state unavailable — live tunnel information could not be reached. Link and runtime addresses are unknown.</p>
          <button onClick={onRetry} className="mt-2 rounded-xs border border-red-500/30 px-3 py-1">Retry</button>
        </div>
      )}

      <div className="mt-4 grid gap-3 text-sm">
        <div className="flex items-center justify-between">
          <span className="text-(--text)">Interface</span>
          <span className="font-mono text-xs text-(--text)">{cfgInterface.trim() || "wg0"}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-(--text)">Link</span>
          {interfaceStateStatus !== "ready" ? (
            <span className="text-(--text-muted)">{interfaceStateStatus === "loading" ? "Loading…" : "interface state unavailable"}</span>
          ) : runtime ? (
            <span className={runtime.up ? "text-emerald-400" : ""}>{runtime.up ? "up" : "down"}</span>
          ) : (
            <span className="text-(--text-muted)">not present</span>
          )}
        </div>
        <div className="flex items-center justify-between">
          <span className="text-(--text)">WireGuard API</span>
          {wgStatus ? <span className="text-emerald-400">ok</span> : <span className="text-(--text-muted)">unavailable</span>}
        </div>
        <div className="flex items-center justify-between">
          <span className="text-(--text)">Addresses</span>
          <span className="text-right font-mono text-xs text-(--text)">
            {interfaceStateStatus !== "ready" ? (interfaceStateStatus === "loading" ? "Loading…" : "interface state unavailable") : runtime?.addrs?.length ? runtime.addrs.join(", ") : "—"}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-(--text)">Peers (configured)</span>
          <span className="text-(--text)">{peerCount}</span>
        </div>
        {wgStatus?.present && (
          <div className="rounded-xs border bg-black/20 px-3 py-2 text-xs text-(--text)">
            <div className="flex items-center justify-between">
              <span className="text-(--text-muted)">Listen</span>
              <span className="font-mono text-(--text)">{wgStatus.listenPort ?? "—"}</span>
            </div>
            <div className="mt-1 flex items-center justify-between">
              <span className="text-(--text-muted)">Public key</span>
              <span className="max-w-[70%] truncate font-mono text-(--text)">{wgStatus.publicKey ?? "—"}</span>
            </div>
          </div>
        )}
        {wgStatus?.present && (wgStatus.peers ?? []).length > 0 && (
          <div className="rounded-xs border bg-black/20 p-2">
            <div className="mb-2 text-xs text-(--text-muted)">Peers (runtime)</div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-xs text-(--text)">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-(--text-muted)">
                    <th className="px-2 py-1">Peer</th>
                    <th className="px-2 py-1">Endpoint</th>
                    <th className="px-2 py-1">Last handshake</th>
                    <th className="px-2 py-1">Rx</th>
                    <th className="px-2 py-1">Tx</th>
                  </tr>
                </thead>
                <tbody>
                  {(wgStatus.peers ?? []).map((peer) => (
                    <tr key={peer.publicKey} className="border-t table-row-hover transition-ui">
                      <td className="px-2 py-1 font-mono">
                        {peerNameByKey.get(peer.publicKey) ? (
                          <span className="font-sans text-emerald-400">{peerNameByKey.get(peer.publicKey)}</span>
                        ) : null}
                        <span className={peerNameByKey.get(peer.publicKey) ? "ml-2 text-(--text-muted)" : ""}>
                          {peer.publicKey.slice(0, 12)}...
                        </span>
                      </td>
                      <td className="px-2 py-1 font-mono text-(--text)">{peer.endpoint || "—"}</td>
                      <td className="px-2 py-1 font-mono text-(--text)">{peer.lastHandshake || "never"}</td>
                      <td className="px-2 py-1 font-mono text-(--text)">
                        {typeof peer.rxBytes === "number" ? peer.rxBytes.toLocaleString() : "—"}
                      </td>
                      <td className="px-2 py-1 font-mono text-(--text)">
                        {typeof peer.txBytes === "number" ? peer.txBytes.toLocaleString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-2 text-[11px] text-(--text-dim)">
              Note: allowed-ips and IPv6 details are phased; use config for policy intent.
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
