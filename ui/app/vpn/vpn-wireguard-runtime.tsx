"use client";

import type { InterfaceState, WireGuardStatus } from "../../lib/api";

export function WireGuardRuntimeCard({
  cfgInterface,
  peerCount,
  peerNameByKey,
  runtime,
  wgStatus,
}: {
  cfgInterface: string;
  peerCount: number;
  peerNameByKey: Map<string, string>;
  runtime: InterfaceState | null;
  wgStatus: WireGuardStatus | null;
}) {
  return (
    <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card backdrop-blur">
      <h2 className="text-lg font-semibold text-[var(--text)]">Runtime</h2>
      <p className="mt-1 text-sm text-[var(--text)]">Kernel state (engine).</p>

      <div className="mt-4 grid gap-3 text-sm">
        <div className="flex items-center justify-between">
          <span className="text-[var(--text)]">Interface</span>
          <span className="font-mono text-xs text-[var(--text)]">{cfgInterface.trim() || "wg0"}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[var(--text)]">Link</span>
          {runtime ? (
            <span className={runtime.up ? "text-emerald-400" : "text-amber-400"}>{runtime.up ? "up" : "down"}</span>
          ) : (
            <span className="text-[var(--text-muted)]">not present</span>
          )}
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[var(--text)]">WireGuard API</span>
          {wgStatus ? <span className="text-emerald-400">ok</span> : <span className="text-[var(--text-muted)]">unavailable</span>}
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[var(--text)]">Addresses</span>
          <span className="text-right font-mono text-xs text-[var(--text)]">
            {(runtime?.addrs ?? []).length > 0 ? (runtime?.addrs ?? []).join(", ") : "—"}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[var(--text)]">Peers (configured)</span>
          <span className="text-[var(--text)]">{peerCount}</span>
        </div>
        {wgStatus?.present && (
          <div className="rounded-sm border border-amber-500/[0.15] bg-black/20 px-3 py-2 text-xs text-[var(--text)]">
            <div className="flex items-center justify-between">
              <span className="text-[var(--text-muted)]">Listen</span>
              <span className="font-mono text-[var(--text)]">{wgStatus.listenPort ?? "—"}</span>
            </div>
            <div className="mt-1 flex items-center justify-between">
              <span className="text-[var(--text-muted)]">Public key</span>
              <span className="max-w-[70%] truncate font-mono text-[var(--text)]">{wgStatus.publicKey ?? "—"}</span>
            </div>
          </div>
        )}
        {wgStatus?.present && (wgStatus.peers ?? []).length > 0 && (
          <div className="rounded-sm border border-amber-500/[0.15] bg-black/20 p-2">
            <div className="mb-2 text-xs text-[var(--text-muted)]">Peers (runtime)</div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-xs text-[var(--text)]">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-muted)]">
                    <th className="px-2 py-1">Peer</th>
                    <th className="px-2 py-1">Endpoint</th>
                    <th className="px-2 py-1">Last handshake</th>
                    <th className="px-2 py-1">Rx</th>
                    <th className="px-2 py-1">Tx</th>
                  </tr>
                </thead>
                <tbody>
                  {(wgStatus.peers ?? []).map((peer) => (
                    <tr key={peer.publicKey} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                      <td className="px-2 py-1 font-mono">
                        {peerNameByKey.get(peer.publicKey) ? (
                          <span className="font-sans text-emerald-400">{peerNameByKey.get(peer.publicKey)}</span>
                        ) : null}
                        <span className={peerNameByKey.get(peer.publicKey) ? "ml-2 text-[var(--text-muted)]" : ""}>
                          {peer.publicKey.slice(0, 12)}...
                        </span>
                      </td>
                      <td className="px-2 py-1 font-mono text-[var(--text)]">{peer.endpoint || "—"}</td>
                      <td className="px-2 py-1 font-mono text-[var(--text)]">{peer.lastHandshake || "never"}</td>
                      <td className="px-2 py-1 font-mono text-[var(--text)]">
                        {typeof peer.rxBytes === "number" ? peer.rxBytes.toLocaleString() : "—"}
                      </td>
                      <td className="px-2 py-1 font-mono text-[var(--text)]">
                        {typeof peer.txBytes === "number" ? peer.txBytes.toLocaleString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-2 text-[11px] text-[var(--text-dim)]">
              Note: allowed-ips and IPv6 details are phased; use config for policy intent.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
