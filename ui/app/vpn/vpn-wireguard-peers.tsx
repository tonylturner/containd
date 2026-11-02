"use client";

import { useState } from "react";
import type { WGPeer } from "../../lib/api-vpn";

export function parsePeers(value: string): WGPeer[] {
  const peers: unknown = JSON.parse(value);
  if (!Array.isArray(peers) || peers.some(p => !p || typeof p !== "object"
    || typeof p.publicKey !== "string"
    || (p.name !== undefined && typeof p.name !== "string")
    || (p.endpoint !== undefined && typeof p.endpoint !== "string")
    || (p.persistentKeepalive !== undefined && (typeof p.persistentKeepalive !== "number" || !Number.isFinite(p.persistentKeepalive)))
    || (p.allowedIPs !== undefined && (!Array.isArray(p.allowedIPs) || p.allowedIPs.some((ip: unknown) => typeof ip !== "string"))))) {
    throw new Error("Peers must be a JSON array of objects with publicKey, optional name, allowedIPs (strings), endpoint and numeric persistentKeepalive.");
  }
  return peers;
}

const button = "rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm transition-ui disabled:opacity-50";

export function WireGuardPeerEditor({ value, onChange, disabled, serverPublicKey, serverAddress }: {
  value: string; onChange: (value: string) => void; disabled: boolean;
  serverPublicKey?: string; serverAddress?: string;
}) {
  const [endpoint, setEndpoint] = useState("");
  let peers: WGPeer[] = [];
  let error: string | null = null;
  try { peers = parsePeers(value); } catch (e) { error = e instanceof Error ? e.message : "Invalid peers JSON."; }
  function update(index: number, patch: Partial<WGPeer>) {
    onChange(JSON.stringify(peers.map((p, i) => i === index ? { ...p, ...patch } : p), null, 2));
  }
  const endpointKnown = /^(?:\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):([0-9]+)$/.test(endpoint)
    && Number(endpoint.slice(endpoint.lastIndexOf(":") + 1)) > 0
    && Number(endpoint.slice(endpoint.lastIndexOf(":") + 1)) <= 65535;
  function download(peer: WGPeer) {
    const content = `# Client template: fill in the client's private key locally.\n# Commit staged server settings before connecting.\n[Interface]\nPrivateKey = REPLACE_WITH_CLIENT_PRIVATE_KEY\nAddress = ${peer.allowedIPs?.filter(Boolean).join(", ") || "REPLACE_WITH_CLIENT_TUNNEL_ADDRESS"}\n\n[Peer]\nPublicKey = ${serverPublicKey}\nEndpoint = ${endpoint}\nAllowedIPs = ${serverAddress || "REPLACE_WITH_SERVER_TUNNEL_NETWORK"}\nPersistentKeepalive = 25\n`;
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${(peer.name || "wireguard-client").replace(/[^a-zA-Z0-9_-]/g, "_")}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return <section aria-label="WireGuard peers" className="min-w-0 space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="font-medium">Peers</h3>
      <button className={button} disabled={disabled || !!error}
        onClick={() => onChange(JSON.stringify([...peers, { name: "", publicKey: "", allowedIPs: [] }], null, 2))}>Add peer</button>
    </div>
    {!error && !peers.length && <p className="text-xs text-(--text-muted)">Add a client public key and the addresses that client may use.</p>}
    {error && <p role="alert" className="break-words text-sm text-red-400">{error} Correct it under Advanced peer settings.</p>}
    {peers.map((peer, index) => <fieldset key={index} className="min-w-0 space-y-2 rounded-xs border p-3">
      <legend className="px-1 text-sm">Peer {index + 1}</legend>
      <div className="grid min-w-0 gap-2">
        <label className="grid min-w-0 gap-1 text-xs">Name
          <input className="w-full min-w-0 input-industrial" value={peer.name ?? ""} disabled={disabled}
            onChange={e => update(index, { name: e.target.value })} /></label>
        <label className="grid min-w-0 gap-1 text-xs">Public key
          <input className="w-full min-w-0 input-industrial font-mono" value={peer.publicKey} disabled={disabled}
            onChange={e => update(index, { publicKey: e.target.value })} /></label>
        <label className="grid min-w-0 gap-1 text-xs">Allowed IPs (comma-separated CIDRs)
          <input className="w-full min-w-0 input-industrial" value={(peer.allowedIPs ?? []).join(", ")} disabled={disabled}
            onChange={e => update(index, { allowedIPs: e.target.value.trim() ? e.target.value.split(",").map(s => s.trim()) : [] })} /></label>
        <label className="grid min-w-0 gap-1 text-xs">Endpoint (optional host:port)
          <input className="w-full min-w-0 input-industrial" value={peer.endpoint ?? ""} disabled={disabled}
            onChange={e => update(index, { endpoint: e.target.value })} /></label>
        <label className="grid min-w-0 gap-1 text-xs">Keepalive (seconds)
          <input className="w-full min-w-0 input-industrial" type="number" min={0} step={1} value={peer.persistentKeepalive ?? 0} disabled={disabled}
            onChange={e => update(index, { persistentKeepalive: Number(e.target.value) })} /></label>
      </div>
      <div className="flex flex-wrap gap-2">
        <button className={button} disabled={disabled} onClick={() => onChange(JSON.stringify(peers.filter((_, i) => i !== index), null, 2))}>Remove peer</button>
        {serverPublicKey && endpointKnown && peer.publicKey && <button className={button} disabled={disabled} onClick={() => download(peer)}>Download client config</button>}
      </div>
    </fieldset>)}
    <label className="grid min-w-0 gap-1 text-xs">Server endpoint for client downloads (host:port)
      <input value={endpoint} disabled={disabled} onChange={e => setEndpoint(e.target.value)} className="w-full min-w-0 input-industrial" placeholder="vpn.example.com:51820" />
    </label>
    <p className="text-xs text-(--text-muted)">Download helper only; endpoint is not saved. Client configs are templates: enter the matching client private key locally and review addresses and routes. No client private keys are stored here. A live server public key may differ from staged settings; commit and verify it before connecting.</p>
    {(!serverPublicKey || !endpointKnown) && <p className="text-xs text-(--text-muted)">Client download unavailable: {!serverPublicKey ? "server public key is unknown (generate a server key or refresh its live status)." : "enter a valid server endpoint including its port."}</p>}
    <details className="min-w-0 rounded-xs border p-3" open={peers.length > 0}>
      <summary className="cursor-pointer text-sm">Advanced peer settings</summary>
      <label htmlFor="wireguard-peers" className="text-xs">Peers (JSON)</label>
      <textarea id="wireguard-peers" rows={8} value={value} disabled={disabled} onChange={e => onChange(e.target.value)}
        className="mt-1 w-full min-w-0 rounded-xs border bg-(--surface) px-3 py-2 font-mono text-xs" />
    </details>
  </section>;
}
