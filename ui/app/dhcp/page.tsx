"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type DHCPConfig, type DHCPLease, type DHCPPool } from "../../lib/api";
import { Shell } from "../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";

function normalize(cfg: DHCPConfig | null): DHCPConfig {
  return {
    enabled: cfg?.enabled ?? false,
    listenIfaces: cfg?.listenIfaces ?? ["lan2"],
    leaseSeconds: cfg?.leaseSeconds ?? 3600,
    router: cfg?.router ?? "",
    dnsServers: cfg?.dnsServers ?? [],
    domain: cfg?.domain ?? "",
    authoritative: cfg?.authoritative ?? true,
    pools: cfg?.pools ?? [],
  };
}

function poolsToText(pools: DHCPPool[]): string {
  return pools.map((p) => `${p.iface},${p.start},${p.end}`).join("\n");
}

function textToPools(text: string): DHCPPool[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [iface, start, end] = l.split(",").map((s) => s.trim());
      return { iface: iface || "", start: start || "", end: end || "" };
    })
    .filter((p) => p.iface && p.start && p.end);
}

export default function DHCPPage() {
  const canEdit = isAdmin();
  const [cfg, setCfg] = useState<DHCPConfig>(() => normalize(null));
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [leases, setLeases] = useState<DHCPLease[]>([]);
  const [leaseError, setLeaseError] = useState<string | null>(null);

  async function refresh() {
    const s = await api.getDHCP();
    setCfg(normalize(s));
  }

  async function refreshLeases() {
    setLeaseError(null);
    try {
      const r = await api.listDHCPLeases();
      setLeases(r?.leases ?? []);
    } catch (e) {
      setLeaseError(e instanceof Error ? e.message : "Failed to load DHCP leases.");
      setLeases([]);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    refreshLeases();
    const t = window.setInterval(() => {
      refreshLeases();
    }, 10_000);
    return () => window.clearInterval(t);
  }, []);

  const listenIfacesText = useMemo(() => (cfg.listenIfaces ?? []).join(", "), [cfg.listenIfaces]);
  const dnsServersText = useMemo(() => (cfg.dnsServers ?? []).join(", "), [cfg.dnsServers]);
  const poolsText = useMemo(() => poolsToText(cfg.pools ?? []), [cfg.pools]);

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setDHCP(cfg);
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save DHCP settings.");
    setTimeout(() => setSaveState("idle"), 1500);
    if (saved) setCfg(normalize(saved));
  }

  return (
    <Shell
      title="DHCP"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          {canEdit && (
            <button onClick={onSave} className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30">
              Save
            </button>
          )}
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="text-lg font-semibold text-white">DHCPv4 Server</h2>
        <p className="mt-1 text-sm text-slate-300">
          Configure LAN-side DHCP. The engine runs a minimal DHCPv4 server (IPv4 only) when enabled and committed.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, enabled: e.target.checked }))}
              className="h-4 w-4"
            />
            Enable DHCP server
          </label>

          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={cfg.authoritative ?? true}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, authoritative: e.target.checked }))}
              className="h-4 w-4"
            />
            Authoritative
          </label>

          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Listen Interfaces (CSV)</label>
            <input
              value={listenIfacesText}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  listenIfaces: e.target.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="lan2, lan3"
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Lease Seconds</label>
            <input
              type="number"
              value={cfg.leaseSeconds ?? 3600}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, leaseSeconds: Number(e.target.value) || 0 }))}
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Router (Gateway)</label>
            <input
              value={cfg.router ?? ""}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, router: e.target.value }))}
              placeholder="192.168.1.1"
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">DNS Servers (CSV)</label>
            <input
              value={dnsServersText}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  dnsServers: e.target.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="192.168.1.1, 1.1.1.1"
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-wide text-slate-400">Domain (optional)</label>
            <input
              value={cfg.domain ?? ""}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, domain: e.target.value }))}
              placeholder="lab.local"
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-wide text-slate-400">Pools (one per line)</label>
            <textarea
              rows={6}
              value={poolsText}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, pools: textToPools(e.target.value) }))}
              placeholder={"lan2,192.168.10.100,192.168.10.200\nlan3,192.168.20.100,192.168.20.200"}
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white"
            />
            <p className="mt-1 text-xs text-slate-400">
              Format: <span className="font-mono">iface,start,end</span>. Pools are validated on save.
            </p>
          </div>
        </div>

        <p className="mt-3 text-xs text-slate-400">
          State:{" "}
          {saveState === "saving"
            ? "saving…"
            : saveState === "saved"
              ? "saved"
              : saveState === "error"
                ? "error"
                : "idle"}
        </p>
      </div>

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Active Leases</h2>
            <p className="mt-1 text-sm text-slate-300">Leases issued by the embedded DHCP server (best-effort).</p>
          </div>
          <button
            onClick={refreshLeases}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
        </div>

        {leaseError && (
          <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
            {leaseError}
          </div>
        )}

        <div className="mt-4 overflow-hidden rounded-xl border border-white/10">
          <table className="w-full text-left text-sm text-slate-200">
            <thead className="bg-black/30 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-3 py-2">Iface</th>
                <th className="px-3 py-2">IP</th>
                <th className="px-3 py-2">MAC</th>
                <th className="px-3 py-2">Hostname</th>
                <th className="px-3 py-2">Expires</th>
              </tr>
            </thead>
            <tbody>
              {leases.length === 0 ? (
                <tr className="border-t border-white/10">
                  <td colSpan={5} className="px-3 py-3 text-sm text-slate-400">
                    No leases.
                  </td>
                </tr>
              ) : (
                leases.map((l) => (
                  <tr key={`${l.iface}-${l.mac}-${l.ip}`} className="border-t border-white/10">
                    <td className="px-3 py-2 font-mono text-xs">{l.iface}</td>
                    <td className="px-3 py-2 font-mono text-xs">{l.ip}</td>
                    <td className="px-3 py-2 font-mono text-xs">{l.mac}</td>
                    <td className="px-3 py-2">{l.hostname || "—"}</td>
                    <td className="px-3 py-2 font-mono text-xs">{l.expiresAt}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Shell>
  );
}
