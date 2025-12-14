"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type VPNConfig, type WireGuardConfig, type OpenVPNConfig } from "../../lib/api";
import { Shell } from "../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";

function normalize(cfg: VPNConfig | null): { wireguard: WireGuardConfig; openvpn: OpenVPNConfig } {
  return {
    wireguard: {
      enabled: cfg?.wireguard?.enabled ?? false,
      interface: cfg?.wireguard?.interface ?? "wg0",
      listenPort: cfg?.wireguard?.listenPort ?? 51820,
      addressCIDR: cfg?.wireguard?.addressCIDR ?? "10.8.0.1/24",
      privateKey: cfg?.wireguard?.privateKey ?? "",
      peers: cfg?.wireguard?.peers ?? [],
    },
    openvpn: {
      enabled: cfg?.openvpn?.enabled ?? false,
      mode: cfg?.openvpn?.mode ?? "server",
    },
  };
}

export default function VPNPage() {
  const canEdit = isAdmin();
  const [cfg, setCfg] = useState(() => normalize(null));
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const current = await api.getVPN();
    setCfg(normalize(current));
  }

  useEffect(() => {
    refresh();
  }, []);

  const peersText = useMemo(() => JSON.stringify(cfg.wireguard.peers ?? [], null, 2), [cfg.wireguard.peers]);

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setVPN({
      wireguard: cfg.wireguard,
      openvpn: cfg.openvpn,
    });
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save VPN settings.");
    setTimeout(() => setSaveState("idle"), 1500);
    if (saved) setCfg(normalize(saved));
  }

  return (
    <Shell
      title="VPN"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
            >
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

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">WireGuard</h2>
          <p className="mt-1 text-sm text-slate-300">Remote access VPN (preferred).</p>

          <div className="mt-4 grid gap-3">
            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={cfg.wireguard.enabled ?? false}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, enabled: e.target.checked } }))}
                className="h-4 w-4"
              />
              Enable WireGuard
            </label>

            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="text-xs uppercase tracking-wide text-slate-400">Interface</label>
                <input
                  value={cfg.wireguard.interface ?? "wg0"}
                  disabled={!canEdit}
                  onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, interface: e.target.value } }))}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                />
              </div>
              <div>
                <label className="text-xs uppercase tracking-wide text-slate-400">Listen Port</label>
                <input
                  type="number"
                  value={cfg.wireguard.listenPort ?? 51820}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setCfg((c) => ({
                      ...c,
                      wireguard: { ...c.wireguard, listenPort: Number(e.target.value) || 0 },
                    }))
                  }
                  className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                />
              </div>
            </div>

            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Address (CIDR)</label>
              <input
                value={cfg.wireguard.addressCIDR ?? ""}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, addressCIDR: e.target.value } }))}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
            </div>

            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Private Key (base64)</label>
              <input
                value={cfg.wireguard.privateKey ?? ""}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, privateKey: e.target.value } }))}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                placeholder="(leave blank to set later)"
              />
              <p className="mt-1 text-xs text-slate-400">
                Stored in config today; encryption-at-rest/redaction is handled by the export pipeline.
              </p>
            </div>

            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Peers (JSON)</label>
              <textarea
                rows={8}
                value={peersText}
                disabled={!canEdit}
                onChange={(e) => {
                  try {
                    const parsed = JSON.parse(e.target.value);
                    setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, peers: Array.isArray(parsed) ? parsed : [] } }));
                  } catch {
                    // Keep text editing until valid JSON is entered.
                  }
                }}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white"
              />
              <p className="mt-1 text-xs text-slate-400">
                Example: <span className="font-mono">[{`{ "name": "laptop", "publicKey": "...", "allowedIPs": ["10.8.0.2/32"] }`}]</span>
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">OpenVPN</h2>
          <p className="mt-1 text-sm text-slate-300">Optional compatibility VPN (phased).</p>

          <div className="mt-4 grid gap-3">
            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={cfg.openvpn.enabled ?? false}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, enabled: e.target.checked } }))}
                className="h-4 w-4"
              />
              Enable OpenVPN (placeholder)
            </label>
            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Mode</label>
              <select
                value={cfg.openvpn.mode ?? "server"}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, mode: e.target.value } }))}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              >
                <option value="server">server</option>
                <option value="client">client</option>
              </select>
            </div>
            <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
              Runtime integration for OpenVPN is intentionally deferred; keep it disabled unless you’re tracking config state.
            </div>
          </div>
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
    </Shell>
  );
}

