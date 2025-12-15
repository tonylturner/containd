"use client";

import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";

import {
  api,
  isAdmin,
  type VPNConfig,
  type WireGuardConfig,
  type OpenVPNConfig,
  type OpenVPNManagedClientConfig,
  type OpenVPNManagedServerConfig,
  type InterfaceState,
  type WireGuardStatus,
  type ServicesStatus,
} from "../../lib/api";
import { Shell } from "../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";
type UploadState = "idle" | "uploading" | "uploaded" | "error";

type FieldIssue = { field: string; message: string; severity: "required" | "recommended" };

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
      mode: cfg?.openvpn?.mode ?? "client",
      configPath: cfg?.openvpn?.configPath ?? "",
      managed: cfg?.openvpn?.managed,
      server: cfg?.openvpn?.server,
    },
  };
}

function Badge({ tone, children, title }: { tone: "ok" | "warn" | "off" | "info"; children: ReactNode; title?: string }) {
  const cls =
    tone === "ok"
      ? "border-mint/30 bg-mint/10 text-mint"
      : tone === "warn"
        ? "border-amber/30 bg-amber/10 text-amber"
        : tone === "info"
          ? "border-white/10 bg-white/5 text-slate-200"
          : "border-white/10 bg-white/0 text-slate-400";
  return (
    <span title={title} className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs ${cls}`}>
      {children}
    </span>
  );
}

type VPNServiceStatus = {
  openvpn_installed?: boolean;
  openvpn_running?: boolean;
  openvpn_config_path?: string;
  openvpn_last_error?: string;
};

function hasNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function hasLikelyPEM(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const t = v.trim();
  if (!t) return false;
  return t.includes("BEGIN") && t.includes("END");
}

function IssuesBanner({ title, issues }: { title: string; issues: FieldIssue[] }) {
  if (!issues.length) return null;
  const required = issues.filter((i) => i.severity === "required");
  const recommended = issues.filter((i) => i.severity === "recommended");
  return (
    <div className="rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
      <div className="font-medium text-amber">{title}</div>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] text-amber/90">
        {required.map((i) => (
          <li key={`${i.field}:${i.message}`}>
            <span className="font-semibold">Required:</span> {i.message}
          </li>
        ))}
        {recommended.map((i) => (
          <li key={`${i.field}:${i.message}`}>
            <span className="font-semibold">Recommended:</span> {i.message}
          </li>
        ))}
      </ul>
    </div>
  );
}

const defaultOpenVPNManaged: OpenVPNManagedClientConfig = {
  remote: "",
  port: 1194,
  proto: "udp",
  username: "",
  password: "",
  ca: "",
  cert: "",
  key: "",
};

const defaultOpenVPNServer: OpenVPNManagedServerConfig = {
  listenPort: 1194,
  proto: "udp",
  tunnelCIDR: "10.9.0.0/24",
  publicEndpoint: "",
  pushDNS: [],
  pushRoutes: [],
  clientToClient: false,
};

export default function VPNPage() {
  const canEdit = isAdmin();
  const [cfg, setCfg] = useState(() => normalize(null));
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [uploadState, setUploadState] = useState<UploadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<InterfaceState | null>(null);
  const [wgStatus, setWgStatus] = useState<WireGuardStatus | null>(null);
  const [svcStatus, setSvcStatus] = useState<VPNServiceStatus | null>(null);
  const [ovpnClients, setOvpnClients] = useState<string[]>([]);
  const [newClientName, setNewClientName] = useState<string>("");

  const wireguardIssues = useMemo<FieldIssue[]>(() => {
    if (!cfg.wireguard.enabled) return [];
    const out: FieldIssue[] = [];
    if (!hasNonEmptyString(cfg.wireguard.interface)) out.push({ field: "wireguard.interface", severity: "required", message: "Interface name is required (e.g. wg0)." });
    if (!cfg.wireguard.listenPort || cfg.wireguard.listenPort <= 0) out.push({ field: "wireguard.listenPort", severity: "required", message: "Listen port must be set." });
    if (!hasNonEmptyString(cfg.wireguard.addressCIDR)) out.push({ field: "wireguard.addressCIDR", severity: "required", message: "Tunnel address CIDR is required (e.g. 10.8.0.1/24)." });
    if (!hasNonEmptyString(cfg.wireguard.privateKey)) out.push({ field: "wireguard.privateKey", severity: "required", message: "Private key is required to bring up a WireGuard server." });
    if (!cfg.wireguard.peers?.length) out.push({ field: "wireguard.peers", severity: "recommended", message: "Add at least one peer so clients can connect." });
    return out;
  }, [cfg.wireguard]);

  const openvpnIssues = useMemo<FieldIssue[]>(() => {
    if (!cfg.openvpn.enabled) return [];
    const out: FieldIssue[] = [];
    const mode = (cfg.openvpn.mode ?? "client").trim();
    if (mode === "client") {
      if (cfg.openvpn.managed) {
        const m = cfg.openvpn.managed;
        if (!hasNonEmptyString(m.remote)) out.push({ field: "openvpn.managed.remote", severity: "required", message: "Remote is required (VPN gateway hostname/IP)." });
        if (!m.port || m.port <= 0) out.push({ field: "openvpn.managed.port", severity: "required", message: "Port must be set." });
        if (!hasNonEmptyString(m.proto)) out.push({ field: "openvpn.managed.proto", severity: "required", message: "Protocol must be set (udp/tcp)." });
        if (!hasLikelyPEM(m.ca)) out.push({ field: "openvpn.managed.ca", severity: "required", message: "CA certificate (PEM) is required." });
        if (!hasLikelyPEM(m.cert)) out.push({ field: "openvpn.managed.cert", severity: "required", message: "Client certificate (PEM) is required." });
        if (!hasLikelyPEM(m.key)) out.push({ field: "openvpn.managed.key", severity: "required", message: "Client key (PEM) is required." });
      } else {
        if (!hasNonEmptyString(cfg.openvpn.configPath)) out.push({ field: "openvpn.configPath", severity: "required", message: "Config Path is required when not using managed config." });
      }
    } else if (mode === "server") {
      const s = cfg.openvpn.server;
      if (!s) out.push({ field: "openvpn.server", severity: "required", message: "Server configuration is required." });
      if (!s?.listenPort || s.listenPort <= 0) out.push({ field: "openvpn.server.listenPort", severity: "required", message: "Listen port must be set." });
      if (!hasNonEmptyString(s?.proto)) out.push({ field: "openvpn.server.proto", severity: "required", message: "Protocol must be set (udp/tcp)." });
      if (!hasNonEmptyString(s?.tunnelCIDR)) out.push({ field: "openvpn.server.tunnelCIDR", severity: "required", message: "Tunnel CIDR is required (client address pool)." });
      if (!hasNonEmptyString(s?.publicEndpoint)) out.push({ field: "openvpn.server.publicEndpoint", severity: "recommended", message: "Set Public Endpoint so generated client profiles know where to connect." });
    }
    return out;
  }, [cfg.openvpn]);

  async function refresh() {
    const current = await api.getVPN();
    setCfg(normalize(current));
    const states = await api.listInterfaceState();
    const ifName = (current?.wireguard?.interface ?? "wg0").trim() || "wg0";
    setRuntime((states ?? []).find((s) => s.name === ifName) ?? null);
    try {
      setWgStatus(await api.getWireGuardStatus(ifName));
    } catch {
      setWgStatus(null);
    }
    try {
      const st = (await api.getServicesStatus()) as ServicesStatus | null;
      const vpn = (st as any)?.vpn ?? null;
      setSvcStatus(vpn as VPNServiceStatus);
    } catch {
      setSvcStatus(null);
    }

    // OpenVPN server: list clients (admin-only).
    try {
      const mode = (current?.openvpn?.mode ?? "client").trim();
      if (mode === "server") {
        const res = await api.listOpenVPNClients();
        setOvpnClients(res?.clients ?? []);
      } else {
        setOvpnClients([]);
      }
    } catch {
      setOvpnClients([]);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  const peersText = useMemo(() => JSON.stringify(cfg.wireguard.peers ?? [], null, 2), [cfg.wireguard.peers]);
  const peerNameByKey = useMemo(() => {
    const out = new Map<string, string>();
    for (const p of cfg.wireguard.peers ?? []) {
      const k = (p.publicKey ?? "").trim();
      const n = (p.name ?? "").trim();
      if (k && n) out.set(k, n);
    }
    return out;
  }, [cfg.wireguard.peers]);

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");

    // If using managed OpenVPN, ensure configPath is cleared so the backend prefers managed.
    const openvpn: OpenVPNConfig = { ...cfg.openvpn };
    if (openvpn.managed) {
      openvpn.configPath = "";
      openvpn.mode = "client";
      openvpn.server = undefined;
    }
    if ((openvpn.mode ?? "client") === "server") {
      openvpn.managed = undefined;
      openvpn.configPath = "";
      openvpn.server = openvpn.server ?? { ...defaultOpenVPNServer };
    }

    const saved = await api.setVPN({
      wireguard: cfg.wireguard,
      openvpn,
    });
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save VPN settings.");
    setTimeout(() => setSaveState("idle"), 1500);
    if (saved) setCfg(normalize(saved));
  }

  async function uploadOpenVPNProfile(file: File) {
    if (!canEdit) return;
    setError(null);
    setUploadState("uploading");
    try {
      const text = await file.text();
      const base = file.name.replace(/\.(ovpn|conf|txt)$/i, "");
      const res = await api.uploadOpenVPNProfile(base || "client", text);
      if (!res?.vpn) {
        setUploadState("error");
        setError("Failed to upload OpenVPN profile.");
        setTimeout(() => setUploadState("idle"), 1500);
        return;
      }
      setUploadState("uploaded");
      // Uploading a profile switches OpenVPN to "configPath" mode (advanced) and clears managed config.
      const next = normalize(res.vpn);
      setCfg({
        ...next,
        openvpn: { ...next.openvpn, managed: undefined },
      });
      setTimeout(() => setUploadState("idle"), 1500);
      // Refresh runtime badges (installed/running/last error) after upload.
      refresh();
    } catch (e) {
      setUploadState("error");
      setError(e instanceof Error ? e.message : "Failed to upload OpenVPN profile.");
      setTimeout(() => setUploadState("idle"), 1500);
    }
  }

  async function createClient() {
    if (!canEdit) return;
    const name = newClientName.trim();
    if (!name) return;
    setError(null);
    try {
      await api.createOpenVPNClient(name);
      setNewClientName("");
      const res = await api.listOpenVPNClients();
      setOvpnClients(res?.clients ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create client.");
    }
  }

  async function downloadClient(name: string) {
    if (!canEdit) return;
    setError(null);
    try {
      const resp = await fetch(api.downloadOpenVPNClientURL(name), { credentials: "include" });
      if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${name}.ovpn`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to download client profile.");
    }
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
        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <div className="pointer-events-none absolute -right-10 -top-10 h-44 w-44 rounded-full bg-mint/10 blur-2xl" />
          <div className="relative flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-xl border border-white/10 bg-gradient-to-br from-mint/25 to-sky/10">
                <img src="/icons/wireguard.svg" alt="WireGuard" className="h-6 w-6 invert opacity-90 drop-shadow" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">WireGuard</h2>
                <p className="mt-0.5 text-sm text-slate-300">Remote access VPN (preferred).</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <Badge tone={cfg.wireguard.enabled ? "ok" : "off"}>{cfg.wireguard.enabled ? "enabled" : "disabled"}</Badge>
              <Badge
                tone={runtime?.up ? "ok" : runtime ? "warn" : "off"}
                title={runtime ? "Kernel interface state" : "Kernel interface not present"}
              >
                {runtime ? (runtime.up ? "link up" : "link down") : "not present"}
              </Badge>
              <Badge tone={wgStatus ? "ok" : "off"} title="WireGuard netlink API reachability">
                {wgStatus ? "api ok" : "api n/a"}
              </Badge>
            </div>
          </div>

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

            {cfg.wireguard.enabled ? <IssuesBanner title="WireGuard setup checklist" issues={wireguardIssues} /> : null}
            <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
              When enabled, containd auto-opens UDP/{cfg.wireguard.listenPort ?? 51820} on the <span className="font-mono">wan</span> zone
              (nftables input) so clients can connect.
            </div>

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
              <p className="mt-1 text-[11px] text-slate-400">
                This is the VPN client network used for policy targeting (e.g. firewall rules can match <span className="font-mono">vpn:wireguard</span>).
              </p>
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
          <h2 className="text-lg font-semibold text-white">Runtime</h2>
          <p className="mt-1 text-sm text-slate-300">Kernel state (engine).</p>

          <div className="mt-4 grid gap-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Interface</span>
              <span className="font-mono text-xs text-white">{(cfg.wireguard.interface ?? "wg0").trim() || "wg0"}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Link</span>
              {runtime ? (
                <span className={runtime.up ? "text-mint" : "text-amber"}>{runtime.up ? "up" : "down"}</span>
              ) : (
                <span className="text-slate-400">not present</span>
              )}
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">WireGuard API</span>
              {wgStatus ? <span className="text-mint">ok</span> : <span className="text-slate-400">unavailable</span>}
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Addresses</span>
              <span className="text-right font-mono text-xs text-slate-200">
                {(runtime?.addrs ?? []).length > 0 ? (runtime?.addrs ?? []).join(", ") : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Peers (configured)</span>
              <span className="text-slate-200">{(cfg.wireguard.peers ?? []).length}</span>
            </div>
            {wgStatus?.present && (
              <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Listen</span>
                  <span className="font-mono text-slate-200">{wgStatus.listenPort ?? "—"}</span>
                </div>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-slate-400">Public key</span>
                  <span className="max-w-[70%] truncate font-mono text-slate-200">{wgStatus.publicKey ?? "—"}</span>
                </div>
              </div>
            )}
            {wgStatus?.present && (wgStatus.peers ?? []).length > 0 && (
              <div className="rounded-lg border border-white/10 bg-black/20 p-2">
                <div className="mb-2 text-xs text-slate-400">Peers (runtime)</div>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-xs text-slate-200">
                    <thead>
                      <tr className="text-left text-[11px] uppercase tracking-wide text-slate-400">
                        <th className="px-2 py-1">Peer</th>
                        <th className="px-2 py-1">Endpoint</th>
                        <th className="px-2 py-1">Last handshake</th>
                        <th className="px-2 py-1">Rx</th>
                        <th className="px-2 py-1">Tx</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(wgStatus.peers ?? []).map((p) => (
                        <tr key={p.publicKey} className="border-t border-white/5">
                          <td className="px-2 py-1 font-mono">
                            {peerNameByKey.get(p.publicKey) ? (
                              <span className="font-sans text-mint">{peerNameByKey.get(p.publicKey)}</span>
                            ) : null}
                            <span className={peerNameByKey.get(p.publicKey) ? "ml-2 text-slate-400" : ""}>
                              {p.publicKey.slice(0, 12)}…
                            </span>
                          </td>
                          <td className="px-2 py-1 font-mono text-slate-300">{p.endpoint || "—"}</td>
                          <td className="px-2 py-1 font-mono text-slate-300">{p.lastHandshake || "never"}</td>
                          <td className="px-2 py-1 font-mono text-slate-300">
                            {typeof p.rxBytes === "number" ? p.rxBytes.toLocaleString() : "—"}
                          </td>
                          <td className="px-2 py-1 font-mono text-slate-300">
                            {typeof p.txBytes === "number" ? p.txBytes.toLocaleString() : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-2 text-[11px] text-slate-500">
                  Note: allowed-ips and IPv6 details are phased; use config for policy intent.
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <div className="pointer-events-none absolute -right-10 -top-10 h-44 w-44 rounded-full bg-amber/10 blur-2xl" />
          <div className="relative flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-xl border border-white/10 bg-gradient-to-br from-amber/25 to-rose/10">
                <img src="/icons/openvpn.svg" alt="OpenVPN" className="h-6 w-6 invert opacity-90 drop-shadow" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">OpenVPN</h2>
                <p className="mt-0.5 text-sm text-slate-300">Compatibility VPN (optional).</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <Badge tone={cfg.openvpn.enabled ? "warn" : "off"}>{cfg.openvpn.enabled ? "enabled" : "disabled"}</Badge>
              <Badge tone={svcStatus?.openvpn_installed ? "info" : "off"}>
                {svcStatus?.openvpn_installed ? "installed" : "not installed"}
              </Badge>
              <Badge tone={svcStatus?.openvpn_running ? "ok" : "off"}>{svcStatus?.openvpn_running ? "running" : "stopped"}</Badge>
            </div>
          </div>

          <div className="mt-4 grid gap-3">
            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={cfg.openvpn.enabled ?? false}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, enabled: e.target.checked } }))}
                className="h-4 w-4"
              />
              Enable OpenVPN
            </label>

            <IssuesBanner title="OpenVPN setup checklist" issues={openvpnIssues} />

            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Mode</label>
              <select
                value={cfg.openvpn.mode ?? "client"}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, mode: e.target.value } }))}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              >
                <option value="client">client</option>
                <option value="server">server</option>
              </select>
            </div>

                {cfg.openvpn.mode === "client" ? (
              <div className="rounded-xl border border-white/10 bg-black/20 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-xs uppercase tracking-wide text-slate-400">Client Configuration</div>
                    <div className="mt-1 text-sm text-slate-200">
                      {cfg.openvpn.managed ? "Managed config (recommended)" : "Advanced profile path"}
                    </div>
                  </div>
                  <label className="inline-flex items-center gap-2 text-xs text-slate-200">
                    <input
                      type="checkbox"
                      checked={!!cfg.openvpn.managed}
                      disabled={!canEdit}
                      onChange={(e) => {
                        const enabled = e.target.checked;
                        setCfg((c) => ({
                          ...c,
                          openvpn: {
                            ...c.openvpn,
                            managed: enabled ? (c.openvpn.managed ?? { ...defaultOpenVPNManaged }) : undefined,
                            configPath: enabled ? "" : c.openvpn.configPath ?? "",
                          },
                        }));
                      }}
                      className="h-4 w-4"
                    />
                    Use managed config
                  </label>
                </div>

                {cfg.openvpn.managed ? (
                  <div className="mt-3 grid gap-3">
                    <div className="grid gap-3 md:grid-cols-3">
                      <div className="md:col-span-2">
                        <label className="text-xs uppercase tracking-wide text-slate-400">Remote</label>
                        <input
                          value={cfg.openvpn.managed.remote ?? ""}
                          disabled={!canEdit}
                          onChange={(e) =>
                            setCfg((c) => ({
                              ...c,
                              openvpn: {
                                ...c.openvpn,
                                managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), remote: e.target.value },
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                          placeholder="vpn.example.com"
                        />
                        <p className="mt-1 text-[11px] text-slate-400">Hostname or IP address of the OpenVPN gateway.</p>
                      </div>
                      <div>
                        <label className="text-xs uppercase tracking-wide text-slate-400">Port</label>
                        <input
                          type="number"
                          value={cfg.openvpn.managed.port ?? 1194}
                          disabled={!canEdit}
                          onChange={(e) =>
                            setCfg((c) => ({
                              ...c,
                              openvpn: {
                                ...c.openvpn,
                                managed: {
                                  ...(c.openvpn.managed ?? defaultOpenVPNManaged),
                                  port: Number(e.target.value) || 0,
                                },
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                        />
                      </div>
                    </div>

                    <div className="grid gap-3 md:grid-cols-2">
                      <div>
                        <label className="text-xs uppercase tracking-wide text-slate-400">Protocol</label>
                        <select
                          value={cfg.openvpn.managed.proto ?? "udp"}
                          disabled={!canEdit}
                          onChange={(e) =>
                            setCfg((c) => ({
                              ...c,
                              openvpn: {
                                ...c.openvpn,
                                managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), proto: e.target.value },
                              },
                            }))
                          }
                          className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                        >
                          <option value="udp">udp</option>
                          <option value="tcp">tcp</option>
                        </select>
                      </div>
                      <div className="grid gap-2">
                        <div className="text-xs uppercase tracking-wide text-slate-400">User/Pass (optional)</div>
                        <div className="grid gap-2 md:grid-cols-2">
                          <input
                            value={cfg.openvpn.managed.username ?? ""}
                            disabled={!canEdit}
                            onChange={(e) =>
                              setCfg((c) => ({
                                ...c,
                                openvpn: {
                                  ...c.openvpn,
                                  managed: {
                                    ...(c.openvpn.managed ?? defaultOpenVPNManaged),
                                    username: e.target.value,
                                  },
                                },
                              }))
                            }
                            className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                            placeholder="username"
                          />
                          <input
                            type="password"
                            value={cfg.openvpn.managed.password ?? ""}
                            disabled={!canEdit}
                            onChange={(e) =>
                              setCfg((c) => ({
                                ...c,
                                openvpn: {
                                  ...c.openvpn,
                                  managed: {
                                    ...(c.openvpn.managed ?? defaultOpenVPNManaged),
                                    password: e.target.value,
                                  },
                                },
                              }))
                            }
                            className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                            placeholder="password"
                          />
                        </div>
                      </div>
                    </div>

                    <PEMField
                      title="CA (PEM)"
                      value={cfg.openvpn.managed.ca ?? ""}
                      disabled={!canEdit}
                      onChange={(v) =>
                        setCfg((c) => ({
                          ...c,
                          openvpn: { ...c.openvpn, managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), ca: v } },
                        }))
                      }
                    />
                    <PEMField
                      title="Client Cert (PEM)"
                      value={cfg.openvpn.managed.cert ?? ""}
                      disabled={!canEdit}
                      onChange={(v) =>
                        setCfg((c) => ({
                          ...c,
                          openvpn: {
                            ...c.openvpn,
                            managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), cert: v },
                          },
                        }))
                      }
                    />
                    <PEMField
                      title="Client Key (PEM)"
                      value={cfg.openvpn.managed.key ?? ""}
                      disabled={!canEdit}
                      onChange={(v) =>
                        setCfg((c) => ({
                          ...c,
                          openvpn: { ...c.openvpn, managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), key: v } },
                        }))
                      }
                    />
                    <div className="text-xs text-slate-400">
                      This is stored in the appliance config for now; secret encryption/redaction is tracked as a follow-up.
                    </div>
                  </div>
                ) : (
                  <div className="mt-3 grid gap-2">
                    <div>
                      <label className="text-xs uppercase tracking-wide text-slate-400">Config Path</label>
                      <input
                        value={cfg.openvpn.configPath ?? ""}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, configPath: e.target.value } }))
                        }
                        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                        placeholder="/data/openvpn/profiles/client.ovpn"
                      />
                      <p className="mt-1 text-xs text-slate-400">
                        Advanced: provide a foreground OpenVPN config file (no <span className="font-mono">daemon</span> directive).
                      </p>
                    </div>
                  </div>
                )}

                <div className="mt-3 rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-xs text-slate-300">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-slate-200">Import profile (advanced)</div>
                      <div className="mt-0.5 text-[11px] text-slate-400">
                        Uploads a .ovpn and sets Config Path automatically (clears managed config).
                      </div>
                    </div>
                    <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-slate-200 hover:bg-white/10">
                      <input
                        type="file"
                        accept=".ovpn,.conf,.txt"
                        disabled={!canEdit}
                        className="hidden"
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) void uploadOpenVPNProfile(f);
                          e.currentTarget.value = "";
                        }}
                      />
                      {uploadState === "uploading" ? "Uploading…" : "Choose file"}
                    </label>
                  </div>
                </div>
              </div>
                ) : cfg.openvpn.mode === "server" ? (
                  <div className="rounded-xl border border-white/10 bg-black/20 p-3">
                    <div className="text-xs uppercase tracking-wide text-slate-400">Server Configuration</div>
                    <div className="mt-3 grid gap-3">
                      <div className="rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-xs text-slate-300">
                        Enabling OpenVPN server automatically opens the listen port on the WAN zone (nftables input) so clients can connect.
                      </div>
                      <div className="grid gap-3 md:grid-cols-3">
                        <div>
                          <label className="text-xs uppercase tracking-wide text-slate-400">Listen Port</label>
                          <input
                            type="number"
                        value={cfg.openvpn.server?.listenPort ?? 1194}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({
                            ...c,
                            openvpn: {
                              ...c.openvpn,
                              server: { ...(c.openvpn.server ?? defaultOpenVPNServer), listenPort: Number(e.target.value) || 0 },
                            },
                          }))
                        }
                        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                      />
                    </div>
                    <div>
                      <label className="text-xs uppercase tracking-wide text-slate-400">Protocol</label>
                      <select
                        value={cfg.openvpn.server?.proto ?? "udp"}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({
                            ...c,
                            openvpn: { ...c.openvpn, server: { ...(c.openvpn.server ?? defaultOpenVPNServer), proto: e.target.value } },
                          }))
                        }
                        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                      >
                        <option value="udp">udp</option>
                        <option value="tcp">tcp</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-xs uppercase tracking-wide text-slate-400">Tunnel CIDR</label>
                      <input
                        value={cfg.openvpn.server?.tunnelCIDR ?? "10.9.0.0/24"}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({
                            ...c,
                            openvpn: {
                              ...c.openvpn,
                              server: { ...(c.openvpn.server ?? defaultOpenVPNServer), tunnelCIDR: e.target.value },
                            },
                          }))
                        }
                        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                      />
                      <p className="mt-1 text-[11px] text-slate-400">
                        Client address pool. Firewall rules can match this network via <span className="font-mono">vpn:openvpn</span>.
                      </p>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs uppercase tracking-wide text-slate-400">Public Endpoint (for client profiles)</label>
                    <input
                      value={cfg.openvpn.server?.publicEndpoint ?? ""}
                      disabled={!canEdit}
                      onChange={(e) =>
                        setCfg((c) => ({
                          ...c,
                          openvpn: {
                            ...c.openvpn,
                            server: { ...(c.openvpn.server ?? defaultOpenVPNServer), publicEndpoint: e.target.value },
                          },
                        }))
                      }
                      className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                      placeholder="vpn.example.com"
                    />
                    <p className="mt-1 text-xs text-slate-400">
                      Used when generating downloadable <span className="font-mono">.ovpn</span> client profiles.
                    </p>
                  </div>

                  <label className="flex items-center gap-2 text-sm text-slate-200">
                    <input
                      type="checkbox"
                      checked={cfg.openvpn.server?.clientToClient ?? false}
                      disabled={!canEdit}
                      onChange={(e) =>
                        setCfg((c) => ({
                          ...c,
                          openvpn: {
                            ...c.openvpn,
                            server: { ...(c.openvpn.server ?? defaultOpenVPNServer), clientToClient: e.target.checked },
                          },
                        }))
                      }
                      className="h-4 w-4"
                    />
                    Allow client-to-client traffic
                  </label>

                  <div className="grid gap-3 md:grid-cols-2">
                    <div>
                      <label className="text-xs uppercase tracking-wide text-slate-400">Push DNS (comma-separated)</label>
                      <input
                        value={(cfg.openvpn.server?.pushDNS ?? []).join(", ")}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({
                            ...c,
                            openvpn: {
                              ...c.openvpn,
                              server: {
                                ...(c.openvpn.server ?? defaultOpenVPNServer),
                                pushDNS: e.target.value
                                  .split(",")
                                  .map((s) => s.trim())
                                  .filter(Boolean),
                              },
                            },
                          }))
                        }
                        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                        placeholder="1.1.1.1, 8.8.8.8"
                      />
                    </div>
                    <div>
                      <label className="text-xs uppercase tracking-wide text-slate-400">Push Routes (comma-separated CIDR)</label>
                      <input
                        value={(cfg.openvpn.server?.pushRoutes ?? []).join(", ")}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({
                            ...c,
                            openvpn: {
                              ...c.openvpn,
                              server: {
                                ...(c.openvpn.server ?? defaultOpenVPNServer),
                                pushRoutes: e.target.value
                                  .split(",")
                                  .map((s) => s.trim())
                                  .filter(Boolean),
                              },
                            },
                          }))
                        }
                        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                        placeholder="192.168.0.0/24, 10.0.0.0/8"
                      />
                    </div>
                  </div>

                  <div className="rounded-lg border border-white/10 bg-black/30 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-slate-200">Client profiles</div>
                        <div className="mt-0.5 text-[11px] text-slate-400">
                          Generates ECDSA certs in the appliance and downloads an inline <span className="font-mono">.ovpn</span>.
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <input
                          value={newClientName}
                          disabled={!canEdit}
                          onChange={(e) => setNewClientName(e.target.value)}
                          className="w-40 rounded-lg border border-white/10 bg-black/40 px-3 py-1.5 text-sm text-white"
                          placeholder="client name"
                        />
                        <button
                          onClick={createClient}
                          disabled={!canEdit || !newClientName.trim()}
                          className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30 disabled:opacity-50"
                        >
                          Create
                        </button>
                      </div>
                    </div>
                    {ovpnClients.length ? (
                      <div className="mt-3 grid gap-2">
                        {ovpnClients.map((n) => (
                          <div key={n} className="flex items-center justify-between rounded-lg border border-white/10 bg-black/20 px-3 py-2">
                            <div className="font-mono text-sm text-slate-200">{n}</div>
                            <button
                              onClick={() => void downloadClient(n)}
                              className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
                            >
                              Download
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="mt-3 text-xs text-slate-400">No clients yet.</div>
                    )}
                  </div>
                </div>
              </div>
            ) : null}

            {svcStatus?.openvpn_last_error ? (
              <div className="rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
                {svcStatus.openvpn_last_error}
              </div>
            ) : (
              <div className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
                OpenVPN is supervised only when the binary is present and a valid config file is provided.
              </div>
            )}
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

function PEMField({
  title,
  value,
  disabled,
  onChange,
}: {
  title: string;
  value: string;
  disabled: boolean;
  onChange: (next: string) => void;
}) {
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="text-xs uppercase tracking-wide text-slate-400">{title}</label>
        <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-[11px] text-slate-200 hover:bg-white/10">
          <input
            type="file"
            accept=".pem,.crt,.key,.txt"
            disabled={disabled}
            className="hidden"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              const text = await f.text();
              onChange(text);
              e.currentTarget.value = "";
            }}
          />
          Upload
        </label>
      </div>
      <textarea
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        rows={5}
        className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white"
        placeholder="-----BEGIN ...-----"
      />
    </div>
  );
}
