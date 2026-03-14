"use client";

import Image from "next/image";
import { useCallback, useEffect, useMemo, useState } from "react";

import {
  api,
  isAdmin,
  type VPNConfig,
  type OpenVPNConfig,
  type Zone,
  type Interface,
  type InterfaceState,
  type WireGuardStatus,
  type ServicesStatus,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { useToast } from "../../components/ToastProvider";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import {
  Badge,
  defaultOpenVPNManaged,
  defaultOpenVPNServer,
  hasLikelyPEM,
  hasNonEmptyString,
  IssuesBanner,
  normalize,
  PEMField,
  type FieldIssue,
  type VPNServiceStatus,
} from "./vpn-shared";
import { OpenVPNEditorCard } from "./vpn-openvpn-editor";
import { VPNRuntimeStatusCard } from "./vpn-runtime-status";
import { WireGuardRuntimeCard } from "./vpn-wireguard-runtime";

type SaveState = "idle" | "saving" | "saved" | "error";
type UploadState = "idle" | "uploading" | "uploaded" | "error";

export default function VPNPage() {
  const canEdit = isAdmin();
  const toast = useToast();
  const confirm = useConfirm();
  const [cfg, setCfg] = useState(() => normalize(null));
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [uploadState, setUploadState] = useState<UploadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<InterfaceState | null>(null);
  const [wgStatus, setWgStatus] = useState<WireGuardStatus | null>(null);
  const [svcStatus, setSvcStatus] = useState<VPNServiceStatus | null>(null);
  const [zones, setZones] = useState<Zone[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [ovpnClients, setOvpnClients] = useState<string[]>([]);
  const [newClientName, setNewClientName] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const wireguardIssues = useMemo<FieldIssue[]>(() => {
    if (!cfg.wireguard.enabled) return [];
    const out: FieldIssue[] = [];
    if (!hasNonEmptyString(cfg.wireguard.interface)) out.push({ field: "wireguard.interface", severity: "required", message: "Interface name is required (e.g. wg0)." });
    if (!cfg.wireguard.listenPort || cfg.wireguard.listenPort <= 0) out.push({ field: "wireguard.listenPort", severity: "required", message: "Listen port must be set." });
    if (!hasNonEmptyString(cfg.wireguard.addressCIDR)) out.push({ field: "wireguard.addressCIDR", severity: "required", message: "Tunnel address CIDR is required (e.g. 10.8.0.1/24)." });
    if (!hasNonEmptyString(cfg.wireguard.privateKey)) out.push({ field: "wireguard.privateKey", severity: "required", message: "Private key is required to bring up a WireGuard server." });
    if (!cfg.wireguard.peers?.length) out.push({ field: "wireguard.peers", severity: "recommended", message: "Add at least one peer so clients can connect." });
    if ((cfg.wireguard.listenInterfaces ?? []).length > 0 && hasNonEmptyString(cfg.wireguard.listenZone)) {
      out.push({
        field: "wireguard.listenTargets",
        severity: "recommended",
        message: "Listen interfaces override listen zone; clear one to avoid confusion.",
      });
    }
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
      if ((s?.listenInterfaces ?? []).length > 0 && hasNonEmptyString(s?.listenZone)) {
        out.push({
          field: "openvpn.server.listenTargets",
          severity: "recommended",
          message: "Listen interfaces override listen zone; clear one to avoid confusion.",
        });
      }
    }
    return out;
  }, [cfg.openvpn]);

  const refresh = useCallback(
    async ({ silent = false }: { silent?: boolean } = {}) => {
      setLoading(true);
      setError(null);
      try {
        const current = await api.getVPN();
        setCfg(normalize(current));
        const [states, zonesResp, ifacesResp] = await Promise.all([
          api.listInterfaceState(),
          api.listZones(),
          api.listInterfaces(),
        ]);
        setZones(zonesResp ?? []);
        setInterfaces(ifacesResp ?? []);
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
        if (!silent) toast("VPN status refreshed", "success");
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Failed to refresh VPN status.";
        setError(msg);
        if (!silent) toast("Failed to refresh VPN status", "error");
      } finally {
        setLoading(false);
        setLastUpdated(new Date());
      }
    },
    [toast],
  );

  useEffect(() => {
    refresh({ silent: true });
  }, [refresh]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh({ silent: true });
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

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
  const vpnSpark = useMemo(
    () => [
      3,
      (wgStatus?.peers?.length ?? 1) + 2,
      5,
      (svcStatus?.openvpn_running ? 6 : 3) + (wgStatus?.peers?.length ?? 0),
      8,
      (wgStatus?.peers?.length ?? 1) + 4,
      7,
    ],
    [wgStatus?.peers?.length, svcStatus?.openvpn_running],
  );
  const interfaceOptions = useMemo(() => {
    return (interfaces ?? [])
      .map((iface) => {
        const value = (iface.device ?? iface.name ?? "").trim();
        if (!value) return null;
        const label = iface.alias ? `${iface.alias} (${value})` : value;
        const zone = iface.zone ? ` · ${iface.zone}` : "";
        return { value, label: `${label}${zone}` };
      })
      .filter((item): item is { value: string; label: string } => Boolean(item));
  }, [interfaces]);

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
    setSaveState(saved.ok ? "saved" : "error");
    if (!saved.ok) {
      const msg = saved.error || "Failed to save VPN settings.";
      setError(msg);
      toast(msg, "error");
    } else {
      setCfg(normalize(saved.data));
      toast(saved.warning ? `VPN saved with warning: ${saved.warning}` : "VPN saved", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function uploadOpenVPNProfile(file: File) {
    if (!canEdit) return;
    setError(null);
    setUploadState("uploading");
    try {
      const text = await file.text();
      const base = file.name.replace(/\.(ovpn|conf|txt)$/i, "");
      const res = await api.uploadOpenVPNProfile(base || "client", text);
      if (!res.ok) {
        setUploadState("error");
        setError(res.error || "Failed to upload OpenVPN profile.");
        setTimeout(() => setUploadState("idle"), 1500);
        return;
      }
      setUploadState("uploaded");
      toast(res.warning ? `Profile uploaded with warning: ${res.warning}` : "Profile uploaded", "success");
      // Uploading a profile switches OpenVPN to "configPath" mode (advanced) and clears managed config.
      const next = normalize(res.data.vpn);
      setCfg({
        ...next,
        openvpn: { ...next.openvpn, managed: undefined },
      });
      setTimeout(() => setUploadState("idle"), 1500);
      // Refresh runtime badges (installed/running/last error) after upload.
      refresh({ silent: true });
    } catch (e) {
      setUploadState("error");
      setError(e instanceof Error ? e.message : "Failed to upload OpenVPN profile.");
      toast("Upload failed", "error");
      setTimeout(() => setUploadState("idle"), 1500);
    }
  }

  async function createClient() {
    if (!canEdit) return;
    const name = newClientName.trim();
    if (!name) return;
    setError(null);
    const created = await api.createOpenVPNClient(name);
    if (!created.ok) {
      const msg = created.error || "Failed to create client.";
      setError(msg);
      toast(msg, "error");
      return;
    }
    setNewClientName("");
    const res = await api.listOpenVPNClients();
    setOvpnClients(res?.clients ?? []);
    toast(created.warning ? `Client created with warning: ${created.warning}` : "Client created", "success");
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
      toast("Client profile downloaded", "success");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to download client profile.");
      toast("Download failed", "error");
    }
  }

  return (
    <Shell
      title="VPN"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => refresh()}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Save
            </button>
          )}
          <label className="ml-2 flex items-center gap-2 text-xs text-[var(--text)]">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded border-amber-500/[0.15] bg-[var(--surface)]"
            />
            Auto
          </label>
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)] shadow-card">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <p className="mb-4 text-xs text-[var(--text-muted)]">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>
      <VPNRuntimeStatusCard cfg={cfg} loading={loading} svcStatus={svcStatus} vpnSpark={vpnSpark} />
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="relative overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card backdrop-blur">
          <div className="pointer-events-none absolute -right-10 -top-10 h-44 w-44 rounded-full bg-amber-500/[0.1] blur-2xl" />
          <div className="relative flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-sm border border-amber-500/[0.15] bg-gradient-to-br from-blue-500/25 to-sky-500/10">
                <Image
                  src="/icons/wireguard.svg"
                  alt="WireGuard"
                  width={24}
                  height={24}
                  className="h-6 w-6 invert opacity-90 drop-shadow"
                />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[var(--text)]">WireGuard</h2>
                <p className="mt-0.5 text-sm text-[var(--text)]">Remote access VPN (preferred).</p>
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
            <label className="flex items-center gap-2 text-sm text-[var(--text)]">
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
            <div className="rounded-sm border border-amber-500/[0.15] bg-black/20 px-3 py-2 text-xs text-[var(--text)]">
              When enabled, containd auto-opens UDP/{cfg.wireguard.listenPort ?? 51820} on the configured listen zone or interfaces
              (default <span className="font-mono">wan</span>) via nftables input so clients can connect.
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Interface</label>
                <input
                  value={cfg.wireguard.interface ?? "wg0"}
                  disabled={!canEdit}
                  onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, interface: e.target.value } }))}
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Listen Port
                  <InfoTip label="UDP port WireGuard listens on (default 51820)." />
                </label>
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
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Listen Zone
                  <InfoTip label="Zone used for auto-open input rules (default wan)." />
                </label>
                <select
                  value={cfg.wireguard.listenZone ?? ""}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setCfg((c) => ({
                      ...c,
                      wireguard: { ...c.wireguard, listenZone: e.target.value },
                    }))
                  }
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                >
                  <option value="">default (wan)</option>
                  {zones.map((z) => (
                    <option key={z.name} value={z.name}>
                      {z.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Listen Interfaces (optional)
                <InfoTip label="Overrides listen zone when set. Select one or more interfaces/devices." />
              </label>
              {interfaceOptions.length ? (
                <div className="mt-2 grid gap-2 md:grid-cols-2">
                  {interfaceOptions.map((opt) => {
                    const active = (cfg.wireguard.listenInterfaces ?? []).includes(opt.value);
                    return (
                      <label key={opt.value} className="flex items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)]">
                        <input
                          type="checkbox"
                          checked={active}
                          disabled={!canEdit}
                          onChange={(e) => {
                            const next = new Set(cfg.wireguard.listenInterfaces ?? []);
                            if (e.target.checked) {
                              next.add(opt.value);
                            } else {
                              next.delete(opt.value);
                            }
                            setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, listenInterfaces: Array.from(next) } }));
                          }}
                          className="h-4 w-4"
                        />
                        {opt.label}
                      </label>
                    );
                  })}
                </div>
              ) : (
                <p className="mt-2 text-xs text-[var(--text-muted)]">No interfaces discovered yet.</p>
              )}
              <p className="mt-2 text-xs text-[var(--text-muted)]">If any interfaces are selected, the listen zone is ignored.</p>
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Address (CIDR)
                <InfoTip label="VPN client network. Policy can target vpn:wireguard." />
              </label>
              <input
                value={cfg.wireguard.addressCIDR ?? ""}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, addressCIDR: e.target.value } }))}
                className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Private Key (base64)
                <InfoTip label="Server private key. Stored in config; export redaction handled elsewhere." />
              </label>
              <input
                value={cfg.wireguard.privateKey ?? ""}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, privateKey: e.target.value } }))}
                className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                placeholder="(leave blank to set later)"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Peers (JSON)
                <InfoTip label="JSON array with name, publicKey, and allowedIPs for each peer." />
              </label>
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
                className="mt-1 w-full rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 font-mono text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
          </div>
        </div>

        <WireGuardRuntimeCard
          cfgInterface={cfg.wireguard.interface ?? "wg0"}
          peerCount={(cfg.wireguard.peers ?? []).length}
          peerNameByKey={peerNameByKey}
          runtime={runtime}
          wgStatus={wgStatus}
        />

        <OpenVPNEditorCard
          canEdit={canEdit}
          cfg={cfg}
          setCfg={setCfg}
          zones={zones}
          interfaceOptions={interfaceOptions}
          openvpnIssues={openvpnIssues}
          svcStatus={svcStatus}
          uploadState={uploadState}
          ovpnClients={ovpnClients}
          newClientName={newClientName}
          setNewClientName={setNewClientName}
          uploadOpenVPNProfile={uploadOpenVPNProfile}
          createClient={createClient}
          downloadClient={downloadClient}
        />
      </div>

      <p className="mt-3 text-xs text-[var(--text-muted)]">
        State:{" "}
        {saveState === "saving"
          ? "saving\u2026"
          : saveState === "saved"
            ? "saved"
            : saveState === "error"
              ? "error"
              : "idle"}
      </p>
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
