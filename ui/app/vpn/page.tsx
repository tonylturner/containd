"use client";

import { revisionError } from "../../lib/config-revision";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigForm } from "../../lib/use-config-form";
import { useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../lib/use-config-editor";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import Image from "next/image";
import { useCallback, useEffect, useMemo, useState } from "react";

import {
  api,
  isAdmin,
  type OpenVPNConfig,
  type Zone,
  type Interface,
  type InterfaceState,
  type WireGuardStatus,
  type ServicesStatus,
} from "../../lib/api";
import { authHeaders, fetchWithSession, handleUnauthorized, staticAssetURL } from "../../lib/api-core";
import { parseErrorBody } from "../../lib/api-request";
import type { OpenVPNCredential } from "../../lib/api-vpn";
import { ServiceFaultBanner } from "../../components/ServiceFaultBanner";
import { Shell } from "../../components/Shell";
import { useToast } from "../../components/ToastProvider";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { InfoTip } from "../../components/InfoTip";
import {
  Badge,
  defaultOpenVPNServer,
  hasLikelyPEM,
  hasNonEmptyString,
  IssuesBanner,
  normalize,
  type FieldIssue,
} from "./vpn-shared";
import { OpenVPNEditorCard } from "./vpn-openvpn-editor";
import { VPNRuntimeStatusCard } from "./vpn-runtime-status";
import { WireGuardRuntimeCard } from "./vpn-wireguard-runtime";

type SaveState = "idle" | "saving" | "saved" | "error";
type UploadState = "idle" | "uploading" | "uploaded" | "error";

export default function VPNPage() {
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const toast = useToast();
  const confirm = useConfirm();
  const { conflictProps, editor, cfg, setCfg, readConfig: adoptConfig, write, text, setText } = useConfigEditor(() => normalize(null), false);
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [uploadState, setUploadState] = useState<UploadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<InterfaceState | null>(null);
  const [interfaceStateStatus, setInterfaceStateStatus] = useState<"loading" | "ready" | "unavailable">("loading");
  const [wgStatus, setWgStatus] = useState<WireGuardStatus | null>(null);
  const [servicesStatus, setServicesStatus] = useState<ServicesStatus | null>(null);
  const svcStatus = servicesStatus?.vpn ?? null;
  const wireguardFaulted = servicesStatus?.wireguard?.state === "faulted";
  const [zones, setZones] = useState<Zone[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [ovpnClients, setOvpnClients] = useState<OpenVPNCredential[]>([]);
  const [revocationsApplied, setRevocationsApplied] = useState(true);
  const [clientsUnavailable, setClientsUnavailable] = useState(false);
  const [clientError, setClientError] = useState<string | null>(null);
  const [clientBusy, setClientBusy] = useState(false);
  const [pendingRevocations, setPendingRevocations] = useState<Record<string, string>>({});
  const clientForm = useConfigForm({ name: "" });
  const [newClientName, setNewClientName] = clientForm.field("name");
  const { readConfig: refreshClient } = clientForm;
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

  const { loading, refresh } = useAsyncRefresh(useCallback(
    async ({ silent = false, keepEdits = true }: { silent?: boolean; keepEdits?: boolean } = {}) => {
      try {
        const currentSnapshot = await api.getVPN();
        const current = currentSnapshot?.data;
        if (!checkLoaded(current)) return;
        setError(null);
        adoptConfig({ data: normalize(current), revision: currentSnapshot?.revision ?? "" }, keepEdits);
        refreshClient({ data: current?.openvpn, revision: currentSnapshot?.revision ?? "" }, keepEdits);
        const [states, zonesRespSnapshot, ifacesRespSnapshot] = await Promise.all([api.listInterfaceState(), api.listZones(), api.listInterfaces()]);
        const zonesResp = zonesRespSnapshot?.data ?? null;
        const ifacesResp = ifacesRespSnapshot?.data ?? null;
        setZones(zonesResp ?? []);
        setInterfaces(ifacesResp ?? []);
        const ifName = (current?.wireguard?.interface ?? "wg0").trim() || "wg0";
        setInterfaceStateStatus(states === null ? "unavailable" : "ready");
        setRuntime(states === null ? null : states.find((s) => s.name === ifName) ?? null);
        try {
          setWgStatus(await api.getWireGuardStatus(ifName));
        } catch {
          setWgStatus(null);
        }
        try {
          setServicesStatus(await api.getServicesStatus());
        } catch {
          setServicesStatus(null);
        }

        // OpenVPN server: list clients (admin-only).
        try {
          const mode = (current?.openvpn?.mode ?? "client").trim();
          if (mode === "server" && canEdit) {
            const res = await api.listOpenVPNClients();
            setClientsUnavailable(res === null);
            if (res) {
              setOvpnClients(res.clients);
              setRevocationsApplied(res.revocationsApplied);
              if (res.revocationsApplied) setPendingRevocations({});
            }
          } else {
            setOvpnClients([]);
            setClientsUnavailable(false);
          }
        } catch {
          setClientsUnavailable(true);
        }
        setLastUpdated(new Date());
        if (!silent) toast("VPN status refreshed", "success");
      } catch (e) {
        checkLoaded(null);
        const msg = e instanceof Error ? e.message : "Failed to refresh VPN status.";
        setError(msg);
        if (!silent) toast("Failed to refresh VPN status", "error");
      }
    },
    [checkLoaded, toast, adoptConfig, refreshClient, canEdit],
  ), { initialArgs: [{ silent: true }] });

  useConfigRefresh(refresh);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh({ silent: true });
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const peersText = text("peers", JSON.stringify(cfg.wireguard.peers ?? [], null, 2));
  const peerNameByKey = useMemo(() => {
    const out = new Map<string, string>();
    for (const p of cfg.wireguard.peers ?? []) {
      const k = (p.publicKey ?? "").trim();
      const n = (p.name ?? "").trim();
      if (k && n) out.set(k, n);
    }
    return out;
  }, [cfg.wireguard.peers]);
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
    if (!canEdit || !canSave || loading) return;
    setError(null);
    let peers;
    try {
      peers = JSON.parse(peersText);
      if (!Array.isArray(peers)) throw new Error("Peers must be a JSON array.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid peers JSON.");
      return;
    }
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

    if (openvpn.server) {
      openvpn.server = { ...openvpn.server,
        pushDNS: text("pushDNS", (openvpn.server.pushDNS ?? []).join(", ")).split(",").map((s) => s.trim()).filter(Boolean),
        pushRoutes: text("pushRoutes", (openvpn.server.pushRoutes ?? []).join(", ")).split(",").map((s) => s.trim()).filter(Boolean),
      };
    }
    const saved = await write(base => api.setVPN(base, {
      ...cfg,
      wireguard: { ...cfg.wireguard, peers },
      openvpn,
    }), { replace: data => normalize(data) });
    setSaveState(saved.ok ? "saved" : revisionError(saved) === null ? "idle" : "error");
    if (!saved.ok) {
      const msg = revisionError(saved);
      setError(msg);
      if (msg) toast(msg, "error");
    } else {
      toast(saved.warning ? `VPN staged — commit to apply. Warning: ${saved.warning}` : "VPN staged — commit to apply.", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function uploadOpenVPNProfile(file: File) {
    if (!canEdit) return;
    setError(null);
    setUploadState("uploading");
    try {
      const base = file.name.replace(/\.(ovpn|conf|txt)$/i, "");
      const res = await write(async revision => api.uploadOpenVPNProfile(revision, base || "client", await file.text()), {
        patch: (current, data) => ({ ...current, openvpn: { ...current.openvpn, configPath: data.configPath, managed: undefined } }),
      });
      if (!res.ok) {
        setUploadState(revisionError(res) === null ? "idle" : "error");
        setError(revisionError(res));
        setTimeout(() => setUploadState("idle"), 1500);
        return;
      }
      setUploadState("uploaded");
      toast(res.warning ? `Profile staged — commit to apply. Warning: ${res.warning}` : "Profile staged — commit to apply.", "success");
      // Uploading a profile switches OpenVPN to "configPath" mode (advanced) and clears managed config.
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
    if (!canEdit || clientBusy) return;
    const submitted = newClientName;
    const name = submitted.trim();
    if (!name) return;
    setClientError(null);
    setClientBusy(true);
    const created = await api.createOpenVPNClient(name);
    setClientBusy(false);
    if (!created.ok) {
      const msg = created.error || "Failed to create client.";
      setClientError(msg);
      toast(msg, "error");
      return;
    }
    setNewClientName((current) => current === submitted ? "" : current);
    setOvpnClients((current) => [...current, created.data]);
    toast(created.warning ? `Client created with warning: ${created.warning}` : "Client created", "success");
  }

  async function downloadClient(credential: OpenVPNCredential) {
    if (!canEdit || credential.revokedAt || clientBusy) return;
    setClientError(null);
    setClientBusy(true);
    try {
      const resp = await fetchWithSession(api.downloadOpenVPNClientURL(credential.id), { headers: authHeaders() });
      handleUnauthorized(resp);
      if (!resp.ok) throw new Error(await parseErrorBody(resp) || `Download failed (${resp.status})`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${credential.name}.ovpn`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast("Client profile downloaded", "success");
    } catch (e) {
      setClientError(e instanceof Error ? e.message : "Failed to download client profile.");
      toast("Download failed", "error");
    } finally {
      setClientBusy(false);
    }
  }

  function revokeClient(credential: OpenVPNCredential) {
    if (!canEdit || clientBusy || (credential.revokedAt && revocationsApplied)) return;
    confirm.open({
      title: credential.revokedAt ? "Apply revocation?" : "Revoke client credential?",
      message: <>Revoke {credential.name} (serial {credential.serial}) and restart the managed server? All clients will reconnect once. Revocation cannot be undone.</>,
      confirmLabel: credential.revokedAt ? (pendingRevocations[credential.id] ? "Retry apply" : "Apply revocation") : "Revoke",
      variant: "danger",
      onConfirm: () => { void applyRevocation(credential); },
    });
  }

  async function applyRevocation(credential: OpenVPNCredential) {
    setClientBusy(true);
    setClientError(null);
    const result = await api.revokeOpenVPNClient(credential.id);
    const revocation = result.ok ? result.data : result.revocation;
    if (revocation?.revoked) {
      setOvpnClients((current) => current.map((c) => c.id === credential.id ? revocation.credential : c));
      setRevocationsApplied(revocation.applied);
      // A successful restart loads the cumulative CRL, confirming every retry.
      if (revocation.applied) setPendingRevocations({});
      else setPendingRevocations((current) => ({
        ...current, [credential.id]: revocation.error || "Runtime not confirmed",
      }));
      if (revocation.applied) toast("Client revoked and applied", "success");
    } else {
      const msg = result.ok ? "Revocation not confirmed." : result.error;
      setClientError(msg);
      toast(msg, "error");
    }
    setClientBusy(false);
  }

  return (
    <Shell
      title="VPN"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              disabled={!canSave || loading || saveState === "saving"}
              className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Save
            </button>
          )}
          <label className="ml-2 flex items-center gap-2 text-xs text-(--text)">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded-sm bg-(--surface)"
            />
            Auto
          </label>
        </div>
      }
    >
      <ServiceFaultBanner status={servicesStatus} loading={loading} only={["wireguard", "openvpn"]} />
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice {...conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={editor.superseded || clientForm.editor.superseded} />
      <fieldset disabled={!canSave} className="min-w-0">
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text) shadow-card">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>
      <VPNRuntimeStatusCard loading={loading} servicesStatus={servicesStatus} />
      {!loading && error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="relative overflow-hidden rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
          <div className="pointer-events-none absolute -right-10 -top-10 h-44 w-44 rounded-full blur-2xl" />
          <div className="relative flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-xs border bg-linear-to-br from-blue-500/25 to-sky-500/10">
                <Image
                  src={staticAssetURL("/icons/wireguard.svg")}
                  alt="WireGuard"
                  width={24}
                  height={24}
                  className="h-6 w-6 invert opacity-90 drop-shadow-sm"
                />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-(--text)">WireGuard</h2>
                <p className="mt-0.5 text-sm text-(--text)">Remote access VPN (preferred).</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <Badge tone={wireguardFaulted ? "warn" : cfg.wireguard.enabled ? "ok" : "off"}>
                {wireguardFaulted ? "faulted" : cfg.wireguard.enabled ? "enabled" : "disabled"}
              </Badge>
              <Badge
                tone={interfaceStateStatus === "unavailable" ? "warn" : runtime?.up ? "ok" : runtime ? "warn" : "off"}
                title={interfaceStateStatus !== "ready" ? "Kernel interface state unknown" : runtime ? "Kernel interface state" : "Kernel interface not present"}
              >
                {interfaceStateStatus === "unavailable" ? "interface state unavailable" : interfaceStateStatus === "loading" ? "Loading…" : runtime ? (runtime.up ? "link up" : "link down") : "not present"}
              </Badge>
              <Badge tone={wgStatus ? "ok" : "off"} title="Tunnel status connection">
                {wgStatus ? "api ok" : "api n/a"}
              </Badge>
            </div>
          </div>

          <div className="mt-4 grid gap-3">
            <label className="flex items-center gap-2 text-sm text-(--text)">
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
            <div className="rounded-xs border bg-black/20 px-3 py-2 text-xs text-(--text)">
              When enabled and not quarantined, containd auto-opens UDP/{cfg.wireguard.listenPort ?? 51820} on the configured listen zone or interfaces
              (default <span className="font-mono">wan</span>) so clients can connect after these settings are applied.
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="text-xs uppercase tracking-wide text-(--text-muted)">Interface</label>
                <input
                  value={cfg.wireguard.interface ?? "wg0"}
                  disabled={!canEdit}
                  onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, interface: e.target.value } }))}
                  className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
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
                  className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
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
                  className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
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
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                Listen Interfaces (optional)
                <InfoTip label="Overrides listen zone when set. Select one or more interfaces/devices." />
              </label>
              {interfaceOptions.length ? (
                <div className="mt-2 grid gap-2 md:grid-cols-2">
                  {interfaceOptions.map((opt) => {
                    const active = (cfg.wireguard.listenInterfaces ?? []).includes(opt.value);
                    return (
                      <label key={opt.value} className="flex items-center gap-2 rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text)">
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
                <p className="mt-2 text-xs text-(--text-muted)">No interfaces discovered yet.</p>
              )}
              <p className="mt-2 text-xs text-(--text-muted)">If any interfaces are selected, the listen zone is ignored.</p>
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                Address (CIDR)
                <InfoTip label="VPN client network. Policy can target vpn:wireguard." />
              </label>
              <input
                value={cfg.wireguard.addressCIDR ?? ""}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, addressCIDR: e.target.value } }))}
                className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                Private Key (base64)
                <InfoTip label="Server private key. Stored in config; export redaction handled elsewhere." />
              </label>
              <input
                value={cfg.wireguard.privateKey ?? ""}
                disabled={!canEdit}
                onChange={(e) => setCfg((c) => ({ ...c, wireguard: { ...c.wireguard, privateKey: e.target.value } }))}
                className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                placeholder="(leave blank to set later)"
              />
            </div>

            <details className="rounded-xs border p-3">
              <summary className="cursor-pointer text-sm">Advanced peer settings</summary>
              <label htmlFor="wireguard-peers" className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                Peers (JSON)
                <InfoTip label="JSON array with name, publicKey, and allowedIPs for each peer." />
              </label>
              <textarea
                id="wireguard-peers"
                rows={8}
                value={peersText}
                disabled={!canEdit}
                onChange={(e) => setText("peers", e.target.value)}
                className="mt-1 w-full rounded-xs border bg-(--surface) px-3 py-2 font-mono text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
              />
            </details>
          </div>
        </div>

        <WireGuardRuntimeCard
          cfgInterface={cfg.wireguard.interface ?? "wg0"}
          peerCount={(cfg.wireguard.peers ?? []).length}
          peerNameByKey={peerNameByKey}
          runtime={runtime}
          interfaceStateStatus={interfaceStateStatus}
          onRetry={() => { void refresh({ silent: true }); }}
          wgStatus={wgStatus}
        />

        <OpenVPNEditorCard
          canEdit={canEdit}
          cfg={cfg}
          setCfg={setCfg}
          text={text}
          setText={setText}
          zones={zones}
          interfaceOptions={interfaceOptions}
          openvpnIssues={openvpnIssues}
          svcStatus={svcStatus}
          faulted={servicesStatus?.openvpn?.state === "faulted"}
          uploadState={uploadState}
          ovpnClients={ovpnClients}
          revocationsApplied={revocationsApplied}
          clientsUnavailable={clientsUnavailable}
          clientError={clientError}
          clientBusy={clientBusy}
          pendingRevocations={pendingRevocations}
          newClientName={newClientName}
          setNewClientName={setNewClientName}
          uploadOpenVPNProfile={uploadOpenVPNProfile}
          createClient={createClient}
          downloadClient={downloadClient}
          revokeClient={revokeClient}
        />
      </div>

      <p className="mt-3 text-xs text-(--text-muted)">
        State:{" "}
        {saveState === "saving"
          ? "saving\u2026"
          : saveState === "saved"
            ? "staged — commit to apply."
            : saveState === "error"
              ? "error"
              : "idle"}
      </p>
      <ConfirmDialog {...confirm.props} />
      </fieldset>
    </Shell>
  );
}
