"use client";

import Image from "next/image";
import type { Dispatch, SetStateAction } from "react";

import type { Zone } from "../../lib/api";
import { InfoTip } from "../../components/InfoTip";
import {
  Badge,
  defaultOpenVPNManaged,
  defaultOpenVPNServer,
  IssuesBanner,
  PEMField,
  type FieldIssue,
  type NormalizedVPNConfig,
  type VPNServiceStatus,
} from "./vpn-shared";

type UploadState = "idle" | "uploading" | "uploaded" | "error";

type InterfaceOption = {
  value: string;
  label: string;
};

type Props = {
  canEdit: boolean;
  cfg: NormalizedVPNConfig;
  setCfg: Dispatch<SetStateAction<NormalizedVPNConfig>>;
  zones: Zone[];
  interfaceOptions: InterfaceOption[];
  openvpnIssues: FieldIssue[];
  svcStatus: VPNServiceStatus | null;
  uploadState: UploadState;
  ovpnClients: string[];
  newClientName: string;
  setNewClientName: Dispatch<SetStateAction<string>>;
  uploadOpenVPNProfile: (file: File) => Promise<void>;
  createClient: () => Promise<void>;
  downloadClient: (name: string) => Promise<void>;
};

export function OpenVPNEditorCard({
  canEdit,
  cfg,
  setCfg,
  zones,
  interfaceOptions,
  openvpnIssues,
  svcStatus,
  uploadState,
  ovpnClients,
  newClientName,
  setNewClientName,
  uploadOpenVPNProfile,
  createClient,
  downloadClient,
}: Props) {
  return (
    <div className="relative overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card backdrop-blur">
      <div className="pointer-events-none absolute -right-10 -top-10 h-44 w-44 rounded-full bg-amber-500/10 blur-2xl" />
      <div className="relative flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-sm border border-amber-500/[0.15] bg-gradient-to-br from-amber-500/25 to-rose-500/10">
            <Image
              src="/icons/openvpn.svg"
              alt="OpenVPN"
              width={24}
              height={24}
              className="h-6 w-6 invert opacity-90 drop-shadow"
            />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-[var(--text)]">OpenVPN</h2>
            <p className="mt-0.5 text-sm text-[var(--text)]">Compatibility VPN (optional).</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Badge tone={cfg.openvpn.enabled ? "warn" : "off"}>{cfg.openvpn.enabled ? "enabled" : "disabled"}</Badge>
          <Badge tone={svcStatus?.openvpn_installed ? "info" : "off"}>
            {svcStatus?.openvpn_installed ? "installed" : "not installed"}
          </Badge>
          <Badge tone={svcStatus?.openvpn_running ? "ok" : "off"}>
            {svcStatus?.openvpn_running ? "running" : "stopped"}
          </Badge>
        </div>
      </div>

      <div className="mt-4 grid gap-3">
        <label className="flex items-center gap-2 text-sm text-[var(--text)]">
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
          <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Mode</label>
          <select
            value={cfg.openvpn.mode ?? "client"}
            disabled={!canEdit}
            onChange={(e) => setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, mode: e.target.value } }))}
            className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
          >
            <option value="client">client</option>
            <option value="server">server</option>
          </select>
        </div>

        {cfg.openvpn.mode === "client" ? (
          <div className="rounded-sm border border-amber-500/[0.15] bg-black/20 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Client Configuration</div>
                <div className="mt-1 text-sm text-[var(--text)]">
                  {cfg.openvpn.managed ? "Managed config (recommended)" : "Advanced profile path"}
                </div>
              </div>
              <label className="inline-flex items-center gap-2 text-xs text-[var(--text)]">
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
                    <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                      Remote
                      <InfoTip label="Hostname or IP address of the OpenVPN gateway." />
                    </label>
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
                      className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                      placeholder="vpn.example.com"
                    />
                  </div>
                  <div>
                    <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Port</label>
                    <input
                      type="number"
                      value={cfg.openvpn.managed.port ?? 1194}
                      disabled={!canEdit}
                      onChange={(e) =>
                        setCfg((c) => ({
                          ...c,
                          openvpn: {
                            ...c.openvpn,
                            managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), port: Number(e.target.value) || 0 },
                          },
                        }))
                      }
                      className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                    />
                  </div>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Protocol</label>
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
                      className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                    >
                      <option value="udp">udp</option>
                      <option value="tcp">tcp</option>
                    </select>
                  </div>
                  <div className="grid gap-2">
                    <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                      User/Pass (optional)
                      <InfoTip label="Only needed when the OpenVPN gateway requires username/password auth." />
                    </div>
                    <div className="grid gap-2 md:grid-cols-2">
                      <input
                        value={cfg.openvpn.managed.username ?? ""}
                        disabled={!canEdit}
                        onChange={(e) =>
                          setCfg((c) => ({
                            ...c,
                            openvpn: {
                              ...c.openvpn,
                              managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), username: e.target.value },
                            },
                          }))
                        }
                        className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
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
                              managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), password: e.target.value },
                            },
                          }))
                        }
                        className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                        placeholder="password"
                      />
                    </div>
                  </div>
                </div>

                <PEMField
                  title="CA (PEM)"
                  tip="Root CA certificate in PEM format."
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
                  tip="Client certificate for this appliance in PEM format."
                  value={cfg.openvpn.managed.cert ?? ""}
                  disabled={!canEdit}
                  onChange={(v) =>
                    setCfg((c) => ({
                      ...c,
                      openvpn: { ...c.openvpn, managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), cert: v } },
                    }))
                  }
                />
                <PEMField
                  title="Client Key (PEM)"
                  tip="Client private key in PEM format."
                  value={cfg.openvpn.managed.key ?? ""}
                  disabled={!canEdit}
                  onChange={(v) =>
                    setCfg((c) => ({
                      ...c,
                      openvpn: { ...c.openvpn, managed: { ...(c.openvpn.managed ?? defaultOpenVPNManaged), key: v } },
                    }))
                  }
                />
                <div className="text-xs text-[var(--text-muted)]">
                  This is stored in the appliance config for now; secret encryption/redaction is tracked as a follow-up.
                </div>
              </div>
            ) : (
              <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
                <summary className="cursor-pointer text-sm text-[var(--text)]">Advanced profile path</summary>
                <div className="mt-3">
                  <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Config Path
                    <InfoTip label="Foreground OpenVPN config file; omit the daemon directive." />
                  </label>
                  <input
                    value={cfg.openvpn.configPath ?? ""}
                    disabled={!canEdit}
                    onChange={(e) => setCfg((c) => ({ ...c, openvpn: { ...c.openvpn, configPath: e.target.value } }))}
                    className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                    placeholder="/data/openvpn/profiles/client.ovpn"
                  />
                </div>
              </details>
            )}

            <div className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-[var(--text)]">
                  Import profile (advanced)
                  <InfoTip label="Uploads a .ovpn and sets Config Path automatically (clears managed config)." />
                </div>
                <label className="inline-flex cursor-pointer items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">
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
          <div className="rounded-sm border border-amber-500/[0.15] bg-black/20 p-3">
            <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Server Configuration</div>
            <div className="mt-3 grid gap-3">
              <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)]">
                Enabling OpenVPN server automatically opens the listen port on the configured listen zone or interfaces
                (default WAN) via nftables input so clients can connect.
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <div>
                  <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Listen Port</label>
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
                    className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  />
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Protocol</label>
                  <select
                    value={cfg.openvpn.server?.proto ?? "udp"}
                    disabled={!canEdit}
                    onChange={(e) =>
                      setCfg((c) => ({
                        ...c,
                        openvpn: { ...c.openvpn, server: { ...(c.openvpn.server ?? defaultOpenVPNServer), proto: e.target.value } },
                      }))
                    }
                    className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  >
                    <option value="udp">udp</option>
                    <option value="tcp">tcp</option>
                  </select>
                </div>
                <div>
                  <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Tunnel CIDR
                    <InfoTip label="Client address pool. Policy can target vpn:openvpn." />
                  </label>
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
                    className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  />
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div>
                  <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Listen Zone
                    <InfoTip label="Zone used for auto-open input rules (default wan)." />
                  </label>
                  <select
                    value={cfg.openvpn.server?.listenZone ?? ""}
                    disabled={!canEdit}
                    onChange={(e) =>
                      setCfg((c) => ({
                        ...c,
                        openvpn: {
                          ...c.openvpn,
                          server: { ...(c.openvpn.server ?? defaultOpenVPNServer), listenZone: e.target.value },
                        },
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
                <div>
                  <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Listen Interfaces (optional)
                    <InfoTip label="Overrides listen zone when set. Select one or more interfaces/devices." />
                  </label>
                  {interfaceOptions.length ? (
                    <div className="mt-2 grid gap-2 md:grid-cols-2">
                      {interfaceOptions.map((opt) => {
                        const active = (cfg.openvpn.server?.listenInterfaces ?? []).includes(opt.value);
                        return (
                          <label
                            key={opt.value}
                            className="flex items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)]"
                          >
                            <input
                              type="checkbox"
                              checked={active}
                              disabled={!canEdit}
                              onChange={(e) => {
                                const next = new Set(cfg.openvpn.server?.listenInterfaces ?? []);
                                if (e.target.checked) {
                                  next.add(opt.value);
                                } else {
                                  next.delete(opt.value);
                                }
                                setCfg((c) => ({
                                  ...c,
                                  openvpn: {
                                    ...c.openvpn,
                                    server: {
                                      ...(c.openvpn.server ?? defaultOpenVPNServer),
                                      listenInterfaces: Array.from(next),
                                    },
                                  },
                                }));
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
              </div>

              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Public Endpoint (for client profiles)
                  <InfoTip label="Used when generating downloadable .ovpn client profiles." />
                </label>
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
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  placeholder="vpn.example.com"
                />
              </div>

              <label className="flex items-center gap-2 text-sm text-[var(--text)]">
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
                  <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Push DNS (comma-separated)
                    <InfoTip label="DNS servers sent to clients when they connect." />
                  </label>
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
                    className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                    placeholder="1.1.1.1, 8.8.8.8"
                  />
                </div>
                <div>
                  <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Push Routes (comma-separated CIDR)
                    <InfoTip label="Networks advertised to VPN clients for reachability." />
                  </label>
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
                    className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                    placeholder="192.168.0.0/24, 10.0.0.0/8"
                  />
                </div>
              </div>

              <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-[var(--text)]">
                    Client profiles
                    <InfoTip label="Generates ECDSA certs and downloads inline .ovpn profiles." />
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      value={newClientName}
                      disabled={!canEdit}
                      onChange={(e) => setNewClientName(e.target.value)}
                      className="w-40 input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                      placeholder="client name"
                    />
                    <button
                      onClick={() => void createClient()}
                      disabled={!canEdit || !newClientName.trim()}
                      className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                    >
                      Create
                    </button>
                  </div>
                </div>
                {ovpnClients.length ? (
                  <div className="mt-3 grid gap-2">
                    {ovpnClients.map((n) => (
                      <div key={n} className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-black/20 px-3 py-2">
                        <div className="font-mono text-sm text-[var(--text)]">{n}</div>
                        <button
                          onClick={() => void downloadClient(n)}
                          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                        >
                          Download
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-3 text-xs text-[var(--text-muted)]">No clients yet.</div>
                )}
              </div>
            </div>
          </div>
        ) : null}

        {svcStatus?.openvpn_last_error ? (
          <div className="rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            {svcStatus.openvpn_last_error}
          </div>
        ) : (
          <div className="rounded-sm border border-amber-500/[0.15] bg-black/20 px-3 py-2 text-xs text-[var(--text)]">
            OpenVPN is supervised only when the binary is present and a valid config file is provided.
          </div>
        )}
      </div>
    </div>
  );
}
