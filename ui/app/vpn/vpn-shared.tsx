"use client";

import type { ReactNode } from "react";

import { InfoTip } from "../../components/InfoTip";
import type {
  OpenVPNConfig,
  OpenVPNManagedClientConfig,
  OpenVPNManagedServerConfig,
  VPNConfig,
  WireGuardConfig,
} from "../../lib/api";

export type FieldIssue = {
  field: string;
  message: string;
  severity: "required" | "recommended";
};

export type VPNServiceStatus = {
  openvpn_installed?: boolean;
  openvpn_running?: boolean;
  openvpn_pid?: number;
  openvpn_config_path?: string;
  openvpn_last_error?: string;
  openvpn_mode?: string;
  openvpn_server_tunnel?: string;
  openvpn_server_endpoint?: string;
};

export function normalize(cfg: VPNConfig | null): {
  wireguard: WireGuardConfig;
  openvpn: OpenVPNConfig;
} {
  return {
    wireguard: {
      enabled: cfg?.wireguard?.enabled ?? false,
      interface: cfg?.wireguard?.interface ?? "wg0",
      listenPort: cfg?.wireguard?.listenPort ?? 51820,
      listenZone: cfg?.wireguard?.listenZone ?? "",
      listenInterfaces: cfg?.wireguard?.listenInterfaces ?? [],
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

export type NormalizedVPNConfig = ReturnType<typeof normalize>;

export function Badge({
  tone,
  children,
  title,
}: {
  tone: "ok" | "warn" | "off" | "info";
  children: ReactNode;
  title?: string;
}) {
  const cls =
    tone === "ok"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
      : tone === "warn"
        ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
        : tone === "info"
          ? "border-amber-500/[0.15] bg-[var(--surface)] text-[var(--text)]"
          : "border-amber-500/[0.15] bg-white/0 text-[var(--text-muted)]";
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs ${cls}`}
    >
      {children}
    </span>
  );
}

export function IssuesBanner({
  title,
  issues,
}: {
  title: string;
  issues: FieldIssue[];
}) {
  if (!issues.length) return null;
  const required = issues.filter((i) => i.severity === "required");
  const recommended = issues.filter((i) => i.severity === "recommended");
  return (
    <div className="rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
      <div className="font-medium text-amber-400">{title}</div>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] text-amber-400/90">
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

export const defaultOpenVPNManaged: OpenVPNManagedClientConfig = {
  remote: "",
  port: 1194,
  proto: "udp",
  username: "",
  password: "",
  ca: "",
  cert: "",
  key: "",
};

export const defaultOpenVPNServer: OpenVPNManagedServerConfig = {
  listenPort: 1194,
  proto: "udp",
  listenZone: "",
  listenInterfaces: [],
  tunnelCIDR: "10.9.0.0/24",
  publicEndpoint: "",
  pushDNS: [],
  pushRoutes: [],
  clientToClient: false,
};

export function hasNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

export function hasLikelyPEM(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const t = v.trim();
  if (!t) return false;
  return t.includes("BEGIN") && t.includes("END");
}

export function PEMField({
  title,
  tip,
  value,
  disabled,
  onChange,
}: {
  title: string;
  tip?: string;
  value: string;
  disabled: boolean;
  onChange: (next: string) => void;
}) {
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
          {title}
          {tip ? <InfoTip label={tip} /> : null}
        </label>
        <label className="inline-flex cursor-pointer items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2.5 py-1 text-[11px] text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">
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
        className="mt-1 w-full rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 font-mono text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
        placeholder="-----BEGIN ...-----"
      />
    </div>
  );
}
