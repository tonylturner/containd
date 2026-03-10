// IEC 62443-3-3 SL scoring — shared between SecurityView and Zones page.

import type { Conduit, ConduitMap, Zone } from "./api";

/* ── Types ── */

export interface ZoneView {
  id: string;
  name: string;
  sl_t: number;
  color: string;
  hosts: number;
  consequence: string;
  overrides: Record<string, boolean>;
}

export interface SRDef {
  id: string;
  sl: number;
  label: string;
  source: "zone" | "conduit";
  check: (z: ZoneView, cs: Conduit[]) => boolean;
}

export interface SRCheck extends SRDef {
  met: boolean;
  auto: boolean;
  overridden: boolean;
}

/* ── SR definitions (SL 0 through SL 4) ── */

export const SR_DEFS: SRDef[] = [
  // SL-0: No security requirements (always met — baseline for unprotected zones)

  // SL-1
  { id: "SR-1.1",  sl: 1, label: "Human interface identification & authentication",            source: "zone",    check: (z) => z.id !== "internet" },
  { id: "SR-3.3",  sl: 1, label: "Security functionality verification",                         source: "zone",    check: () => true },
  { id: "SR-5.1",  sl: 1, label: "Network segmentation — zone has explicit policy",             source: "zone",    check: (_, cs) => cs.some((c) => c.defaultDeny || c.state === "block") },
  { id: "SR-2.8",  sl: 1, label: "Auditable events — conduit traffic logged",                    source: "conduit", check: (_, cs) => cs.every((c) => c.auditLogged) },

  // SL-2
  { id: "SR-1.2",  sl: 2, label: "Software process & device identification (IDS)",               source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.ids === "full" || c.ids === "partial") },
  { id: "SR-3.1",  sl: 2, label: "Communication integrity — TLS on active conduits",             source: "conduit", check: (_, cs) => cs.filter((c) => c.state === "allow" || c.state === "partial").every((c) => c.tlsEnforced) },
  { id: "SR-5.2",  sl: 2, label: "Zone boundary protection — explicit default deny",             source: "zone",    check: (_, cs) => cs.some((c) => c.defaultDeny) },
  { id: "SR-5.4",  sl: 2, label: "Application partitioning — protocol whitelisting",             source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.protoWhitelist) },

  // SL-3
  { id: "SR-1.13", sl: 3, label: "Access via untrusted networks requires MFA",                   source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.mfaRequired) },
  { id: "SR-2.12", sl: 3, label: "Non-repudiation — signed/tamper-evident audit log",            source: "zone",    check: () => false },
  { id: "SR-3.2",  sl: 3, label: "Malicious code protection — AV scanning on conduit",           source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.avEnabled) },
  { id: "SR-5.4b", sl: 3, label: "Full DPI + protocol whitelist on all active conduits",         source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.protoWhitelist && c.ids === "full") },

  // SL-4
  { id: "SR-1.14", sl: 4, label: "Mutual device-level certificate authentication",               source: "conduit", check: () => false },
  { id: "SR-2.13", sl: 4, label: "Continuous integrity monitoring — real-time tamper detection",   source: "zone",    check: () => false },
  { id: "SR-3.4",  sl: 4, label: "Hardware-backed crypto for all conduit encryption",             source: "conduit", check: () => false },
  { id: "SR-5.5",  sl: 4, label: "Micro-segmentation — per-service network isolation",            source: "zone",    check: () => false },
  { id: "SR-7.7",  sl: 4, label: "Deterministic output — verified safe-state on failure",         source: "zone",    check: () => false },
];

export const MAX_SL = 4;

/* ── Zone colors ── */

const ZONE_COLORS: Record<string, string> = {
  internet: "#6b7280", wan: "#ef4444", dmz: "#f97316",
  lan: "#f59e0b", mgmt: "#22c55e", enclave: "#a855f7",
  corp: "#f59e0b", ot: "#a855f7", scada: "#a855f7",
};

export function zoneColor(name: string): string {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(ZONE_COLORS)) {
    if (lower.includes(k)) return v;
  }
  const colors = ["#06b6d4", "#a855f7", "#f59e0b", "#22c55e", "#ef4444", "#f97316"];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0;
  return colors[Math.abs(h) % colors.length];
}

/* ── Map API Zone → ZoneView ── */

export function mapZone(z: Zone): ZoneView {
  return {
    id: z.name.toLowerCase().replace(/[^a-z0-9]+/g, "_"),
    name: z.name.toUpperCase(),
    sl_t: z.slTarget ?? 0,
    color: zoneColor(z.name),
    hosts: 0,
    consequence: z.consequence || "",
    overrides: z.slOverrides || {},
  };
}

/* ── Score a zone against its outbound conduits ── */

export function scoreZone(zone: ZoneView, conduits: ConduitMap): { sl_a: number; checks: SRCheck[] } {
  // Conduit keys use original zone names from the backend.
  // Match by comparing lowercased key prefix against zone.id.
  const cs = Object.entries(conduits)
    .filter(([k]) => {
      const from = k.split("\u2192")[0];
      return from.toLowerCase().replace(/[^a-z0-9]+/g, "_") === zone.id;
    })
    .map(([, v]) => v);
  const checks: SRCheck[] = SR_DEFS.map((sr) => {
    const auto = sr.check(zone, cs);
    const overridden = Object.prototype.hasOwnProperty.call(zone.overrides, sr.id);
    const met = overridden ? zone.overrides[sr.id] : auto;
    return { ...sr, met, auto, overridden };
  });
  let sl_a = 0;
  for (let lvl = 1; lvl <= MAX_SL; lvl++) {
    if (checks.filter((c) => c.sl <= lvl).every((c) => c.met)) sl_a = lvl;
    else break;
  }
  return { sl_a, checks };
}

/* ── SL color helper ── */

export function slColor(sl_a: number, sl_t: number): string {
  if (sl_t === 0) return "var(--text-dim)";
  return sl_a >= sl_t ? "var(--topo-green)" : sl_a === sl_t - 1 ? "var(--amber)" : "var(--topo-red)";
}
