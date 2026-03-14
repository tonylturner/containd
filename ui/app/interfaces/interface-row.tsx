"use client";

import Image from "next/image";
import { useMemo, useState } from "react";

import type { Interface, InterfaceState, Zone } from "../../lib/api";

export function runtimeFor(
  iface: Interface,
  state: InterfaceState[],
): InterfaceState | null {
  const effectiveDev = iface.device || iface.name;
  return state.find((s) => s.name === effectiveDev) ?? null;
}

export function InterfaceRow({
  iface,
  runtime,
  zones,
  allIfaces,
  osState,
  onDelete,
  onUpdate,
  canEdit,
}: {
  iface: Interface;
  runtime: InterfaceState | null;
  zones: Zone[];
  allIfaces: Interface[];
  osState: InterfaceState[];
  onDelete: (name: string) => Promise<void>;
  onUpdate: (name: string, patch: Partial<Interface>) => Promise<void>;
  canEdit: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [itype, setIType] = useState((iface.type ?? "physical").toLowerCase());
  const [members, setMembers] = useState((iface.members ?? []).join(", "));
  const [parent, setParent] = useState(iface.parent ?? "");
  const [vlanId, setVlanId] = useState(
    typeof iface.vlanId === "number" ? String(iface.vlanId) : "",
  );
  const [device, setDevice] = useState(iface.device ?? "");
  const [alias, setAlias] = useState(iface.alias ?? "");
  const [zone, setZone] = useState(iface.zone ?? "");
  const [mode, setMode] = useState(
    (iface.addressMode ?? "static").toLowerCase(),
  );
  const [addresses, setAddresses] = useState((iface.addresses ?? []).join(", "));
  const [gateway, setGateway] = useState(iface.gateway ?? "");
  const [mgmt, setMgmt] = useState(iface.access?.mgmt ?? true);
  const [http, setHTTP] = useState(iface.access?.http ?? true);
  const [https, setHTTPS] = useState(iface.access?.https ?? true);
  const [ssh, setSSH] = useState(iface.access?.ssh ?? true);

  const detectedCIDR = firstIPv4CIDR(runtime?.addrs);
  const suggestedGateway = suggestGatewayFromCIDR(detectedCIDR);

  const memberCandidates = useMemo(() => {
    const logical = (allIfaces ?? [])
      .filter((x) => x.name !== iface.name)
      .map((x) => x.name);
    const os = (osState ?? [])
      .map((s) => s.name)
      .filter((n) => n !== "lo");
    return Array.from(new Set([...logical, ...os])).sort();
  }, [allIfaces, osState, iface.name]);

  const parentCandidates = memberCandidates;

  function typeLabel(): string {
    const t = (iface.type ?? "physical").toLowerCase();
    if (t === "bridge") {
      const ms = iface.members ?? [];
      return ms.length ? `bridge (${ms.length})` : "bridge";
    }
    if (t === "vlan") {
      const p = iface.parent ? iface.parent : "parent";
      const id = typeof iface.vlanId === "number" ? String(iface.vlanId) : "?";
      return `vlan (${p}.${id})`;
    }
    return "physical";
  }

  const zoneLabel = (z: Zone): string =>
    z.alias ? `${z.alias} (${z.name})` : z.name;
  const zoneDisplay = iface.zone
    ? zoneLabel(zones.find((z) => z.name === iface.zone) ?? { name: iface.zone })
    : "—";

  return (
    <tr className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
      <td className="px-4 py-3 font-medium text-[var(--text)]">{iface.name}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            disabled={!canEdit}
            placeholder="alias (optional)"
            className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none placeholder:text-[var(--text-dim)]"
          />
        ) : (
          <span className="text-[var(--text)]">{iface.alias || "—"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <div className="space-y-2">
            <select
              value={itype}
              onChange={(e) => setIType(e.target.value)}
              disabled={!canEdit}
              className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              <option value="physical">physical</option>
              <option value="bridge">bridge</option>
              <option value="vlan">vlan</option>
            </select>
            {itype === "bridge" ? (
              <div className="space-y-1">
                <input
                  value={members}
                  onChange={(e) => setMembers(e.target.value)}
                  disabled={!canEdit}
                  placeholder="members (comma-separated)"
                  className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none placeholder:text-[var(--text-dim)]"
                />
                <select
                  value=""
                  onChange={(e) => {
                    const v = e.target.value;
                    if (!v) return;
                    const existing = members
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean);
                    if (!existing.includes(v)) existing.push(v);
                    setMembers(existing.join(", "));
                  }}
                  disabled={!canEdit}
                  className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  title="Quick-pick a member (appends)"
                >
                  <option value="">+ add member…</option>
                  {memberCandidates.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </div>
            ) : itype === "vlan" ? (
              <div className="space-y-1">
                <select
                  value={parent}
                  onChange={(e) => setParent(e.target.value)}
                  disabled={!canEdit}
                  className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                >
                  <option value="">(parent)</option>
                  {parentCandidates.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
                <input
                  value={vlanId}
                  onChange={(e) => setVlanId(e.target.value)}
                  disabled={!canEdit}
                  placeholder="vlan id (1-4094)"
                  className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none placeholder:text-[var(--text-dim)]"
                />
              </div>
            ) : null}
          </div>
        ) : (
          <span className="text-[var(--text)]">{typeLabel()}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={device}
            onChange={(e) => setDevice(e.target.value)}
            disabled={!canEdit}
            placeholder="os iface (e.g. eth0)"
            className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none placeholder:text-[var(--text-dim)]"
          />
        ) : (
          <span className="text-[var(--text)]">{iface.device || "—"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {runtime ? (
          <span className={chipClass(runtime.up)}>{runtime.up ? "up" : "down"}</span>
        ) : (
          <span className="text-[var(--text-muted)]">—</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <select
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
          >
            <option value="">(no zone)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {zoneLabel(z)}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-[var(--text)]">{zoneDisplay}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <div className="space-y-2">
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              disabled={!canEdit}
              className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              <option value="static">static</option>
              <option value="dhcp">dhcp</option>
            </select>
            <input
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              disabled={!canEdit || mode === "dhcp"}
              placeholder="CIDRs (comma-separated)"
              className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none placeholder:text-[var(--text-dim)]"
            />
            <input
              value={gateway}
              onChange={(e) => setGateway(e.target.value)}
              disabled={!canEdit || mode === "dhcp"}
              placeholder="gateway (optional)"
              className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none placeholder:text-[var(--text-dim)]"
            />
            {canEdit && mode !== "dhcp" && detectedCIDR && (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--text)]">
                <button
                  type="button"
                  onClick={() => {
                    setMode("static");
                    setAddresses(detectedCIDR);
                    if (suggestedGateway) setGateway(suggestedGateway);
                  }}
                  className="rounded-md bg-amber-500/[0.15] px-2 py-1 text-[var(--amber)] transition-ui hover:bg-amber-500/[0.25]"
                  title="Use the currently detected OS address as this interface's static address (and infer gateway)."
                >
                  Use detected
                </button>
                <span className="text-[var(--text-muted)]">
                  Applies <span className="text-[var(--text)]">{detectedCIDR}</span>
                  {suggestedGateway ? (
                    <>
                      {" "}
                      and gateway <span className="text-[var(--text)]">{suggestedGateway}</span>
                    </>
                  ) : null}
                </span>
              </div>
            )}
            <div className="text-[11px] text-[var(--text-muted)]">
              {mode === "dhcp" ? (
                <span>
                  DHCP uses OS/Docker-assigned addresses (in containers,
                  assigned at startup).
                </span>
              ) : detectedCIDR ? (
                <span>
                  Detected subnet:{" "}
                  <span className="text-[var(--text)]">{detectedCIDR}</span>
                  {suggestedGateway ? (
                    <>
                      {" "}
                      (gateway often{" "}
                      <span className="text-[var(--text)]">
                        {suggestedGateway}
                      </span>
                      )
                    </>
                  ) : null}
                </span>
              ) : (
                <span>No IPv4 address detected on the bound OS device yet.</span>
              )}
            </div>
          </div>
        ) : (
          <span className="text-[var(--text)]">
            {(iface.addressMode ?? "static").toLowerCase() === "dhcp" ? (
              runtime && runtime.addrs?.length ? (
                <span>
                  dhcp{" "}
                  <span className="text-[var(--text-muted)]">
                    ({runtime.addrs.join(", ")})
                  </span>
                </span>
              ) : (
                <span>dhcp</span>
              )
            ) : (iface.addresses ?? []).length > 0 ? (
              (iface.addresses ?? []).join(", ")
            ) : (
              "—"
            )}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        {(() => {
          const configured =
            (iface.addressMode ?? "static").toLowerCase() === "dhcp"
              ? "dhcp"
              : (iface.addresses ?? []).length > 0
                ? (iface.addresses ?? []).join(", ")
                : "—";
          const network = runtime?.addrs?.length ? runtime.addrs.join(", ") : "—";
          const hasNetwork = network !== "—";
          return (
            <span className="relative inline-flex items-center justify-center rounded-md border border-amber-500/[0.15] bg-[var(--surface)] p-1 text-[var(--text)] group">
              <Image
                src="/icons/docker.svg"
                alt="Docker"
                width={16}
                height={16}
                className="h-4 w-4"
              />
              <span className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 w-72 -translate-x-1/2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] opacity-0 shadow-lg backdrop-blur-sm group-hover:opacity-100">
                <div className="font-semibold text-[var(--text)]">Network</div>
                <div className="mt-1 text-[var(--text)]">
                  <span className="text-[var(--text-muted)]">
                    OS/Docker address:
                  </span>{" "}
                  {network}
                </div>
                <div className="text-[var(--text)]">
                  <span className="text-[var(--text-muted)]">
                    Interface address:
                  </span>{" "}
                  {configured}
                </div>
                {!hasNetwork ? (
                  <div className="mt-1 text-[var(--text-muted)]">
                    No OS/Docker IP detected yet (check device binding / link
                    state).
                  </div>
                ) : null}
                <span className="absolute left-1/2 top-full -translate-x-1/2 border-8 border-transparent border-t-[var(--surface)]" />
              </span>
            </span>
          );
        })()}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <div className="grid grid-cols-2 gap-2 text-xs text-[var(--text)]">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={mgmt}
                disabled={!canEdit}
                onChange={(e) => setMgmt(e.target.checked)}
              />
              mgmt
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={ssh}
                disabled={!canEdit}
                onChange={(e) => setSSH(e.target.checked)}
              />
              ssh
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={http}
                disabled={!canEdit || !mgmt}
                onChange={(e) => setHTTP(e.target.checked)}
              />
              http
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={https}
                disabled={!canEdit || !mgmt}
                onChange={(e) => setHTTPS(e.target.checked)}
              />
              https
            </label>
          </div>
        ) : (
          <div className="flex flex-wrap gap-1 text-xs">
            <span className={chipClass(iface.access?.mgmt ?? true)}>mgmt</span>
            <span className={chipClass(iface.access?.ssh ?? true)}>ssh</span>
            <span className={chipClass(iface.access?.http ?? true)}>http</span>
            <span className={chipClass(iface.access?.https ?? true)}>https</span>
          </div>
        )}
      </td>
      <td className="px-4 py-3 text-right">
        {editing ? (
          <div className="inline-flex gap-2">
            <button
              onClick={async () => {
                await onUpdate(iface.name, {
                  type: itype || undefined,
                  alias: alias.trim() || undefined,
                  members:
                    itype === "bridge"
                      ? members
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean)
                      : [],
                  parent: itype === "vlan" ? parent.trim() || undefined : undefined,
                  vlanId:
                    itype === "vlan" && vlanId.trim()
                      ? Number.parseInt(vlanId, 10)
                      : undefined,
                  device: device.trim() || undefined,
                  zone: zone || undefined,
                  addressMode: mode,
                  addresses:
                    mode === "dhcp"
                      ? []
                      : addresses
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                  gateway: mode === "dhcp" ? "" : gateway.trim(),
                  access: {
                    mgmt,
                    ssh,
                    http,
                    https,
                  },
                });
                setEditing(false);
              }}
              className="rounded-sm bg-[var(--amber)] px-2 py-1 text-xs font-medium text-white transition-ui hover:brightness-110"
            >
              Save
            </button>
            <button
              onClick={() => {
                setIType((iface.type ?? "physical").toLowerCase());
                setMembers((iface.members ?? []).join(", "));
                setParent(iface.parent ?? "");
                setVlanId(
                  typeof iface.vlanId === "number" ? String(iface.vlanId) : "",
                );
                setDevice(iface.device ?? "");
                setAlias(iface.alias ?? "");
                setZone(iface.zone ?? "");
                setMode((iface.addressMode ?? "static").toLowerCase());
                setAddresses((iface.addresses ?? []).join(", "));
                setGateway(iface.gateway ?? "");
                setMgmt(iface.access?.mgmt ?? true);
                setSSH(iface.access?.ssh ?? true);
                setHTTP(iface.access?.http ?? true);
                setHTTPS(iface.access?.https ?? true);
                setEditing(false);
              }}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
            >
              Cancel
            </button>
          </div>
        ) : (
          <div className="inline-flex gap-2">
            {canEdit && (
              <>
                <button
                  onClick={() => setEditing(true)}
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                >
                  Edit
                </button>
                <button
                  onClick={async () => onDelete(iface.name)}
                  className="rounded-sm px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                >
                  Delete
                </button>
              </>
            )}
          </div>
        )}
      </td>
    </tr>
  );
}

function firstIPv4CIDR(addrs: string[] | null | undefined): string | null {
  for (const a of addrs ?? []) {
    const s = a.trim();
    if (!s) continue;
    const [ip] = s.split("/");
    if (!ip) continue;
    const parts = ip.split(".");
    if (parts.length !== 4) continue;
    if (parts.some((p) => p.trim() === "" || Number.isNaN(Number(p)))) continue;
    return s;
  }
  return null;
}

function suggestGatewayFromCIDR(cidr: string | null): string | null {
  if (!cidr) return null;
  const [ip, prefix] = cidr.split("/");
  if (!ip || !prefix) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const a = Number(parts[0]);
  const b = Number(parts[1]);
  const c = Number(parts[2]);
  if (![a, b, c].every((n) => Number.isFinite(n) && n >= 0 && n <= 255)) {
    return null;
  }
  return `${a}.${b}.${c}.1`;
}

export function chipClass(ok: boolean) {
  return ok
    ? "rounded-md bg-emerald-500/15 px-2 py-1 text-emerald-400"
    : "rounded-md bg-amber-500/15 px-2 py-1 text-amber-400";
}
