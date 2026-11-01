"use client";

import type { ConfigFields } from "../../lib/use-config-editor";

import Image from "next/image";
import { useId, useLayoutEffect, useMemo, useRef, useState } from "react";

import type { Interface, InterfaceState, Zone } from "../../lib/api";
import { interfaceAddresses, OS_ADDRESS_HINT } from "../../lib/interface-addresses";
import { staticAssetURL } from "../../lib/api-core";
import { zoneLabel, zoneName } from "../../lib/zones";

export function InterfaceRow({
  draft,
  iface,
  runtime,
  zones,
  allIfaces,
  osState,
  onDelete,
  onUpdate,
  canEdit,
}: {
  draft: ConfigFields;
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
  const [inspecting, setInspecting] = useState<boolean | null>(null);
  const defaultOpen = (
    (iface.type ?? "physical") !== "physical" ||
    Object.values(iface.access ?? {}).some(value => value === false) ||
    !!iface.gateway
  );
  const detailId = useId();
  const inspectButton = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef(false);
  useLayoutEffect(() => {
    if (!editing && returnFocus.current) {
      returnFocus.current = false;
      inspectButton.current?.focus();
    }
  }, [editing]);
  const expanded = editing || (inspecting ?? defaultOpen);
  const [itype, setIType] = draft.field(`${JSON.stringify(iface.name)}.itype`, (iface.type ?? "physical").toLowerCase());
  const [members, setMembers] = draft.field(`${JSON.stringify(iface.name)}.members`, (iface.members ?? []).join(", "));
  const [parent, setParent] = draft.field(`${JSON.stringify(iface.name)}.parent`, iface.parent ?? "");
  const [vlanId, setVlanId] = draft.field(`${JSON.stringify(iface.name)}.vlanId`, typeof iface.vlanId === "number" ? String(iface.vlanId) : "");
  const [device, setDevice] = draft.field(`${JSON.stringify(iface.name)}.device`, iface.device ?? "");
  const [alias, setAlias] = draft.field(`${JSON.stringify(iface.name)}.alias`, iface.alias ?? "");
  const [zone, setZone] = draft.field(`${JSON.stringify(iface.name)}.zone`, iface.zone ?? "");
  const [mode, setMode] = draft.field(`${JSON.stringify(iface.name)}.mode`, iface.addressMode ?? "");
  const [addresses, setAddresses] = draft.field(`${JSON.stringify(iface.name)}.addresses`, (iface.addresses ?? []).join(", "));
  const [gateway, setGateway] = draft.field(`${JSON.stringify(iface.name)}.gateway`, iface.gateway ?? "");
  const [mgmt, setMgmt] = draft.field(`${JSON.stringify(iface.name)}.mgmt`, iface.access?.mgmt ?? true);
  const [http, setHTTP] = draft.field(`${JSON.stringify(iface.name)}.http`, iface.access?.http ?? true);
  const [https, setHTTPS] = draft.field(`${JSON.stringify(iface.name)}.https`, iface.access?.https ?? true);
  const [ssh, setSSH] = draft.field(`${JSON.stringify(iface.name)}.ssh`, iface.access?.ssh ?? true);

  const detectedCIDR = firstIPv4CIDR(runtime?.addrs);
  const suggestedGateway = suggestGatewayFromCIDR(detectedCIDR);
  const display = interfaceAddresses(iface, osState);
  const modeLabel = iface.addressMode || (iface.addresses?.length ? "static" : "external");

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

  const zoneDisplay = iface.zone ? zoneName(zones, iface.zone) : "—";

  return (
    <>
      <tr className="border-t table-row-hover transition-ui">
        <td className="px-4 py-3">{iface.name}</td>
        <td className="px-4 py-3">
          {editing ? (
            <input
              value={alias}
              onChange={(e) => setAlias(e.target.value)}
              disabled={!canEdit}
              placeholder="alias (optional)"
              className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden placeholder:text-(--text-dim)"
            />
          ) : (
            <span className="text-(--text)">{iface.alias || "—"}</span>
          )}
        </td>
        <td className="px-4 py-3">
          {editing ? (
            <input
              value={device}
              onChange={(e) => setDevice(e.target.value)}
              disabled={!canEdit}
              placeholder="Network device (e.g. eth0)"
              className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden placeholder:text-(--text-dim)"
            />
          ) : (
            <span className="text-(--text)">{iface.device || "—"}</span>
          )}
        </td>
        <td className="px-4 py-3">
          {runtime ? (
            <span className={chipClass(runtime.up)}>{runtime.up ? "up" : "down"}</span>
          ) : (
            <span className="text-(--text-muted)">—</span>
          )}
        </td>
        <td className="px-4 py-3">
          {editing ? (
            <select
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              disabled={!canEdit}
              className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
            >
              <option value="">(no zone)</option>
              {zones.map((z) => (
                <option key={z.name} value={z.name}>
                  {zoneLabel(z)}
                </option>
              ))}
            </select>
          ) : (
            <span className="text-(--text)">{zoneDisplay}</span>
          )}
        </td>
        <td className="px-4 py-3">
          {editing ? (
            <div className="space-y-2">
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                disabled={!canEdit}
                className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
              >
                <option value="">{addresses.trim() ? "static (implicit)" : "external"}</option>
                <option value="static">static</option>
                <option value="dhcp">dhcp</option>
              </select>
              <input
                value={addresses}
                onChange={(e) => setAddresses(e.target.value)}
                disabled={!canEdit || mode === "dhcp"}
                placeholder={display.source === "os" ? display.addrs.join(", ") : "CIDRs (comma-separated)"}
                className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden placeholder:text-(--text-dim)"
              />
              <input
                value={gateway}
                onChange={(e) => setGateway(e.target.value)}
                disabled={!canEdit || mode === "dhcp"}
                placeholder="gateway (optional)"
                className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden placeholder:text-(--text-dim)"
              />
              {canEdit && mode !== "dhcp" && detectedCIDR && (
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-(--text)">
                  <button
                    type="button"
                    onClick={() => {
                      setMode("static");
                      setAddresses(detectedCIDR);
                      if (suggestedGateway) setGateway(suggestedGateway);
                    }}
                    className="rounded-md px-2 py-1 text-(--amber) transition-ui"
                    title="Use the currently detected address as this interface's static address (and infer gateway)."
                  >
                    Use detected
                  </button>
                  <span className="text-(--text-muted)">
                    Applies <span className="text-(--text)">{detectedCIDR}</span>
                    {suggestedGateway ? (
                      <>
                        {" "}
                        and gateway <span className="text-(--text)">{suggestedGateway}</span>
                      </>
                    ) : null}
                  </span>
                </div>
              )}
              <div className="text-[11px] text-(--text-muted)">
                {mode === "dhcp" ? (
                  <span>
                    DHCP uses OS/Docker-assigned addresses (in containers,
                    assigned at startup).
                  </span>
                ) : detectedCIDR ? (
                  <span>
                    Detected subnet:{" "}
                    <span className="text-(--text)">{detectedCIDR}</span>
                    {suggestedGateway ? (
                      <>
                        {" "}
                        (gateway often{" "}
                        <span className="text-(--text)">
                          {suggestedGateway}
                        </span>
                        )
                      </>
                    ) : null}
                  </span>
                ) : (
                  <span>No IPv4 address detected on the connected network device yet.</span>
                )}
              </div>
            </div>
          ) : (
            <span
              className="inline-flex items-center gap-1 text-(--text)"
              title={(display.source === "config" ? iface.addresses : runtime?.addrs)?.join(", ")}
            >
              {display.source === "os" && (
                <span title={OS_ADDRESS_HINT}>
                  <Image src={staticAssetURL("/icons/docker.svg")} alt="Detected address" width={16} height={16} />
                </span>
              )}
              {display.source === "dhcp"
                ? `dhcp${display.addrs.length ? ` (${display.addrs.join(", ")})` : ""}`
                : display.addrs.join(", ") || "—"}
            </span>
          )}
        </td>
        <td className="px-4 py-3 text-right">
          <div className="flex flex-wrap justify-end gap-2">
            <button ref={inspectButton} type="button" aria-expanded={expanded} aria-controls={detailId}
              onClick={() => setInspecting(!expanded)} disabled={editing}
              className="rounded-xs border px-2 py-1 text-xs text-(--text)">
              Inspect
            </button>

            {editing ? (
              <div className="inline-flex gap-2">
                <button
                  onClick={async () => {
                    await onUpdate(iface.name, {
                      type: itype,
                      alias: alias.trim(),
                      members:
                        itype === "bridge"
                          ? members
                            .split(",")
                            .map((s) => s.trim())
                            .filter(Boolean)
                          : [],
                      parent: itype === "vlan" ? parent.trim() : "",
                      vlanId:
                        itype === "vlan" && vlanId.trim()
                          ? Number.parseInt(vlanId, 10)
                          : 0,
                      device: device.trim(),
                      zone,
                      addressMode: mode === (iface.addressMode ?? "") ? iface.addressMode : mode,
                      addresses:
                        mode === (iface.addressMode ?? "") && addresses === (iface.addresses ?? []).join(", ")
                          ? iface.addresses
                          : mode === "dhcp"
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
                    returnFocus.current = true;
                    setEditing(false);
                  }}
                  className="rounded-xs bg-(--amber) px-2 py-1 text-xs font-medium text-white transition-ui hover:brightness-110"
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
                    setMode(iface.addressMode ?? "");
                    setAddresses((iface.addresses ?? []).join(", "));
                    setGateway(iface.gateway ?? "");
                    setMgmt(iface.access?.mgmt ?? true);
                    setSSH(iface.access?.ssh ?? true);
                    setHTTP(iface.access?.http ?? true);
                    setHTTPS(iface.access?.https ?? true);
                    returnFocus.current = true;
                    setEditing(false);
                  }}
                  className="rounded-xs border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <div className="inline-flex gap-2">
                {canEdit && (
                  <>
                    <button
                      onClick={() => { setEditing(true); setInspecting(true); }}
                      className="rounded-xs border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui"
                    >
                      Edit
                    </button>
                    <button
                      onClick={async () => onDelete(iface.name)}
                      className="rounded-xs px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                    >
                      Delete
                    </button>
                  </>
                )}
              </div>
            )}

          </div>
          <p className="mt-1 text-xs text-(--text-muted)">
            {modeLabel} · {typeLabel()}{!runtime ? " · Live unknown" : !runtime.up ? " · Link down" : ""}
            {Object.values(iface.access ?? {}).some(value => value === false) ? " · Access customized" : ""}
            {iface.gateway ? " · Gateway set" : ""}
          </p>
        </td>
      </tr>
      <tr hidden={!expanded} id={detailId}>
        <td colSpan={7} className="border-t px-4 py-3">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div><div className="mb-2 text-xs font-semibold text-(--text-muted)">Type</div>
              {editing ? (
                <div className="space-y-2">
                  <select
                    value={itype}
                    onChange={(e) => setIType(e.target.value)}
                    disabled={!canEdit}
                    className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
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
                        className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden placeholder:text-(--text-dim)"
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
                        className="w-full rounded-md border bg-(--surface) px-2 py-1 text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
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
                        className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
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
                        className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden placeholder:text-(--text-dim)"
                      />
                    </div>
                  ) : null}
                </div>
              ) : (
                <span className="text-(--text)">{typeLabel()}</span>
              )}
            </div>
            <div><div className="mb-2 text-xs font-semibold text-(--text-muted)">Mode</div>{modeLabel}</div>
            <div><div className="mb-2 text-xs font-semibold text-(--text-muted)">Access</div>
              {editing ? (
                <div className="grid grid-cols-2 gap-2 text-xs text-(--text)">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={mgmt}
                      disabled={!canEdit}
                      onChange={(e) => setMgmt(e.target.checked)}
                    />
                    Management access
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
                  <span className={chipClass(iface.access?.mgmt ?? true)}>Management access</span>
                  <span className={chipClass(iface.access?.ssh ?? true)}>ssh</span>
                  <span className={chipClass(iface.access?.http ?? true)}>http</span>
                  <span className={chipClass(iface.access?.https ?? true)}>https</span>
                </div>
              )}
            </div>
            <div className="space-y-1 break-all text-xs text-(--text)">
              <div className="font-semibold text-(--text-muted)">Network</div>
              <p>Detected address: {runtime ? runtime.addrs?.join(", ") || "None reported" : "Unknown"}</p>
              <p>Interface address: {iface.addressMode === "dhcp" ? "dhcp" : iface.addresses?.join(", ") || "—"}</p>
              <p>Gateway: {iface.gateway || "—"}</p>
              <p>MAC: {runtime?.mac || "Unknown"}</p>
              <p>MTU: {runtime?.mtu || "Unknown"}</p>
              {runtime && !runtime.addrs?.length && <p>No OS/Docker IP detected yet (check device binding / link state).</p>}
            </div>
          </div>
        </td>
      </tr>
    </>
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
    : "rounded-md px-2 py-1 ";
}
