"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type Interface, type InterfaceState, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";

function DockerIcon({
  className,
}: {
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      aria-hidden
      className={className ?? "h-4 w-4"}
      fill="currentColor"
    >
      <path d="M22 11.5c-.3-1.4-1.4-2.4-2.8-2.4h-2V7c0-.6-.4-1-1-1h-2V4c0-.6-.4-1-1-1H9c-.6 0-1 .4-1 1v2H6c-.6 0-1 .4-1 1v2H3c-.6 0-1 .4-1 1 0 6 4.9 11 11 11 4.6 0 8.6-2.8 10.2-6.9.2-.5 0-1-.5-1.1-.4-.2-.9-.3-1.7-.3h-2.2zM9 5h3v2H9V5zm-2 3h3v2H7V8zm5 0h3v2h-3V8zM5 9h1v1H5V9zm0 2h3v2H5v-2zm5 0h3v2H10v-2zm5 0h3v2h-3v-2zm0 3h2.1c.5 0 1 .1 1.4.1C17 18 13.7 20 10 20 6 20 2.7 16.9 2.1 13H15v1z" />
    </svg>
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
  if (![a, b, c].every((n) => Number.isFinite(n) && n >= 0 && n <= 255)) return null;
  // Docker bridge networks commonly use .1 as the gateway for the subnet.
  return `${a}.${b}.${c}.1`;
}

export default function InterfacesPage() {
  const [ifaces, setIfaces] = useState<Interface[]>([]);
  const [state, setState] = useState<InterfaceState[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [name, setName] = useState("");
  const [zone, setZone] = useState("");
  const [addresses, setAddresses] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const [reconciling, setReconciling] = useState(false);

  async function refresh() {
    const [i, z, s] = await Promise.all([
      api.listInterfaces(),
      api.listZones(),
      api.listInterfaceState(),
    ]);
    setIfaces(i ?? []);
    setZones(z ?? []);
    setState(s ?? []);
  }

  const unboundConfigured = useMemo(() => {
    const byDev = new Set(
      ifaces
        .map((i) => (i.device || "").trim())
        .filter(Boolean),
    );
    const missingRuntime = ifaces.filter((i) => !runtimeFor(i, state));
    const osIfaces = state
      .map((s) => s.name)
      .filter((n) => n !== "lo")
      .sort();
    const unassignedOS = osIfaces.filter((n) => !byDev.has(n));
    return {
      missingRuntime,
      unassignedOS,
    };
  }, [ifaces, state]);

  useEffect(() => {
    refresh();
  }, []);

  async function onAutoAssign() {
    setError(null);
    setAssigning(true);
    const res = await api.assignInterfaces("auto");
    setAssigning(false);
    if (!res) {
      setError("Failed to auto-assign interfaces.");
      return;
    }
    await refresh();
  }

  async function onReconcileReplace() {
    setError(null);
    if (
      typeof window !== "undefined" &&
      !window.confirm(
        "Reconcile will REPLACE OS interface addresses for interfaces with configured static addresses. Continue?",
      )
    ) {
      return;
    }
    setReconciling(true);
    const res = await api.reconcileInterfacesReplace();
    setReconciling(false);
    if (!res) {
      setError("Failed to reconcile interfaces.");
      return;
    }
    await refresh();
  }

  async function onCreate() {
    setError(null);
    if (!name.trim()) {
      setError("Interface name is required.");
      return;
    }
    setSaving(true);
    const payload: Interface = {
      name: name.trim(),
      zone: zone || undefined,
      addresses: addresses
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    };
    const created = await api.createInterface(payload);
    setSaving(false);
    if (!created) {
      setError("Failed to create interface.");
      return;
    }
    setName("");
    setZone("");
    setAddresses("");
    refresh();
  }

  async function onDelete(ifaceName: string) {
    setError(null);
    const ok = await api.deleteInterface(ifaceName);
    if (!ok) {
      setError("Failed to delete interface.");
      return;
    }
    refresh();
  }

  async function onUpdate(ifaceName: string, patch: Partial<Interface>) {
    setError(null);
    const updated = await api.updateInterface(ifaceName, patch);
    if (!updated) {
      setError("Failed to update interface.");
      return;
    }
    refresh();
  }

  return (
    <Shell
      title="Interfaces"
      actions={
        <div className="flex items-center gap-2">
          {isAdmin() && (
            <>
              <button
                onClick={onAutoAssign}
                disabled={assigning}
                className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30 disabled:opacity-50"
                title="Auto-assign default logical interfaces (wan/dmz/lan1-6) to detected OS interfaces"
              >
                {assigning ? "Assigning..." : "Auto-assign"}
              </button>
              <button
                onClick={onReconcileReplace}
                disabled={reconciling}
                className="rounded-lg border border-amber/30 bg-amber/10 px-3 py-1.5 text-sm text-amber hover:bg-amber/15 disabled:opacity-50"
                title="Reconcile interface addresses (replace semantics for configured static addresses)"
              >
                {reconciling ? "Reconciling..." : "Reconcile"}
              </button>
            </>
          )}
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {isAdmin() && unboundConfigured.missingRuntime.length > 0 && unboundConfigured.unassignedOS.length > 0 && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          <div className="font-semibold">Interface bindings needed</div>
          <div className="mt-1 text-amber/90">
            Some configured interfaces are not bound to OS devices. Use <span className="font-semibold">Auto-assign</span>{" "}
            or set the <span className="font-semibold">Device</span> field per interface.
          </div>
        </div>
      )}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="text-sm font-semibold text-white">Create interface</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name (e.g. tunnel1)"
            disabled={!isAdmin()}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
          />
          <select
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            disabled={!isAdmin()}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="">(no zone)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {z.name}
              </option>
            ))}
          </select>
          <input
            value={addresses}
            onChange={(e) => setAddresses(e.target.value)}
            placeholder="addresses (CIDR, comma-separated)"
            disabled={!isAdmin()}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
          />
        </div>
        <div className="mt-3 flex items-center justify-between">
          {error && <p className="text-sm text-amber">{error}</p>}
          {isAdmin() && (
            <button
              onClick={onCreate}
              disabled={saving}
              className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
            >
              {saving ? "Creating..." : "Create"}
            </button>
          )}
        </div>
      </div>

      <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Device</th>
              <th className="px-4 py-3">Link</th>
              <th className="px-4 py-3">Zone</th>
              <th className="px-4 py-3">Addresses</th>
              <th className="px-4 py-3">Network</th>
              <th className="px-4 py-3">Access</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {ifaces.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={8}>
                  No interfaces configured.
                </td>
              </tr>
            )}
            {ifaces.map((i) => (
              <InterfaceRow
                key={i.name}
                iface={i}
                runtime={runtimeFor(i, state)}
                zones={zones}
                onDelete={onDelete}
                onUpdate={onUpdate}
                canEdit={isAdmin()}
              />
            ))}
          </tbody>
        </table>
      </div>

      {state.length > 0 && (
        <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-sm font-semibold text-white">Detected OS interfaces</h2>
          <div className="mt-1 text-xs text-slate-400">
            This is what the kernel currently exposes (used for device binding and link/address state).
          </div>
          <div className="mt-3 overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Link</th>
                  <th className="px-4 py-3">MAC</th>
                  <th className="px-4 py-3">MTU</th>
                  <th className="px-4 py-3">Addrs</th>
                </tr>
              </thead>
              <tbody>
                {state
                  .slice()
                  .sort((a, b) => a.index - b.index)
                  .filter((s) => s.name !== "lo")
                  .map((s) => (
                    <tr key={s.name} className="border-t border-white/5">
                      <td className="px-4 py-3 font-medium text-white">{s.name}</td>
                      <td className="px-4 py-3">
                        <span className={chipClass(s.up)}>{s.up ? "up" : "down"}</span>
                      </td>
                      <td className="px-4 py-3 text-slate-200">{s.mac || "—"}</td>
                      <td className="px-4 py-3 text-slate-200">{s.mtu || "—"}</td>
                      <td className="px-4 py-3 text-slate-200">{(s.addrs ?? []).join(", ") || "—"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Shell>
  );
}

function runtimeFor(iface: Interface, state: InterfaceState[]): InterfaceState | null {
  const effectiveDev = iface.device || iface.name;
  return state.find((s) => s.name === effectiveDev) ?? null;
}

function InterfaceRow({
  iface,
  runtime,
  zones,
  onDelete,
  onUpdate,
  canEdit,
}: {
  iface: Interface;
  runtime: InterfaceState | null;
  zones: Zone[];
  onDelete: (name: string) => void;
  onUpdate: (name: string, patch: Partial<Interface>) => void;
  canEdit: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [device, setDevice] = useState(iface.device ?? "");
  const [zone, setZone] = useState(iface.zone ?? "");
  const [mode, setMode] = useState((iface.addressMode ?? "static").toLowerCase());
  const [addresses, setAddresses] = useState((iface.addresses ?? []).join(", "));
  const [gateway, setGateway] = useState(iface.gateway ?? "");
  const [mgmt, setMgmt] = useState(iface.access?.mgmt ?? true);
  const [http, setHTTP] = useState(iface.access?.http ?? true);
  const [https, setHTTPS] = useState(iface.access?.https ?? true);
  const [ssh, setSSH] = useState(iface.access?.ssh ?? true);

  const detectedCIDR = firstIPv4CIDR(runtime?.addrs);
  const suggestedGateway = suggestGatewayFromCIDR(detectedCIDR);

  return (
    <tr className="border-t border-white/5">
      <td className="px-4 py-3 font-medium text-white">{iface.name}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={device}
            onChange={(e) => setDevice(e.target.value)}
            disabled={!canEdit}
            placeholder="os iface (e.g. eth0)"
            className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white placeholder:text-slate-500"
          />
        ) : (
          <span className="text-slate-200">{iface.device || "—"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {runtime ? (
          <span className={chipClass(runtime.up)}>{runtime.up ? "up" : "down"}</span>
        ) : (
          <span className="text-slate-400">—</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <select
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
          >
            <option value="">(no zone)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {z.name}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-slate-200">{iface.zone || "—"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <div className="space-y-2">
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              disabled={!canEdit}
              className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
            >
              <option value="static">static</option>
              <option value="dhcp">dhcp</option>
            </select>
            <input
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              disabled={!canEdit || mode === "dhcp"}
              placeholder="CIDRs (comma-separated)"
              className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white placeholder:text-slate-500"
            />
            <input
              value={gateway}
              onChange={(e) => setGateway(e.target.value)}
              disabled={!canEdit || mode === "dhcp"}
              placeholder="gateway (optional)"
              className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white placeholder:text-slate-500"
            />
            {canEdit && mode !== "dhcp" && detectedCIDR && (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-300">
                <button
                  type="button"
                  onClick={() => {
                    setMode("static");
                    setAddresses(detectedCIDR);
                    if (suggestedGateway) setGateway(suggestedGateway);
                  }}
                  className="rounded-md bg-mint/15 px-2 py-1 text-mint hover:bg-mint/20"
                  title="Use the currently detected OS address as this interface's static address (and infer gateway)."
                >
                  Use detected
                </button>
                <span className="text-slate-400">
                  Applies <span className="text-slate-200">{detectedCIDR}</span>
                  {suggestedGateway ? (
                    <>
                      {" "}
                      and gateway <span className="text-slate-200">{suggestedGateway}</span>
                    </>
                  ) : null}
                </span>
              </div>
            )}
            <div className="text-[11px] text-slate-400">
              {mode === "dhcp" ? (
                <span>DHCP uses OS/Docker-assigned addresses (in containers, assigned at startup).</span>
              ) : detectedCIDR ? (
                <span>
                  Detected subnet: <span className="text-slate-200">{detectedCIDR}</span>
                  {suggestedGateway ? (
                    <>
                      {" "}
                      (gateway often <span className="text-slate-200">{suggestedGateway}</span>)
                    </>
                  ) : null}
                </span>
              ) : (
                <span>No IPv4 address detected on the bound OS device yet.</span>
              )}
            </div>
          </div>
        ) : (
          <span className="text-slate-200">
            {(iface.addressMode ?? "static").toLowerCase() === "dhcp" ? (
              runtime && runtime.addrs?.length ? (
                <span title="OS/Docker-assigned addresses">
                  dhcp <span className="text-slate-400">({runtime.addrs.join(", ")})</span>
                </span>
              ) : (
                <span title="DHCP enabled (no OS/Docker address detected yet)">dhcp</span>
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
          if (!hasNetwork) return <span className="text-slate-400">—</span>;
          return (
            <span className="relative inline-flex items-center justify-center rounded-md border border-white/10 bg-white/5 p-1 text-slate-200 group">
              <DockerIcon className="h-4 w-4 text-[#2496ED]" />
              <span className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 w-72 -translate-x-1/2 rounded-lg border border-white/10 bg-black/90 px-3 py-2 text-xs text-slate-200 opacity-0 shadow-lg backdrop-blur-sm group-hover:opacity-100">
                <div className="font-semibold text-white">Network</div>
                <div className="mt-1 text-slate-200">
                  <span className="text-slate-400">OS/Docker address:</span> {network}
                </div>
                <div className="text-slate-200">
                  <span className="text-slate-400">Interface address:</span> {configured}
                </div>
                <span className="absolute left-1/2 top-full -translate-x-1/2 border-8 border-transparent border-t-black/90" />
              </span>
            </span>
          );
        })()}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <div className="grid grid-cols-2 gap-2 text-xs text-slate-200">
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
              onClick={() => {
                onUpdate(iface.name, {
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
              className="rounded-md bg-white/10 px-2 py-1 text-xs hover:bg-white/20"
            >
              Save
            </button>
            <button
              onClick={() => {
                setDevice(iface.device ?? "");
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
              className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
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
                  className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
                >
                  Edit
                </button>
                <button
                  onClick={() => onDelete(iface.name)}
                  className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30"
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

function chipClass(ok: boolean) {
  return ok
    ? "rounded-md bg-mint/15 px-2 py-1 text-mint"
    : "rounded-md bg-amber/15 px-2 py-1 text-amber";
}
