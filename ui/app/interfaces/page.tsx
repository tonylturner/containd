"use client";

import { useEffect, useMemo, useState } from "react";
import Image from "next/image";
import Link from "next/link";

import { api, isAdmin, type Interface, type InterfaceState, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { validateCIDRList, validateIP } from "../../lib/validate";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

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
  const [alias, setAlias] = useState("");
  const [zone, setZone] = useState("");
  const [ifaceType, setIfaceType] = useState<"physical" | "bridge" | "vlan">("physical");
  const [members, setMembers] = useState("");
  const [parent, setParent] = useState("");
  const [vlanId, setVlanId] = useState("10");
  const [addresses, setAddresses] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const [reconciling, setReconciling] = useState(false);

  const confirm = useConfirm();

  const zoneLabel = (z: Zone): string => (z.alias ? `${z.alias} (${z.name})` : z.name);
  const tips: Tip[] = [
    {
      id: "interfaces:zones",
      title: "Create zones first",
      body: (
        <>
          Add zones in{" "}
          <Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
            Zones
          </Link>{" "}
          so you can assign them to interfaces.
        </>
      ),
      when: () => zones.length === 0,
    },
    {
      id: "interfaces:binding",
      title: "Bind interfaces to OS devices",
      body: "Use Auto-assign or pick a Device so the engine can apply addresses and rules.",
      when: () => unboundConfigured.missingRuntime.length > 0 && unboundConfigured.unassignedOS.length > 0,
    },
    {
      id: "interfaces:ips",
      title: "Add IP addresses",
      body: "Set static addresses or DHCP per interface to make routing work.",
      when: () => ifaces.length > 0,
    },
  ];

  async function refresh() {
    const [i, z, s] = await Promise.all([
      api.listInterfaces(),
      api.listZones(),
      api.listInterfaceState(),
    ]);
    setIfaces(i ?? []);
    setZones(z ?? []);
    setState(s ?? []);
    if (s === null) {
      setError(
        "Unable to load interface runtime state from the engine (engine unreachable). Check CONTAIND_ENGINE_URL/NGFW_ENGINE_URL and restart.",
      );
    }
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
    if (!res.ok) {
      setError(res.error || "Failed to auto-assign interfaces.");
      return;
    }
    await refresh();
    setNotice(res.warning ? `Auto-assign completed with warning: ${res.warning}` : "Interfaces auto-assigned.");
  }

  async function onReconcileReplace() {
    setError(null);
    confirm.open({
      title: "Reconcile interfaces",
      message:
        "Reconcile will REPLACE OS interface addresses for interfaces with configured static addresses. Continue?",
      confirmLabel: "Reconcile",
      variant: "warning",
      onConfirm: async () => {
        setReconciling(true);
        const res = await api.reconcileInterfacesReplace();
        setReconciling(false);
        if (!res.ok) {
          setError(res.error || "Failed to reconcile interfaces.");
          return;
        }
        await refresh();
        setNotice(res.warning ? `Reconcile completed with warning: ${res.warning}` : "Interfaces reconciled.");
      },
    });
  }

  async function onCreate() {
    setError(null);
    setNotice(null);
    if (!name.trim()) {
      setError("Interface name is required.");
      return;
    }
    if (addresses.trim()) {
      const addrErr = validateCIDRList(addresses);
      if (addrErr) { setError(addrErr); return; }
    }
    setSaving(true);
    const base: Interface = {
      name: name.trim(),
      alias: alias.trim() || undefined,
      zone: zone || undefined,
    };
    const addrs = addresses
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const payload: Interface =
      ifaceType === "bridge"
        ? {
            ...base,
            type: "bridge",
            members: members
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
            addresses: addrs,
          }
        : ifaceType === "vlan"
          ? {
              ...base,
              type: "vlan",
              parent: parent.trim() || undefined,
              vlanId: Number.parseInt(vlanId, 10) || undefined,
              addresses: addrs,
            }
          : {
              ...base,
              type: "physical",
              addresses: addrs,
            };
    const created = await api.createInterface(payload);
    setSaving(false);
    if (!created.ok) {
      setError(created.error || "Failed to create interface.");
      return;
    }
    setName("");
    setAlias("");
    setZone("");
    setIfaceType("physical");
    setMembers("");
    setParent("");
    setVlanId("10");
    setAddresses("");
    await refresh();
    setNotice(created.warning ? `Interface created with warning: ${created.warning}` : "Interface created.");
  }

  async function onDelete(ifaceName: string) {
    setError(null);
    setNotice(null);
    const result = await api.deleteInterface(ifaceName);
    if (!result.ok) {
      setError(result.error || "Failed to delete interface.");
      return;
    }
    await refresh();
    setNotice(result.warning ? `Interface deleted with warning: ${result.warning}` : "Interface deleted.");
  }

  async function onUpdate(ifaceName: string, patch: Partial<Interface>) {
    setError(null);
    setNotice(null);
    if (patch.addresses?.length) {
      const addrErr = validateCIDRList(patch.addresses.join(", "));
      if (addrErr) { setError(addrErr); return; }
    }
    if (patch.gateway) {
      const gwErr = validateIP(patch.gateway);
      if (gwErr) { setError(gwErr); return; }
    }
    const updated = await api.updateInterface(ifaceName, patch);
    if (!updated.ok) {
      setError(updated.error || "Failed to update interface.");
      return;
    }
    // Optimistic config update so the row reflects immediately even if runtime state is slightly delayed.
    setIfaces((prev) => prev.map((i) => (i.name === ifaceName ? { ...i, ...updated.data } : i)));
    await refresh();
    setNotice(updated.warning ? `Saved with warning: ${updated.warning}` : "Saved.");
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
                className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                title="Auto-assign default logical interfaces (wan/dmz/lan1-6) to detected OS interfaces"
              >
                {assigning ? "Assigning..." : "Auto-assign"}
              </button>
              <button
                onClick={onReconcileReplace}
                disabled={reconciling}
                className="rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-sm text-amber-400 transition-ui hover:bg-amber-500/15 disabled:opacity-50"
                title="Reconcile interface addresses (replace semantics for configured static addresses)"
              >
                {reconciling ? "Reconciling..." : "Reconcile"}
              </button>
            </>
          )}
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {!isAdmin() && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      {notice && (
        <div className="mb-4 rounded-sm border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {notice}
        </div>
      )}
      {state.length === 0 && (
        <div className="mb-4 rounded-sm border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-400">
          <div className="font-semibold">Interface runtime state unavailable</div>
          <div className="mt-1 text-amber-400/90">
            The UI cannot see OS/Docker-assigned addresses right now (the engine interface-state feed is empty). In the
            current compose setup this usually means the management plane cannot reach the engine. Check{" "}
            <span className="font-semibold">CONTAIND_ENGINE_URL</span> in <span className="font-semibold">.env</span>{" "}
            (should be <span className="font-mono">http://127.0.0.1:8081</span> in shared-network-namespace mode) and then
            restart.
          </div>
        </div>
      )}
      {isAdmin() && unboundConfigured.missingRuntime.length > 0 && unboundConfigured.unassignedOS.length > 0 && (
        <div className="mb-4 rounded-sm border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-400">
          <div className="font-semibold">Interface bindings needed</div>
          <div className="mt-1 text-amber-400/90">
            Some configured interfaces are not bound to OS devices. Use <span className="font-semibold">Auto-assign</span>{" "}
            or set the <span className="font-semibold">Device</span> field per interface.
          </div>
        </div>
      )}
      <Card padding="lg">
        <h2 className="text-sm font-semibold text-[var(--text)]">Create interface</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-6">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name (e.g. tunnel1)"
            disabled={!isAdmin()}
            className="input-industrial"
          />
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="alias (optional)"
            disabled={!isAdmin()}
            className="input-industrial"
          />
          <select
            value={ifaceType}
            onChange={(e) =>
              setIfaceType(
                (e.target.value as "physical" | "bridge" | "vlan") || "physical",
              )
            }
            disabled={!isAdmin()}
            className="input-industrial"
            title="Interface type"
          >
            <option value="physical">physical</option>
            <option value="bridge">bridge</option>
            <option value="vlan">vlan</option>
          </select>
          <select
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            disabled={!isAdmin()}
            className="input-industrial"
          >
            <option value="">(no zone)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {zoneLabel(z)}
              </option>
            ))}
          </select>
          {zones.length === 0 && (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:col-span-2">
              No zones yet.{" "}
              <Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
                Create a zone
              </Link>{" "}
              to assign it here.
            </div>
          )}
          {ifaceType === "bridge" ? (
            <input
              value={members}
              onChange={(e) => setMembers(e.target.value)}
              placeholder="members (comma-separated)"
              disabled={!isAdmin()}
              className="input-industrial md:col-span-2"
            />
          ) : ifaceType === "vlan" ? (
            <>
              <input
                value={parent}
                onChange={(e) => setParent(e.target.value)}
                placeholder="parent (e.g. wan or eth0)"
                disabled={!isAdmin()}
                className="input-industrial"
              />
              <input
                value={vlanId}
                onChange={(e) => setVlanId(e.target.value)}
                placeholder="vlan id (1-4094)"
                disabled={!isAdmin()}
                className="input-industrial"
              />
            </>
          ) : null}
          <input
            value={addresses}
            onChange={(e) => setAddresses(e.target.value)}
            placeholder="addresses (CIDR, comma-separated)"
            disabled={!isAdmin()}
            className="input-industrial md:col-span-2"
          />
        </div>
        <div className="mt-2 text-xs text-[var(--text-muted)]">
          {ifaceType === "bridge" ? (
            <span>
              Bridge members should be L2-only; assign IPs to the bridge interface (not the member interfaces).
            </span>
          ) : ifaceType === "vlan" ? (
            <span>
              VLAN creates a subinterface in the engine netns. Use <span className="font-semibold">parent</span> as a
              logical interface name (e.g. <span className="font-mono">wan</span>) or an OS device name (e.g.{" "}
              <span className="font-mono">eth0</span>).
            </span>
          ) : (
            <span />
          )}
        </div>
        <div className="mt-3 flex items-center justify-between">
          {error && <p className="rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>}
          {isAdmin() && (
            <button
              onClick={onCreate}
              disabled={saving}
              className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
            >
              {saving ? "Creating..." : "Create"}
            </button>
          )}
        </div>
      </Card>

      <div className="mt-6 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Alias</th>
              <th className="px-4 py-3">Type</th>
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
                <td colSpan={10} className="px-4 py-6">
                  <EmptyState
                    title="No interfaces configured"
                    description="Create an interface above to bind a network port to a zone."
                  />
                </td>
              </tr>
            )}
            {ifaces.map((i) => (
              <InterfaceRow
                key={i.name}
                iface={i}
                runtime={runtimeFor(i, state)}
                zones={zones}
                allIfaces={ifaces}
                osState={state}
                onDelete={onDelete}
                onUpdate={onUpdate}
                canEdit={isAdmin()}
              />
            ))}
          </tbody>
        </table>
      </div>

      {state.length > 0 && (
        <Card padding="lg" className="mt-6">
          <h2 className="text-sm font-semibold text-[var(--text)]">Detected OS interfaces</h2>
          <div className="mt-1 text-xs text-[var(--text-muted)]">
            This is what the kernel currently exposes (used for device binding and link/address state).
          </div>
          <div className="mt-3 overflow-hidden rounded-sm border border-amber-500/[0.15]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                    <tr key={s.name} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                      <td className="px-4 py-3 font-medium text-[var(--text)]">{s.name}</td>
                      <td className="px-4 py-3">
                        <span className={chipClass(s.up)}>{s.up ? "up" : "down"}</span>
                      </td>
                      <td className="px-4 py-3 text-[var(--text)]">{s.mac || "—"}</td>
                      <td className="px-4 py-3 text-[var(--text)]">{s.mtu || "—"}</td>
                      <td className="px-4 py-3 text-[var(--text)]">{(s.addrs ?? []).join(", ") || "—"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Card>
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
  const [mode, setMode] = useState((iface.addressMode ?? "static").toLowerCase());
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

  const zoneLabel = (z: Zone): string => (z.alias ? `${z.alias} (${z.name})` : z.name);
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
                <span>DHCP uses OS/Docker-assigned addresses (in containers, assigned at startup).</span>
              ) : detectedCIDR ? (
                <span>
                  Detected subnet: <span className="text-[var(--text)]">{detectedCIDR}</span>
                  {suggestedGateway ? (
                    <>
                      {" "}
                      (gateway often <span className="text-[var(--text)]">{suggestedGateway}</span>)
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
                  dhcp <span className="text-[var(--text-muted)]">({runtime.addrs.join(", ")})</span>
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
              <Image src="/icons/docker.svg" alt="Docker" width={16} height={16} className="h-4 w-4" />
              <span className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 w-72 -translate-x-1/2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] opacity-0 shadow-lg backdrop-blur-sm group-hover:opacity-100">
                <div className="font-semibold text-[var(--text)]">Network</div>
                <div className="mt-1 text-[var(--text)]">
                  <span className="text-[var(--text-muted)]">OS/Docker address:</span> {network}
                </div>
                <div className="text-[var(--text)]">
                  <span className="text-[var(--text-muted)]">Interface address:</span> {configured}
                </div>
                {!hasNetwork ? (
                  <div className="mt-1 text-[var(--text-muted)]">
                    No OS/Docker IP detected yet (check device binding / link state).
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
                setVlanId(typeof iface.vlanId === "number" ? String(iface.vlanId) : "");
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

function chipClass(ok: boolean) {
  return ok
    ? "rounded-md bg-emerald-500/15 px-2 py-1 text-emerald-400"
    : "rounded-md bg-amber-500/15 px-2 py-1 text-amber-400";
}
