"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type Interface, type InterfaceState, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { validateCIDRList, validateIP } from "../../lib/validate";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { chipClass, InterfaceRow, runtimeFor } from "./interface-row";

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
