"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { reconcileRows, upsertRow } from "../../lib/config-editor";

import { useConfigForm } from "../../lib/use-config-form";
import { ConfigEditNotice, useConfigEditor } from "../../lib/use-config-editor";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type Interface, type InterfaceState, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { validateCIDRList, validateIP } from "../../lib/validate";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { chipClass, InterfaceRow } from "./interface-row";
import { BootFaultStatus } from "./boot-fault-notice";
import type { ManagementReservation } from "../../lib/api-console";
import { runtimeFor } from "../../lib/interface-addresses";
import { zoneLabel } from "../../lib/zones";

export default function InterfacesPage() {
  const [reservation, setReservation] = useState<ManagementReservation | null>(null);
  const rowsDraft = useConfigEditor<Interface[]>([]);
  const { cfg: ifaces, adoptConfig: adoptRows } = rowsDraft;
  const [runtimeStatus, setRuntimeStatus] = useState<"loading" | "ready" | "unavailable">("loading");
  const [state, setState] = useState<InterfaceState[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const form = useConfigForm({
    name: "", alias: "", zone: "", ifaceType: "physical" as "physical" | "bridge" | "vlan",
    members: "", parent: "", vlanId: "10", addresses: "",
  });
  const { refreshForm } = form;
  const [name, setName] = form.field("name");
  const [alias, setAlias] = form.field("alias");
  const [zone, setZone] = form.field("zone");
  const [ifaceType, setIfaceType] = form.field("ifaceType");
  const [members, setMembers] = form.field("members");
  const [parent, setParent] = form.field("parent");
  const [vlanId, setVlanId] = form.field("vlanId");
  const [addresses, setAddresses] = form.field("addresses");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const [reconciling, setReconciling] = useState(false);

  const confirm = useConfirm();

  const tips: Tip[] = [
    {
      id: "interfaces:zones",
      title: "Create zones first",
      body: (
        <>
          Add zones in{" "}
          <Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">
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

  const { refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [i, z, s, r] = await Promise.all([
      api.listInterfaces(),
      api.listZones(),
      api.listInterfaceState(),
      api.getManagementReservation(),
    ]);
    refreshForm(i, keepEdits);
    setReservation(r);
    adoptRows(i ?? [], keepEdits);
    setZones(z ?? []);
    setState(s ?? []);
    setRuntimeStatus(s === null ? "unavailable" : "ready");
  }, [refreshForm, adoptRows]));

  const boundDevices = new Set(ifaces.map((iface) => (iface.device || "").trim()).filter(Boolean));
  const unboundConfigured = {
    missingRuntime: ifaces.filter((iface) => !runtimeFor(iface, state)),
    unassignedOS: state.map((iface) => iface.name).filter((name) => name !== "lo" && !boundDevices.has(name)).sort(),
  };

  useConfigRefresh(refresh);

  async function onAutoAssign() {
    setError(null);
    setAssigning(true);
    const before = rowsDraft.editor.server;
    const res = await api.assignInterfaces("auto");
    setAssigning(false);
    if (!res.ok) {
      setError(res.error || "Failed to auto-assign interfaces.");
      return;
    }
    rowsDraft.acceptCollection((rows) => reconcileRows(rows, before, res.data.interfaces, (row) => row.name));
    await refresh();
    setNotice(res.warning ? `Interface assignments staged — commit to apply. Warning: ${res.warning}` : "Interface assignments staged — commit to apply.");
  }

  async function onReconcileReplace() {
    setError(null);
    confirm.open({
      title: "Reconcile interfaces",
      message:
        "Live reconcile reapplies running config and will REPLACE OS interface addresses for interfaces with configured static addresses. Continue?",
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
    const submitted = form.editor;
    const created = await api.createInterface(payload);
    setSaving(false);
    if (!created.ok) {
      setError(created.error || "Failed to create interface.");
      return;
    }
    rowsDraft.acceptCollection((rows) => upsertRow(rows, created.data, (row) => row.name));
    await refresh();
    setNotice(created.warning ? `Interface staged — commit to apply. Warning: ${created.warning}` : "Interface staged — commit to apply.");
    form.acceptFields(submitted, ["name", "alias", "zone", "ifaceType", "members", "parent", "vlanId", "addresses"]);
  }

  async function onDelete(ifaceName: string) {
    setError(null);
    setNotice(null);
    const result = await api.deleteInterface(ifaceName);
    if (!result.ok) {
      setError(result.error || "Failed to delete interface.");
      return;
    }
    rowsDraft.acceptCollection((rows) => rows.filter((row) => row.name !== ifaceName), [`${JSON.stringify(ifaceName)}.`]);
    await refresh();
    setNotice(result.warning ? `Interface staged — commit to apply. Warning: ${result.warning}` : "Interface staged — commit to apply.");
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
    const submitted = rowsDraft.beginSave();
    const updated = await api.updateInterface(ifaceName, patch);
    if (!updated.ok) {
      rowsDraft.failSave(submitted);
      setError(updated.error || "Failed to update interface.");
      return;
    }
    // Reflect candidate state; the separate OS state remains live until commit.
    rowsDraft.acceptRow(submitted, (rows) => upsertRow(rows, updated.data, (row) => row.name), `${JSON.stringify(ifaceName)}.`);
    await refresh();
    setNotice(updated.warning ? `Interface staged — commit to apply. Warning: ${updated.warning}` : "Interface staged — commit to apply.");
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
                className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                title="Auto-assign default logical interfaces (wan/dmz/lan1-6) to detected OS interfaces"
              >
                {assigning ? "Assigning..." : "Auto-assign"}
              </button>
              <button
                onClick={onReconcileReplace}
                disabled={reconciling}
                className="rounded-xs border px-3 py-1.5 text-sm transition-ui disabled:opacity-50"
                title="Reconcile interface addresses (replace semantics for configured static addresses)"
              >
                {reconciling ? "Reconciling..." : "Reconcile live"}
              </button>
            </>
          )}
          <button
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {reservation?.active && (
        <aside aria-label="Reserved management path" className="mb-4 rounded-xs border border-(--border) bg-(--surface) px-4 py-3 text-sm text-(--text)">
          <p className="font-semibold">RangerDanger management access is reserved</p>
          <p className="mt-1 wrap-break-word">
            {reservation.sources?.join(", ")} can reach HTTP management on {reservation.device} ({reservation.local}, port {reservation.port}),
            even when all interface access is disabled. Login is still required. Keep this device physical and unaddressed in config.
          </p>
          {(!reservation.guard?.active || reservation.guard?.error) && (
            <p className="mt-1">Guard fault: {reservation.guard?.error || "engine guard unavailable"}</p>
          )}
          {!!reservation.guard?.faults && (
            <p className="mt-1">Guard repairs/faults: {reservation.guard.faults}. {reservation.guard.lastFault?.reason}</p>
          )}
          {reservation.bootFault && (
            <BootFaultStatus bootFault={reservation.bootFault} recovery={reservation.recovery} reserved className="mt-2" />
          )}
          {!!reservation.listenerFaults?.length && (
            <div role="status" className="mt-2">
              <p className="font-semibold">Optional listener boot faults</p>
              <p>Reserved HTTP management remains available. Correct the listener settings and restart to restore these listeners.</p>
              <ul className="list-disc pl-5">
                {reservation.listenerFaults.map((fault, index) => <li key={index}>{fault}</li>)}
              </ul>
            </div>
          )}
          {reservation.rollbackFault && <p className="mt-1">{reservation.rollbackFault}</p>}
        </aside>
      )}
      {reservation && !reservation.active && reservation.bootFault && (
        <aside aria-label="Boot fault" className="mb-4 text-sm">
          <BootFaultStatus bootFault={reservation.bootFault} recovery={reservation.recovery} reserved={false} />
        </aside>
      )}
      <ConfigEditNotice superseded={form.editor.superseded || rowsDraft.editor.superseded} />
      {!isAdmin() && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      {notice && (
        <div className="mb-4 rounded-xs border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {notice}
        </div>
      )}
      {runtimeStatus === "unavailable" && (
        <div role="status" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <p>Interface runtime state unavailable — the engine could not be reached. Link and address state is unknown.</p>
          <button onClick={() => refresh()} className="mt-2 rounded-xs border border-red-500/30 px-3 py-1">Retry</button>
        </div>
      )}
      {runtimeStatus === "ready" && state.length === 0 && <p role="status" className="mb-4 text-sm text-(--text)">No OS interfaces reported.</p>}
      {isAdmin() && unboundConfigured.missingRuntime.length > 0 && unboundConfigured.unassignedOS.length > 0 && (
        <div className="mb-4 rounded-xs border px-4 py-3 text-sm">
          <div className="font-semibold">Interface bindings needed</div>
          <div className="mt-1">
            Some configured interfaces are not bound to OS devices. Use <span className="font-semibold">Auto-assign</span>{" "}
            or set the <span className="font-semibold">Device</span> field per interface.
          </div>
        </div>
      )}
      <Card padding="lg">
        <h2 className="text-sm font-semibold text-(--text)">Create interface</h2>
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
            <div className="rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text) md:col-span-2">
              No zones yet.{" "}
              <Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">
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
        <div className="mt-2 text-xs text-(--text-muted)">
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
          {error && <p className="rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>}
          {isAdmin() && (
            <button
              onClick={onCreate}
              disabled={saving}
              className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
            >
              {saving ? "Creating..." : "Create"}
            </button>
          )}
        </div>
      </Card>

      <div className="mt-6 overflow-hidden rounded-xs border bg-(--surface) shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Alias</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Device</th>
              <th className="px-4 py-3">Link</th>
              <th className="px-4 py-3">Zone</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3">Addresses</th>
              <th className="px-4 py-3">Network</th>
              <th className="px-4 py-3">Access</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {ifaces.length === 0 && (
              <tr>
                <td colSpan={11} className="px-4 py-6">
                  <EmptyState
                    title="No interfaces configured"
                    description="Create an interface above to bind a network port to a zone."
                  />
                </td>
              </tr>
            )}
            {ifaces.map((i) => (
              <InterfaceRow
                draft={rowsDraft}
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
          <h2 className="text-sm font-semibold text-(--text)">Detected OS interfaces</h2>
          <div className="mt-1 text-xs text-(--text-muted)">
            This is what the kernel currently exposes (used for device binding and link/address state).
          </div>
          <div className="mt-3 overflow-hidden rounded-xs border">
            <table className="w-full text-sm">
              <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
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
                    <tr key={s.name} className="border-t table-row-hover transition-ui">
                      <td className="px-4 py-3 font-medium text-(--text)">{s.name}</td>
                      <td className="px-4 py-3">
                        <span className={chipClass(s.up)}>{s.up ? "up" : "down"}</span>
                      </td>
                      <td className="px-4 py-3 text-(--text)">{s.mac || "—"}</td>
                      <td className="px-4 py-3 text-(--text)">{s.mtu || "—"}</td>
                      <td className="px-4 py-3 text-(--text)">{(s.addrs ?? []).join(", ") || "—"}</td>
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
