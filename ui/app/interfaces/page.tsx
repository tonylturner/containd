"use client";

import { useEffect, useState } from "react";

import { api, isAdmin, type Interface, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function InterfacesPage() {
  const [ifaces, setIfaces] = useState<Interface[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [name, setName] = useState("");
  const [zone, setZone] = useState("");
  const [addresses, setAddresses] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function refresh() {
    const [i, z] = await Promise.all([api.listInterfaces(), api.listZones()]);
    setIfaces(i ?? []);
    setZones(z ?? []);
  }

  useEffect(() => {
    refresh();
  }, []);

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
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
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
              <th className="px-4 py-3">Zone</th>
              <th className="px-4 py-3">Addresses</th>
              <th className="px-4 py-3">Access</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {ifaces.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={6}>
                  No interfaces configured.
                </td>
              </tr>
            )}
            {ifaces.map((i) => (
              <InterfaceRow
                key={i.name}
                iface={i}
                zones={zones}
                onDelete={onDelete}
                onUpdate={onUpdate}
                canEdit={isAdmin()}
              />
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}

function InterfaceRow({
  iface,
  zones,
  onDelete,
  onUpdate,
  canEdit,
}: {
  iface: Interface;
  zones: Zone[];
  onDelete: (name: string) => void;
  onUpdate: (name: string, patch: Partial<Interface>) => void;
  canEdit: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [device, setDevice] = useState(iface.device ?? "");
  const [zone, setZone] = useState(iface.zone ?? "");
  const [addresses, setAddresses] = useState((iface.addresses ?? []).join(", "));
  const [mgmt, setMgmt] = useState(iface.access?.mgmt ?? true);
  const [http, setHTTP] = useState(iface.access?.http ?? true);
  const [https, setHTTPS] = useState(iface.access?.https ?? true);
  const [ssh, setSSH] = useState(iface.access?.ssh ?? true);

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
          <input
            value={addresses}
            onChange={(e) => setAddresses(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
          />
        ) : (
          <span className="text-slate-200">
            {(iface.addresses ?? []).length > 0
              ? (iface.addresses ?? []).join(", ")
              : "—"}
          </span>
        )}
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
                  addresses: addresses
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
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
                setAddresses((iface.addresses ?? []).join(", "));
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
