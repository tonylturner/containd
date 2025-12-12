 "use client";

import { useEffect, useState } from "react";

import { api, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function ZonesPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function refresh() {
    const list = await api.listZones();
    setZones(list ?? []);
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onCreate() {
    setError(null);
    if (!name.trim()) {
      setError("Zone name is required.");
      return;
    }
    setSaving(true);
    const created = await api.createZone({
      name: name.trim(),
      description: description.trim() || undefined,
    });
    setSaving(false);
    if (!created) {
      setError("Failed to create zone.");
      return;
    }
    setName("");
    setDescription("");
    refresh();
  }

  async function onDelete(zoneName: string) {
    setError(null);
    const ok = await api.deleteZone(zoneName);
    if (!ok) {
      setError("Failed to delete zone (may be in use).");
      return;
    }
    refresh();
  }

  async function onUpdate(zoneName: string, patch: Partial<Zone>) {
    setError(null);
    const updated = await api.updateZone(zoneName, patch);
    if (!updated) {
      setError("Failed to update zone.");
      return;
    }
    refresh();
  }

  return (
    <Shell
      title="Zones"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="text-sm font-semibold text-white">Create zone</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name (e.g. ot)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
          />
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="description"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
          />
        </div>
        <div className="mt-3 flex items-center justify-between">
          {error && <p className="text-sm text-amber">{error}</p>}
          <button
            onClick={onCreate}
            disabled={saving}
            className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
          >
            {saving ? "Creating..." : "Create"}
          </button>
        </div>
      </div>

      <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {zones.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={3}>
                  No zones configured.
                </td>
              </tr>
            )}
            {zones.map((z) => (
              <ZoneRow key={z.name} zone={z} onDelete={onDelete} onUpdate={onUpdate} />
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}

function ZoneRow({
  zone,
  onDelete,
  onUpdate,
}: {
  zone: Zone;
  onDelete: (name: string) => void;
  onUpdate: (name: string, patch: Partial<Zone>) => void;
}) {
  const [desc, setDesc] = useState(zone.description ?? "");
  const [editing, setEditing] = useState(false);

  return (
    <tr className="border-t border-white/5">
      <td className="px-4 py-3 font-medium text-white">{zone.name}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
          />
        ) : (
          <span className="text-slate-200">{zone.description || "—"}</span>
        )}
      </td>
      <td className="px-4 py-3 text-right">
        {editing ? (
          <div className="inline-flex gap-2">
            <button
              onClick={() => {
                onUpdate(zone.name, { description: desc.trim() || undefined });
                setEditing(false);
              }}
              className="rounded-md bg-white/10 px-2 py-1 text-xs hover:bg-white/20"
            >
              Save
            </button>
            <button
              onClick={() => {
                setDesc(zone.description ?? "");
                setEditing(false);
              }}
              className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
            >
              Cancel
            </button>
          </div>
        ) : (
          <div className="inline-flex gap-2">
            <button
              onClick={() => setEditing(true)}
              className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
            >
              Edit
            </button>
            <button
              onClick={() => onDelete(zone.name)}
              className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30"
            >
              Delete
            </button>
          </div>
        )}
      </td>
    </tr>
  );
}

