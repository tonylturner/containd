"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { useTableControls } from "../../hooks/useTableControls";
import { SearchBar, SortableHeader, Pagination } from "../../components/TableControls";

export default function ZonesPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [name, setName] = useState("");
  const [alias, setAlias] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const ZONE_NAME_RE = /^[a-zA-Z0-9_-]+$/;

  async function refresh() {
    const list = await api.listZones();
    setZones(list ?? []);
  }

  useEffect(() => {
    refresh();
  }, []);

  function validateName(v: string): string | null {
    if (!v.trim()) return "Zone name is required.";
    if (!ZONE_NAME_RE.test(v.trim())) return "Only letters, numbers, dash, and underscore allowed (no spaces).";
    return null;
  }

  async function onCreate() {
    setError(null);
    const nameErr = validateName(name);
    setNameError(nameErr);
    if (nameErr) return;
    setSaving(true);
    const result = await api.createZone({
      name: name.trim(),
      alias: alias.trim() || undefined,
      description: description.trim() || undefined,
    });
    setSaving(false);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setName("");
    setAlias("");
    setDescription("");
    refresh();
  }

  async function onDelete(zoneName: string) {
    if (!confirm("Delete this zone? This cannot be undone.")) return;
    setError(null);
    const result = await api.deleteZone(zoneName);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    refresh();
  }

  async function onUpdate(zoneName: string, patch: Partial<Zone>) {
    setError(null);
    const result = await api.updateZone(zoneName, patch);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    refresh();
  }

  const table = useTableControls(zones, {
    defaultSort: "name",
    searchKeys: ["name", "alias"],
  });

  const tips: Tip[] = [
    {
      id: "zones:create",
      title: "Create your first zone",
      body: "Start with WAN, DMZ, and LAN to segment traffic.",
      when: () => zones.length === 0,
    },
    {
      id: "zones:assign",
      title: "Assign zones to interfaces",
      body: (
        <>
          Go to{" "}
          <Link href="/interfaces/" className="font-semibold text-mint hover:text-mint/80">
            Interfaces
          </Link>{" "}
          to bind zones to ports.
        </>
      ),
      when: () => zones.length > 0,
    },
  ];

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
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="text-sm font-semibold text-white">Create zone</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div>
            <label htmlFor="zone-name" className="sr-only">Zone name</label>
            <input
              id="zone-name"
              value={name}
              onChange={(e) => { setName(e.target.value); setNameError(validateName(e.target.value)); }}
              placeholder="name (e.g. ot)"
              disabled={!isAdmin()}
              className={"w-full rounded-lg border bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 " + (nameError ? "border-amber/50" : "border-white/10")}
            />
            {nameError && <p className="mt-1 text-xs text-amber">{nameError}</p>}
          </div>
          <div>
            <label htmlFor="zone-alias" className="sr-only">Zone alias</label>
            <input
              id="zone-alias"
              value={alias}
              onChange={(e) => setAlias(e.target.value)}
              placeholder="alias (optional)"
              disabled={!isAdmin()}
              className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
            />
          </div>
          <div>
            <label htmlFor="zone-description" className="sr-only">Zone description</label>
            <input
              id="zone-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="description"
              disabled={!isAdmin()}
              className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-1"
            />
          </div>
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

      <div className="mt-6 flex items-center gap-3">
        <SearchBar value={table.search} onChange={table.setSearch} placeholder="Search zones..." />
      </div>

      <div className="mt-3 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <SortableHeader label="Name" sortKey="name" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Alias" sortKey="alias" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <SortableHeader label="Description" sortKey="description" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {table.data.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={4}>
                  {zones.length === 0
                    ? "No zones configured. Create zones (e.g. WAN, DMZ, OT) to segment network traffic."
                    : "No zones match your search."}
                </td>
              </tr>
            )}
            {table.data.map((z) => (
              <ZoneRow
                key={z.name}
                zone={z}
                onDelete={onDelete}
                onUpdate={onUpdate}
                canEdit={isAdmin()}
              />
            ))}
          </tbody>
        </table>
        <Pagination page={table.page} totalPages={table.totalPages} totalItems={table.totalItems} onPage={table.setPage} />
      </div>
    </Shell>
  );
}

function ZoneRow({
  zone,
  onDelete,
  onUpdate,
  canEdit,
}: {
  zone: Zone;
  onDelete: (name: string) => void;
  onUpdate: (name: string, patch: Partial<Zone>) => void;
  canEdit: boolean;
}) {
  const [desc, setDesc] = useState(zone.description ?? "");
  const [alias, setAlias] = useState(zone.alias ?? "");
  const [editing, setEditing] = useState(false);

  return (
    <tr className="border-t border-white/5">
      <td className="px-4 py-3 font-medium text-white">{zone.name}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
          />
        ) : (
          <span className="text-slate-200">{zone.alias || "—"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            disabled={!canEdit}
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
                onUpdate(zone.name, { alias: alias.trim() || undefined, description: desc.trim() || undefined });
                setEditing(false);
              }}
              className="rounded-md bg-white/10 px-2 py-1 text-xs hover:bg-white/20"
            >
              Save
            </button>
            <button
              onClick={() => {
                setDesc(zone.description ?? "");
                setAlias(zone.alias ?? "");
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
                  onClick={() => onDelete(zone.name)}
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
