"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { useTableControls } from "../../hooks/useTableControls";
import { SearchBar, SortableHeader, Pagination } from "../../components/TableControls";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";

export default function ZonesPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [name, setName] = useState("");
  const [alias, setAlias] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const confirm = useConfirm();

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
    confirm.open({
      title: "Delete zone",
      message: `Delete zone "${zoneName}"? This cannot be undone.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: async () => {
        setError(null);
        const result = await api.deleteZone(zoneName);
        if (!result.ok) {
          setError(result.error);
          return;
        }
        refresh();
      },
    });
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
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] hover:text-[var(--text)]"
        >
          Refresh
        </button>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <Card padding="lg">
        <h2 className="text-sm font-semibold text-[var(--text)]">Create zone</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div>
            <label htmlFor="zone-name" className="sr-only">Zone name</label>
            <input
              id="zone-name"
              value={name}
              onChange={(e) => { setName(e.target.value); setNameError(validateName(e.target.value)); }}
              placeholder="name (e.g. ot)"
              disabled={!isAdmin()}
              className={"w-full input-industrial " + (nameError ? "border-red-500/30" : "border-amber-500/[0.15]")}
            />
            {nameError && <p className="mt-1 text-xs text-red-400">{nameError}</p>}
          </div>
          <div>
            <label htmlFor="zone-alias" className="sr-only">Zone alias</label>
            <input
              id="zone-alias"
              value={alias}
              onChange={(e) => setAlias(e.target.value)}
              placeholder="alias (optional)"
              disabled={!isAdmin()}
              className="w-full input-industrial"
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
              className="w-full input-industrial md:col-span-1"
            />
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          {error && <p className="rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-sm text-red-400">{error}</p>}
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

      {zones.length === 0 ? (
        <EmptyState
          className="mt-6"
          title="No zones configured"
          description="Create zones (e.g. WAN, DMZ, OT) to segment network traffic."
        />
      ) : (
        <>
          <div className="mt-6 flex items-center gap-3">
            <SearchBar value={table.search} onChange={table.setSearch} placeholder="Search zones..." />
          </div>

          <div className="mt-3 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                    <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={4}>
                      No zones match your search.
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
        </>
      )}
      <ConfirmDialog {...confirm.props} />
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
    <tr className="table-row-hover border-t border-amber-500/[0.08] transition-ui">
      <td className="px-4 py-3 font-medium text-[var(--text)]">{zone.name}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
          />
        ) : (
          <span className="text-[var(--text)]">{zone.alias || "\u2014"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
          />
        ) : (
          <span className="text-[var(--text)]">{zone.description || "\u2014"}</span>
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
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
            >
              Save
            </button>
            <button
              onClick={() => {
                setDesc(zone.description ?? "");
                setAlias(zone.alias ?? "");
                setEditing(false);
              }}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
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
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                >
                  Edit
                </button>
                <button
                  onClick={() => onDelete(zone.name)}
                  className="text-red-400 transition-ui hover:bg-red-500/10 hover:text-red-300 rounded-sm px-3 py-1.5 text-sm"
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
