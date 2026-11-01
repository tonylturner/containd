"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { upsertRow } from "../../lib/config-editor";

import type { ConfigFields } from "../../lib/use-config-editor";

import { useConfigForm } from "../../lib/use-config-form";
import { ConfigEditNotice, useConfigLoad, useConfigEditor } from "../../lib/use-config-editor";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type Zone, type Conduit } from "../../lib/api";
import { mapZone, scoreZone, slColor } from "../../lib/security-scoring";
import { validateZoneName } from "../../lib/validate";
import { useToast } from "../../components/ToastProvider";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { useTableControls } from "../../hooks/useTableControls";
import { SearchBar, SortableHeader, Pagination } from "../../components/TableControls";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";

export default function ZonesPage() {
  const { canSave, canSaveNow, loadError: configLoadError, checkLoaded } = useConfigLoad();
  const toast = useToast();
  const rowsDraft = useConfigEditor<Zone[]>([], false);
  const { cfg: zones, adoptConfig: adoptRows } = rowsDraft;
  const [conduits, setConduits] = useState<Conduit[]>([]);
  const form = useConfigForm({ name: "", alias: "", description: "", slTarget: 0 });
  const { refreshForm } = form;
  const [name, setName] = form.field("name");
  const [alias, setAlias] = form.field("alias");
  const [description, setDescription] = form.field("description");
  const [slTarget, setSlTarget] = form.field("slTarget");
  const [error, setError] = useState<string | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const confirm = useConfirm();

  const { refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [list, conds] = await Promise.all([
      api.listZones(),
      api.getSecurityConduits(),
    ]);
    if (!checkLoaded(list)) return;
    adoptRows(list, keepEdits);
    setConduits(conds ?? []);
    refreshForm(list, keepEdits);
  }, [checkLoaded, refreshForm, adoptRows]));

  useConfigRefresh(refresh);

  async function onCreate() {
    if (!canSaveNow()) return;
    setError(null);
    // The name is sent as typed: the server refuses surrounding whitespace
    // rather than trimming it, so the form does too.
    const nameErr = validateZoneName(name);
    setNameError(nameErr);
    if (nameErr) return;
    setSaving(true);
    const submitted = form.editor;
    const result = await api.createZone({
      name,
      alias: alias.trim() || undefined,
      description: description.trim() || undefined,
      slTarget: slTarget || undefined,
    });
    setSaving(false);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    rowsDraft.acceptCollection((rows) => upsertRow(rows, result.data, (row) => row.name));
    toast("Zone staged — commit to apply.", "success");
    refresh();
    form.acceptFields(submitted, ["name", "alias", "description", "slTarget"]);
  }

  async function onDelete(zoneName: string) {
    if (!canSaveNow()) return;
    confirm.open({
      title: "Delete zone",
      message: `Delete zone "${zoneName}"? This cannot be undone.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: async () => {
        if (!canSaveNow()) return;
        setError(null);
        const result = await api.deleteZone(zoneName);
        if (!result.ok) {
          setError(result.error);
          return;
        }
        rowsDraft.acceptCollection((rows) => rows.filter((row) => row.name !== zoneName), [`${JSON.stringify(zoneName)}.`]);
        toast("Zone staged — commit to apply.", "success");
        refresh();
      },
    });
  }

  async function onUpdate(zoneName: string, patch: Partial<Zone>) {
    if (!canSaveNow()) return;
    setError(null);
    const submitted = rowsDraft.beginSave();
    const result = await api.updateZone(zoneName, patch);
    if (!result.ok) {
      rowsDraft.failSave(submitted);
      setError(result.error);
      return;
    }
    rowsDraft.acceptRow(submitted, (rows) => upsertRow(rows, result.data, (row) => row.name), `${JSON.stringify(zoneName)}.`);
    toast("Zone staged — commit to apply.", "success");
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
          onClick={() => refresh({ keepEdits: false })}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui hover:text-(--text)"
        >
          Refresh
        </button>
      }
    >
      {configLoadError && <p role="alert" className="mb-4 text-sm text-red-400">{configLoadError}</p>}
      <ConfigEditNotice superseded={form.editor.superseded || rowsDraft.editor.superseded} />
      <fieldset disabled={!canSave} className="min-w-0">
      {!isAdmin() && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      <Card padding="lg">
        <h2 className="text-sm font-semibold text-(--text)">Create zone</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <div>
            <label htmlFor="zone-name" className="sr-only">Zone name</label>
            <input
              id="zone-name"
              value={name}
              onChange={(e) => { setName(e.target.value); setNameError(validateZoneName(e.target.value)); }}
              placeholder="name (e.g. ot)"
              disabled={!isAdmin()}
              className={"w-full input-industrial " + (nameError ? "border-red-500/30" : "")}
            />
            {nameError && <p role="alert" aria-label="Zone name error" className="mt-1 text-xs text-red-400">{nameError}</p>}
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
              className="w-full input-industrial"
            />
          </div>
          <div>
            <label htmlFor="zone-slt" className="sr-only">Security Level Target</label>
            <select
              id="zone-slt"
              value={slTarget}
              onChange={(e) => setSlTarget(Number(e.target.value))}
              disabled={!isAdmin()}
              className="w-full input-industrial"
            >
              <option value={0}>SL-T: 0 (None)</option>
              <option value={1}>SL-T: 1</option>
              <option value={2}>SL-T: 2</option>
              <option value={3}>SL-T: 3</option>
              <option value={4}>SL-T: 4</option>
            </select>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          {error && <p role="alert" aria-label="Zone save error" className="rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-sm text-red-400">{error}</p>}
          {isAdmin() && (
            <button
              onClick={onCreate}
              disabled={saving || !canSave}
              className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
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

          <div className="mt-3 overflow-hidden rounded-xs border bg-(--surface) shadow-card">
            <table className="w-full text-sm">
              <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
                <tr>
                  <SortableHeader label="Name" sortKey="name" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
                  <SortableHeader label="Alias" sortKey="alias" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
                  <SortableHeader label="Description" sortKey="description" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
                  <th className="px-4 py-3 text-center whitespace-nowrap">SL-T</th>
                  <th className="px-4 py-3 text-center whitespace-nowrap">Check-based SL</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {table.data.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-(--text-muted)" colSpan={6}>
                      No zones match your search.
                    </td>
                  </tr>
                )}
                {table.data.map((z) => (
                  <ZoneRow
                    draft={rowsDraft}
                    key={z.name}
                    zone={z}
                    conduits={conduits}
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
      </fieldset>
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}

function SLBadge({ value, color }: { value: number; color: string }) {
  if (value === 0) return <span className="text-xs text-(--text-muted)">&mdash;</span>;
  return (
    <span
      className="inline-flex items-center justify-center rounded-xs px-2 py-0.5 text-xs font-bold tabular-nums"
      style={{ color, background: `color-mix(in srgb, ${color} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 30%, transparent)` }}
    >
      {value}
    </span>
  );
}

function ZoneRow({
  draft,
  zone,
  conduits,
  onDelete,
  onUpdate,
  canEdit,
}: {
  draft: ConfigFields;
  zone: Zone;
  conduits: Conduit[];
  onDelete: (name: string) => void;
  onUpdate: (name: string, patch: Partial<Zone>) => void;
  canEdit: boolean;
}) {
  const [desc, setDesc] = draft.field(`${JSON.stringify(zone.name)}.desc`, zone.description ?? "");
  const [alias, setAlias] = draft.field(`${JSON.stringify(zone.name)}.alias`, zone.alias ?? "");
  const [editSlt, setEditSlt] = draft.field(`${JSON.stringify(zone.name)}.editSlt`, zone.slTarget ?? 0);
  const [editing, setEditing] = useState(false);

  // Compute check-based SL from conduit data
  const zv = mapZone(zone);
  const { sl_a } = scoreZone(zv, conduits);
  const sl_t = zone.slTarget ?? 0;

  return (
    <tr className="table-row-hover border-t transition-ui">
      <td className="px-4 py-3 font-medium text-(--text)">{zone.name}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
        ) : (
          <span className="text-(--text)">{zone.alias || "\u2014"}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {editing ? (
          <input
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            disabled={!canEdit}
            className="w-full rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
        ) : (
          <span className="text-(--text)">{zone.description || "\u2014"}</span>
        )}
      </td>
      <td className="px-4 py-3 text-center">
        {editing ? (
          <select
            value={editSlt}
            onChange={(e) => setEditSlt(Number(e.target.value))}
            disabled={!canEdit}
            className="rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            <option value={0}>&mdash;</option>
            <option value={1}>1</option>
            <option value={2}>2</option>
            <option value={3}>3</option>
            <option value={4}>4</option>
          </select>
        ) : (
          <SLBadge value={sl_t} color="var(--amber)" />
        )}
      </td>
      <td className="px-4 py-3 text-center">
        <SLBadge value={sl_a} color={slColor(sl_a, sl_t)} />
      </td>
      <td className="px-4 py-3 text-right">
        {editing ? (
          <div className="inline-flex gap-2">
            <button
              onClick={() => {
                onUpdate(zone.name, {
                  alias: alias.trim() || undefined,
                  description: desc.trim() || undefined,
                  slTarget: editSlt,
                });
                setEditing(false);
              }}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              Save
            </button>
            <button
              onClick={() => {
                setDesc(zone.description ?? "");
                setAlias(zone.alias ?? "");
                setEditSlt(zone.slTarget ?? 0);
                setEditing(false);
              }}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
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
                  className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
                >
                  Edit
                </button>
                <button
                  onClick={() => onDelete(zone.name)}
                  className="text-red-400 transition-ui hover:bg-red-500/10 hover:text-red-300 rounded-xs px-3 py-1.5 text-sm"
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
