"use client";

import { useConfigRevision } from "../../lib/use-config-revision";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { IEC104Inventory } from "./IEC104Inventory";
import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useLayoutEffect, useRef, useState } from "react";

import { api, isAdmin, type Asset, type Zone } from "../../lib/api";
import { useToast } from "../../components/ToastProvider";
import { Shell } from "../../components/Shell";
import { validateIPOrCIDRList } from "../../lib/validate";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import { zoneLabel, zoneName } from "../../lib/zones";

const criticalityVariant = (c: string) =>
  c === "CRITICAL" ? "error" as const
    : c === "HIGH" ? "warning" as const
    : c === "MEDIUM" ? "info" as const
    : "neutral" as const;

export default function AssetsPage() {
  const { readConfig, expectedRevision, handleRevision, revisionNotice } = useConfigRevision();
  const toast = useToast();
  const [inventoryRefresh, setInventoryRefresh] = useState(0);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Asset | null>(null);
  const confirm = useConfirm();

  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [alias, setAlias] = useState("");
  const [type, setType] = useState("PLC");
  const [zone, setZone] = useState("");
  const [ips, setIps] = useState("");
  const [criticality, setCriticality] = useState("HIGH");

  const retainedDraft = useRef(false);
  useLayoutEffect(() => {
    retainedDraft.current = !!(id || name || alias || zone || ips || type !== "PLC" || criticality !== "HIGH" || editing);
  }, [id, name, alias, zone, ips, type, criticality, editing]);

  const { refresh } = useAsyncRefresh(useCallback(async () => {
    const [aSnapshot, zSnapshot] = await Promise.all([api.listAssets(), api.listZones()]);
    const a = readConfig(aSnapshot, true, retainedDraft.current);
    const z = zSnapshot?.data ?? null;
    setInventoryRefresh((key) => key + 1);
    setAssets(a ?? []);
    setZones(z ?? []);
  }, [readConfig]));

  useConfigRefresh(refresh);

  async function onCreate() {
    setError(null);
    if (!id.trim() || !name.trim()) {
      setError("Asset id and name are required.");
      return;
    }
    if (ips.trim()) {
      const ipErr = validateIPOrCIDRList(ips);
      if (ipErr) { setError(ipErr); return; }
    }
    const result = await api.createAsset(expectedRevision(), {
      id: id.trim(),
      name: name.trim(),
      alias: alias.trim() || undefined,
      type,
      zone: zone || undefined,
      ips: ips
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      criticality,
    }).then(handleRevision(expectedRevision()));
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toast("Asset staged — commit to apply.", "success");
    setId("");
    setName("");
    setAlias("");
    setIps("");
    refresh();
  }

  async function onDelete(assetID: string) {
    setError(null);
    const result = await api.deleteAsset(expectedRevision(), assetID).then(handleRevision(expectedRevision()));
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toast("Asset staged — commit to apply.", "success");
    refresh();
  }

  async function onUpdate(assetID: string, patch: Partial<Asset>) {
    setError(null);
    const result = await api.updateAsset(expectedRevision(), assetID, patch).then(handleRevision(expectedRevision()));
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toast("Asset staged — commit to apply.", "success");
    setEditing(null);
    refresh();
  }

  return (
    <Shell title="Assets" actions={<button onClick={refresh} className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui">Refresh</button>}>
      {!isAdmin() && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {revisionNotice(() => window.location.reload())}
      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {isAdmin() && (
      <Card title="Create asset" padding="lg">
        <div className="grid gap-3 md:grid-cols-3">
          <input
            value={id}
            onChange={(e) => setId(e.target.value)}
            placeholder="id (e.g. plc-1)"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="alias (optional)"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            {["PLC", "HMI", "SIS", "RTU", "HISTORIAN", "EWS", "GATEWAY", "LAPTOP", "OTHER"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <select
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            <option value="">Zone (optional)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {zoneLabel(z)}
              </option>
            ))}
          </select>
          <input
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder="IPs (csv)"
            className="input-industrial md:col-span-2 transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div className="mt-3 flex justify-end">
          <button
            onClick={onCreate}
            className="rounded-xs bg-(--amber) hover:brightness-110 px-4 py-2 text-sm font-medium text-white transition-ui"
          >
            Create asset
          </button>
        </div>
      </Card>
      )}

      <div className="mt-6 rounded-xs border bg-(--surface) overflow-hidden shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Alias</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Zone</th>
              <th className="px-4 py-3">IPs</th>
              <th className="px-4 py-3">Criticality</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {assets.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <EmptyState
                    title="No assets configured"
                    description="Add an asset above to begin tracking OT/ICS devices."
                  />
                </td>
              </tr>
            )}
            {assets.map((a) => (
              <tr key={a.id} className="border-t table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-(--text)">
                  {a.id}
                </td>
                <td className="px-4 py-3 text-(--text)">{a.name}</td>
                <td className="px-4 py-3 text-(--text)">{a.alias || "\u2014"}</td>
                <td className="px-4 py-3 text-(--text)">{a.type || "\u2014"}</td>
                <td className="px-4 py-3 text-(--text)">
                  {a.zone ? zoneName(zones, a.zone) : "\u2014"}
                </td>
                <td className="px-4 py-3 text-(--text)">
                  {(a.ips ?? []).join(", ") || "\u2014"}
                </td>
                <td className="px-4 py-3">
                  {a.criticality ? (
                    <StatusBadge variant={criticalityVariant(a.criticality)}>
                      {a.criticality}
                    </StatusBadge>
                  ) : "\u2014"}
                </td>
                <td className="px-4 py-3 text-right">
                  {isAdmin() && (
                    <>
                      <button
                        onClick={() => setEditing(a)}
                        className="mr-2 rounded-md bg-(--surface2) px-2 py-1 text-xs transition-ui"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() =>
                          confirm.open({
                            title: "Delete asset",
                            message: `Are you sure you want to delete asset "${a.id}"? This action cannot be undone.`,
                            confirmLabel: "Delete",
                            variant: "danger",
                            onConfirm: () => onDelete(a.id),
                          })
                        }
                        className="rounded-md text-red-400 hover:bg-red-500/10 px-2 py-1 text-xs transition-ui"
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <IEC104Inventory refreshKey={inventoryRefresh} />

      {editing && isAdmin() && (
        <EditAssetModal
          asset={editing}
          zones={zones}
          onClose={() => setEditing(null)}
          onSave={(patch) => onUpdate(editing.id, patch)}
        />
      )}
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}

function EditAssetModal({
  asset,
  zones,
  onClose,
  onSave,
}: {
  asset: Asset;
  zones: Zone[];
  onClose: () => void;
  onSave: (patch: Partial<Asset>) => void;
}) {
  const [name, setName] = useState(asset.name);
  const [alias, setAlias] = useState(asset.alias ?? "");
  const [type, setType] = useState(asset.type ?? "PLC");
  const [zone, setZone] = useState(asset.zone ?? "");
  const [ips, setIps] = useState((asset.ips ?? []).join(", "));
  const [criticality, setCriticality] = useState(
    asset.criticality ?? "HIGH",
  );
  const [tags, setTags] = useState((asset.tags ?? []).join(", "));
  const [description, setDescription] = useState(asset.description ?? "");

  function save() {
    onSave({
      name: name.trim() || asset.name,
      alias: alias.trim() || undefined,
      type,
      zone: zone || undefined,
      ips: ips
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      criticality,
      tags: tags
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      description: description.trim() || undefined,
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-xl rounded-xs bg-(--surface) border p-5 shadow-card-lg animate-fade-in animate-slide-down">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-(--text)">
            Edit asset {asset.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md bg-(--surface2) px-2 py-1 text-xs transition-ui"
          >
            Close
          </button>
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="alias (optional)"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            {["PLC", "HMI", "SIS", "RTU", "HISTORIAN", "EWS", "GATEWAY", "LAPTOP", "OTHER"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <select
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            <option value="">Zone (optional)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {zoneLabel(z)}
              </option>
            ))}
          </select>
          <input
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder="IPs (csv)"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="tags (csv)"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="description"
            rows={3}
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) md:col-span-2 transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-xs bg-(--amber) hover:brightness-110 px-4 py-2 text-sm font-medium text-white transition-ui"
          >
            Save changes
          </button>
        </div>
      </div>
    </div>
  );
}
