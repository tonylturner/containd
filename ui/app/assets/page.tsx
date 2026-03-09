"use client";

import { useEffect, useState } from "react";

import { api, isAdmin, type Asset, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { validateIPOrCIDRList } from "../../lib/validate";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";

const criticalityVariant = (c: string) =>
  c === "CRITICAL" ? "error" as const
    : c === "HIGH" ? "warning" as const
    : c === "MEDIUM" ? "info" as const
    : "neutral" as const;

export default function AssetsPage() {
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

  const zoneLabel = (z: Zone): string => (z.alias ? `${z.alias} (${z.name})` : z.name);

  async function refresh() {
    const [a, z] = await Promise.all([api.listAssets(), api.listZones()]);
    setAssets(a ?? []);
    setZones(z ?? []);
  }

  useEffect(() => {
    refresh();
  }, []);

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
    const result = await api.createAsset({
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
    });
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setId("");
    setName("");
    setAlias("");
    setIps("");
    refresh();
  }

  async function onDelete(assetID: string) {
    setError(null);
    const result = await api.deleteAsset(assetID);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    refresh();
  }

  async function onUpdate(assetID: string, patch: Partial<Asset>) {
    setError(null);
    const result = await api.updateAsset(assetID, patch);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setEditing(null);
    refresh();
  }

  return (
    <Shell title="Assets" actions={<button onClick={refresh} className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui">Refresh</button>}>
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
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
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="alias (optional)"
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
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
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
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
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
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
            className="rounded-lg bg-blue-600 hover:bg-blue-500 px-4 py-2 text-sm font-medium text-white transition-ui"
          >
            Create asset
          </button>
        </div>
      </Card>
      )}

      <div className="mt-6 rounded-xl border border-white/[0.08] bg-white/[0.03] overflow-hidden shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
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
              <tr key={a.id} className="border-t border-white/[0.06] table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {a.id}
                </td>
                <td className="px-4 py-3 text-slate-200">{a.name}</td>
                <td className="px-4 py-3 text-slate-200">{a.alias || "\u2014"}</td>
                <td className="px-4 py-3 text-slate-200">{a.type || "\u2014"}</td>
                <td className="px-4 py-3 text-slate-200">
                  {a.zone ? zoneLabel(zones.find((z) => z.name === a.zone) ?? { name: a.zone }) : "\u2014"}
                </td>
                <td className="px-4 py-3 text-slate-200">
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
                        className="mr-2 rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10 transition-ui"
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
  const zoneLabel = (z: Zone): string => (z.alias ? `${z.alias} (${z.name})` : z.name);

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
      <div className="w-full max-w-xl rounded-xl bg-surface-raised border border-white/[0.08] p-5 shadow-card-lg animate-fade-in animate-slide-down">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Edit asset {asset.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10 transition-ui"
          >
            Close
          </button>
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <input
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="alias (optional)"
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
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
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
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
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
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
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="description"
            rows={3}
            className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white md:col-span-2 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
          />
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-lg bg-blue-600 hover:bg-blue-500 px-4 py-2 text-sm font-medium text-white transition-ui"
          >
            Save changes
          </button>
        </div>
      </div>
    </div>
  );
}
