"use client";

import { useEffect, useState } from "react";

import { api, isAdmin, type Asset, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Asset | null>(null);

  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [type, setType] = useState("PLC");
  const [zone, setZone] = useState("");
  const [ips, setIps] = useState("");
  const [criticality, setCriticality] = useState("HIGH");

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
    const created = await api.createAsset({
      id: id.trim(),
      name: name.trim(),
      type,
      zone: zone || undefined,
      ips: ips
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      criticality,
    });
    if (!created) {
      setError("Failed to create asset.");
      return;
    }
    setId("");
    setName("");
    setIps("");
    refresh();
  }

  async function onDelete(assetID: string) {
    setError(null);
    const ok = await api.deleteAsset(assetID);
    if (!ok) {
      setError("Failed to delete asset.");
      return;
    }
    refresh();
  }

  async function onUpdate(assetID: string, patch: Partial<Asset>) {
    setError(null);
    const updated = await api.updateAsset(assetID, patch);
    if (!updated) {
      setError("Failed to update asset.");
      return;
    }
    setEditing(null);
    refresh();
  }

  return (
    <Shell title="Assets" actions={<button onClick={refresh} className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10">Refresh</button>}>
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      {isAdmin() && (
      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="text-sm font-semibold text-white">Create asset</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <input
            value={id}
            onChange={(e) => setId(e.target.value)}
            placeholder="id (e.g. plc-1)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
          />
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
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
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="">Zone (optional)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {z.name}
              </option>
            ))}
          </select>
          <input
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder="IPs (csv)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
          />
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
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
            className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30"
          >
            Create asset
          </button>
        </div>
      </div>
      )}

      <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Name</th>
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
                <td className="px-4 py-4 text-slate-400" colSpan={7}>
                  No assets configured.
                </td>
              </tr>
            )}
            {assets.map((a) => (
              <tr key={a.id} className="border-t border-white/5">
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {a.id}
                </td>
                <td className="px-4 py-3 text-slate-200">{a.name}</td>
                <td className="px-4 py-3 text-slate-200">{a.type || "—"}</td>
                <td className="px-4 py-3 text-slate-200">{a.zone || "—"}</td>
                <td className="px-4 py-3 text-slate-200">
                  {(a.ips ?? []).join(", ") || "—"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {a.criticality || "—"}
                </td>
                <td className="px-4 py-3 text-right">
                  {isAdmin() && (
                    <>
                      <button
                        onClick={() => setEditing(a)}
                        className="mr-2 rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => onDelete(a.id)}
                        className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30"
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-2xl border border-white/10 bg-ink p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Edit asset {asset.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
          >
            Close
          </button>
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
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
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="">Zone (optional)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {z.name}
              </option>
            ))}
          </select>
          <input
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder="IPs (csv)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
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
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="description"
            rows={3}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2"
          />
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30"
          >
            Save changes
          </button>
        </div>
      </div>
    </div>
  );
}
