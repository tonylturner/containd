"use client";

import { useEffect, useState } from "react";
import type { ApiResult, DataPlaneConfig } from "../../lib/api";
import type { ConfigBase } from "../../lib/config-boundary";
import { ConfigEditNotice, revisionError, useConfigEditor } from "../../lib/use-config-editor";

const settings = [
  { key: "maxFlows", label: "Directional flow slots", default: 16384, min: 1024, max: 262144 },
  { key: "maxTopTalkers", label: "Recently active host-pair rows", default: 8192, min: 64, max: 262144 },
  { key: "maxInspectionBytes", label: "Retained inspection bytes", default: 67108864, min: 8388608, max: 1073741824 },
] as const;

function fields(config: DataPlaneConfig) {
  return { maxFlows: String(config.limits?.maxFlows ?? 0), maxTopTalkers: String(config.limits?.maxTopTalkers ?? 0),
    maxInspectionBytes: String(config.limits?.maxInspectionBytes ?? 0), context: config };
}

export function StateLimitsSettings({ config, revision, available, canEdit, onSave }: {
  config: DataPlaneConfig; revision: string; available: boolean; canEdit: boolean;
  onSave: (base: ConfigBase, config: DataPlaneConfig) => Promise<ApiResult<DataPlaneConfig> | null>;
}) {
  const draft = useConfigEditor(() => fields(config), available, revision);
  const { cfg, setCfg, readConfig } = draft;
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<{ warning?: string } | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { readConfig({ data: fields(config), revision }, true); }, [config, revision, readConfig]);

  async function stage() {
    if (!canEdit || !available || saving || !draft.writable) return;
    setSaved(null);
    const limits = { ...cfg.context.limits };
    for (const field of settings) {
      const raw = cfg[field.key];
      const value = Number(raw);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || (value !== 0 && (value < field.min || value > field.max))) {
        setError(`dataplane.limits.${field.key} must be 0 (default) or ${field.min}–${field.max}.`);
        return;
      }
      // Preserve omitted defaults rather than writing resolved values back.
      if (value === 0) delete limits[field.key];
      else limits[field.key] = value;
    }
    setError(null);
    setSaving(true);
    const result = await draft.write((base, submitted) => onSave(base, { ...submitted.context, limits }), { replace: data => fields(data) });
    setSaving(false);
    if (!result.ok) { setError(revisionError(result)); return; }
    if (result.adopted) setSaved({ warning: result.warning });
  }

  return <section aria-label="Traffic state limits" className="rounded-xs border bg-(--surface2) p-3">
    <h3 className="text-sm font-semibold">Traffic state limits</h3>
    <p className="mt-1 text-xs text-(--text-muted)">0 selects the default, never unlimited. Two directional slots are reserved per connection.
      Inspection bytes bound retained inspection allocations, not engine memory. Applying a change rebuilds the dataplane and resets traffic state.</p>
    <ConfigEditNotice superseded={draft.editor.superseded} {...draft.conflictProps} onReload={() => window.location.reload()} />
    <fieldset disabled={!canEdit || !available || saving || !draft.writable} className="mt-3 min-w-0 space-y-3">
      {settings.map(field => <label key={field.key} className="block text-xs">
        {field.label}
        <input type="number" min={0} max={field.max} step={1} value={cfg[field.key]}
          onChange={event => { setSaved(null); setCfg(current => ({ ...current, [field.key]: event.target.value })); }}
          className="input-industrial mt-1 block w-full sm:max-w-xs" />
        <span className="mt-1 block text-(--text-muted)">{available ? `Effective candidate: ${config.limits?.[field.key] || field.default}` : "Effective candidate unavailable"}; default: {field.default}; range: {field.min}–{field.max}.</span>
      </label>)}
      {canEdit && <button type="button" onClick={() => void stage()} className="rounded-xs border px-3 py-1.5 text-xs disabled:opacity-50">{saving ? "Staging…" : "Stage state limits"}</button>}
    </fieldset>
    {error && <p role="alert" className="mt-2 text-xs text-red-400">{error}</p>}
    {saved && <p role="status" className="mt-2 text-xs text-emerald-400">State limits staged — review changes and commit to apply.{saved.warning && ` Warning: ${saved.warning}`}</p>}
  </section>;
}
