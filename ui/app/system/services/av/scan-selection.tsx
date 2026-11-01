"use client";

import type { Asset, AVConfig, ScanDownloadMode, ScanExclude, ScanInclude, ScanSelection, Zone } from "../../../../lib/api";
import { zoneLabel } from "../../../../lib/zones";
import { excludeIsEmpty, ICS_DECODER_PORTS, icsPortConflict, joinList, splitList } from "./scan-model";

const label = "text-xs uppercase tracking-wide text-(--text-muted)";
const rowClass = "grid gap-3 rounded-lg border bg-(--surface) p-3 md:grid-cols-3";
const deleteClass = "rounded-xs border px-3 py-2 text-xs text-red-400 transition-ui hover:bg-red-500/10";
const addClass = "rounded-xs border bg-(--surface2) px-3 py-2 text-sm text-(--text) transition-ui";

type Choice = { value: string; label: string };

/** A checkbox group over the configured zones or assets. */
function ChoiceList({ legend, hint, choices, selected, disabled, onChange }: {
  legend: string;
  hint: string;
  choices: Choice[];
  selected: string[] | undefined;
  disabled: boolean;
  onChange: (next: string[]) => void;
}) {
  const current = selected ?? [];
  function toggle(value: string, on: boolean) {
    onChange(on ? [...current, value] : current.filter((v) => v !== value));
  }
  return (
    <fieldset>
      <legend className={label}>{legend} <span className="text-(--text-dim) normal-case tracking-normal">({hint})</span></legend>
      {choices.length === 0 ? (
        <p className="mt-1 text-xs text-(--text-dim)">None configured.</p>
      ) : (
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1.5 text-xs text-(--text)">
          {choices.map((c) => (
            <label key={c.value} className="flex items-center gap-1.5">
              <input type="checkbox" checked={current.includes(c.value)} disabled={disabled} onChange={(e) => toggle(c.value, e.target.checked)} className="h-4 w-4" />
              {c.label}
            </label>
          ))}
        </div>
      )}
    </fieldset>
  );
}

/** A comma-separated list field. */
function ListInput({ name, hint, value, placeholder, disabled, onChange }: {
  name: string;
  hint?: string;
  value: string[] | undefined;
  placeholder: string;
  disabled: boolean;
  onChange: (next: string[]) => void;
}) {
  return (
    <div>
      <label className={label}>
        {name}{hint && <span className="text-(--text-dim) normal-case tracking-normal"> ({hint})</span>}
        <input
          aria-label={name}
          value={joinList(value)}
          disabled={disabled}
          placeholder={placeholder}
          onChange={(e) => onChange(splitList(e.target.value))}
          className="mt-1 w-full input-industrial"
        />
      </label>
    </div>
  );
}

function assetChoice(a: Asset): Choice {
  const name = a.name || a.id;
  return { value: a.id, label: a.alias ? `${a.alias} (${name})` : name };
}

/**
 * Edits the scan selection and HTTP directions of the AV settings. The
 * selection is stored as typed, with list fields trimmed when the page saves.
 */
export function ScanSelectionEditor({ cfg, update, zones, assets, canEdit }: {
  cfg: AVConfig;
  update: (fn: (c: AVConfig) => AVConfig) => void;
  zones: Zone[];
  assets: Asset[];
  canEdit: boolean;
}) {
  const scan = cfg.scan ?? {};
  const include = scan.include ?? [];
  const exclude = scan.exclude ?? [];
  const zoneChoices = zones.map((z) => ({ value: z.name, label: zoneLabel(z) }));
  const assetChoices = assets.map(assetChoice);
  const disabled = !canEdit;
  const icsPorts = Object.keys(ICS_DECODER_PORTS).join(", ");

  function setScan(fn: (s: ScanSelection) => ScanSelection) {
    update((c) => ({ ...c, scan: fn(c.scan ?? {}) }));
  }
  function setInclude(idx: number, patch: Partial<ScanInclude>) {
    setScan((s) => ({ ...s, include: (s.include ?? []).map((e, i) => (i === idx ? { ...e, ...patch } : e)) }));
  }
  function setExclude(idx: number, patch: Partial<ScanExclude>) {
    setScan((s) => ({ ...s, exclude: (s.exclude ?? []).map((e, i) => (i === idx ? { ...e, ...patch } : e)) }));
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs text-(--text-muted)">
          Selected traffic is scanned using HTTP/1.x on the listed destination ports between the listed zones; excludes win over includes,
          and ports and addresses are the destination after NAT. HTTPS, HTTP/2 and files inside ICS protocols are not scanned.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-(--text)">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={cfg.httpDownload ?? false} disabled={disabled} onChange={(e) => update((c) => ({ ...c, httpDownload: e.target.checked }))} className="h-4 w-4" />
            Scan HTTP downloads
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={cfg.httpUpload ?? false} disabled={disabled} onChange={(e) => update((c) => ({ ...c, httpUpload: e.target.checked }))} className="h-4 w-4" />
            Scan HTTP uploads
          </label>
          <span className="text-xs text-(--text-muted)">Traffic scanning runs only while scanning is enabled, at least one include exists and one direction is scanned.</span>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-(--text)">Include</h4>
        <p className="text-xs text-(--text-muted)">Destination ports are required: single ports or ranges such as 80, 8080, 8000-8099. Reserved industrial ports ({icsPorts}) cannot be selected.</p>
        <div className="mt-3 space-y-2">
          {include.map((entry, idx) => {
            const conflict = icsPortConflict(entry.destPorts);
            return (
              <div key={idx} className={rowClass} data-testid="scan-include">
                <ChoiceList legend="Source zones" hint="none = any" choices={zoneChoices} selected={entry.sourceZones} disabled={disabled} onChange={(v) => setInclude(idx, { sourceZones: v })} />
                <ChoiceList legend="Destination zones" hint="none = any" choices={zoneChoices} selected={entry.destZones} disabled={disabled} onChange={(v) => setInclude(idx, { destZones: v })} />
                <div className="space-y-2">
                  <ListInput name="Destination ports" value={entry.destPorts} placeholder="80, 8080, 8000-8099" disabled={disabled} onChange={(v) => setInclude(idx, { destPorts: v })} />
                  {conflict && <p className="text-xs text-(--amber)">{conflict}</p>}
                  {canEdit && (
                    <button onClick={() => setScan((s) => ({ ...s, include: (s.include ?? []).filter((_, i) => i !== idx) }))} className={deleteClass}>
                      Delete include
                    </button>
                  )}
                </div>
              </div>
            );
          })}
          {include.length === 0 && <p className="text-xs text-(--text-dim)">No include: the gate intercepts nothing.</p>}
          {canEdit && (
            <button onClick={() => setScan((s) => ({ ...s, include: [...(s.include ?? []), { destPorts: [] }] }))} className={addClass}>
              Add include
            </button>
          )}
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-(--text)">Exclude</h4>
        <p className="text-xs text-(--text-muted)">Each exclude needs at least one field; sources and destinations are CIDRs.</p>
        <div className="mt-3 space-y-2">
          {exclude.map((entry, idx) => (
            <div key={idx} className={rowClass} data-testid="scan-exclude">
              <ChoiceList legend="Source zones" hint="none = any" choices={zoneChoices} selected={entry.sourceZones} disabled={disabled} onChange={(v) => setExclude(idx, { sourceZones: v })} />
              <ChoiceList legend="Destination zones" hint="none = any" choices={zoneChoices} selected={entry.destZones} disabled={disabled} onChange={(v) => setExclude(idx, { destZones: v })} />
              <ListInput name="Destination ports" value={entry.destPorts} placeholder="80, 8000-8099" disabled={disabled} onChange={(v) => setExclude(idx, { destPorts: v })} />
              <ListInput name="Sources" hint="CIDR" value={entry.sources} placeholder="10.0.0.0/24, 2001:db8::/64" disabled={disabled} onChange={(v) => setExclude(idx, { sources: v })} />
              <ListInput name="Destinations" hint="CIDR" value={entry.destinations} placeholder="192.0.2.10/32" disabled={disabled} onChange={(v) => setExclude(idx, { destinations: v })} />
              <div className="flex flex-col justify-end gap-2">
                {excludeIsEmpty(entry) && <p className="text-xs text-(--amber)">Set at least one field; the server refuses an empty exclude.</p>}
                {canEdit && (
                  <button onClick={() => setScan((s) => ({ ...s, exclude: (s.exclude ?? []).filter((_, i) => i !== idx) }))} className={`${deleteClass} self-start`}>
                    Delete exclude
                  </button>
                )}
              </div>
            </div>
          ))}
          {canEdit && (
            <button onClick={() => setScan((s) => ({ ...s, exclude: [...(s.exclude ?? []), {}] }))} className={addClass}>
              Add exclude
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <label className={label}>Download mode</label>
          <select
            aria-label="Download mode"
            value={scan.downloadMode ?? "hold"}
            disabled={disabled}
            onChange={(e) => setScan((s) => ({ ...s, downloadMode: e.target.value as ScanDownloadMode }))}
            className="mt-1 w-full input-industrial"
          >
            <option value="hold">Wait for scanning before sending</option>
            <option value="stream_tail">Send while scanning; hold the final part</option>
          </select>
          <p className="mt-1 text-xs text-(--text-muted)">
            Sending while scanning forwards most of a download before the result and resets the connection on a detection; uploads are always held.
          </p>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-(--text)">ICS endpoints</h4>
        <p className="text-xs text-(--text-muted)">
          Unscanned traffic to or from these passes even when the fail policy is closed; infected files are always blocked.
        </p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <ChoiceList legend="ICS zones" hint="optional" choices={zoneChoices} selected={scan.icsZones} disabled={disabled} onChange={(v) => setScan((s) => ({ ...s, icsZones: v }))} />
          <ChoiceList legend="ICS assets" hint="optional" choices={assetChoices} selected={scan.icsAssets} disabled={disabled} onChange={(v) => setScan((s) => ({ ...s, icsAssets: v }))} />
        </div>
      </div>
    </div>
  );
}
