import type { Protocol, Zone } from "../../lib/api";
import { zoneLabel } from "../../lib/zones";

/** Explicit rows make removing the last match (any) distinct from removing one. */
export function RuleZoneList({ label, anyLabel, value, zones, onChange }: {
  label: string; anyLabel: string; value: string[]; zones: Zone[]; onChange: (value: string[]) => void;
}) {
  const next = zones.find(zone => !value.includes(zone.name));
  return <fieldset className="min-w-0 space-y-2">
    <legend className="text-xs text-(--text-muted)">{label}</legend>
    {value.length === 0 && <p className="text-xs text-(--text-muted)">{anyLabel}</p>}
    {value.map((name, index) => <div key={index} className="flex min-w-0 gap-2">
      <select aria-label={`${label} ${index + 1}`} value={name}
        onChange={event => onChange(value.map((entry, i) => i === index ? event.target.value : entry))}
        className="input-industrial min-w-0 flex-1">
        {!zones.some(zone => zone.name === name) && <option value={name}>{name} (no longer on server)</option>}
        {zones.map(zone => <option key={zone.name} value={zone.name} disabled={zone.name !== name && value.includes(zone.name)}>{zoneLabel(zone)}</option>)}
      </select>
      <button type="button" aria-label={`Remove ${label.toLowerCase()} ${index + 1}`}
        onClick={() => onChange(value.filter((_, i) => i !== index))} className="rounded-xs border px-2 text-xs">Remove</button>
    </div>)}
    <button type="button" disabled={!next} onClick={() => next && onChange([...value, next.name])}
      className="rounded-xs border px-2 py-1 text-xs disabled:opacity-50">Add {label.toLowerCase()}</button>
  </fieldset>;
}

export function RuleProtocolList({ value, onChange }: { value: Protocol[]; onChange: (value: Protocol[]) => void }) {
  function update(index: number, patch: Partial<Protocol>) {
    onChange(value.map((entry, i) => i === index ? { ...entry, ...patch } : entry));
  }
  return <fieldset className="min-w-0 space-y-2">
    <legend className="text-xs text-(--text-muted)">Protocols</legend>
    {value.length === 0 && <p className="text-xs text-(--text-muted)">Any protocol</p>}
    {value.map((protocol, index) => <div key={index} className="grid min-w-0 grid-cols-[1fr_1fr_auto] gap-2">
      <select aria-label={`Protocol ${index + 1}`} value={protocol.name} className="input-industrial min-w-0"
        onChange={event => update(index, { name: event.target.value })}>
        {!["tcp", "udp", "icmp"].includes(protocol.name) && <option value={protocol.name}>{protocol.name}</option>}
        <option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option>
      </select>
      <input aria-label={`Protocol ${index + 1} port/range`} placeholder="port/range" value={protocol.port ?? ""}
        onChange={event => update(index, { port: event.target.value || undefined })} className="input-industrial min-w-0" />
      <button type="button" aria-label={`Remove protocol ${index + 1}`} onClick={() => onChange(value.filter((_, i) => i !== index))}
        className="rounded-xs border px-2 text-xs">Remove</button>
    </div>)}
    <button type="button" onClick={() => onChange([...value, { name: "tcp" }])} className="rounded-xs border px-2 py-1 text-xs">Add protocol</button>
  </fieldset>;
}
