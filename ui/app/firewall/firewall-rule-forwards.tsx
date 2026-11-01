"use client";

import type { PortForward } from "../../lib/api";

export function RuleForwardFields({
  forwards, value, onChange,
}: {
  forwards: PortForward[];
  value: string[];
  onChange: (ids: string[]) => void;
}) {
  return (
    <fieldset className="mt-3 rounded-xs border p-3 text-sm text-(--text)">
      <legend className="px-1">Via port forward</legend>
      <p className="mb-2 text-xs text-(--text-muted)">Select translated connections only. No selection leaves this rule unconstrained by port forward.</p>
      {forwards.length === 0 && <p className="text-xs text-(--text-muted)">No port forwards configured.</p>}
      {value.filter((id) => !forwards.some((f) => f.id === id)).map((id) => (
        <label key={id} className="flex items-center gap-2">
          <input type="checkbox" checked onChange={() => onChange(value.filter((v) => v !== id))} />
          {id} (no longer on server)
        </label>
      ))}
      {forwards.map((f) => (
        <label key={f.id} className="flex items-center gap-2">
          <input type="checkbox" checked={value.includes(f.id)} onChange={(e) => onChange(
            e.target.checked ? [...value, f.id] : value.filter((id) => id !== f.id),
          )} />
          <span>{f.id}: {f.ingressZone} {f.proto} {f.listenAddress || "ingress-local"}:{f.listenPort} → {f.destIp}:{f.destPort || f.listenPort}{!f.enabled && " (disabled)"}</span>
        </label>
      ))}
    </fieldset>
  );
}
