"use client";

import type { FirewallRule, Position } from "../../lib/api";
import { useEffect, useRef, useState } from "react";

export function MoveRuleDialog({ available, rule, rules, onMove, onClose }: {
  available: boolean;
  rule: FirewallRule;
  rules: FirewallRule[];
  onMove: (position: Position) => void;
  onClose: () => void;
}) {
  const [position, setPosition] = useState<Position>("bottom");
  const dialog = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog.current?.querySelector("select")?.focus();
    return () => previous?.focus();
  }, []);
  return (
    <div ref={dialog} role="dialog" aria-modal="true" aria-label={`Move rule ${rule.id}`} className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onKeyDown={(e) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
      if (e.key !== "Tab") return;
      const controls = dialog.current?.querySelectorAll<HTMLElement>("select:not(:disabled), button:not(:disabled)");
      if (!controls?.length) return;
      const first = controls[0], last = controls[controls.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }}>
      <div className="w-full max-w-md space-y-4 rounded-xs border bg-(--surface) p-6 shadow-card-lg">
        <h2 className="text-sm font-semibold text-(--text)">Move rule {rule.id}</h2>
        <RulePositionSelect disabled={!available} rules={rules.filter((r) => r.id !== rule.id)} value={position} onChange={setPosition} />
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="rounded-xs border bg-(--surface2) px-3 py-2 text-sm">Cancel</button>
          <button disabled={!available} onClick={() => onMove(position)} className="rounded-xs bg-(--amber) px-3 py-2 text-sm text-white">Move</button>
        </div>
      </div>
    </div>
  );
}

/** The same explicit placements are available when creating and moving rules. */
export function RulePositionSelect({
  rules, value, onChange, label = "Position", disabled,
}: {
  rules: FirewallRule[];
  value?: Position;
  onChange: (position: Position) => void;
  label?: string;
  disabled?: boolean;
}) {
  const anchor = value && typeof value === "object" ? ("before" in value ? value.before : value.after) : undefined;
  const missingAnchor = anchor !== undefined && !rules.some((r) => r.id === anchor);
  return (
    <label className="text-xs text-(--text)">
      <span className="mr-2">{label}</span>
      <select
        aria-label={label}
        className="input-industrial"
        disabled={disabled}
        value={value === undefined ? "" : JSON.stringify(value)}
        onChange={(e) => onChange(JSON.parse(e.target.value) as Position)}
      >
        {value === undefined && <option value="" disabled>Choose position</option>}
        <option value={'"top"'}>Top</option>
        <option value={'"bottom"'}>Bottom</option>
        {missingAnchor && <option value={JSON.stringify(value)}>{value && typeof value === "object" && "before" in value ? "Before" : "After"} {anchor} (no longer on server)</option>}
        {rules.map((r) => (
          <optgroup key={r.id} label={r.id}>
            <option value={JSON.stringify({ before: r.id })}>Before {r.id}</option>
            <option value={JSON.stringify({ after: r.id })}>After {r.id}</option>
          </optgroup>
        ))}
      </select>
    </label>
  );
}
