"use client";

import { formatICSMode, type ICSModeSelection } from "./ics-shared";
import { ICSInlinePrerequisite } from "./ics-inline-prerequisite";

/** Shared candidate-mode control; the global fallback itself defaults to monitor. */
export function ICSModeSelect({ value, onChange, globalMode, label = "Rule Mode", disabled = false, inlineConfigured, onSetupInline }: {
  value: ICSModeSelection;
  onChange: (value: ICSModeSelection) => void;
  globalMode?: string;
  label?: string;
  disabled?: boolean;
  inlineConfigured?: boolean;
  onSetupInline?: () => void;
}) {
  return (
    <div className="text-xs text-(--text-muted)">
      <label className="block">
        {label}
        <select aria-label={label} value={value} disabled={disabled}
          onChange={(event) => onChange(event.target.value as ICSModeSelection)}
          className="mt-1 input-industrial w-full disabled:opacity-60">
          <option value="">{formatICSMode(undefined, globalMode).label}</option>
          <option value="monitor">Monitor (safe)</option>
          <option value="enforce">Enforce</option>
        </select>
      </label>
      <span className="mt-1 block text-xs text-(--text-muted)">Monitor never admits or blocks; other enforcing rules, defaults and strict scopes still apply.</span>
      {formatICSMode(value, globalMode).effectiveMode === "enforce" && <ICSInlinePrerequisite configured={inlineConfigured} onSetup={onSetupInline} />}
    </div>
  );
}
