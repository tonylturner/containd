"use client";

import type { ICSPredicate } from "../../lib/api";
import { messageClassError } from "./ics-shared";

export function ICSMessageClass({ value, direction, onChange, disabled }: {
  value: NonNullable<ICSPredicate["messageClass"]> | "";
  direction: string;
  onChange: (value: NonNullable<ICSPredicate["messageClass"]> | "") => void;
  disabled?: boolean;
}) {
  const error = messageClassError(value, direction);
  return (
    <div className="space-y-2">
      <label className="block text-xs text-(--text)">Message class
        <select aria-label="Message class" value={value} disabled={disabled}
          onChange={e => onChange(e.target.value as typeof value)}
          className="mt-1 input-industrial w-full disabled:opacity-60">
          <option value="">Ordinary (selector omitted)</option>
          <option value="autonomous">Autonomous</option>
          <option value="session">Session</option>
        </select>
      </label>
      <p className="text-xs text-(--text-muted)">In enforce mode, ordinary ALLOW covers requests and paired replies, not autonomous data or session controls. Autonomous is response-only; both explicit classes require direction. Station and point filters remain optional where applicable; session controls have no application object selectors.</p>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    </div>
  );
}
