"use client";

import { addressFilterError, protoMeta } from "./ics-shared";

/** Unsupported stored filters stay visible until the user explicitly removes them. */
export function ICSAddressFields({
  protocol, addresses, onChange, disabled = false,
}: {
  protocol: string;
  addresses: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const error = addressFilterError(protocol, addresses);
  if (error) {
    return (
      <div className="space-y-2">
        <p role="alert" className="text-sm text-red-400">{error}</p>
        <div className="text-sm text-(--text)">
          Existing address filter: <code className="break-all">{addresses}</code>
        </div>
        <button
          type="button"
          disabled={disabled}
          onClick={() => onChange("")}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) disabled:opacity-50"
        >
          Remove address filter
        </button>
      </div>
    );
  }
  if (protocol !== "modbus") return null;
  const meta = protoMeta(protocol);
  return (
    <label className="block text-xs text-(--text)">
      {meta.addrLabel}
      <input
        aria-label={meta.addrLabel}
        value={addresses}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="mt-1 w-full input-industrial disabled:opacity-60"
        placeholder={meta.addrPlaceholder}
      />
      <span className="mt-1 block text-(--text-muted)">{meta.addrHelp}</span>
    </label>
  );
}
