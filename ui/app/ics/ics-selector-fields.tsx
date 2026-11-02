"use client";

import { UNSUPPORTED_UNIT_ID, type GenericSelectorDraft } from "./ics-shared";
import { Disclosure } from "../../components/Disclosure";

/** Shared by both rule editors; blank selectors mean ANY. */
export function ICSSelectorFields({
  protocol, draft, onChange, unitId, onUnitIdChange, disabled,
}: {
  protocol: string;
  draft: GenericSelectorDraft;
  onChange: (draft: GenericSelectorDraft) => void;
  unitId: string;
  onUnitIdChange: (value: string) => void;
  disabled?: boolean;
}) {
  const fields = protocol === "dnp3"
    ? [["masters", "Masters (0-65519)"], ["outstations", "Outstations (0-65519)"], ["groups", "Object groups (0-255)"], ["variations", "Variations (0-255)"]] as const
    : protocol === "cip"
      ? [["instances", "Instances (0-65535)"], ["attributes", "Attributes (0-65535)"], ["tags", "Tag paths"]] as const
      : [];
  const advancedSet = fields.some(([key]) => draft[key].trim() !== "") || draft.direction !== "";
  return (
    <div className="space-y-3">
      {(protocol === "dnp3" || protocol === "cip") && unitId !== "" && (
        <div className="space-y-2">
          <p role="alert" className="text-sm text-red-400">{UNSUPPORTED_UNIT_ID}</p>
          <p className="break-words text-xs text-(--text-muted)">Existing unitId: <code>{unitId}</code></p>
          <button type="button" disabled={disabled} onClick={() => onUnitIdChange("")} className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) disabled:opacity-50">
            Remove unit ID filter
          </button>
        </div>
      )}
      <Disclosure title="Advanced protocol fields"
        defaultOpen={advancedSet}
        indicator={advancedSet ? "Protocol fields set — values still apply" : undefined}>
        <div className="mt-2 grid gap-3 md:grid-cols-2">
          {fields.map(([key, label]) => (
            <label key={key} className="block text-xs text-(--text)">
              {label}
              <input aria-label={label} value={draft[key]} disabled={disabled} onChange={(e) => onChange({ ...draft, [key]: e.target.value })} placeholder="Empty = any; comma-separated" className="mt-1 input-industrial w-full disabled:opacity-60" />
            </label>
          ))}
          <label className="block text-xs text-(--text)">Direction
            <select aria-label="Direction" value={draft.direction} disabled={disabled} onChange={(e) => onChange({ ...draft, direction: e.target.value as GenericSelectorDraft["direction"] })} className="mt-1 input-industrial w-full disabled:opacity-60">
              <option value="">Any</option><option value="request">Request</option><option value="response">Response</option>
            </select>
          </label>
        </div>
        {protocol === "dnp3" && <p className="text-xs text-(--text-muted)">Station filters apply to application messages, not link-only frames. Variation 0 is not a wildcard: ALLOW must list 0; a constrained DENY always matches wire variation 0.</p>}
        {protocol === "cip" && <p className="text-xs text-(--text-muted)">Tags cannot combine with logical class/instance/attribute selectors. Names are case-insensitive subtrees, including all elements. Tag DENY does not see logical targets; prefer tag ALLOW lists with default deny.</p>}
      </Disclosure>
    </div>
  );
}
