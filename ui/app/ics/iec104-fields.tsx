"use client";

import { InfoTip } from "../../components/InfoTip";
import type { IEC104Class } from "../../lib/api";
import {
  IEC104_CLASSES,
  iec104TypeInfo,
  parseTypeIds,
  type IEC104Draft,
} from "./iec104";

export const IEC104_CLASS_CHIP: Record<IEC104Class, string> = {
  monitor: "border-emerald-500/20 bg-emerald-500/10 text-emerald-400",
  control: "border-red-500/20 bg-red-500/10 text-red-400",
  system: "border-blue-500/20 bg-blue-500/10 text-blue-400",
  unknown: "border-white/[0.06] bg-white/[0.02] text-[var(--text-dim)]",
};

const CHIP_OFF =
  "border-white/[0.06] bg-white/[0.02] text-[var(--text-dim)] line-through";

const LABEL = "block text-[10px] font-medium text-[var(--text-muted)] mb-1";

/** IEC 104 predicate inputs. Mode is owned by the surrounding editor. */
export function IEC104Fields({
  draft,
  onChange,
  disabled,
}: {
  draft: IEC104Draft;
  onChange: (next: IEC104Draft) => void;
  disabled?: boolean;
}) {
  const parsedTypes = parseTypeIds(draft.typeIds);

  function set<K extends keyof IEC104Draft>(key: K, value: IEC104Draft[K]) {
    onChange({ ...draft, [key]: value });
  }

  function toggleClass(c: IEC104Class) {
    set(
      "classes",
      draft.classes.includes(c)
        ? draft.classes.filter((x) => x !== c)
        : [...draft.classes, c],
    );
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <label className={LABEL}>
            Type IDs <span className="text-[var(--text-dim)]">(comma-separated, 1-255; empty = any)</span>
          </label>
          <input
            value={draft.typeIds}
            onChange={(e) => set("typeIds", e.target.value)}
            disabled={disabled}
            placeholder="46, 100"
            className="input-industrial w-full disabled:opacity-60"
          />
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {parsedTypes.ok ? (
              parsedTypes.value.map((t) => {
                const info = iec104TypeInfo(t);
                return (
                  <span
                    key={t}
                    title={info.name}
                    className={`rounded-sm border px-1.5 py-0.5 text-[9px] ${IEC104_CLASS_CHIP[info.cls]}`}
                  >
                    {t} · {info.cls}
                    {!info.descriptor && " · not decoded"}
                  </span>
                );
              })
            ) : (
              <span className="text-[10px] text-red-400">{parsedTypes.error}</span>
            )}
          </div>
        </div>
        <div>
          <label className={LABEL}>
            Classes <span className="text-[var(--text-dim)]">(any selected; none = any)</span>
          </label>
          <div className="flex flex-wrap gap-1.5 pt-1">
            {IEC104_CLASSES.map((c) => {
              const on = draft.classes.includes(c);
              return (
                <button
                  key={c}
                  type="button"
                  aria-pressed={on}
                  disabled={disabled}
                  onClick={() => toggleClass(c)}
                  className={`rounded-sm border px-2 py-1 text-[10px] transition-ui disabled:opacity-60 ${on ? IEC104_CLASS_CHIP[c] : CHIP_OFF}`}
                >
                  {c}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <div>
          <label className={LABEL}>Direction</label>
          <select
            value={draft.direction}
            onChange={(e) => set("direction", e.target.value as IEC104Draft["direction"])}
            disabled={disabled}
            className="input-industrial w-full disabled:opacity-60"
          >
            <option value="">Both halves of the session</option>
            <option value="request">Request (client to server)</option>
            <option value="response">Response (server to client)</option>
          </select>
        </div>
        <div>
          <label className={LABEL}>
            Common address (CA) <span className="text-[var(--text-dim)]">(0-65534)</span>
          </label>
          <input
            value={draft.ca}
            onChange={(e) => set("ca", e.target.value)}
            disabled={disabled}
            placeholder="1"
            className="input-industrial w-full disabled:opacity-60"
          />
        </div>
        <div>
          <label className={LABEL}>
            IOA ranges <span className="text-[var(--text-dim)]">(0-16777215)</span>
          </label>
          <input
            value={draft.ioa}
            onChange={(e) => set("ioa", e.target.value)}
            disabled={disabled}
            placeholder="2001, 65536-65567"
            className="input-industrial w-full disabled:opacity-60"
          />
        </div>
      </div>

      <label className="flex items-center gap-2 text-sm text-[var(--text)]">
        <input
          type="checkbox"
          checked={draft.readOnly}
          onChange={(e) => set("readOnly", e.target.checked)}
          disabled={disabled}
          className="h-4 w-4 rounded border-white/20 bg-[var(--surface)] disabled:opacity-60"
        />
        Read-only
        <InfoTip label="Matches monitor data from the server, general interrogation, read requests, end of initialization, S-frames and STARTDT/STOPDT/TESTFR. It never matches commands, counter interrogation, clock sync, reset process, broadcast CA, or malformed or unsupported traffic. Unchecked means no access constraint, not write-only." />
      </label>
      <div className="text-[10px] text-[var(--text-dim)]">
        Rules match the session (client to port 2404) in both directions; Direction picks which half. CA and IOA need an object, so S- and U-frames never match a rule that sets them. Broadcast CA 65535 never matches an allow rule.
      </div>
    </div>
  );
}
