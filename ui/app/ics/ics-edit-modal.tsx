"use client";

import { useState } from "react";

import {
  api,
  type FirewallRule,
  type ICSPredicate,
  type ICSPredicatePatch,
  type RulePreview,
} from "../../lib/api";
import { InfoTip } from "../../components/InfoTip";
import { RuleImpactSummary } from "../firewall/firewall-rule-warnings";
import {
  buildICSRuleUpdate,
  type ICSMode,
  type ICSModeSelection,
  PROTOCOL_KEYS,
  PROTOCOLS,
  protoMeta,
} from "./ics-shared";
import {
  buildIEC104RuleICS,
  iec104DraftFrom,
} from "./iec104";
import { IEC104Fields } from "./iec104-fields";

export function EditICSModal({
  rule,
  globalMode,
  onClose,
  onSave,
}: {
  rule: FirewallRule;
  globalMode?: ICSMode;
  onClose: () => void;
  /** The predicate to stage; undefined removes it. */
  onSave: (ics: ICSPredicatePatch | undefined) => void;
}) {
  const [enabled, setEnabled] = useState(!!rule.ics?.protocol);
  const [protocol, setProtocol] = useState(rule.ics?.protocol ?? "modbus");
  const [functionCodes, setFunctionCodes] = useState(
    (rule.ics?.functionCode ?? []).join(", "),
  );
  const [addresses, setAddresses] = useState(
    (rule.ics?.addresses ?? []).join(", "),
  );
  const [unitId, setUnitId] = useState(rule.ics?.unitId?.toString() ?? "");
  const [objectClasses, setObjectClasses] = useState(
    (rule.ics?.objectClasses ?? []).map((v) => "0x" + v.toString(16)).join(", "),
  );
  const [readOnly, setReadOnly] = useState(rule.ics?.readOnly ?? false);
  const [writeOnly, setWriteOnly] = useState(rule.ics?.writeOnly ?? false);
  const [mode, setMode] = useState<ICSModeSelection>(rule.ics?.mode ?? "");
  const [iec, setIec] = useState(() => iec104DraftFrom(rule.ics));
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);

  const meta = protoMeta(protocol);
  const isIEC104 = protocol === "iec104";

  // The predicate Save would stage; preview checks the same one.
  function buildICS():
    | { ok: true; ics: ICSPredicate | undefined }
    | { ok: false; error: string } {
    if (!enabled) return { ok: true, ics: undefined };
    if (isIEC104) {
      return buildIEC104RuleICS(iec, mode, rule.action, rule.ics, globalMode);
    }
    return {
      ok: true,
      ics: buildICSRuleUpdate(
        protocol,
        functionCodes,
        addresses,
        unitId,
        objectClasses,
        readOnly,
        writeOnly,
        mode,
      ),
    };
  }

  function save() {
    setError(null);
    const built = buildICS();
    if (!built.ok) {
      setError(built.error);
      return;
    }
    // Rule updates merge, so inheriting clears a stored mode with an empty one.
    onSave(built.ics && mode === "" && rule.ics?.mode ? { ...built.ics, mode: "" } : built.ics);
  }

  // Previews the whole rule with the edited predicate, so the zones, sources,
  // identities and schedule this modal does not edit still apply.
  async function previewImpact() {
    setError(null);
    const built = buildICS();
    if (!built.ok) {
      setError(built.error);
      return;
    }
    setPreviewing(true);
    const res = await api.previewFirewallRule({ ...rule, ics: built.ics });
    setPreviewing(false);
    if (!res.ok) {
      setPreview(null);
      setError(`Impact preview failed: ${res.error}`);
      return;
    }
    setPreview(res.data);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-xl rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-(--text)">
            ICS filter &mdash; rule{" "}
            <span className="font-mono text-(--amber)">{rule.id}</span>
          </h2>
          <button
            onClick={onClose}
            className="rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui"
          >
            Close
          </button>
        </div>

        <div className="space-y-4 text-sm">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)"
            />
            Enable ICS protocol filter
          </label>

          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text)">
                Protocol
                <InfoTip label="Select the ICS/OT protocol for this rule." />
              </label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                disabled={!enabled}
                className="mt-1 w-full input-industrial disabled:opacity-60"
              >
                {PROTOCOL_KEYS.map((k) => (
                  <option key={k} value={k}>
                    {PROTOCOLS[k].label} (port {PROTOCOLS[k].port})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text)">
                Safety mode
                <InfoTip label="Safe learning only alerts; enforce will block on match." />
              </label>
              <select
                aria-label="Safety mode"
                value={mode}
                onChange={(e) => setMode(e.target.value as ICSModeSelection)}
                disabled={!enabled}
                className="mt-1 w-full input-industrial disabled:opacity-60"
              >
                <option value="">
                  Inherit global ({globalMode === "enforce" ? "enforce" : "learning"})
                </option>
                <option value="learn">Safe learning (alert-only)</option>
                <option value="enforce">Enforce (block)</option>
              </select>
            </div>
          </div>

          {isIEC104 ? (
            <IEC104Fields draft={iec} onChange={setIec} disabled={!enabled} />
          ) : (
            <>
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text)">
                {meta.fcLabel}
                <InfoTip label={meta.fcHelp} />
              </label>
              <input
                value={functionCodes}
                onChange={(e) => setFunctionCodes(e.target.value)}
                disabled={!enabled}
                className="mt-1 w-full input-industrial disabled:opacity-60"
                placeholder={meta.fcPlaceholder || "Leave empty for all"}
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text)">
                {meta.addrLabel}
                <InfoTip label={meta.addrHelp} />
              </label>
              <input
                value={addresses}
                onChange={(e) => setAddresses(e.target.value)}
                disabled={!enabled}
                className="mt-1 w-full input-industrial disabled:opacity-60"
                placeholder={meta.addrPlaceholder || "Leave empty for all"}
              />
            </div>

            {protocol === "modbus" && (
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text)">
                  Unit ID
                  <InfoTip label="Modbus unit identifier (slave address). 0-255. Leave empty for all." />
                </label>
                <input
                  value={unitId}
                  onChange={(e) => setUnitId(e.target.value)}
                  disabled={!enabled}
                  className="mt-1 w-full input-industrial disabled:opacity-60"
                  placeholder="0-255 (leave empty for all)"
                />
              </div>
            )}

            {protocol === "cip" && (
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text)">
                  Object Classes
                  <InfoTip label="CIP object class IDs (comma-separated, hex with 0x prefix or decimal). Leave empty for all." />
                </label>
                <input
                  value={objectClasses}
                  onChange={(e) => setObjectClasses(e.target.value)}
                  disabled={!enabled}
                  className="mt-1 w-full input-industrial disabled:opacity-60"
                  placeholder="0x02, 0x04 (leave empty for all)"
                />
              </div>
            )}

            <div className="grid gap-3 md:grid-cols-2">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={readOnly}
                  onChange={(e) => {
                    setReadOnly(e.target.checked);
                    if (e.target.checked) setWriteOnly(false);
                  }}
                  disabled={!enabled}
                  className="h-4 w-4 rounded-sm border-white/20 bg-(--surface) disabled:opacity-60"
                />
                Read-only
                <InfoTip label="Only match read operations. Mutually exclusive with write-only." />
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={writeOnly}
                  onChange={(e) => {
                    setWriteOnly(e.target.checked);
                    if (e.target.checked) setReadOnly(false);
                  }}
                  disabled={!enabled}
                  className="h-4 w-4 rounded-sm border-white/20 bg-(--surface) disabled:opacity-60"
                />
                Write-only
                <InfoTip label="Only match write/control operations. Mutually exclusive with read-only." />
              </label>
            </div>
            </>
          )}

          <div className="rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text-muted)">
            <strong className="text-(--text)">{meta.label}</strong> &mdash;
            port {meta.port}.{" "}
            {protocol === "modbus" &&
              "Common: 3=Read Holding Regs, 4=Read Input Regs, 5=Write Single Coil, 6=Write Single Reg, 15=Write Multiple Coils, 16=Write Multiple Regs."}
            {protocol === "dnp3" &&
              "Common: 1=Read, 2=Write, 3=Select, 4=Operate, 13=Cold Restart, 14=Warm Restart, 18=Stop Application."}
            {protocol === "cip" &&
              "Common: 0x4C(76)=Read Tag, 0x4D(77)=Write Tag, 0x0E(14)=Get Attribute, 0x10(16)=Set Attribute."}
            {protocol === "s7comm" &&
              "Common: 4=Read Var, 5=Write Var, 0x28(40)=PLC Control, 0x29(41)=PLC Stop."}
            {protocol === "mms" &&
              "IEC 61850 Manufacturing Message Specification over ISO/ACSE."}
            {protocol === "bacnet" &&
              "Common: 12=ReadProperty, 14=ReadPropertyMultiple, 15=WriteProperty, 8=WhoIs, 0=IAm."}
            {protocol === "opcua" &&
              "OPC Unified Architecture binary protocol."}
            {isIEC104 &&
              "First course types: 1, 3, 13, 30, 31 (monitor), 46 (double command), 100 (general interrogation). Unmatched IEC 104 traffic inside an enforce envelope is denied and the session is reset."}
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>

        {preview && <RuleImpactSummary preview={preview} />}
        <div className="mt-5 flex items-center justify-end gap-2">
          <button
            onClick={previewImpact}
            disabled={previewing}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
          >
            {previewing ? "Previewing..." : "Preview impact"}
          </button>
          <button
            onClick={onClose}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
          >
            Save filter
          </button>
        </div>
      </div>
    </div>
  );
}
