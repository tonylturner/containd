"use client";

import { useState } from "react";

import type { FirewallRule, ICSPredicate } from "../../lib/api";
import { InfoTip } from "../../components/InfoTip";
import { RulePreviewButton } from "../../components/RulePreview";
import {
  buildICSRulePreview,
  buildICSRuleUpdate,
  PROTOCOL_KEYS,
  PROTOCOLS,
  protoMeta,
} from "./ics-shared";

export function EditICSModal({
  rule,
  onClose,
  onSave,
}: {
  rule: FirewallRule;
  onClose: () => void;
  onSave: (ics: ICSPredicate | undefined) => void;
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
  const [mode, setMode] = useState<"enforce" | "learn">(
    rule.ics?.mode ?? "learn",
  );

  const meta = protoMeta(protocol);

  function save() {
    if (!enabled) {
      onSave(undefined);
      return;
    }
    onSave(
      buildICSRuleUpdate(
        protocol,
        functionCodes,
        addresses,
        unitId,
        objectClasses,
        readOnly,
        writeOnly,
        mode,
      ),
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[var(--text)]">
            ICS filter &mdash; rule{" "}
            <span className="font-mono text-[var(--amber)]">{rule.id}</span>
          </h2>
          <button
            onClick={onClose}
            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
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
              className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
            />
            Enable ICS protocol filter
          </label>

          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
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
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
                Safety mode
                <InfoTip label="Safe learning only alerts; enforce will block on match." />
              </label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as "enforce" | "learn")}
                disabled={!enabled}
                className="mt-1 w-full input-industrial disabled:opacity-60"
              >
                <option value="learn">Safe learning (alert-only)</option>
                <option value="enforce">Enforce (block)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
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
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
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
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
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
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
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
                className="h-4 w-4 rounded border-white/20 bg-[var(--surface)] disabled:opacity-60"
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
                className="h-4 w-4 rounded border-white/20 bg-[var(--surface)] disabled:opacity-60"
              />
              Write-only
              <InfoTip label="Only match write/control operations. Mutually exclusive with read-only." />
            </label>
          </div>

          <div className="rounded-sm border border-amber-500/[0.1] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text-muted)]">
            <strong className="text-[var(--text)]">{meta.label}</strong> &mdash;
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
          </div>
        </div>

        <div className="mt-5 flex items-center justify-end gap-2">
          <RulePreviewButton
            rule={buildICSRulePreview(
              rule,
              enabled,
              protocol,
              functionCodes,
              addresses,
              readOnly,
              writeOnly,
              mode,
            )}
          />
          <button
            onClick={onClose}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
          >
            Save filter
          </button>
        </div>
      </div>
    </div>
  );
}
