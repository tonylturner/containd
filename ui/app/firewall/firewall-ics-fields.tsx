"use client";

import { useState } from "react";

import { InfoTip } from "../../components/InfoTip";
import type { FirewallRule, ICSPredicate } from "../../lib/api";
import { buildIEC104RuleICS, type IEC104Draft } from "../ics/iec104";
import { IEC104Fields } from "../ics/iec104-fields";
import { formatICSMode, type ICSMode, type ICSModeSelection } from "../ics/ics-shared";
import { ICS_PROTOCOL_KEYS, ICS_PROTOCOLS, icsProtoMeta } from "./firewall-utils";

// The ICS predicate part of the firewall rule forms: its fields and the
// predicate they build.

export function ICSPredicateFields({
  protocol, onProtocolChange,
  mode, onModeChange, globalMode,
  functionCodes, onFunctionCodesChange,
  addresses, onAddressesChange,
  unitId, onUnitIdChange,
  objectClasses, onObjectClassesChange,
  readOnly, onReadOnlyChange,
  writeOnly, onWriteOnlyChange,
  iec, onIecChange,
}: {
  protocol: string; onProtocolChange: (v: string) => void;
  mode: ICSModeSelection; onModeChange: (v: ICSModeSelection) => void;
  /** The global DPI mode an empty rule mode inherits. */
  globalMode: string | undefined;
  functionCodes: string; onFunctionCodesChange: (v: string) => void;
  addresses: string; onAddressesChange: (v: string) => void;
  unitId: string; onUnitIdChange: (v: string) => void;
  objectClasses: string; onObjectClassesChange: (v: string) => void;
  readOnly: boolean; onReadOnlyChange: (v: boolean) => void;
  writeOnly: boolean; onWriteOnlyChange: (v: boolean) => void;
  iec: IEC104Draft; onIecChange: (v: IEC104Draft) => void;
}) {
  const meta = icsProtoMeta(protocol);
  const [showHelp, setShowHelp] = useState(false);

  return (
    <div className="mt-3 rounded-xs border bg-(--surface) p-4 space-y-3">
      <div className="grid gap-3 md:grid-cols-4">
        <div className="md:col-span-2">
          <label className="block text-[10px] font-medium text-(--text-muted) mb-1">ICS Protocol</label>
          <select value={protocol} onChange={(e) => onProtocolChange(e.target.value)} className="input-industrial w-full">
            {ICS_PROTOCOL_KEYS.map((k) => (<option key={k} value={k}>{ICS_PROTOCOLS[k].label} (:{ICS_PROTOCOLS[k].port})</option>))}
          </select>
        </div>
        <div>
          <label className="block text-[10px] font-medium text-(--text-muted) mb-1">Rule Mode</label>
          <select aria-label="Rule Mode" value={mode} onChange={(e) => onModeChange(e.target.value as ICSModeSelection)} className="input-industrial w-full">
            <option value="">Inherit global ({formatICSMode(undefined, globalMode).effectiveMode === "enforce" ? "enforce" : "learning"})</option>
            <option value="learn">Learning (passive)</option>
            <option value="enforce">Enforcement (after commit)</option>
          </select>
        </div>
        <div className="flex items-end">
          <button
            onClick={() => setShowHelp(!showHelp)}
            className="rounded-xs border border-blue-500/20 bg-blue-500/10 px-2.5 py-2 text-[10px] text-blue-400 hover:bg-blue-500/20 transition-ui w-full"
          >
            {showHelp ? "Hide" : "Show"} protocol reference
          </button>
        </div>
      </div>

      {showHelp && (
        <div className="rounded-xs border border-blue-500/10 bg-blue-500/3 p-3 space-y-2">
          <div className="text-xs font-medium text-blue-400">{meta.label} Reference</div>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <div className="text-[10px] font-medium text-(--text)">{meta.fcLabel}</div>
              <div className="text-[10px] text-(--text-muted) mt-0.5 leading-relaxed">{meta.fcHelp}</div>
            </div>
            <div>
              <div className="text-[10px] font-medium text-(--text)">{meta.addrLabel}</div>
              <div className="text-[10px] text-(--text-muted) mt-0.5 leading-relaxed">{meta.addrHelp}</div>
            </div>
          </div>
          {meta.notes && (
            <div className="text-[10px] text-(--text-dim) border-t border-white/4 pt-2 mt-2">{meta.notes}</div>
          )}
        </div>
      )}

      {protocol === "iec104" ? (
        <IEC104Fields draft={iec} onChange={onIecChange} />
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="block text-[10px] font-medium text-(--text-muted) mb-1">{meta.fcLabel} <span className="text-(--text-dim)">(comma-separated)</span></label>
              <input value={functionCodes} onChange={(e) => onFunctionCodesChange(e.target.value)} placeholder={meta.fcPlaceholder || `${meta.fcLabel}`} className="input-industrial w-full" />
            </div>
            <div>
              <label className="block text-[10px] font-medium text-(--text-muted) mb-1">{meta.addrLabel} <span className="text-(--text-dim)">(comma-separated)</span></label>
              <input value={addresses} onChange={(e) => onAddressesChange(e.target.value)} placeholder={meta.addrPlaceholder || meta.addrLabel} className="input-industrial w-full" />
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            {meta.showUnitId && (
              <div>
                <label className="block text-[10px] font-medium text-(--text-muted) mb-1">Unit ID <span className="text-(--text-dim)">(0-255, Modbus slave)</span></label>
                <input value={unitId} onChange={(e) => onUnitIdChange(e.target.value)} placeholder="e.g. 1" className="input-industrial w-full" />
              </div>
            )}
            {meta.showObjectClasses && (
              <div className="md:col-span-2">
                <label className="block text-[10px] font-medium text-(--text-muted) mb-1">CIP Object Classes <span className="text-(--text-dim)">(hex csv)</span></label>
                <input value={objectClasses} onChange={(e) => onObjectClassesChange(e.target.value)} placeholder="0x02, 0x04, 0x66" className="input-industrial w-full" />
              </div>
            )}
            {meta.showStationAddrs && (
              <div className="md:col-span-2">
                <label className="block text-[10px] font-medium text-(--text-muted) mb-1">Station Addresses <span className="text-(--text-dim)">(source/destination, 0-65534)</span></label>
                <input value={addresses} onChange={(e) => onAddressesChange(e.target.value)} placeholder="1-10" className="input-industrial w-full" />
              </div>
            )}
            {meta.showDbNumber && (
              <div>
                <label className="block text-[10px] font-medium text-(--text-muted) mb-1">DB Numbers <span className="text-(--text-dim)">(Siemens data blocks)</span></label>
                <input value={addresses} onChange={(e) => onAddressesChange(e.target.value)} placeholder="DB1, DB100" className="input-industrial w-full" />
              </div>
            )}
            {meta.showObjectType && (
              <div>
                <label className="block text-[10px] font-medium text-(--text-muted) mb-1">Object Type <span className="text-(--text-dim)">(BACnet)</span></label>
                <input disabled placeholder="analog-input, binary-output" className="input-industrial w-full opacity-60" title="Object type filtering coming soon" />
              </div>
            )}
            {meta.showPropertyId && (
              <div>
                <label className="block text-[10px] font-medium text-(--text-muted) mb-1">Property ID <span className="text-(--text-dim)">(BACnet)</span></label>
                <input disabled placeholder="85 (present-value)" className="input-industrial w-full opacity-60" title="Property ID filtering coming soon" />
              </div>
            )}
          </div>

          <div className="flex items-center gap-4 text-sm text-(--text)">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={readOnly} onChange={(e) => onReadOnlyChange(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
              Read-only
              <InfoTip label="Only match read operations (function codes that read data without modifying state)." />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={writeOnly} onChange={(e) => onWriteOnlyChange(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
              Write-only
              <InfoTip label="Only match write/control operations (function codes that modify device state)." />
            </label>
          </div>
        </>
      )}
    </div>
  );
}

type RuleICSInput = {
  enabled: boolean;
  protocol: string;
  functionCodes: string;
  addresses: string;
  unitId: string;
  objectClasses: string;
  readOnly: boolean;
  writeOnly: boolean;
  mode: ICSModeSelection;
  globalMode?: ICSMode;
  iec: IEC104Draft;
  action: FirewallRule["action"];
  existing?: ICSPredicate;
};

export function buildRuleICS(
  input: RuleICSInput,
): { ok: true; ics: ICSPredicate | undefined } | { ok: false; error: string } {
  if (!input.enabled) return { ok: true, ics: undefined };
  if (input.protocol === "iec104") {
    return buildIEC104RuleICS(input.iec, input.mode, input.action, input.existing, input.globalMode);
  }
  return { ok: true, ics: buildICSPredicate(input) };
}

function buildICSPredicate({
  protocol,
  functionCodes,
  addresses,
  unitId,
  objectClasses,
  readOnly,
  writeOnly,
  mode,
}: RuleICSInput): ICSPredicate {
  const icsMeta = icsProtoMeta(protocol);
  const ics: ICSPredicate = {
    protocol,
    functionCode: functionCodes
      .split(",")
      .map((v) => Number(v.trim()))
      .filter((n) => Number.isFinite(n))
      .map((n) => Math.max(0, Math.min(255, n))),
    addresses: addresses.split(",").map((s) => s.trim()).filter(Boolean),
    readOnly,
    writeOnly,
    ...(mode ? { mode } : {}),
  };
  if (icsMeta.showUnitId && unitId.trim()) {
    const uid = Number(unitId.trim());
    if (Number.isFinite(uid) && uid >= 0 && uid <= 255) ics.unitId = uid;
  }
  if (icsMeta.showObjectClasses && objectClasses.trim()) {
    ics.objectClasses = objectClasses
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => parseInt(s, s.startsWith("0x") ? 16 : 10))
      .filter((n) => Number.isFinite(n) && n >= 0);
  }
  if ((ics.functionCode?.length ?? 0) === 0) delete ics.functionCode;
  if ((ics.addresses?.length ?? 0) === 0) delete ics.addresses;
  if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;
  return ics;
}
