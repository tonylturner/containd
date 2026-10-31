"use client";

import { useEffect, useRef, useState } from "react";
import { ConfigEditNotice, useConfigEditor } from "../../lib/use-config-editor";
import { sameConfig } from "../../lib/config-editor";

import {
  api,
  type FirewallRule,
  type ICSPredicatePatch,
  type RulePreview,
} from "../../lib/api";
import { InfoTip } from "../../components/InfoTip";
import { RuleImpactSummary } from "../firewall/firewall-rule-warnings";
import {
  genericSelectorDraftFrom,
  effectivePredicate,
  selectorFieldError,
  icsAddressDraftFrom,
  type ICSModeSelection,
  PROTOCOL_KEYS,
  PROTOCOLS,
  protoMeta,
} from "./ics-shared";
import { iec104DraftFrom } from "./iec104";
import { buildRuleICS } from "../firewall/firewall-ics-fields";
import { ICSModeSelect } from "./ics-mode-select";
import { ICSSelectorFields } from "./ics-selector-fields";
import { IEC104Fields } from "./iec104-fields";
import { ICSAddressFields } from "./ics-address-fields";

function filterDraftFrom(rule: FirewallRule, rules: FirewallRule[], globalMode: ICSModeSelection | undefined) {
  return {
    context: { rules, globalMode },
    enabled: !!rule.ics?.protocol,
    protocol: rule.ics?.protocol ?? "modbus",
    functionCodes: (rule.ics?.functionCode ?? []).join(", "),
    addresses: icsAddressDraftFrom(rule.ics),
    unitId: rule.ics?.unitId?.toString() ?? "",
    objectClasses: (rule.ics?.objectClasses ?? []).map((v) => "0x" + v.toString(16)).join(", "),
    readOnly: rule.ics?.readOnly ?? false,
    writeOnly: rule.ics?.writeOnly ?? false,
    mode: (rule.ics?.mode ?? "") as ICSModeSelection,
    selectors: genericSelectorDraftFrom(rule.ics),
    iec: iec104DraftFrom(rule.ics),
  };
}

export function EditICSModal({
  context,
  rule,
  globalMode,
  onClose,
  onSave,
}: {
  context: FirewallRule[];
  rule: FirewallRule;
  globalMode?: ICSModeSelection;
  onClose: () => void;
  /** The predicate to stage; undefined removes it. */
  onSave: (ics: ICSPredicatePatch | undefined) => Promise<FirewallRule | null>;
}) {
  const draft = useConfigEditor(() => filterDraftFrom(rule, context, globalMode));
  const { cfg, setCfg, adoptConfig } = draft;
  const latest = useRef(draft.editor);
  latest.current = draft.editor;
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { adoptConfig(filterDraftFrom(rule, context, globalMode)); }, [adoptConfig, rule, context, globalMode]);
  const enabled = cfg.enabled;
  const setEnabled = (enabled: typeof cfg.enabled) => setCfg((c) => ({ ...c, enabled }));
  const protocol = cfg.protocol;
  const setProtocol = (protocol: typeof cfg.protocol) => setCfg((c) => ({ ...c, protocol }));
  const functionCodes = cfg.functionCodes;
  const setFunctionCodes = (functionCodes: typeof cfg.functionCodes) => setCfg((c) => ({ ...c, functionCodes }));
  const addresses = cfg.addresses;
  const setAddresses = (addresses: typeof cfg.addresses) => setCfg((c) => ({ ...c, addresses }));
  const unitId = cfg.unitId;
  const setUnitId = (unitId: typeof cfg.unitId) => setCfg((c) => ({ ...c, unitId }));
  const objectClasses = cfg.objectClasses;
  const setObjectClasses = (objectClasses: typeof cfg.objectClasses) => setCfg((c) => ({ ...c, objectClasses }));
  const readOnly = cfg.readOnly;
  const setReadOnly = (readOnly: typeof cfg.readOnly) => setCfg((c) => ({ ...c, readOnly }));
  const writeOnly = cfg.writeOnly;
  const setWriteOnly = (writeOnly: typeof cfg.writeOnly) => setCfg((c) => ({ ...c, writeOnly }));
  const mode = cfg.mode;
  const setMode = (mode: typeof cfg.mode) => setCfg((c) => ({ ...c, mode }));
  const selectors = cfg.selectors;
  const setSelectors = (selectors: typeof cfg.selectors) => setCfg((c) => ({ ...c, selectors }));
  const iec = cfg.iec;
  const setIec = (iec: typeof cfg.iec) => setCfg((c) => ({ ...c, iec }));
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [saving, setSaving] = useState(false);

  const meta = protoMeta(protocol);
  const selectorError = enabled ? selectorFieldError(protocol, functionCodes, unitId, objectClasses) : null;
  const isIEC104 = protocol === "iec104";

  // Both surfaces use the same validated builder. Only PATCH carries nulls.
  function buildICS() {
    return buildRuleICS({ enabled, protocol, functionCodes, addresses, unitId,
      objectClasses, readOnly, writeOnly, mode, iec, selectors,
      action: rule.action, existing: rule.ics, globalMode });
  }

  async function save() {
    setError(null);
    const built = buildICS();
    if (!built.ok) {
      setError(built.error);
      return;
    }
    const submitted = draft.beginSave();
    setSaving(true);
    const saved = await onSave(built.ics);
    setSaving(false);
    if (!saved || !mounted.current) { draft.failSave(submitted); return; }
    draft.acceptConfig(submitted, filterDraftFrom(saved, context, globalMode));
    if (sameConfig(latest.current.cfg, submitted.cfg)) onClose();
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
    const res = await api.previewFirewallRule({ ...rule, ics: effectivePredicate(built.ics) });
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
      <div className="max-h-[95vh] overflow-y-auto w-full max-w-xl rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
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

        <ConfigEditNotice superseded={draft.editor.superseded} />
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
            {enabled && protocol && <ICSModeSelect value={mode} onChange={setMode} globalMode={globalMode} label="Safety mode" />}
          </div>

          {selectorError && <p role="alert" className="text-sm text-red-400">{selectorError}</p>}
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

            <ICSAddressFields protocol={protocol} addresses={addresses} onChange={setAddresses} disabled={!enabled} />

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

            <ICSSelectorFields protocol={protocol} draft={selectors} onChange={setSelectors} unitId={unitId} onUnitIdChange={setUnitId} disabled={!enabled} />
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
            disabled={saving}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
          >
            Save filter
          </button>
        </div>
      </div>
    </div>
  );
}
