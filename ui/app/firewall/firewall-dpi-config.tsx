"use client";

import { useState } from "react";

import type { ConfigBase, ConfigWriteResult } from "../../lib/config-boundary";
import type { ApiResult } from "../../lib/api";
import { revisionError } from "../../lib/config-revision";

import { ICSModeSelect } from "../ics/ics-mode-select";
import { formatICSMode, type ICSModeSelection } from "../ics/ics-shared";
import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import { StatusBadge } from "../../components/StatusBadge";
import {
  isAdmin,
  type DataPlaneConfig,
  type DPIExclusion,
  type HealthResponse,
} from "../../lib/api";
import { IEC104HealthIndicator } from "../ics/iec104-health";
import { ICS_DPI_PROTOCOLS, IT_PROTOCOLS } from "./firewall-utils";
import {
  DPIExclusionModal,
  DPIProtocolModal,
  ICSDPIConfigModal,
} from "./firewall-dpi-modals";

export function DPIConfigSection({
  config: cfg,
  revision,
  onSave, onSaveDraft,
  health,
  available,
}: {
  config: DataPlaneConfig;
  revision: string;
  onSave: (update: (config: DataPlaneConfig) => DataPlaneConfig) => Promise<ConfigWriteResult<DataPlaneConfig>>;
  onSaveDraft: (base: ConfigBase, config: DataPlaneConfig) => Promise<ApiResult<DataPlaneConfig> | null>;
  available: boolean;
  /** Runtime health; undefined while unknown. */
  health: HealthResponse | undefined;
}) {
  const [saving, setSaving] = useState(false);
  const [saveState, setSaveState] = useState<"idle" | "saved" | "error">(
    "idle",
  );
  const [saveError, setSaveError] = useState<string | null>(null);
  const [showProtoModal, setShowProtoModal] = useState(false);
  const [showExclModal, setShowExclModal] = useState(false);
  const [showICSConfigModal, setShowICSConfigModal] = useState(false);
  const canEdit = isAdmin();
  const dpiOn = cfg.dpiEnabled ?? false;
  const dpiMode = cfg.dpiMode ?? "";
  const protos = cfg.dpiProtocols ?? {};
  const icsProtos = cfg.dpiIcsProtocols ?? {};
  const exclusions = cfg.dpiExclusions ?? [];
  const unsupportedICSKeys = Object.keys(icsProtos).filter(
    (key) => !ICS_DPI_PROTOCOLS.some((protocol) => protocol.key === key),
  );

  const nonDefault = dpiOn || (dpiMode !== "" && dpiMode !== "monitor") ||
    Object.entries(protos).some(([key, value]) => value !== true || !IT_PROTOCOLS.some(p => p.key === key)) ||
    Object.values(icsProtos).some(value => value !== true) || unsupportedICSKeys.length > 0 ||
    Object.entries(cfg.dpiIcsParsing ?? {}).some(([key, value]) => value !== "tolerant" || !ICS_DPI_PROTOCOLS.some(p => p.key === key)) || exclusions.length > 0;
  const [disclosure, setDisclosure] = useState<{ revision: string; open: boolean } | null>(null);
  const expanded = disclosure?.revision === revision ? disclosure.open : nonDefault;

  const enabledProtoCount = IT_PROTOCOLS.filter(
    (p) => protos[p.key] !== false,
  ).length;
  const enabledICSCount = ICS_DPI_PROTOCOLS.filter(
    (p) => icsProtos[p.key] !== false,
  ).length;

  // Failed requests leave the editor open; only acknowledged state replaces
  // the displayed server copy.
  async function save(update: (config: DataPlaneConfig) => DataPlaneConfig, expectedRevision?: ConfigBase) {
    if (!canEdit || !available || saving) return null;
    setSaving(true);
    setSaveError(null);
    const result = expectedRevision === undefined ? await onSave(update) : await onSaveDraft(expectedRevision, update(cfg));
    if (!result) { setSaving(false); return null; }
    setSaving(false);
    setSaveState(result.ok ? "saved" : revisionError(result) === null ? "idle" : "error");
    if (!result.ok) {
      setSaveError(revisionError(result));
      return result;
    }
    return result;
  }

  function toggleDPI() {
    save(current => ({ ...current, dpiEnabled: !(current.dpiEnabled ?? false) }));
  }

  function setMode(mode: ICSModeSelection) {
    save(current => ({ ...current, dpiMode: mode }));
  }

  function saveProtos(newProtos: Record<string, boolean>, expectedRevision: ConfigBase) {
    return save(current => ({ ...current, dpiProtocols: newProtos }), expectedRevision);
  }

  function saveICSProtos(
    newICSProtos: Record<string, boolean>,
    parsing: NonNullable<DataPlaneConfig["dpiIcsParsing"]>,
    expectedRevision: ConfigBase,
  ) {
    return save(current => ({
      ...current,
      dpiIcsProtocols: newICSProtos,
      ...(Object.keys(parsing).length > 0 ? { dpiIcsParsing: parsing } : {}),
    }), expectedRevision);
  }

  function saveExclusions(newExcl: DPIExclusion[], expectedRevision: ConfigBase) {
    return save(current => ({ ...current, dpiExclusions: newExcl }), expectedRevision);
  }

  return (
    <>
      <Card padding="md" className="mt-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-(--text)">
              Deep Packet Inspection
            </h2>
            <p className="mt-1 text-xs text-(--text-muted)">
              Inspect ICS and IT protocol traffic for visibility, IDS alerting,
              and policy enforcement.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {saving && (
              <span className="text-[10px] text-(--text-muted)">
                Saving...
              </span>
            )}
            {saveState === "saved" && (
              <span className="text-[10px] text-emerald-400">Staged — commit to apply.</span>
            )}
            {saveState === "error" && (
              <span className="text-[10px] text-red-400">Error</span>
            )}
            {canEdit && (
              <button
                onClick={toggleDPI}
                aria-label="Toggle DPI"
                disabled={saving || !available}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  dpiOn ? "bg-emerald-500" : "bg-white/10"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                    dpiOn ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
            )}
            <StatusBadge variant={available && dpiOn ? "success" : "neutral"} dot>
              {!available ? "Unknown" : dpiOn ? "Enabled" : "Disabled"}
            </StatusBadge>
          </div>
        </div>

        {saveError && (
          <div className="mt-3 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            Not saved: {saveError}
          </div>
        )}

        <div className="mt-3"><IEC104HealthIndicator health={health?.iec104Enforcement} /></div>
        <button type="button" aria-expanded={expanded} aria-controls="dpi-settings" onClick={() => setDisclosure({ revision, open: !expanded })}
          className="mt-3 rounded-xs border bg-(--surface2) px-2.5 py-1 text-xs text-(--text)">
          DPI settings{unsupportedICSKeys.length > 0 ? " · unsupported settings" : nonDefault ? " · saved settings" : ""}
        </button>
        <div id="dpi-settings" hidden={!expanded}>
          <div className="mt-4 space-y-3">
            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    ICS DPI Mode
                  </span>
                  <InfoTip label="Monitor rules observe independently and never admit or block. Other enforcing rules and scopes still apply. Monitoring does not start learning." />
                </div>
                {canEdit && <ICSModeSelect label="ICS DPI Mode" value={dpiMode} onChange={setMode} disabled={saving || !available} />}
              </div>
              <p className="mt-1 text-[10px] text-(--text-dim)">
                Candidate {formatICSMode(dpiMode, undefined).label} — commit to apply. Per-rule overrides take precedence.
              </p>
            </div>

            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    Industrial protocols
                  </span>
                  <span className="ml-2 text-[10px] text-(--text-muted)">
                    {enabledICSCount}/{ICS_DPI_PROTOCOLS.length} enabled
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {canEdit && (
                    <button
                      onClick={() => setShowICSConfigModal(true)}
                      className="rounded-xs border bg-(--surface) px-2.5 py-1 text-[10px] font-medium text-(--text) transition-ui"
                    >
                      Configure
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {ICS_DPI_PROTOCOLS.map((p) => {
                  const on = icsProtos[p.key] !== false;
                  return (
                    <span
                      key={p.key}
                      className={`rounded-xs border px-1.5 py-0.5 text-[9px] ${
                        on
                          ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                          : "border-white/6 bg-white/2 text-(--text-dim) line-through"
                      }`}
                    >
                      {p.label}
                    </span>
                  );
                })}
                {unsupportedICSKeys.map((key) => (
                  <span
                    key={key}
                    className="rounded-xs border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[9px] text-amber-300"
                  >
                    {key} — unsupported
                  </span>
                ))}
              </div>
            </div>

            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    Network protocols
                  </span>
                  <span className="ml-2 text-[10px] text-(--text-muted)">
                    {enabledProtoCount}/{IT_PROTOCOLS.length} enabled
                  </span>
                </div>
                {canEdit && (
                  <button
                    onClick={() => setShowProtoModal(true)}
                    className="rounded-xs border bg-(--surface) px-2.5 py-1 text-[10px] font-medium text-(--text) transition-ui"
                  >
                    Configure
                  </button>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {IT_PROTOCOLS.map((p) => {
                  const on = protos[p.key] !== false;
                  return (
                    <span
                      key={p.key}
                      className={`rounded-xs border px-1.5 py-0.5 text-[9px] ${
                        on
                          ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                          : "border-white/6 bg-white/2 text-(--text-dim) line-through"
                      }`}
                    >
                      {p.label}
                    </span>
                  );
                })}
              </div>
            </div>

            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    DPI Exclusions
                  </span>
                  <span className="ml-2 text-[10px] text-(--text-muted)">
                    {exclusions.length === 0
                      ? "None"
                      : `${exclusions.length} excluded`}
                  </span>
                </div>
                {canEdit && (
                  <button
                    onClick={() => setShowExclModal(true)}
                    className="rounded-xs border bg-(--surface) px-2.5 py-1 text-[10px] font-medium text-(--text) transition-ui"
                  >
                    {exclusions.length > 0 ? "Manage" : "Add Exclusion"}
                  </button>
                )}
              </div>
              {exclusions.length > 0 && (
                <div className="mt-2 space-y-1">
                  {exclusions.map((e, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between rounded-xs border border-white/4 bg-(--surface) px-2 py-1 text-[10px]"
                    >
                      <div className="flex items-center gap-2">
                        <span className="rounded-xs border px-1 py-0.5 text-[9px] uppercase">
                          {e.type}
                        </span>
                        <span className="font-mono text-(--text)">
                          {e.value}
                        </span>
                      </div>
                      {e.reason && (
                        <span className="text-(--text-muted) truncate max-w-[180px]">
                          {e.reason}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="text-[10px] text-(--text-dim)">
              Monitor (safe) observes rule-local matches; learning is a separate, explicit operation.
              You can select Enforce directly. DPI exclusions skip inspection for
              specific IPs, CIDRs, or domains. TLS inspection covers handshake
              metadata only (SNI, JA3) — full interception is planned.
            </div>
          </div>
        </div>
      </Card>

      {showProtoModal && (
        <DPIProtocolModal
          revision={revision}
          context={cfg}
          protocols={protos}
          saving={saving || !available}
          onSave={saveProtos}
          onClose={() => setShowProtoModal(false)}
        />
      )}
      {showExclModal && (
        <DPIExclusionModal
          revision={revision}
          context={cfg}
          exclusions={exclusions}
          saving={saving || !available}
          onSave={saveExclusions}
          onClose={() => setShowExclModal(false)}
        />
      )}
      {showICSConfigModal && (
        <ICSDPIConfigModal
          revision={revision}
          context={cfg}
          icsProtocols={icsProtos}
          parsing={cfg.dpiIcsParsing ?? {}}
          saving={saving || !available}
          onSave={saveICSProtos}
          onClose={() => setShowICSConfigModal(false)}
        />
      )}
    </>
  );
}
