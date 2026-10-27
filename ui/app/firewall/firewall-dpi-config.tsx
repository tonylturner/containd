"use client";

import { useState } from "react";

import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import { StatusBadge } from "../../components/StatusBadge";
import {
  isAdmin,
  setDataPlane,
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
  health,
  onChange,
}: {
  config: DataPlaneConfig;
  /** Runtime health; undefined while unknown. */
  health: HealthResponse | undefined;
  onChange: (c: DataPlaneConfig) => void;
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
  const dpiMode = cfg.dpiMode ?? "learn";
  const protos = cfg.dpiProtocols ?? {};
  const icsProtos = cfg.dpiIcsProtocols ?? {};
  const exclusions = cfg.dpiExclusions ?? [];
  const unsupportedICSKeys = Object.keys(icsProtos).filter(
    (key) => !ICS_DPI_PROTOCOLS.some((protocol) => protocol.key === key),
  );

  const enabledProtoCount = IT_PROTOCOLS.filter(
    (p) => protos[p.key] !== false,
  ).length;
  const enabledICSCount = ICS_DPI_PROTOCOLS.filter(
    (p) => icsProtos[p.key] !== false,
  ).length;

  // Stages the change optimistically and reverts it when the server
  // rejects it, for example an IEC 104 enforce policy that needs the decoder.
  async function save(updated: DataPlaneConfig) {
    if (!canEdit) return;
    const previous = cfg;
    onChange(updated);
    setSaving(true);
    setSaveError(null);
    const result = await setDataPlane(updated);
    setSaving(false);
    setSaveState(result.ok ? "saved" : "error");
    if (!result.ok) {
      onChange(previous);
      setSaveError(result.error);
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  function toggleDPI() {
    save({ ...cfg, dpiEnabled: !dpiOn });
  }

  function setMode(mode: "learn" | "enforce") {
    save({ ...cfg, dpiMode: mode });
  }

  function saveProtos(newProtos: Record<string, boolean>) {
    save({ ...cfg, dpiProtocols: newProtos });
  }

  function saveICSProtos(newICSProtos: Record<string, boolean>) {
    save({ ...cfg, dpiIcsProtocols: newICSProtos });
  }

  function saveExclusions(newExcl: DPIExclusion[]) {
    save({ ...cfg, dpiExclusions: newExcl });
  }

  return (
    <>
      <Card padding="md" className="mt-6">
        <div className="flex items-center justify-between">
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
            <StatusBadge variant={dpiOn ? "success" : "neutral"} dot>
              {dpiOn ? "Enabled" : "Disabled"}
            </StatusBadge>
          </div>
        </div>

        {saveError && (
          <div className="mt-3 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            {saveError}
          </div>
        )}

        {dpiOn && (
          <div className="mt-4 space-y-3">
            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    ICS DPI Mode
                  </span>
                  <InfoTip label="Learning mode passively observes traffic to build a baseline. Enforcement mode actively applies DPI policy rules." />
                </div>
                {canEdit && (
                  <div className="flex items-center rounded-xs border overflow-hidden">
                    <button
                      onClick={() => setMode("learn")}
                      className={`px-3 py-1 text-[10px] font-medium transition-ui ${
                        dpiMode === "learn"
                          ? "bg-blue-500/20 text-blue-400 border-r "
                          : "bg-(--surface) text-(--text-muted) hover:bg-white/4 border-r "
                      }`}
                    >
                      Learning
                    </button>
                    <button
                      onClick={() => setMode("enforce")}
                      className={`px-3 py-1 text-[10px] font-medium transition-ui ${
                        dpiMode === "enforce"
                          ? ""
                          : "bg-(--surface) text-(--text-muted) hover:bg-white/4"
                      }`}
                    >
                      Enforcement
                    </button>
                  </div>
                )}
              </div>
              <p className="mt-1 text-[10px] text-(--text-dim)">
                {dpiMode === "learn"
                  ? "Candidate learning mode — commit to apply. Observes traffic without blocking."
                  : "Candidate enforcement mode — commit to apply. Non-conforming traffic may then be blocked."}
              </p>
            </div>

            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    ICS Protocol Decoders
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
              <div className="mt-2">
                <IEC104HealthIndicator health={health?.iec104Enforcement} />
              </div>
            </div>

            <div className="rounded-xs border bg-(--surface2) px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-(--text)">
                    IT Protocol Decoders
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
              Use Learning mode to passively build a traffic baseline before
              switching to Enforcement. DPI exclusions skip inspection for
              specific IPs, CIDRs, or domains. TLS inspection covers handshake
              metadata only (SNI, JA3) — full interception is planned.
            </div>
          </div>
        )}
      </Card>

      {showProtoModal && (
        <DPIProtocolModal
          protocols={protos}
          onSave={(p) => {
            saveProtos(p);
            setShowProtoModal(false);
          }}
          onClose={() => setShowProtoModal(false)}
        />
      )}
      {showExclModal && (
        <DPIExclusionModal
          exclusions={exclusions}
          onSave={(e) => {
            saveExclusions(e);
            setShowExclModal(false);
          }}
          onClose={() => setShowExclModal(false)}
        />
      )}
      {showICSConfigModal && (
        <ICSDPIConfigModal
          icsProtocols={icsProtos}
          onSave={(p) => {
            saveICSProtos(p);
            setShowICSConfigModal(false);
          }}
          onClose={() => setShowICSConfigModal(false)}
        />
      )}
    </>
  );
}
