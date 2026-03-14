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
} from "../../lib/api";
import {
  ICS_DPI_PROTOCOLS,
  ICS_PROTOCOL_OPTIONS,
  IT_PROTOCOLS,
} from "./firewall-utils";

export function DPIConfigSection({
  config: cfg,
  onChange,
}: {
  config: DataPlaneConfig;
  onChange: (c: DataPlaneConfig) => void;
}) {
  const [saving, setSaving] = useState(false);
  const [saveState, setSaveState] = useState<"idle" | "saved" | "error">(
    "idle",
  );
  const [showProtoModal, setShowProtoModal] = useState(false);
  const [showExclModal, setShowExclModal] = useState(false);
  const [showICSConfigModal, setShowICSConfigModal] = useState(false);
  const canEdit = isAdmin();
  const dpiOn = cfg.dpiEnabled ?? false;
  const dpiMode = cfg.dpiMode ?? "learn";
  const protos = cfg.dpiProtocols ?? {};
  const icsProtos = cfg.dpiIcsProtocols ?? {};
  const exclusions = cfg.dpiExclusions ?? [];

  const enabledProtoCount = IT_PROTOCOLS.filter(
    (p) => protos[p.key] !== false,
  ).length;
  const enabledICSCount = ICS_DPI_PROTOCOLS.filter(
    (p) => icsProtos[p.key] !== false,
  ).length;

  async function save(updated: DataPlaneConfig) {
    if (!canEdit) return;
    setSaving(true);
    const result = await setDataPlane(updated);
    setSaving(false);
    setSaveState(result.ok ? "saved" : "error");
    setTimeout(() => setSaveState("idle"), 1500);
  }

  function toggleDPI() {
    const updated = { ...cfg, dpiEnabled: !dpiOn };
    onChange(updated);
    save(updated);
  }

  function setMode(mode: "learn" | "enforce") {
    const updated = { ...cfg, dpiMode: mode };
    onChange(updated);
    save(updated);
  }

  function saveProtos(newProtos: Record<string, boolean>) {
    const updated = { ...cfg, dpiProtocols: newProtos };
    onChange(updated);
    save(updated);
  }

  function saveICSProtos(newICSProtos: Record<string, boolean>) {
    const updated = { ...cfg, dpiIcsProtocols: newICSProtos };
    onChange(updated);
    save(updated);
  }

  function saveExclusions(newExcl: DPIExclusion[]) {
    const updated = { ...cfg, dpiExclusions: newExcl };
    onChange(updated);
    save(updated);
  }

  return (
    <>
      <Card padding="md" className="mt-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              Deep Packet Inspection
            </h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Inspect ICS and IT protocol traffic for visibility, IDS alerting,
              and policy enforcement.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {saving && (
              <span className="text-[10px] text-[var(--text-muted)]">
                Saving...
              </span>
            )}
            {saveState === "saved" && (
              <span className="text-[10px] text-emerald-400">Saved</span>
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

        {dpiOn && (
          <div className="mt-4 space-y-3">
            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">
                    ICS DPI Mode
                  </span>
                  <InfoTip label="Learning mode passively observes traffic to build a baseline. Enforcement mode actively applies DPI policy rules." />
                </div>
                {canEdit && (
                  <div className="flex items-center rounded-sm border border-amber-500/[0.1] overflow-hidden">
                    <button
                      onClick={() => setMode("learn")}
                      className={`px-3 py-1 text-[10px] font-medium transition-ui ${
                        dpiMode === "learn"
                          ? "bg-blue-500/20 text-blue-400 border-r border-amber-500/[0.1]"
                          : "bg-[var(--surface)] text-[var(--text-muted)] hover:bg-white/[0.04] border-r border-amber-500/[0.1]"
                      }`}
                    >
                      Learning
                    </button>
                    <button
                      onClick={() => setMode("enforce")}
                      className={`px-3 py-1 text-[10px] font-medium transition-ui ${
                        dpiMode === "enforce"
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-[var(--surface)] text-[var(--text-muted)] hover:bg-white/[0.04]"
                      }`}
                    >
                      Enforcement
                    </button>
                  </div>
                )}
              </div>
              <p className="mt-1 text-[10px] text-[var(--text-dim)]">
                {dpiMode === "learn"
                  ? "Passively observing ICS traffic to build protocol baseline. No traffic will be blocked."
                  : "Actively enforcing DPI policy rules. Non-conforming traffic may be blocked."}
              </p>
            </div>

            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">
                    ICS Protocol Decoders
                  </span>
                  <span className="ml-2 text-[10px] text-[var(--text-muted)]">
                    {enabledICSCount}/{ICS_DPI_PROTOCOLS.length} enabled
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {canEdit && (
                    <button
                      onClick={() => setShowICSConfigModal(true)}
                      className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-medium text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
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
                      className={`rounded-sm border px-1.5 py-0.5 text-[9px] ${
                        on
                          ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                          : "border-white/[0.06] bg-white/[0.02] text-[var(--text-dim)] line-through"
                      }`}
                    >
                      {p.label}
                    </span>
                  );
                })}
              </div>
            </div>

            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">
                    IT Protocol Decoders
                  </span>
                  <span className="ml-2 text-[10px] text-[var(--text-muted)]">
                    {enabledProtoCount}/{IT_PROTOCOLS.length} enabled
                  </span>
                </div>
                {canEdit && (
                  <button
                    onClick={() => setShowProtoModal(true)}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-medium text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
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
                      className={`rounded-sm border px-1.5 py-0.5 text-[9px] ${
                        on
                          ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                          : "border-white/[0.06] bg-white/[0.02] text-[var(--text-dim)] line-through"
                      }`}
                    >
                      {p.label}
                    </span>
                  );
                })}
              </div>
            </div>

            <div className="rounded-sm border border-amber-500/[0.08] bg-[var(--surface2)] px-3 py-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-[var(--text)]">
                    DPI Exclusions
                  </span>
                  <span className="ml-2 text-[10px] text-[var(--text-muted)]">
                    {exclusions.length === 0
                      ? "None"
                      : `${exclusions.length} excluded`}
                  </span>
                </div>
                {canEdit && (
                  <button
                    onClick={() => setShowExclModal(true)}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-medium text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
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
                      className="flex items-center justify-between rounded-sm border border-white/[0.04] bg-[var(--surface)] px-2 py-1 text-[10px]"
                    >
                      <div className="flex items-center gap-2">
                        <span className="rounded-sm border border-amber-500/20 bg-amber-500/10 px-1 py-0.5 text-[9px] text-amber-400 uppercase">
                          {e.type}
                        </span>
                        <span className="font-mono text-[var(--text)]">
                          {e.value}
                        </span>
                      </div>
                      {e.reason && (
                        <span className="text-[var(--text-muted)] truncate max-w-[180px]">
                          {e.reason}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="text-[10px] text-[var(--text-dim)]">
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

function DPIProtocolModal({
  protocols,
  onSave,
  onClose,
}: {
  protocols: Record<string, boolean>;
  onSave: (p: Record<string, boolean>) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<Record<string, boolean>>({ ...protocols });

  function toggle(key: string) {
    setDraft((d) => ({ ...d, [key]: d[key] === false ? true : false }));
  }

  function enableAll() {
    const next: Record<string, boolean> = {};
    IT_PROTOCOLS.forEach((p) => {
      next[p.key] = true;
    });
    setDraft(next);
  }

  function disableAll() {
    const next: Record<string, boolean> = {};
    IT_PROTOCOLS.forEach((p) => {
      next[p.key] = false;
    });
    setDraft(next);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-lg rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-[var(--text)]">
            IT Protocol DPI Configuration
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={enableAll}
              className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-500/20"
            >
              Enable All
            </button>
            <button
              onClick={disableAll}
              className="rounded-sm border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20"
            >
              Disable All
            </button>
          </div>
        </div>

        <div className="space-y-1">
          {IT_PROTOCOLS.map((p) => {
            const on = draft[p.key] !== false;
            return (
              <div
                key={p.key}
                onClick={() => toggle(p.key)}
                className={`flex items-center justify-between rounded-sm border px-3 py-2.5 cursor-pointer transition-ui ${
                  on
                    ? "border-emerald-500/20 bg-emerald-500/[0.04] hover:bg-emerald-500/[0.08]"
                    : "border-white/[0.04] bg-white/[0.01] hover:bg-white/[0.03]"
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-sm font-medium ${on ? "text-[var(--text)]" : "text-[var(--text-dim)]"}`}
                    >
                      {p.label}
                    </span>
                    <span className="font-mono text-[10px] text-[var(--text-muted)]">
                      :{p.port}
                    </span>
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)] mt-0.5">
                    {p.desc}
                  </div>
                </div>
                <div
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${on ? "bg-emerald-500" : "bg-white/10"}`}
                >
                  <span
                    className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${on ? "translate-x-4" : "translate-x-0.5"}`}
                  />
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-4 text-[10px] text-[var(--text-dim)]">
          ICS protocol decoders (Modbus, DNP3, CIP, S7comm, IEC 61850 MMS,
          BACnet, OPC UA) are always active and cannot be disabled. TLS
          inspection covers handshake metadata only (SNI, JA3, cipher suites) —
          full TLS interception is planned for a future release.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={() => onSave(draft)}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

function ICSDPIConfigModal({
  icsProtocols,
  onSave,
  onClose,
}: {
  icsProtocols: Record<string, boolean>;
  onSave: (p: Record<string, boolean>) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<Record<string, boolean>>({
    ...icsProtocols,
  });
  const [activeProto, setActiveProto] = useState<string | null>(null);

  function toggle(key: string) {
    setDraft((d) => ({ ...d, [key]: d[key] === false ? true : false }));
  }

  function enableAll() {
    const next: Record<string, boolean> = {};
    ICS_DPI_PROTOCOLS.forEach((p) => {
      next[p.key] = true;
    });
    setDraft(next);
  }

  function disableAll() {
    const next: Record<string, boolean> = {};
    ICS_DPI_PROTOCOLS.forEach((p) => {
      next[p.key] = false;
    });
    setDraft(next);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-2xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              ICS Protocol DPI Configuration
            </h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Enable or disable individual ICS protocol decoders and view
              protocol-specific options.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={enableAll}
              className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-500/20"
            >
              Enable All
            </button>
            <button
              onClick={disableAll}
              className="rounded-sm border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20"
            >
              Disable All
            </button>
          </div>
        </div>

        <div className="space-y-1">
          {ICS_DPI_PROTOCOLS.map((p) => {
            const on = draft[p.key] !== false;
            const expanded = activeProto === p.key;
            const opts = ICS_PROTOCOL_OPTIONS[p.key];
            return (
              <div key={p.key}>
                <div
                  className={`flex items-center justify-between rounded-sm border px-3 py-2.5 transition-ui ${
                    on
                      ? "border-emerald-500/20 bg-emerald-500/[0.04]"
                      : "border-white/[0.04] bg-white/[0.01]"
                  } ${expanded ? "rounded-b-none" : ""}`}
                >
                  <div
                    className="flex items-center gap-3 flex-1 min-w-0 cursor-pointer"
                    onClick={() => setActiveProto(expanded ? null : p.key)}
                  >
                    <svg
                      className={`w-3 h-3 text-[var(--text-muted)] transition-transform ${expanded ? "rotate-90" : ""}`}
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9 5l7 7-7 7"
                      />
                    </svg>
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-sm font-medium ${on ? "text-[var(--text)]" : "text-[var(--text-dim)]"}`}
                        >
                          {p.label}
                        </span>
                        <span className="font-mono text-[10px] text-[var(--text-muted)]">
                          :{p.port}
                        </span>
                      </div>
                      <div className="text-[10px] text-[var(--text-muted)] mt-0.5">
                        {p.desc}
                      </div>
                    </div>
                  </div>
                  <div
                    onClick={() => toggle(p.key)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors cursor-pointer shrink-0 ${on ? "bg-emerald-500" : "bg-white/10"}`}
                  >
                    <span
                      className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${on ? "translate-x-4" : "translate-x-0.5"}`}
                    />
                  </div>
                </div>

                {expanded && opts && (
                  <div className="border border-t-0 border-amber-500/[0.08] rounded-b-sm bg-[var(--surface2)] px-4 py-3 space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">
                          {opts.fcLabel}
                        </label>
                        <p className="text-[9px] text-[var(--text-dim)] mb-1.5">
                          {opts.fcHelp}
                        </p>
                        <div className="text-[10px] text-[var(--text-dim)] italic">
                          Configured in firewall rules per-entry
                        </div>
                      </div>
                      <div>
                        <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">
                          {opts.addrLabel}
                        </label>
                        <p className="text-[9px] text-[var(--text-dim)] mb-1.5">
                          {opts.addrHelp}
                        </p>
                        <div className="text-[10px] text-[var(--text-dim)] italic">
                          Configured in firewall rules per-entry
                        </div>
                      </div>
                    </div>
                    {opts.hasUnitId && (
                      <div className="text-[10px] text-[var(--text-dim)]">
                        Unit ID filtering available in firewall rules (per-entry
                        ICS predicate).
                      </div>
                    )}
                    {opts.hasObjectClasses && (
                      <div className="text-[10px] text-[var(--text-dim)]">
                        CIP object class filtering available in firewall rules
                        (per-entry ICS predicate).
                      </div>
                    )}
                    <div className="pt-2 border-t border-white/[0.04]">
                      <div className="flex items-center gap-2 text-[10px]">
                        <span className="text-[var(--text-muted)]">
                          Decoder status:
                        </span>
                        {on ? (
                          <span className="text-emerald-400">
                            Active — inspecting traffic on port {p.port}
                          </span>
                        ) : (
                          <span className="text-[var(--text-dim)]">
                            Disabled — traffic on port {p.port} will not be
                            decoded
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="mt-4 text-[10px] text-[var(--text-dim)]">
          Protocol-specific DPI parameters (function codes, register addresses,
          unit IDs) are configured per-rule in firewall entries with ICS
          predicates. This panel controls which ICS decoders are active at the
          engine level.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={() => onSave(draft)}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

function DPIExclusionModal({
  exclusions,
  onSave,
  onClose,
}: {
  exclusions: DPIExclusion[];
  onSave: (e: DPIExclusion[]) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<DPIExclusion[]>([...exclusions]);
  const [newValue, setNewValue] = useState("");
  const [newType, setNewType] = useState<"ip" | "cidr" | "domain">("ip");
  const [newReason, setNewReason] = useState("");

  function detectType(v: string): "ip" | "cidr" | "domain" {
    if (v.includes("/")) return "cidr";
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return "ip";
    if (v.includes(":") && !v.includes(".")) return "ip";
    return "domain";
  }

  function add() {
    const val = newValue.trim();
    if (!val) return;
    if (draft.some((e) => e.value === val)) return;
    setDraft([
      ...draft,
      {
        value: val,
        type: detectType(val),
        reason: newReason.trim() || undefined,
      },
    ]);
    setNewValue("");
    setNewReason("");
  }

  function remove(i: number) {
    setDraft(draft.filter((_, idx) => idx !== i));
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-lg rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <h2 className="text-sm font-semibold text-[var(--text)] mb-4">
          DPI Exclusions
        </h2>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          Exclude specific IP addresses, CIDR ranges, or domains from deep
          packet inspection. Traffic to or from excluded targets will bypass DPI
          entirely.
        </p>

        <div className="flex gap-2 mb-4">
          <select
            value={newType}
            onChange={(e) =>
              setNewType(e.target.value as "ip" | "cidr" | "domain")
            }
            className="rounded-sm border border-amber-500/[0.1] bg-[var(--surface2)] px-2.5 py-2.5 text-sm text-[var(--text)] outline-none"
          >
            <option value="ip">IP</option>
            <option value="cidr">CIDR</option>
            <option value="domain">Domain</option>
          </select>
          <input
            value={newValue}
            onChange={(e) => {
              setNewValue(e.target.value);
              setNewType(detectType(e.target.value));
            }}
            placeholder={
              newType === "domain"
                ? "example.com"
                : newType === "cidr"
                  ? "10.0.0.0/8"
                  : "192.168.1.1"
            }
            className="flex-1 input-industrial py-2.5 text-sm"
            onKeyDown={(e) => {
              if (e.key === "Enter") add();
            }}
          />
          <input
            value={newReason}
            onChange={(e) => setNewReason(e.target.value)}
            placeholder="Reason (optional)"
            className="w-40 input-industrial py-2.5 text-sm"
            onKeyDown={(e) => {
              if (e.key === "Enter") add();
            }}
          />
          <button
            onClick={add}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Add
          </button>
        </div>

        <div className="max-h-[280px] overflow-y-auto space-y-1">
          {draft.length === 0 ? (
            <div className="text-center py-6 text-xs text-[var(--text-muted)]">
              No exclusions configured.
            </div>
          ) : (
            draft.map((e, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded-sm border border-white/[0.04] bg-[var(--surface2)] px-3 py-2"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="shrink-0 rounded-sm border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[9px] text-amber-400 uppercase">
                    {e.type}
                  </span>
                  <span className="font-mono text-xs text-[var(--text)] truncate">
                    {e.value}
                  </span>
                  {e.reason && (
                    <span className="text-[10px] text-[var(--text-muted)] truncate">
                      — {e.reason}
                    </span>
                  )}
                </div>
                <button
                  onClick={() => remove(i)}
                  className="shrink-0 ml-2 rounded-sm border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 transition-ui"
                >
                  Remove
                </button>
              </div>
            ))
          )}
        </div>

        <div className="mt-3 text-[10px] text-[var(--text-dim)]">
          IP and CIDR exclusions take effect immediately. Domain exclusions will
          be supported when TLS interception is added.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={() => onSave(draft)}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
