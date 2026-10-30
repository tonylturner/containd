"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ConfigEditNotice, useConfigEditor } from "../../lib/use-config-editor";
import { useConfigForm } from "../../lib/use-config-form";
import { sameConfig } from "../../lib/config-editor";

import type { DataPlaneConfig, DPIExclusion } from "../../lib/api";
import {
  ICS_DPI_PROTOCOLS,
  ICS_PROTOCOL_OPTIONS,
  IT_PROTOCOLS,
} from "./firewall-utils";

// The DPI section's editors: IT decoders, ICS decoders and exclusions.

export function DPIProtocolModal({
  context,
  saving,
  protocols,
  onSave,
  onClose,
}: {
  context: DataPlaneConfig;
  saving: boolean;
  protocols: Record<string, boolean>;
  onSave: (p: Record<string, boolean>) => Promise<DataPlaneConfig | null>;
  onClose: () => void;
}) {
  const editor = useConfigEditor({ protocols, context });
  const { cfg, setCfg, adoptConfig } = editor;
  const draft = cfg.protocols;
  const setDraft = (update: React.SetStateAction<typeof protocols>) => setCfg((c) => ({
    ...c, protocols: typeof update === "function" ? update(c.protocols) : update,
  }));
  const latest = useRef(editor.editor);
  useLayoutEffect(() => { latest.current = editor.editor; });
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { adoptConfig({ protocols, context }); }, [adoptConfig, protocols, context]);

  async function save() {
    const submitted = editor.beginSave();
    const saved = await onSave(draft);
    if (!saved || !mounted.current) { editor.failSave(submitted); return; }
    editor.acceptConfig(submitted, { protocols: saved.dpiProtocols ?? {}, context: saved });
    if (sameConfig(latest.current.cfg, submitted.cfg)) onClose();
  }

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
      <div className="w-full max-w-lg rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-(--text)">
            IT Protocol DPI Configuration
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={enableAll}
              className="rounded-xs border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-500/20"
            >
              Enable All
            </button>
            <button
              onClick={disableAll}
              className="rounded-xs border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20"
            >
              Disable All
            </button>
          </div>
        </div>

        <ConfigEditNotice superseded={editor.editor.superseded} />
        <div className="space-y-1">
          {IT_PROTOCOLS.map((p) => {
            const on = draft[p.key] !== false;
            return (
              <div
                key={p.key}
                onClick={() => toggle(p.key)}
                className={`flex items-center justify-between rounded-xs border px-3 py-2.5 cursor-pointer transition-ui ${
                  on
                    ? "border-emerald-500/20 bg-emerald-500/4 hover:bg-emerald-500/8"
                    : "border-white/4 bg-white/1 hover:bg-white/3"
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-sm font-medium ${on ? "text-(--text)" : "text-(--text-dim)"}`}
                    >
                      {p.label}
                    </span>
                    <span className="font-mono text-[10px] text-(--text-muted)">
                      :{p.port}
                    </span>
                  </div>
                  <div className="text-[10px] text-(--text-muted) mt-0.5">
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

        <div className="mt-4 text-[10px] text-(--text-dim)">
          ICS protocol decoders are enabled or disabled separately under ICS
          Protocol Decoders. TLS inspection covers handshake metadata only
          (SNI, JA3, cipher suites) — full TLS interception is planned for a
          future release.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

export function ICSDPIConfigModal({
  context,
  saving,
  icsProtocols,
  parsing,
  onSave,
  onClose,
}: {
  context: DataPlaneConfig;
  saving: boolean;
  icsProtocols: Record<string, boolean>;
  parsing: NonNullable<DataPlaneConfig["dpiIcsParsing"]>;
  onSave: (
    p: Record<string, boolean>,
    parsing: NonNullable<DataPlaneConfig["dpiIcsParsing"]>,
  ) => Promise<DataPlaneConfig | null>;
  onClose: () => void;
}) {
  const editor = useConfigEditor({ protocols: icsProtocols, parsing, context });
  const { cfg, setCfg, adoptConfig } = editor;
  const draft = cfg.protocols;
  const draftParsing = cfg.parsing;
  const setDraft = (update: React.SetStateAction<Record<string, boolean>>) => setCfg((c) => ({
    ...c, protocols: typeof update === "function" ? update(c.protocols) : update,
  }));
  const setDraftParsing = (update: React.SetStateAction<typeof parsing>) => setCfg((c) => ({
    ...c, parsing: typeof update === "function" ? update(c.parsing) : update,
  }));
  const latest = useRef(editor.editor);
  useLayoutEffect(() => { latest.current = editor.editor; });
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { adoptConfig({ protocols: icsProtocols, parsing, context }); }, [adoptConfig, icsProtocols, parsing, context]);
  const [activeProto, setActiveProto] = useState<string | null>(null);

  async function save() {
    const submitted = editor.beginSave();
    const saved = await onSave(draft, draftParsing);
    if (!saved || !mounted.current) { editor.failSave(submitted); return; }
    editor.acceptConfig(submitted, { protocols: saved.dpiIcsProtocols ?? {}, parsing: saved.dpiIcsParsing ?? {}, context: saved });
    if (sameConfig(latest.current.cfg, submitted.cfg)) onClose();
  }

  function toggle(key: string) {
    setDraft((d) => ({ ...d, [key]: d[key] === false ? true : false }));
  }

  function enableAll() {
    const next: Record<string, boolean> = { ...draft };
    ICS_DPI_PROTOCOLS.forEach((p) => {
      next[p.key] = true;
    });
    setDraft(next);
  }

  function disableAll() {
    const next: Record<string, boolean> = { ...draft };
    ICS_DPI_PROTOCOLS.forEach((p) => {
      next[p.key] = false;
    });
    setDraft(next);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-2xl rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-(--text)">
              ICS Protocol DPI Configuration
            </h2>
            <p className="mt-1 text-xs text-(--text-muted)">
              Stage protocol decoders and parsing modes. Commit to apply.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={enableAll}
              className="rounded-xs border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 hover:bg-emerald-500/20"
            >
              Enable All
            </button>
            <button
              onClick={disableAll}
              className="rounded-xs border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20"
            >
              Disable All
            </button>
          </div>
        </div>

        <ConfigEditNotice superseded={editor.editor.superseded} />
        <div className="space-y-1">
          {ICS_DPI_PROTOCOLS.map((p) => {
            const on = draft[p.key] !== false;
            const expanded = activeProto === p.key;
            const opts = ICS_PROTOCOL_OPTIONS[p.key];
            return (
              <div key={p.key}>
                <div
                  className={`flex flex-wrap items-center justify-between gap-3 rounded-xs border px-3 py-2.5 transition-ui ${
                    on
                      ? "border-emerald-500/20 bg-emerald-500/4"
                      : "border-white/4 bg-white/1"
                  } ${expanded ? "rounded-b-none" : ""}`}
                >
                  <div
                    className="flex items-center gap-3 flex-1 min-w-0 cursor-pointer"
                    onClick={() => setActiveProto(expanded ? null : p.key)}
                  >
                    <svg
                      className={`w-3 h-3 text-(--text-muted) transition-transform ${expanded ? "rotate-90" : ""}`}
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
                          className={`text-sm font-medium ${on ? "text-(--text)" : "text-(--text-dim)"}`}
                        >
                          {p.label}
                        </span>
                        <span className="font-mono text-[10px] text-(--text-muted)">
                          :{p.port}
                        </span>
                      </div>
                      <div className="text-[10px] text-(--text-muted) mt-0.5">
                        {p.desc}
                      </div>
                    </div>
                  </div>
                  <label className="flex items-center gap-2 text-xs text-(--text-muted)">
                    Parsing
                    <select
                      aria-label={`${p.label} parsing`}
                      value={draftParsing[p.key] === "strict" ? "strict" : "tolerant"}
                      onChange={(e) => setDraftParsing((current) => ({
                        ...current,
                        [p.key]: e.target.value as "tolerant" | "strict",
                      }))}
                      className="rounded-xs border bg-(--surface2) px-2 py-1.5 text-xs text-(--text) outline-hidden focus-visible:ring-2 focus-visible:ring-(--amber)"
                    >
                      <option value="tolerant">Tolerant</option>
                      <option value="strict">Strict</option>
                    </select>
                  </label>
                  <button
                    type="button"
                    role="switch"
                    aria-label={`${p.label} decoder`}
                    aria-checked={on}
                    onClick={() => toggle(p.key)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors cursor-pointer shrink-0 ${on ? "bg-emerald-500" : "bg-white/10"}`}
                  >
                    <span
                      className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${on ? "translate-x-4" : "translate-x-0.5"}`}
                    />
                  </button>
                </div>

                {expanded && opts && (
                  <div className="border border-t-0 rounded-b-xs bg-(--surface2) px-4 py-3 space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-[10px] font-medium text-(--text-muted) mb-1">
                          {opts.fcLabel}
                        </label>
                        <p className="text-[9px] text-(--text-dim) mb-1.5">
                          {opts.fcHelp}
                        </p>
                        <div className="text-[10px] text-(--text-dim) italic">
                          Configured in firewall rules per-entry
                        </div>
                      </div>
                      {opts.addrLabel && opts.addrHelp && (
                        <div>
                          <label className="block text-[10px] font-medium text-(--text-muted) mb-1">
                            {opts.addrLabel}
                          </label>
                          <p className="text-[9px] text-(--text-dim) mb-1.5">
                            {opts.addrHelp}
                          </p>
                          <div className="text-[10px] text-(--text-dim) italic">
                            Configured in firewall rules per-entry
                          </div>
                        </div>
                      )}
                    </div>
                    {opts.hasUnitId && (
                      <div className="text-[10px] text-(--text-dim)">
                        Unit ID filtering available in firewall rules (per-entry
                        ICS predicate).
                      </div>
                    )}
                    {opts.hasObjectClasses && (
                      <div className="text-[10px] text-(--text-dim)">
                        CIP object class filtering available in firewall rules
                        (per-entry ICS predicate).
                      </div>
                    )}
                    <div className="pt-2 border-t border-white/4">
                      <div className="flex items-center gap-2 text-[10px]">
                        <span className="text-(--text-muted)">
                          Decoder status:
                        </span>
                        {on ? (
                          <span className="text-emerald-400">
                            Candidate decoder enabled on port {p.port}
                          </span>
                        ) : (
                          <span className="text-(--text-dim)">
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

        {Object.entries(draft)
          .filter(([key]) => !ICS_DPI_PROTOCOLS.some((protocol) => protocol.key === key))
          .map(([key, enabled]) => (
            <div
              key={key}
              className="mt-3 flex items-center justify-between rounded-xs border border-amber-500/20 bg-amber-500/5 px-3 py-2.5"
            >
              <div className="text-sm text-(--text)">
                <span className="font-mono">{key}</span>{" "}
                <span className="text-amber-300">unsupported</span>
                <div className="mt-0.5 text-[10px] text-(--text-muted)">
                  Stored value: {String(enabled)}. Remove this key to repair the decoder map.
                </div>
              </div>
              <button
                type="button"
                aria-label={`Remove unsupported protocol ${key}`}
                onClick={() => {
                  const next = { ...draft };
                  delete next[key];
                  setDraft(next);
                }}
                className="rounded-xs border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs text-red-300"
              >
                Remove
              </button>
            </div>
          ))}

        <div className="mt-4 text-[10px] text-(--text-dim)">
          Tolerant enforces what is decoded and alerts on the rest. Strict drops
          nonconformant frames and resets the session in enforce mode; learning
          reports would-drop without blocking. A lost frame boundary and integrity
          faults reset the session in both parsing modes when enforcing.
        </div>

        <div className="mt-3 text-[10px] text-(--text-dim)">
          Protocol-specific DPI parameters (function codes, register addresses,
          unit IDs) are configured per-rule in firewall entries with ICS
          predicates. This panel controls which ICS decoders will be enabled after commit at the
          engine level.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

export function DPIExclusionModal({
  context,
  saving,
  exclusions,
  onSave,
  onClose,
}: {
  context: DataPlaneConfig;
  saving: boolean;
  exclusions: DPIExclusion[];
  onSave: (e: DPIExclusion[]) => Promise<DataPlaneConfig | null>;
  onClose: () => void;
}) {
  const editor = useConfigEditor({ rows: exclusions, context });
  const { cfg, setCfg, adoptConfig } = editor;
  const draft = cfg.rows;
  const setDraft = (rows: DPIExclusion[]) => setCfg((c) => ({ ...c, rows }));
  const form = useConfigForm({ newValue: "", newType: "ip" as "ip" | "cidr" | "domain", newReason: "" });
  const { refreshForm } = form;
  const [newValue, setNewValue] = form.field("newValue");
  const [newType, setNewType] = form.field("newType");
  const [newReason, setNewReason] = form.field("newReason");
  const latest = useRef({ editor: editor.editor, fields: form.editor.cfg.fields });
  useLayoutEffect(() => { latest.current = { editor: editor.editor, fields: form.editor.cfg.fields }; });
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { adoptConfig({ rows: exclusions, context }); refreshForm(context); }, [adoptConfig, refreshForm, exclusions, context]);

  async function save() {
    const submitted = editor.beginSave();
    const saved = await onSave(draft);
    if (!saved || !mounted.current) { editor.failSave(submitted); return; }
    editor.acceptConfig(submitted, { rows: saved.dpiExclusions ?? [], context: saved });
    if (sameConfig(latest.current.editor.cfg, submitted.cfg) && !latest.current.fields.newValue && !latest.current.fields.newReason) onClose();
  }

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
      <div className="w-full max-w-lg rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
        <h2 className="text-sm font-semibold text-(--text) mb-4">
          DPI Exclusions
        </h2>
        <p className="text-xs text-(--text-muted) mb-3">
          Exclude specific IP addresses, CIDR ranges, or domains from deep
          packet inspection. Traffic to or from excluded targets will bypass DPI
          entirely.
        </p>

        <ConfigEditNotice superseded={editor.editor.superseded || form.editor.superseded} />
        <div className="flex gap-2 mb-4">
          <select
            value={newType}
            onChange={(e) =>
              setNewType(e.target.value as "ip" | "cidr" | "domain")
            }
            className="rounded-xs border bg-(--surface2) px-2.5 py-2.5 text-sm text-(--text) outline-hidden"
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
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Add
          </button>
        </div>

        <div className="max-h-[280px] overflow-y-auto space-y-1">
          {draft.length === 0 ? (
            <div className="text-center py-6 text-xs text-(--text-muted)">
              No exclusions configured.
            </div>
          ) : (
            draft.map((e, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded-xs border border-white/4 bg-(--surface2) px-3 py-2"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="shrink-0 rounded-xs border px-1.5 py-0.5 text-[9px] uppercase">
                    {e.type}
                  </span>
                  <span className="font-mono text-xs text-(--text) truncate">
                    {e.value}
                  </span>
                  {e.reason && (
                    <span className="text-[10px] text-(--text-muted) truncate">
                      — {e.reason}
                    </span>
                  )}
                </div>
                <button
                  onClick={() => remove(i)}
                  className="shrink-0 ml-2 rounded-xs border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 transition-ui"
                >
                  Remove
                </button>
              </div>
            ))
          )}
        </div>

        <div className="mt-3 text-[10px] text-(--text-dim)">
          Exclusions take effect after commit. Domains use visible TLS SNI or
          observed DNS answers at the first client payload. Use example.com for
          an exact name or *.example.com for subdomains only. DNS can exclude
          other traffic sharing an IP. Domain exclusions never bypass IEC 104
          inspection.
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-xs font-medium text-white transition-ui hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
