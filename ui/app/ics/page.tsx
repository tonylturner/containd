"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

import {
  api,
  fetchDataPlane,
  isAdmin,
  type DataPlaneConfig,
  type FirewallRule,
  type ICSPredicate,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { InfoTip } from "../../components/InfoTip";
import { RulePreviewButton } from "../../components/RulePreview";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";

/* -- Protocol metadata for the UI ---------------------------------------- */

type ProtocolMeta = {
  label: string;
  port: string;
  fcLabel: string; // column header for function/service codes
  fcPlaceholder: string;
  fcHelp: string;
  addrLabel: string;
  addrPlaceholder: string;
  addrHelp: string;
};

const PROTOCOLS: Record<string, ProtocolMeta> = {
  modbus: {
    label: "Modbus/TCP",
    port: "502",
    fcLabel: "Function codes",
    fcPlaceholder: "3, 16",
    fcHelp:
      "Modbus function codes (e.g., 1=Read Coils, 3=Read Holding, 5=Write Coil, 6=Write Register, 15=Write Coils, 16=Write Registers).",
    addrLabel: "Register / coil addresses",
    addrPlaceholder: "0x0000-0x00FF, 40001",
    addrHelp:
      "Comma-separated register or coil ranges. Supports decimal (100-200) and hex (0x0064-0x00C8).",
  },
  dnp3: {
    label: "DNP3",
    port: "20000",
    fcLabel: "Function codes",
    fcPlaceholder: "1, 2, 3",
    fcHelp:
      "DNP3 application function codes (1=Read, 2=Write, 3=Select, 4=Operate, 5=Direct Operate, 13=Cold Restart, 14=Warm Restart).",
    addrLabel: "Station addresses",
    addrPlaceholder: "1-10",
    addrHelp:
      "DNP3 outstation destination addresses (decimal). Use ranges for address groups.",
  },
  cip: {
    label: "CIP / EtherNet/IP",
    port: "44818",
    fcLabel: "Service codes",
    fcPlaceholder: "76, 77",
    fcHelp:
      "CIP service codes (0x0E=Get_Attribute, 0x10=Set_Attribute, 0x4C/76=Read_Tag, 0x4D/77=Write_Tag, 0x52=Unconnected_Send).",
    addrLabel: "CIP path",
    addrPlaceholder: "",
    addrHelp: "Optional CIP class/instance path filter (hex string).",
  },
  s7comm: {
    label: "S7comm (Siemens)",
    port: "102",
    fcLabel: "Function codes",
    fcPlaceholder: "4, 5",
    fcHelp:
      "S7comm parameter function codes (4=Read Var, 5=Write Var, 0x1A=Download, 0x28=PLC Control, 0x29=PLC Stop).",
    addrLabel: "DB / address",
    addrPlaceholder: "",
    addrHelp: "Optional S7 data block or address filter.",
  },
  mms: {
    label: "IEC 61850 MMS",
    port: "102",
    fcLabel: "Service codes",
    fcPlaceholder: "",
    fcHelp:
      "MMS confirmed-request service tags (Read=0xA4, Write=0xA5, GetVariableAccessAttributes=0xA6).",
    addrLabel: "Named variable",
    addrPlaceholder: "",
    addrHelp: "Optional MMS named-variable filter.",
  },
  bacnet: {
    label: "BACnet/IP",
    port: "47808",
    fcLabel: "Service codes",
    fcPlaceholder: "12, 15",
    fcHelp:
      "BACnet service choice (12=ReadProperty, 14=ReadPropertyMultiple, 15=WriteProperty, 16=WritePropertyMultiple, 8=WhoIs).",
    addrLabel: "Object instance",
    addrPlaceholder: "",
    addrHelp: "Optional BACnet object instance filter.",
  },
  opcua: {
    label: "OPC UA",
    port: "4840",
    fcLabel: "Service IDs",
    fcPlaceholder: "",
    fcHelp:
      "OPC UA service node IDs (631=ReadRequest, 673=WriteRequest, 527=BrowseRequest).",
    addrLabel: "Node ID",
    addrPlaceholder: "",
    addrHelp: "Optional OPC UA node ID filter.",
  },
};

const PROTOCOL_KEYS = Object.keys(PROTOCOLS);

function protoMeta(name: string): ProtocolMeta {
  return (
    PROTOCOLS[name] ?? {
      label: name,
      port: "",
      fcLabel: "Function codes",
      fcPlaceholder: "",
      fcHelp: "Protocol-specific function or service codes.",
      addrLabel: "Addresses",
      addrPlaceholder: "",
      addrHelp: "Protocol-specific address filter.",
    }
  );
}

/* -- Page ----------------------------------------------------------------- */

export default function ICSPolicyPage() {
  const canEdit = isAdmin();
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [filterProto, setFilterProto] = useState<string>("all");
  const [dpiConfig, setDpiConfig] = useState<DataPlaneConfig>({
    captureInterfaces: [],
    dpiMock: false,
  });

  async function refresh() {
    setError(null);
    const list = await api.listFirewallRules();
    if (!list) {
      setError("Failed to load firewall rules.");
      return;
    }
    setRules(list);
  }

  useEffect(() => {
    refresh();
  }, []);
  useEffect(() => {
    fetchDataPlane().then((dp) => {
      if (dp) setDpiConfig(dp);
    });
  }, []);

  const icsRules = useMemo(
    () =>
      rules
        .filter((r) => !!r.ics?.protocol)
        .filter(
          (r) => filterProto === "all" || r.ics?.protocol === filterProto,
        ),
    [rules, filterProto],
  );

  const protoCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of rules) {
      if (r.ics?.protocol) m[r.ics.protocol] = (m[r.ics.protocol] ?? 0) + 1;
    }
    return m;
  }, [rules]);

  async function onSave(id: string, ics: ICSPredicate | undefined) {
    setError(null);
    const result = await api.updateFirewallRule(id, { ics });
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setEditing(null);
    refresh();
  }

  return (
    <Shell
      title="ICS / OT Protocol Filters"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* -- DPI capture config ------------------------------------------ */}
      <Card
        title="DPI Capture (Required)"
        titleRight={
          canEdit ? (
            <button
              onClick={saveDpiConfig}
              className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-ui hover:bg-blue-500"
            >
              {dpiSaveState === "saving" ? "Saving..." : "Save"}
            </button>
          ) : undefined
        }
        className="mb-4"
      >
        <div className="mb-3 text-sm text-slate-200">
          ICS filters require DPI capture to be enabled on at least one
          interface.
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-400">
              Capture interfaces
              <InfoTip label="Comma-separated interfaces to inspect for ICS protocol traffic." />
            </label>
            <input
              value={dpiIfaceCSV}
              disabled={!canEdit}
              onChange={(e) =>
                setDpiConfig((c) => ({
                  ...c,
                  captureInterfaces: e.target.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="lan2, lan3"
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={dpiConfig.dpiMock ?? false}
              disabled={!canEdit}
              onChange={(e) =>
                setDpiConfig((c) => ({ ...c, dpiMock: e.target.checked }))
              }
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            Safe learning lab mode (DPI inspect-all)
            <InfoTip label="Lab-only: inspect all traffic for DPI learning and UI visibility." />
          </label>
        </div>
        {!canEdit && (
          <div className="mt-2 text-xs text-slate-400">
            View-only mode: DPI capture settings are read-only.
          </div>
        )}
        <div className="mt-2 text-xs text-slate-400">
          PCAP management lives in{" "}
          <Link href="/dataplane/" className="text-blue-400 hover:text-blue-300">
            PCAP &rarr;
          </Link>
        </div>
      </Card>

      {/* -- Protocol summary cards -------------------------------------- */}
      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <Card title="Supported Protocols">
          <div className="flex flex-wrap gap-2">
            {PROTOCOL_KEYS.map((k) => (
              <StatusBadge key={k} variant="neutral">
                {PROTOCOLS[k].label}
              </StatusBadge>
            ))}
          </div>
        </Card>
        <Card title="Quick Start">
          <ol className="space-y-1 text-xs text-slate-400">
            <li>1. Create a firewall rule matching your PLC/RTU zone.</li>
            <li>2. Select the protocol and define criteria here.</li>
            <li>3. Start with Safe Learning, then switch to Enforce.</li>
          </ol>
          <Link
            href="/firewall/"
            className="mt-3 inline-block text-xs text-blue-400 hover:text-blue-300"
          >
            Go to Firewall Rules &rarr;
          </Link>
        </Card>
        <Card title="Active Filters">
          {Object.keys(protoCounts).length === 0 ? (
            <div className="text-xs text-slate-400">
              No ICS filters configured yet.
            </div>
          ) : (
            <div className="space-y-1">
              {Object.entries(protoCounts).map(([p, n]) => (
                <div
                  key={p}
                  className="flex items-center justify-between text-sm text-[var(--text)]"
                >
                  <span>{protoMeta(p).label}</span>
                  <StatusBadge variant="neutral">{n}</StatusBadge>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* -- Protocol filter tabs ---------------------------------------- */}
      <div className="mb-3 flex gap-2 overflow-x-auto">
        <button
          onClick={() => setFilterProto("all")}
          className={`rounded-lg px-3 py-1.5 text-xs transition-ui ${filterProto === "all" ? "bg-blue-600 text-white font-medium" : "bg-white/[0.04] text-slate-300 hover:bg-white/[0.08]"}`}
        >
          All
        </button>
        {PROTOCOL_KEYS.map((k) => (
          <button
            key={k}
            onClick={() => setFilterProto(k)}
            className={`rounded-lg px-3 py-1.5 text-xs transition-ui ${filterProto === k ? "bg-blue-600 text-white font-medium" : "bg-white/[0.04] text-slate-300 hover:bg-white/[0.08]"}`}
          >
            {PROTOCOLS[k].label}
            {protoCounts[k] ? ` (${protoCounts[k]})` : ""}
          </button>
        ))}
      </div>

      {/* -- Rules table ------------------------------------------------- */}
      <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
            <tr>
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">
                {filterProto !== "all"
                  ? protoMeta(filterProto).fcLabel
                  : "Codes"}
              </th>
              <th className="px-4 py-3">
                {filterProto !== "all"
                  ? protoMeta(filterProto).addrLabel
                  : "Addresses"}
              </th>
              <th className="px-4 py-3">R/W</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {icsRules.length === 0 && (
              <tr>
                <td className="px-4 py-8" colSpan={8}>
                  <EmptyState
                    title={`No ICS filters${filterProto !== "all" ? ` for ${protoMeta(filterProto).label}` : ""} configured`}
                    description="Create firewall rules with ICS protocol filters to monitor and control industrial traffic."
                    action={
                      <Link
                        href="/firewall/"
                        className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-ui hover:bg-blue-500"
                      >
                        Open Firewall Rules
                      </Link>
                    }
                  />
                </td>
              </tr>
            )}
            {icsRules.map((r) => (
              <tr key={r.id} className="border-t border-white/[0.06] table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {(r.sourceZones ?? []).join(", ") || "any"} &rarr;{" "}
                  {(r.destZones ?? []).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  <StatusBadge variant="neutral">
                    {protoMeta(r.ics?.protocol ?? "").label}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {(r.ics?.functionCode ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {(r.ics?.addresses ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 text-xs text-[var(--text)]">
                  {r.ics?.readOnly
                    ? "R"
                    : r.ics?.writeOnly
                      ? "W"
                      : "R/W"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  <StatusBadge
                    variant={r.ics?.mode === "learn" ? "warning" : "success"}
                    dot
                  >
                    {r.ics?.mode === "learn" ? "learning" : "enforce"}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => setEditing(r)}
                    className="rounded-md border border-white/[0.08] bg-white/[0.04] px-2 py-1 text-xs transition-ui hover:bg-white/[0.08]"
                  >
                    Edit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && (
        <EditICSModal
          rule={editing}
          onClose={() => setEditing(null)}
          onSave={(ics) => onSave(editing.id, ics)}
        />
      )}
    </Shell>
  );
}

/* -- Edit modal with protocol-specific fields ----------------------------- */

function EditICSModal({
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
    const ics: ICSPredicate = {
      protocol,
      functionCode: functionCodes
        .split(",")
        .map((v) => Number(v.trim()))
        .filter((n) => Number.isFinite(n) && n >= 0)
        .map((n) => Math.min(255, n)),
      addresses: addresses
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      readOnly,
      writeOnly,
      mode,
    };
    // Modbus-specific: unit ID
    if (protocol === "modbus" && unitId.trim()) {
      const uid = Number(unitId.trim());
      if (Number.isFinite(uid) && uid >= 0 && uid <= 255) ics.unitId = uid;
    }
    // CIP-specific: object classes
    if (protocol === "cip" && objectClasses.trim()) {
      ics.objectClasses = objectClasses
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => parseInt(s, s.startsWith("0x") ? 16 : 10))
        .filter((n) => Number.isFinite(n) && n >= 0);
    }
    // Strip empty arrays
    if (ics.functionCode?.length === 0) delete ics.functionCode;
    if (ics.addresses?.length === 0) delete ics.addresses;
    if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;
    onSave(ics);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-xl rounded-xl border border-white/[0.08] bg-surface-raised p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[var(--text)]">
            ICS filter &mdash; rule{" "}
            <span className="font-mono text-blue-400">{rule.id}</span>
          </h2>
          <button
            onClick={onClose}
            className="rounded-md border border-white/[0.08] bg-white/[0.04] px-2 py-1 text-xs transition-ui hover:bg-white/[0.08]"
          >
            Close
          </button>
        </div>

        <div className="space-y-4 text-sm">
          {/* Enable toggle */}
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
            />
            Enable ICS protocol filter
          </label>

          {/* Protocol + Mode row */}
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
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
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
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
              >
                <option value="learn">Safe learning (alert-only)</option>
                <option value="enforce">Enforce (block)</option>
              </select>
            </div>
          </div>

          {/* Protocol-specific: function/service codes */}
          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
              {meta.fcLabel}
              <InfoTip label={meta.fcHelp} />
            </label>
            <input
              value={functionCodes}
              onChange={(e) => setFunctionCodes(e.target.value)}
              disabled={!enabled}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
              placeholder={meta.fcPlaceholder || "Leave empty for all"}
            />
          </div>

          {/* Protocol-specific: addresses */}
          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text)]">
              {meta.addrLabel}
              <InfoTip label={meta.addrHelp} />
            </label>
            <input
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              disabled={!enabled}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
              placeholder={meta.addrPlaceholder || "Leave empty for all"}
            />
          </div>

          {/* Modbus-specific: Unit ID */}
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
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
                placeholder="0-255 (leave empty for all)"
              />
            </div>
          )}

          {/* CIP-specific: Object Classes */}
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
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
                placeholder="0x02, 0x04 (leave empty for all)"
              />
            </div>
          )}

          {/* Read/Write classification */}
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

          {/* Protocol hint */}
          <div className="rounded-lg border border-white/[0.06] bg-white/[0.03] px-3 py-2 text-xs text-slate-400">
            <strong className="text-slate-300">{meta.label}</strong> &mdash;
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
            rule={{
              id: rule.id,
              ics: enabled
                ? {
                    protocol,
                    functionCode: functionCodes
                      .split(",")
                      .map((v) => Number(v.trim()))
                      .filter((n) => Number.isFinite(n) && n >= 0),
                    addresses: addresses
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                    readOnly,
                    writeOnly,
                    mode,
                  }
                : undefined,
            }}
          />
          <button
            onClick={onClose}
            className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-ui hover:bg-blue-500"
          >
            Save filter
          </button>
        </div>
      </div>
    </div>
  );
}
