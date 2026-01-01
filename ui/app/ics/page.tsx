"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

import {
  api,
  fetchDataPlane,
  isAdmin,
  setDataPlane,
  type DataPlaneConfig,
  type FirewallRule,
  type ICSPredicate,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { InfoTip } from "../../components/InfoTip";

export default function ICSPolicyPage() {
  const canEdit = isAdmin();
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [dpiConfig, setDpiConfig] = useState<DataPlaneConfig>({ captureInterfaces: [], dpiMock: false });
  const [dpiSaveState, setDpiSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");

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
      if (!dp) return;
      setDpiConfig({
        captureInterfaces: dp.captureInterfaces ?? [],
        dpiMock: dp.dpiMock ?? false,
      });
    });
  }, []);

  const icsRules = useMemo(
    () => rules.filter((r) => !!r.ics?.protocol),
    [rules],
  );
  const dpiIfaceCSV = useMemo(() => (dpiConfig.captureInterfaces ?? []).join(", "), [dpiConfig.captureInterfaces]);

  async function onSave(id: string, ics: ICSPredicate | undefined) {
    setError(null);
    const updated = await api.updateFirewallRule(id, { ics });
    if (!updated) {
      setError("Failed to update ICS filter.");
      return;
    }
    setEditing(null);
    refresh();
  }
  async function saveDpiConfig() {
    if (!canEdit) return;
    setDpiSaveState("saving");
    const saved = await setDataPlane({
      captureInterfaces: dpiConfig.captureInterfaces ?? [],
      dpiMock: dpiConfig.dpiMock ?? false,
    });
    setDpiSaveState(saved ? "saved" : "error");
    setTimeout(() => setDpiSaveState("idle"), 1500);
  }

  return (
    <Shell
      title="ICS Filters"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      <div className="mb-4 rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-slate-300">DPI Capture (Required)</div>
            <div className="mt-1 text-sm text-slate-200">ICS filters only work when DPI capture is enabled.</div>
          </div>
          {canEdit && (
            <button
              onClick={saveDpiConfig}
              className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
            >
              {dpiSaveState === "saving" ? "Saving..." : "Save"}
            </button>
          )}
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-400">
              Capture interfaces
              <InfoTip label="Comma-separated interfaces to inspect for Modbus traffic." />
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
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={dpiConfig.dpiMock ?? false}
              disabled={!canEdit}
              onChange={(e) => setDpiConfig((c) => ({ ...c, dpiMock: e.target.checked }))}
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            Safe learning lab mode (DPI inspect-all)
            <InfoTip label="Lab-only: emit synthetic Modbus events for learning and UI visibility." />
          </label>
        </div>
        {!canEdit && (
          <div className="mt-2 text-xs text-slate-400">
            View-only mode: DPI capture settings are read-only.
          </div>
        )}
        <div className="mt-2 text-xs text-slate-400">
          PCAP management lives in{" "}
          <Link href="/dataplane/" className="text-mint hover:text-mint/80">
            PCAP →
          </Link>
        </div>
      </div>

      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-300">What This Does</div>
          <p className="mt-2 text-sm text-slate-200">
            Adds OT/ICS-aware filters to firewall rules (Modbus/TCP today).
          </p>
          <ul className="mt-3 space-y-1 text-xs text-slate-400">
            <li>• Match Modbus function codes and register ranges.</li>
            <li>• Enforce read-only or write-only per rule.</li>
            <li>• Choose safe learning (alert-only) or enforce (block).</li>
            <li>• Emit DPI events for audits and alerts.</li>
          </ul>
        </div>
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-300">Quick Start</div>
          <ol className="mt-2 space-y-1 text-xs text-slate-400">
            <li>1. Create a firewall rule that matches your PLC zone.</li>
            <li>2. Open the rule here and set Modbus filters.</li>
            <li>3. Start with Safe Learning, then enforce.</li>
          </ol>
          <Link href="/firewall/" className="mt-3 inline-block text-xs text-mint hover:text-mint/80">
            Go to Firewall Rules →
          </Link>
        </div>
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-300">Status</div>
          <div className="mt-3 flex items-center justify-between text-sm text-slate-200">
            <span>ICS filters</span>
            <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs">{icsRules.length}</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Supported now: Modbus/TCP. More protocols are phased.
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Function Codes</th>
              <th className="px-4 py-3">Addresses</th>
              <th className="px-4 py-3">Safety Mode</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {icsRules.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={7}>
                  No ICS filters configured. Add them on a firewall rule, then edit here.
                  <Link href="/firewall/" className="ml-2 text-mint hover:text-mint/80">
                    Open Firewall Rules →
                  </Link>
                </td>
              </tr>
            )}
            {icsRules.map((r) => (
              <tr key={r.id} className="border-t border-white/5">
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.sourceZones ?? []).join(", ") || "any"} →{" "}
                  {(r.destZones ?? []).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {r.ics?.protocol}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.ics?.functionCode ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.ics?.addresses ?? []).join(", ") || "*"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {r.ics?.mode === "learn" ? "safe learning" : "enforce"}
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => setEditing(r)}
                    className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
                  >
                    Edit ICS filter
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
    (rule.ics?.functionCode ?? []).join(", ") || "3,16",
  );
  const [addresses, setAddresses] = useState(
    (rule.ics?.addresses ?? []).join(", ") || "0-100",
  );
  const [readOnly, setReadOnly] = useState(rule.ics?.readOnly ?? false);
  const [writeOnly, setWriteOnly] = useState(rule.ics?.writeOnly ?? false);
  const [mode, setMode] = useState<"enforce" | "learn">(rule.ics?.mode ?? "learn");

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
        .filter((n) => Number.isFinite(n))
        .map((n) => Math.max(0, Math.min(255, n))),
      addresses: addresses
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      readOnly,
      writeOnly,
      mode,
    };
    onSave(ics);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-2xl border border-white/10 bg-ink p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            ICS filter for rule {rule.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
          >
            Close
          </button>
        </div>

        <div className="space-y-3 text-sm">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            Enable ICS filter
            <InfoTip label="Turns on ICS-aware matching for this rule." />
          </label>

          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-300">
                Safety mode
                <InfoTip label="Safe learning only alerts; enforce will block on match." />
              </label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as "enforce" | "learn")}
                disabled={!enabled}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white disabled:opacity-60"
              >
                <option value="learn">safe learning (alert-only)</option>
                <option value="enforce">enforce (block)</option>
              </select>
            </div>
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-300">
                Protocol
                <InfoTip label="Currently only Modbus/TCP is supported." />
              </label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                disabled={!enabled}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white disabled:opacity-60"
              >
                <option value="modbus">modbus</option>
              </select>
            </div>
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-300">
                Function codes
                <InfoTip label="Comma-separated Modbus function codes (e.g., 3=Read Holding, 16=Write Multiple)." />
              </label>
              <input
                value={functionCodes}
                onChange={(e) => setFunctionCodes(e.target.value)}
                disabled={!enabled}
                className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white disabled:opacity-60"
                placeholder="3,16"
              />
            </div>
          </div>

          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-300">
              Addresses
              <InfoTip label="Comma-separated register/coil ranges, e.g., 0-100, 40001-40100." />
            </label>
            <input
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              disabled={!enabled}
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white disabled:opacity-60"
              placeholder="0-100"
            />
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={readOnly}
                onChange={(e) => setReadOnly(e.target.checked)}
                disabled={!enabled}
                className="h-4 w-4 rounded border-white/20 bg-black/30 disabled:opacity-60"
              />
              Read-only class
              <InfoTip label="Allow read functions; deny writes (leave both unchecked for read/write)." />
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={writeOnly}
                onChange={(e) => setWriteOnly(e.target.checked)}
                disabled={!enabled}
                className="h-4 w-4 rounded border-white/20 bg-black/30 disabled:opacity-60"
              />
              Write-only class
              <InfoTip label="Allow write functions; deny reads (leave both unchecked for read/write)." />
            </label>
          </div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
          >
            Save filter
          </button>
        </div>
      </div>
    </div>
  );
}
