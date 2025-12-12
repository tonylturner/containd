"use client";

import { useEffect, useMemo, useState } from "react";

import { api, type FirewallRule, type ICSPredicate } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function ICSPolicyPage() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);

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

  const icsRules = useMemo(
    () => rules.filter((r) => !!r.ics?.protocol),
    [rules],
  );

  async function onSave(id: string, ics: ICSPredicate | undefined) {
    setError(null);
    const updated = await api.updateFirewallRule(id, { ics });
    if (!updated) {
      setError("Failed to update ICS predicate.");
      return;
    }
    setEditing(null);
    refresh();
  }

  return (
    <Shell
      title="ICS Policy"
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

      <div className="overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Function Codes</th>
              <th className="px-4 py-3">Addresses</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {icsRules.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={7}>
                  No ICS predicates configured. Add them in Firewall Rules.
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
                  {r.ics?.readOnly
                    ? "read-only"
                    : r.ics?.writeOnly
                      ? "write-only"
                      : "rw"}
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => setEditing(r)}
                    className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
                  >
                    Edit ICS
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
    };
    onSave(ics);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-2xl border border-white/10 bg-ink p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            ICS predicate for rule {rule.id}
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
            Enable ICS predicate
          </label>

          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="block text-xs uppercase tracking-wide text-slate-300">
                Protocol
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
              <label className="block text-xs uppercase tracking-wide text-slate-300">
                Function codes
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
            <label className="block text-xs uppercase tracking-wide text-slate-300">
              Addresses
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
            Save ICS
          </button>
        </div>
      </div>
    </div>
  );
}

