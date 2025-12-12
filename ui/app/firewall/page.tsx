"use client";

import { useEffect, useState } from "react";

import {
  api,
  isAdmin,
  type FirewallRule,
  type Protocol,
  type Zone,
  type ICSPredicate,
} from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FirewallRule | null>(null);

  async function refresh() {
    const [r, z] = await Promise.all([api.listFirewallRules(), api.listZones()]);
    setRules(r ?? []);
    setZones(z ?? []);
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onDelete(id: string) {
    setError(null);
    const ok = await api.deleteFirewallRule(id);
    if (!ok) {
      setError("Failed to delete rule.");
      return;
    }
    refresh();
  }

  async function onCreate(rule: FirewallRule) {
    setError(null);
    const created = await api.createFirewallRule(rule);
    if (!created) {
      setError("Failed to create rule (check zones/CIDRs).");
      return;
    }
    refresh();
  }

  async function onUpdate(id: string, patch: Partial<FirewallRule>) {
    setError(null);
    const updated = await api.updateFirewallRule(id, patch);
    if (!updated) {
      setError("Failed to update rule.");
      return;
    }
    setEditing(null);
    refresh();
  }

  return (
    <Shell
      title="Firewall Rules"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}

      {isAdmin() && <CreateRuleForm zones={zones} onCreate={onCreate} />}

      <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3">Zones</th>
              <th className="px-4 py-3">Protocols</th>
              <th className="px-4 py-3">ICS</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={7}>
                  No firewall rules configured.
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id} className="border-t border-white/5">
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {r.description || "—"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.sourceZones ?? []).join(", ") || "any"} →{" "}
                  {(r.destZones ?? []).join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.protocols ?? [])
                    .map((p) => `${p.name}${p.port ? ":" + p.port : ""}`)
                    .join(", ") || "any"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {r.ics?.protocol
                    ? `${r.ics.protocol} fc=${(r.ics.functionCode ?? []).join(
                        ",",
                      ) || "*"}`
                    : "—"}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={
                      r.action === "ALLOW"
                        ? "rounded-full bg-mint/20 px-2 py-0.5 text-xs text-mint"
                        : "rounded-full bg-amber/20 px-2 py-0.5 text-xs text-amber"
                    }
                  >
                    {r.action}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  {isAdmin() && (
                    <>
                      <button
                        onClick={() => setEditing(r)}
                        className="mr-2 rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => onDelete(r.id)}
                        className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30"
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && isAdmin() && (
        <EditRuleModal
          zones={zones}
          rule={editing}
          onClose={() => setEditing(null)}
          onSave={(patch) => onUpdate(editing.id, patch)}
        />
      )}
    </Shell>
  );
}

function EditRuleModal({
  zones,
  rule,
  onClose,
  onSave,
}: {
  zones: Zone[];
  rule: FirewallRule;
  onClose: () => void;
  onSave: (patch: Partial<FirewallRule>) => void;
}) {
  const [description, setDescription] = useState(rule.description ?? "");
  const [action, setAction] = useState<"ALLOW" | "DENY">(rule.action);
  const [srcZone, setSrcZone] = useState((rule.sourceZones ?? [])[0] ?? "");
  const [dstZone, setDstZone] = useState((rule.destZones ?? [])[0] ?? "");
  const [sources, setSources] = useState((rule.sources ?? []).join(", "));
  const [destinations, setDestinations] = useState(
    (rule.destinations ?? []).join(", "),
  );
  const [proto, setProto] = useState((rule.protocols ?? [])[0]?.name ?? "tcp");
  const [port, setPort] = useState((rule.protocols ?? [])[0]?.port ?? "");
  const [icsEnabled, setIcsEnabled] = useState(!!rule.ics?.protocol);
  const [functionCodes, setFunctionCodes] = useState(
    (rule.ics?.functionCode ?? []).join(", ") || "3,16",
  );
  const [addresses, setAddresses] = useState(
    (rule.ics?.addresses ?? []).join(", ") || "0-100",
  );
  const [readOnly, setReadOnly] = useState(rule.ics?.readOnly ?? false);
  const [writeOnly, setWriteOnly] = useState(rule.ics?.writeOnly ?? false);

  function save() {
    const protocols: Protocol[] = proto
      ? [{ name: proto, port: port.trim() || undefined }]
      : [];
    let ics: ICSPredicate | undefined;
    if (icsEnabled) {
      ics = {
        protocol: "modbus",
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
    }
    onSave({
      description: description.trim() || undefined,
      action,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols,
      ics,
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-2xl rounded-2xl border border-white/10 bg-ink p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Edit rule {rule.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
          >
            Close
          </button>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="description"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-3"
          />
          <select
            value={srcZone}
            onChange={(e) => setSrcZone(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="">Source zone (any)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {z.name}
              </option>
            ))}
          </select>
          <select
            value={dstZone}
            onChange={(e) => setDstZone(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="">Dest zone (any)</option>
            {zones.map((z) => (
              <option key={z.name} value={z.name}>
                {z.name}
              </option>
            ))}
          </select>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
          </select>
          <input
            value={sources}
            onChange={(e) => setSources(e.target.value)}
            placeholder="sources CIDR (csv)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2"
          />
          <input
            value={destinations}
            onChange={(e) => setDestinations(e.target.value)}
            placeholder="destinations CIDR (csv)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2"
          />
          <select
            value={proto}
            onChange={(e) => setProto(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="port/range"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={icsEnabled}
              onChange={(e) => setIcsEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            ICS (Modbus)
          </label>
        </div>

        {icsEnabled && (
          <div className="mt-3 grid gap-3 rounded-xl border border-white/10 bg-black/30 p-4 md:grid-cols-4">
            <input
              value={functionCodes}
              onChange={(e) => setFunctionCodes(e.target.value)}
              placeholder="function codes (csv)"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <input
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              placeholder="addresses/ranges (csv)"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white md:col-span-2"
            />
            <div className="flex items-center gap-4 text-sm text-slate-200">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={readOnly}
                  onChange={(e) => setReadOnly(e.target.checked)}
                  className="h-4 w-4 rounded border-white/20 bg-black/30"
                />
                Read-only
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={writeOnly}
                  onChange={(e) => setWriteOnly(e.target.checked)}
                  className="h-4 w-4 rounded border-white/20 bg-black/30"
                />
                Write-only
              </label>
            </div>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30"
          >
            Save changes
          </button>
        </div>
      </div>
    </div>
  );
}

function CreateRuleForm({
  zones,
  onCreate,
}: {
  zones: Zone[];
  onCreate: (rule: FirewallRule) => void;
}) {
  const [id, setId] = useState("");
  const [description, setDescription] = useState("");
  const [action, setAction] = useState<"ALLOW" | "DENY">("ALLOW");
  const [srcZone, setSrcZone] = useState("");
  const [dstZone, setDstZone] = useState("");
  const [sources, setSources] = useState("");
  const [destinations, setDestinations] = useState("");
  const [proto, setProto] = useState("tcp");
  const [port, setPort] = useState("502");
  const [icsEnabled, setIcsEnabled] = useState(false);
  const [functionCodes, setFunctionCodes] = useState("3,16");
  const [addresses, setAddresses] = useState("0-100");
  const [readOnly, setReadOnly] = useState(false);
  const [writeOnly, setWriteOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit() {
    setError(null);
    if (!id.trim()) {
      setError("Rule ID is required.");
      return;
    }
    const protocols: Protocol[] = proto
      ? [{ name: proto, port: port.trim() || undefined }]
      : [];
    let ics: ICSPredicate | undefined;
    if (icsEnabled) {
      ics = {
        protocol: "modbus",
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
    }
    const rule: FirewallRule = {
      id: id.trim(),
      description: description.trim() || undefined,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols,
      ics,
      action,
    };
    setSaving(true);
    await onCreate(rule);
    setSaving(false);
    setId("");
    setDescription("");
    setSources("");
    setDestinations("");
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
      <h2 className="text-sm font-semibold text-white">Create rule</h2>
      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <input
          value={id}
          onChange={(e) => setId(e.target.value)}
          placeholder="id (e.g. mb-allow)"
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
        />
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="description"
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
        />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select
          value={srcZone}
          onChange={(e) => setSrcZone(e.target.value)}
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
        >
          <option value="">Source zone (any)</option>
          {zones.map((z) => (
            <option key={z.name} value={z.name}>
              {z.name}
            </option>
          ))}
        </select>
        <select
          value={dstZone}
          onChange={(e) => setDstZone(e.target.value)}
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
        >
          <option value="">Dest zone (any)</option>
          {zones.map((z) => (
            <option key={z.name} value={z.name}>
              {z.name}
            </option>
          ))}
        </select>
        <input
          value={sources}
          onChange={(e) => setSources(e.target.value)}
          placeholder="sources CIDR (csv)"
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
        />
        <input
          value={destinations}
          onChange={(e) => setDestinations(e.target.value)}
          placeholder="destinations CIDR (csv)"
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
        />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select
          value={proto}
          onChange={(e) => setProto(e.target.value)}
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
        >
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
        </select>
        <input
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="port/range"
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
        />
        <select
          value={action}
          onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")}
          className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
        >
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-slate-200">
          <input
            type="checkbox"
            checked={icsEnabled}
            onChange={(e) => setIcsEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-white/20 bg-black/30"
          />
          ICS (Modbus) predicate
        </label>
      </div>

      {icsEnabled && (
        <div className="mt-3 grid gap-3 rounded-xl border border-white/10 bg-black/30 p-4 md:grid-cols-4">
          <input
            value={functionCodes}
            onChange={(e) => setFunctionCodes(e.target.value)}
            placeholder="function codes (csv)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
          />
          <input
            value={addresses}
            onChange={(e) => setAddresses(e.target.value)}
            placeholder="addresses/ranges (csv)"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
          />
          <div className="flex items-center gap-4 text-sm text-slate-200">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={readOnly}
                onChange={(e) => setReadOnly(e.target.checked)}
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Read-only
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={writeOnly}
                onChange={(e) => setWriteOnly(e.target.checked)}
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Write-only
            </label>
          </div>
        </div>
      )}

      <div className="mt-3 flex items-center justify-between">
        {error && <p className="text-sm text-amber">{error}</p>}
        <button
          onClick={submit}
          disabled={saving}
          className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
        >
          {saving ? "Creating..." : "Create rule"}
        </button>
      </div>
    </div>
  );
}

function splitCSV(v: string): string[] | undefined {
  const out = v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return out.length > 0 ? out : undefined;
}
