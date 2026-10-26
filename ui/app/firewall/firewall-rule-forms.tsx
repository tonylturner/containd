"use client";

import Link from "next/link";
import { useState } from "react";

import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import {
  api,
  type FirewallRule,
  type FirewallRulePatch,
  type Protocol,
  type RulePreview,
  type Zone,
} from "../../lib/api";
import { validateIPOrCIDRList } from "../../lib/validate";
import { iec104DraftFrom, type IEC104Draft } from "../ics/iec104";
import { zoneLabel } from "./firewall-utils";
import { ICSPredicateFields, buildRuleICS } from "./firewall-ics-fields";
import { RuleImpactSummary } from "./firewall-rule-warnings";

export function EditRuleModal({
  zones,
  rule,
  onClose,
  onSave,
}: {
  zones: Zone[];
  rule: FirewallRule;
  onClose: () => void;
  onSave: (patch: FirewallRulePatch) => void;
}) {
  const [description, setDescription] = useState(rule.description ?? "");
  const [action, setAction] = useState<"ALLOW" | "DENY">(rule.action);
  const [log, setLog] = useState(rule.log ?? false);
  const [srcZone, setSrcZone] = useState((rule.sourceZones ?? [])[0] ?? "");
  const [dstZone, setDstZone] = useState((rule.destZones ?? [])[0] ?? "");
  const [sources, setSources] = useState((rule.sources ?? []).join(", "));
  const [destinations, setDestinations] = useState((rule.destinations ?? []).join(", "));
  const [proto, setProto] = useState((rule.protocols ?? [])[0]?.name ?? "tcp");
  const [port, setPort] = useState((rule.protocols ?? [])[0]?.port ?? "");
  const [icsEnabled, setIcsEnabled] = useState(!!rule.ics?.protocol);
  const [icsProtocol, setIcsProtocol] = useState(rule.ics?.protocol ?? "modbus");
  const [functionCodes, setFunctionCodes] = useState((rule.ics?.functionCode ?? []).join(", ") || "3,16");
  const [addresses, setAddresses] = useState((rule.ics?.addresses ?? []).join(", ") || "0-100");
  const [icsUnitId, setIcsUnitId] = useState(rule.ics?.unitId?.toString() ?? "");
  const [objectClasses, setObjectClasses] = useState((rule.ics?.objectClasses ?? []).map((v) => "0x" + v.toString(16)).join(", "));
  const [readOnly, setReadOnly] = useState(rule.ics?.readOnly ?? false);
  const [writeOnly, setWriteOnly] = useState(rule.ics?.writeOnly ?? false);
  const [mode, setMode] = useState<"enforce" | "learn">(rule.ics?.mode ?? "learn");
  const [iec, setIec] = useState<IEC104Draft>(() => iec104DraftFrom(rule.ics));
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);

  function buildPatch(): FirewallRulePatch | null {
    setError(null);
    const ics = buildRuleICS({
      enabled: icsEnabled,
      protocol: icsProtocol,
      functionCodes,
      addresses,
      unitId: icsUnitId,
      objectClasses,
      readOnly,
      writeOnly,
      mode,
      iec,
      action,
      existing: rule.ics,
    });
    if (!ics.ok) {
      setError(ics.error);
      return null;
    }
    // The PATCH keeps every omitted key, so a cleared field sends its empty
    // value and a disabled ICS filter sends null.
    return {
      description: description.trim(),
      action,
      log,
      sourceZones: srcZone ? [srcZone] : [],
      destZones: dstZone ? [dstZone] : [],
      sources: splitCSV(sources) ?? [],
      destinations: splitCSV(destinations) ?? [],
      protocols: buildProtocols(proto, port),
      ics: ics.ics ?? null,
    };
  }

  function save() {
    const patch = buildPatch();
    if (patch) onSave(patch);
  }

  // Previews the edited rule, including the identities and schedule this form
  // does not edit: their warnings explain an inactive ALLOW rule.
  async function previewImpact() {
    const patch = buildPatch();
    if (!patch) return;
    setPreviewing(true);
    const res = await api.previewFirewallRule({ ...rule, ...patch, ics: patch.ics ?? undefined });
    setPreviewing(false);
    if (!res.ok) {
      setPreview(null);
      setError(`Impact preview failed: ${res.error}`);
      return;
    }
    setPreview(res.data);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-(--surface) px-4 animate-fade-in">
      <div className="w-full max-w-2xl rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-(--text)">Edit rule {rule.id}</h2>
          <button onClick={onClose} className="rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui">Close</button>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="input-industrial md:col-span-3" />
          <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="input-industrial">
            <option value="">Source zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          {zones.length === 0 && (
            <div className="rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text) md:col-span-2">
              No zones yet.{" "}<Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">Create a zone</Link> to target policies.
            </div>
          )}
          <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="input-industrial">
            <option value="">Dest zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          <select value={action} onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")} className="input-industrial">
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
          </select>
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input type="checkbox" checked={log} onChange={(e) => setLog(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
            Log hits
            <InfoTip label="When enabled, matching traffic is logged as a firewall.rule.hit event." />
          </label>
          <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="input-industrial md:col-span-2" />
          <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="input-industrial md:col-span-2" />
          <select value={proto} onChange={(e) => setProto(e.target.value)} className="input-industrial">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
          <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="input-industrial" />
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
            ICS Protocol Filter
            <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
          </label>
          <span className="text-xs text-(--text-muted) md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
          <span className="text-xs text-(--text-muted) md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-(--amber) hover:text-(--amber)">PCAP Capture</a>).</span>
        </div>

        {icsEnabled && (
          <ICSPredicateFields
            protocol={icsProtocol} onProtocolChange={setIcsProtocol}
            mode={mode} onModeChange={setMode}
            functionCodes={functionCodes} onFunctionCodesChange={setFunctionCodes}
            addresses={addresses} onAddressesChange={setAddresses}
            unitId={icsUnitId} onUnitIdChange={setIcsUnitId}
            objectClasses={objectClasses} onObjectClassesChange={setObjectClasses}
            readOnly={readOnly} onReadOnlyChange={setReadOnly}
            writeOnly={writeOnly} onWriteOnlyChange={setWriteOnly}
            iec={iec} onIecChange={setIec}
          />
        )}

        {preview && <RuleImpactSummary preview={preview} />}
        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={previewImpact} disabled={previewing} className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50">
            {previewing ? "Previewing..." : "Preview impact"}
          </button>
          <button onClick={onClose} className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui">Cancel</button>
          <button onClick={save} className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110">Save changes</button>
        </div>
      </div>
    </div>
  );
}

export function CreateRuleForm({ zones, onCreate }: { zones: Zone[]; onCreate: (rule: FirewallRule) => void }) {
  const [id, setId] = useState("");
  const [description, setDescription] = useState("");
  const [action, setAction] = useState<"ALLOW" | "DENY">("ALLOW");
  const [log, setLog] = useState(false);
  const [srcZone, setSrcZone] = useState("");
  const [dstZone, setDstZone] = useState("");
  const [sources, setSources] = useState("");
  const [destinations, setDestinations] = useState("");
  const [proto, setProto] = useState("tcp");
  const [port, setPort] = useState("502");
  const [icsEnabled, setIcsEnabled] = useState(false);
  const [icsProtocol, setIcsProtocol] = useState("modbus");
  const [functionCodes, setFunctionCodes] = useState("3,16");
  const [addresses, setAddresses] = useState("0-100");
  const [icsUnitId, setIcsUnitId] = useState("");
  const [objectClasses, setObjectClasses] = useState("");
  const [readOnly, setReadOnly] = useState(false);
  const [writeOnly, setWriteOnly] = useState(false);
  const [mode, setMode] = useState<"enforce" | "learn">("learn");
  const [iec, setIec] = useState<IEC104Draft>(() => iec104DraftFrom(undefined));
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit() {
    setError(null);
    if (!id.trim()) {
      setError("Rule ID is required.");
      return;
    }
    if (sources.trim()) {
      const srcErr = validateIPOrCIDRList(sources);
      if (srcErr) {
        setError("Source: " + srcErr);
        return;
      }
    }
    if (destinations.trim()) {
      const dstErr = validateIPOrCIDRList(destinations);
      if (dstErr) {
        setError("Destination: " + dstErr);
        return;
      }
    }
    const ics = buildRuleICS({
      enabled: icsEnabled,
      protocol: icsProtocol,
      functionCodes,
      addresses,
      unitId: icsUnitId,
      objectClasses,
      readOnly,
      writeOnly,
      mode,
      iec,
      action,
    });
    if (!ics.ok) {
      setError(ics.error);
      return;
    }
    const rule: FirewallRule = {
      id: id.trim(),
      description: description.trim() || undefined,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols: buildProtocols(proto, port),
      ics: ics.ics,
      action,
      log: log || undefined,
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
    <Card padding="lg" className="mt-6">
      <h2 className="text-sm font-semibold text-(--text)">Create rule</h2>
      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder="id (e.g. mb-allow)" className="input-industrial" />
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="input-industrial md:col-span-2" />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="input-industrial">
          <option value="">Source zone (any)</option>
          {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
        </select>
        {zones.length === 0 && (
          <div className="rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text) md:col-span-2">
            No zones yet.{" "}<Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">Create a zone</Link> to target policies.
          </div>
        )}
        <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="input-industrial">
          <option value="">Dest zone (any)</option>
          {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
        </select>
        <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="input-industrial" />
        <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="input-industrial" />
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <select value={proto} onChange={(e) => setProto(e.target.value)} className="input-industrial">
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
        </select>
        <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="input-industrial" />
        <select value={action} onChange={(e) => setAction(e.target.value as "ALLOW" | "DENY")} className="input-industrial">
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-(--text)">
          <input type="checkbox" checked={log} onChange={(e) => setLog(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
          Log hits
          <InfoTip label="When enabled, matching traffic is logged as a firewall.rule.hit event." />
        </label>
        <label className="flex items-center gap-2 text-sm text-(--text)">
          <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
          ICS Protocol Filter
          <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
        </label>
        <span className="text-xs text-(--text-muted) md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
        <span className="text-xs text-(--text-muted) md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-(--amber) hover:text-(--amber)">PCAP Capture</a>).</span>
      </div>

      {icsEnabled && (
        <ICSPredicateFields
          protocol={icsProtocol} onProtocolChange={setIcsProtocol}
          mode={mode} onModeChange={setMode}
          functionCodes={functionCodes} onFunctionCodesChange={setFunctionCodes}
          addresses={addresses} onAddressesChange={setAddresses}
          unitId={icsUnitId} onUnitIdChange={setIcsUnitId}
          objectClasses={objectClasses} onObjectClassesChange={setObjectClasses}
          readOnly={readOnly} onReadOnlyChange={setReadOnly}
          writeOnly={writeOnly} onWriteOnlyChange={setWriteOnly}
          iec={iec} onIecChange={setIec}
        />
      )}

      <div className="mt-3 flex items-center justify-between">
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button onClick={submit} disabled={saving} className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
          {saving ? "Creating..." : "Create rule"}
        </button>
      </div>
    </Card>
  );
}

function buildProtocols(proto: string, port: string): Protocol[] {
  return proto ? [{ name: proto, port: port.trim() || undefined }] : [];
}

function splitCSV(v: string): string[] | undefined {
  const out = v.split(",").map((s) => s.trim()).filter(Boolean);
  return out.length > 0 ? out : undefined;
}
