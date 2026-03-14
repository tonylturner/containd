"use client";

import Link from "next/link";
import { useState } from "react";

import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import {
  type FirewallRule,
  type ICSPredicate,
  type Protocol,
  type Zone,
} from "../../lib/api";
import { validateIPOrCIDRList } from "../../lib/validate";
import {
  ICS_PROTOCOL_KEYS,
  ICS_PROTOCOLS,
  icsProtoMeta,
  zoneLabel,
} from "./firewall-utils";

export function EditRuleModal({
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

  function save() {
    onSave({
      description: description.trim() || undefined,
      action,
      log: log || undefined,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols: buildProtocols(proto, port),
      ics: buildICSPredicate({
        enabled: icsEnabled,
        protocol: icsProtocol,
        functionCodes,
        addresses,
        unitId: icsUnitId,
        objectClasses,
        readOnly,
        writeOnly,
        mode,
      }),
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface)] px-4 animate-fade-in">
      <div className="w-full max-w-2xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[var(--text)]">Edit rule {rule.id}</h2>
          <button onClick={onClose} className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]">Close</button>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="description" className="input-industrial md:col-span-3" />
          <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="input-industrial">
            <option value="">Source zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          {zones.length === 0 && (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:col-span-2">
              No zones yet.{" "}<Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">Create a zone</Link> to target policies.
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
          <label className="flex items-center gap-2 text-sm text-[var(--text)]">
            <input type="checkbox" checked={log} onChange={(e) => setLog(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
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
          <label className="flex items-center gap-2 text-sm text-[var(--text)]">
            <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
            ICS Protocol Filter
            <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
          </label>
          <span className="text-xs text-[var(--text-muted)] md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
          <span className="text-xs text-[var(--text-muted)] md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-[var(--amber)] hover:text-[var(--amber)]">PCAP Capture</a>).</span>
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
          />
        )}

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]">Cancel</button>
          <button onClick={save} className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110">Save changes</button>
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
    const rule: FirewallRule = {
      id: id.trim(),
      description: description.trim() || undefined,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols: buildProtocols(proto, port),
      ics: buildICSPredicate({
        enabled: icsEnabled,
        protocol: icsProtocol,
        functionCodes,
        addresses,
        unitId: icsUnitId,
        objectClasses,
        readOnly,
        writeOnly,
        mode,
      }),
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
      <h2 className="text-sm font-semibold text-[var(--text)]">Create rule</h2>
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
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:col-span-2">
            No zones yet.{" "}<Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">Create a zone</Link> to target policies.
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
        <label className="flex items-center gap-2 text-sm text-[var(--text)]">
          <input type="checkbox" checked={log} onChange={(e) => setLog(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
          Log hits
          <InfoTip label="When enabled, matching traffic is logged as a firewall.rule.hit event." />
        </label>
        <label className="flex items-center gap-2 text-sm text-[var(--text)]">
          <input type="checkbox" checked={icsEnabled} onChange={(e) => setIcsEnabled(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
          ICS Protocol Filter
          <InfoTip label="Adds OT/ICS-aware matching to this firewall rule." />
        </label>
        <span className="text-xs text-[var(--text-muted)] md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
        <span className="text-xs text-[var(--text-muted)] md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-[var(--amber)] hover:text-[var(--amber)]">PCAP Capture</a>).</span>
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
        />
      )}

      <div className="mt-3 flex items-center justify-between">
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button onClick={submit} disabled={saving} className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
          {saving ? "Creating..." : "Create rule"}
        </button>
      </div>
    </Card>
  );
}

function ICSPredicateFields({
  protocol, onProtocolChange,
  mode, onModeChange,
  functionCodes, onFunctionCodesChange,
  addresses, onAddressesChange,
  unitId, onUnitIdChange,
  objectClasses, onObjectClassesChange,
  readOnly, onReadOnlyChange,
  writeOnly, onWriteOnlyChange,
}: {
  protocol: string; onProtocolChange: (v: string) => void;
  mode: string; onModeChange: (v: "enforce" | "learn") => void;
  functionCodes: string; onFunctionCodesChange: (v: string) => void;
  addresses: string; onAddressesChange: (v: string) => void;
  unitId: string; onUnitIdChange: (v: string) => void;
  objectClasses: string; onObjectClassesChange: (v: string) => void;
  readOnly: boolean; onReadOnlyChange: (v: boolean) => void;
  writeOnly: boolean; onWriteOnlyChange: (v: boolean) => void;
}) {
  const meta = icsProtoMeta(protocol);
  const [showHelp, setShowHelp] = useState(false);

  return (
    <div className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 space-y-3">
      <div className="grid gap-3 md:grid-cols-4">
        <div className="md:col-span-2">
          <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">ICS Protocol</label>
          <select value={protocol} onChange={(e) => onProtocolChange(e.target.value)} className="input-industrial w-full">
            {ICS_PROTOCOL_KEYS.map((k) => (<option key={k} value={k}>{ICS_PROTOCOLS[k].label} (:{ICS_PROTOCOLS[k].port})</option>))}
          </select>
        </div>
        <div>
          <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">Rule Mode</label>
          <select value={mode} onChange={(e) => onModeChange(e.target.value as "enforce" | "learn")} className="input-industrial w-full">
            <option value="learn">Learning (passive)</option>
            <option value="enforce">Enforcement (active)</option>
          </select>
        </div>
        <div className="flex items-end">
          <button
            onClick={() => setShowHelp(!showHelp)}
            className="rounded-sm border border-blue-500/20 bg-blue-500/10 px-2.5 py-2 text-[10px] text-blue-400 hover:bg-blue-500/20 transition-ui w-full"
          >
            {showHelp ? "Hide" : "Show"} protocol reference
          </button>
        </div>
      </div>

      {showHelp && (
        <div className="rounded-sm border border-blue-500/[0.1] bg-blue-500/[0.03] p-3 space-y-2">
          <div className="text-xs font-medium text-blue-400">{meta.label} Reference</div>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <div className="text-[10px] font-medium text-[var(--text)]">{meta.fcLabel}</div>
              <div className="text-[10px] text-[var(--text-muted)] mt-0.5 leading-relaxed">{meta.fcHelp}</div>
            </div>
            <div>
              <div className="text-[10px] font-medium text-[var(--text)]">{meta.addrLabel}</div>
              <div className="text-[10px] text-[var(--text-muted)] mt-0.5 leading-relaxed">{meta.addrHelp}</div>
            </div>
          </div>
          {meta.notes && (
            <div className="text-[10px] text-[var(--text-dim)] border-t border-white/[0.04] pt-2 mt-2">{meta.notes}</div>
          )}
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">{meta.fcLabel} <span className="text-[var(--text-dim)]">(comma-separated)</span></label>
          <input value={functionCodes} onChange={(e) => onFunctionCodesChange(e.target.value)} placeholder={meta.fcPlaceholder || `${meta.fcLabel}`} className="input-industrial w-full" />
        </div>
        <div>
          <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">{meta.addrLabel} <span className="text-[var(--text-dim)]">(comma-separated)</span></label>
          <input value={addresses} onChange={(e) => onAddressesChange(e.target.value)} placeholder={meta.addrPlaceholder || meta.addrLabel} className="input-industrial w-full" />
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        {meta.showUnitId && (
          <div>
            <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">Unit ID <span className="text-[var(--text-dim)]">(0-255, Modbus slave)</span></label>
            <input value={unitId} onChange={(e) => onUnitIdChange(e.target.value)} placeholder="e.g. 1" className="input-industrial w-full" />
          </div>
        )}
        {meta.showObjectClasses && (
          <div className="md:col-span-2">
            <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">CIP Object Classes <span className="text-[var(--text-dim)]">(hex csv)</span></label>
            <input value={objectClasses} onChange={(e) => onObjectClassesChange(e.target.value)} placeholder="0x02, 0x04, 0x66" className="input-industrial w-full" />
          </div>
        )}
        {meta.showStationAddrs && (
          <div className="md:col-span-2">
            <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">Station Addresses <span className="text-[var(--text-dim)]">(source/destination, 0-65534)</span></label>
            <input value={addresses} onChange={(e) => onAddressesChange(e.target.value)} placeholder="1-10" className="input-industrial w-full" />
          </div>
        )}
        {meta.showDbNumber && (
          <div>
            <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">DB Numbers <span className="text-[var(--text-dim)]">(Siemens data blocks)</span></label>
            <input value={addresses} onChange={(e) => onAddressesChange(e.target.value)} placeholder="DB1, DB100" className="input-industrial w-full" />
          </div>
        )}
        {meta.showObjectType && (
          <div>
            <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">Object Type <span className="text-[var(--text-dim)]">(BACnet)</span></label>
            <input disabled placeholder="analog-input, binary-output" className="input-industrial w-full opacity-60" title="Object type filtering coming soon" />
          </div>
        )}
        {meta.showPropertyId && (
          <div>
            <label className="block text-[10px] font-medium text-[var(--text-muted)] mb-1">Property ID <span className="text-[var(--text-dim)]">(BACnet)</span></label>
            <input disabled placeholder="85 (present-value)" className="input-industrial w-full opacity-60" title="Property ID filtering coming soon" />
          </div>
        )}
      </div>

      <div className="flex items-center gap-4 text-sm text-[var(--text)]">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={readOnly} onChange={(e) => onReadOnlyChange(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
          Read-only
          <InfoTip label="Only match read operations (function codes that read data without modifying state)." />
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={writeOnly} onChange={(e) => onWriteOnlyChange(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]" />
          Write-only
          <InfoTip label="Only match write/control operations (function codes that modify device state)." />
        </label>
      </div>
    </div>
  );
}

function buildProtocols(proto: string, port: string): Protocol[] {
  return proto ? [{ name: proto, port: port.trim() || undefined }] : [];
}

function buildICSPredicate({
  enabled,
  protocol,
  functionCodes,
  addresses,
  unitId,
  objectClasses,
  readOnly,
  writeOnly,
  mode,
}: {
  enabled: boolean;
  protocol: string;
  functionCodes: string;
  addresses: string;
  unitId: string;
  objectClasses: string;
  readOnly: boolean;
  writeOnly: boolean;
  mode: "enforce" | "learn";
}): ICSPredicate | undefined {
  if (!enabled) return undefined;
  const icsMeta = icsProtoMeta(protocol);
  const ics: ICSPredicate = {
    protocol,
    functionCode: functionCodes
      .split(",")
      .map((v) => Number(v.trim()))
      .filter((n) => Number.isFinite(n))
      .map((n) => Math.max(0, Math.min(255, n))),
    addresses: addresses.split(",").map((s) => s.trim()).filter(Boolean),
    readOnly,
    writeOnly,
    mode,
  };
  if (icsMeta.showUnitId && unitId.trim()) {
    const uid = Number(unitId.trim());
    if (Number.isFinite(uid) && uid >= 0 && uid <= 255) ics.unitId = uid;
  }
  if (icsMeta.showObjectClasses && objectClasses.trim()) {
    ics.objectClasses = objectClasses
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => parseInt(s, s.startsWith("0x") ? 16 : 10))
      .filter((n) => Number.isFinite(n) && n >= 0);
  }
  if ((ics.functionCode?.length ?? 0) === 0) delete ics.functionCode;
  if ((ics.addresses?.length ?? 0) === 0) delete ics.addresses;
  if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;
  return ics;
}

function splitCSV(v: string): string[] | undefined {
  const out = v.split(",").map((s) => s.trim()).filter(Boolean);
  return out.length > 0 ? out : undefined;
}
