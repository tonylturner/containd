"use client";

import Link from "next/link";
import { useState } from "react";

import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import {
  api,
  type FirewallRule,
  type FirewallRulePatch,
  type ICSPredicate,
  type ICSPredicatePatch,
  type Protocol,
  type RulePreview,
  type Zone,
} from "../../lib/api";
import { validateIPOrCIDRList } from "../../lib/validate";
import { iec104DraftFrom, type IEC104Draft } from "../ics/iec104";
import type { ICSMode, ICSModeSelection } from "../ics/ics-shared";
import { zoneLabel } from "./firewall-utils";
import { ICSPredicateFields, buildRuleICS } from "./firewall-ics-fields";
import {
  actionTakesICS,
  buildPolicy,
  policyDraftFrom,
  type PolicyDraft,
  type PolicyFields,
} from "./firewall-rule-policy";
import { RulePolicyFields } from "./firewall-rule-policy-fields";
import { RuleImpactSummary } from "./firewall-rule-warnings";

const LOG_HELP =
  "Logs matching traffic as firewall.rule.hit events. A RATE_LIMIT rule logs the packets it drops over the limit; a TAG rule logs the connections it labels.";

type ICSDraft = {
  enabled: boolean;
  protocol: string;
  functionCodes: string;
  addresses: string;
  unitId: string;
  objectClasses: string;
  readOnly: boolean;
  writeOnly: boolean;
  mode: ICSModeSelection;
  iec: IEC104Draft;
};

// A new filter starts from example values; an existing one keeps its own,
// so editing never narrows a predicate the user did not touch.
function icsDraftFrom(ics: ICSPredicate | undefined, mode: ICSModeSelection): ICSDraft {
  const existing = !!ics?.protocol;
  return {
    enabled: existing,
    protocol: ics?.protocol ?? "modbus",
    functionCodes: existing ? (ics?.functionCode ?? []).join(", ") : "3,16",
    addresses: existing ? (ics?.addresses ?? []).join(", ") : "0-100",
    unitId: ics?.unitId?.toString() ?? "",
    objectClasses: (ics?.objectClasses ?? []).map((v) => "0x" + v.toString(16)).join(", "),
    readOnly: ics?.readOnly ?? false,
    writeOnly: ics?.writeOnly ?? false,
    mode,
    iec: iec104DraftFrom(ics),
  };
}

type Built<T> = { ok: true; value: T } | { ok: false; error: string };

/** The action, conditions and ICS predicate a form stages. */
function buildRuleParts(
  policy: PolicyDraft,
  ics: ICSDraft,
  tagsInUse: string[],
  globalMode: ICSMode | undefined,
  existing?: ICSPredicate,
): Built<{ fields: PolicyFields; ics: ICSPredicate | undefined }> {
  const fields = buildPolicy(policy, tagsInUse);
  if (!fields.ok) return fields;
  if (ics.enabled && !actionTakesICS(fields.value.action)) {
    return { ok: false, error: `${fields.value.action} rules take no ICS protocol; turn off the ICS filter.` };
  }
  const built = buildRuleICS({ ...ics, action: fields.value.action, existing, globalMode });
  if (!built.ok) return built;
  return { ok: true, value: { fields: fields.value, ics: built.ics } };
}

function ICSToggle({ draft, onChange }: { draft: ICSDraft; onChange: (d: ICSDraft) => void }) {
  return (
    <>
      <label className="flex items-center gap-2 text-sm text-(--text)">
        <input type="checkbox" checked={draft.enabled} onChange={(e) => onChange({ ...draft, enabled: e.target.checked })} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
        ICS Protocol Filter
        <InfoTip label="Adds OT/ICS-aware matching to an ALLOW or DENY rule." />
      </label>
      <span className="text-xs text-(--text-muted) md:col-span-4">ICS filters let you allow or block specific protocol actions beyond basic L3/L4 rules.</span>
      <span className="text-xs text-(--text-muted) md:col-span-4">Requires DPI capture to see ICS traffic (configure in <a href="/dataplane/" className="text-(--amber) hover:text-(--amber)">PCAP Capture</a>).</span>
    </>
  );
}

function ICSDraftFields({ draft, onChange, globalMode }: { draft: ICSDraft; onChange: (d: ICSDraft) => void; globalMode: string | undefined }) {
  if (!draft.enabled) return null;
  const set = (patch: Partial<ICSDraft>) => onChange({ ...draft, ...patch });
  return (
    <ICSPredicateFields
      protocol={draft.protocol} onProtocolChange={(protocol) => set({ protocol })}
      mode={draft.mode} onModeChange={(mode) => set({ mode })} globalMode={globalMode}
      functionCodes={draft.functionCodes} onFunctionCodesChange={(functionCodes) => set({ functionCodes })}
      addresses={draft.addresses} onAddressesChange={(addresses) => set({ addresses })}
      unitId={draft.unitId} onUnitIdChange={(unitId) => set({ unitId })}
      objectClasses={draft.objectClasses} onObjectClassesChange={(objectClasses) => set({ objectClasses })}
      readOnly={draft.readOnly} onReadOnlyChange={(readOnly) => set({ readOnly })}
      writeOnly={draft.writeOnly} onWriteOnlyChange={(writeOnly) => set({ writeOnly })}
      iec={draft.iec} onIecChange={(iec) => set({ iec })}
    />
  );
}

function NoZonesHint({ zones }: { zones: Zone[] }) {
  if (zones.length > 0) return null;
  return (
    <div className="rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text) md:col-span-2">
      No zones yet.{" "}<Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">Create a zone</Link> to target policies.
    </div>
  );
}

export function EditRuleModal({
  zones,
  rule,
  globalMode,
  tagsInUse,
  onClose,
  onSave,
}: {
  zones: Zone[];
  rule: FirewallRule;
  globalMode: ICSMode | undefined;
  /** Distinct TAG labels of the other rules. */
  tagsInUse: string[];
  onClose: () => void;
  onSave: (patch: FirewallRulePatch) => void;
}) {
  const [description, setDescription] = useState(rule.description ?? "");
  const [log, setLog] = useState(rule.log ?? false);
  const [srcZone, setSrcZone] = useState((rule.sourceZones ?? [])[0] ?? "");
  const [dstZone, setDstZone] = useState((rule.destZones ?? [])[0] ?? "");
  const [sources, setSources] = useState((rule.sources ?? []).join(", "));
  const [destinations, setDestinations] = useState((rule.destinations ?? []).join(", "));
  const [proto, setProto] = useState((rule.protocols ?? [])[0]?.name ?? "tcp");
  const [port, setPort] = useState((rule.protocols ?? [])[0]?.port ?? "");
  const [policy, setPolicy] = useState(() => policyDraftFrom(rule));
  // An empty ICS mode inherits the global mode; keep it empty.
  const [ics, setIcs] = useState(() => icsDraftFrom(rule.ics, rule.ics?.mode ?? ""));
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);

  function build(): { patch: FirewallRulePatch; preview: FirewallRule } | null {
    setError(null);
    const parts = buildRuleParts(policy, ics, tagsInUse, globalMode, rule.ics);
    if (!parts.ok) {
      setError(parts.error);
      return null;
    }
    const { fields } = parts.value;
    // Rule updates merge, so a stored mode is cleared with an empty one.
    let icsPatch: ICSPredicatePatch | null = parts.value.ics ?? null;
    if (icsPatch && ics.mode === "" && rule.ics?.mode) icsPatch = { ...icsPatch, mode: "" };
    const base = {
      description: description.trim(),
      action: fields.action,
      log,
      sourceZones: srcZone ? [srcZone] : [],
      destZones: dstZone ? [dstZone] : [],
      sources: splitCSV(sources) ?? [],
      destinations: splitCSV(destinations) ?? [],
      protocols: buildProtocols(proto, port),
      identities: fields.identities,
    };
    // The PATCH keeps every omitted key, so a cleared field sends its empty
    // value and a removed predicate, rate limit or schedule sends null.
    return {
      patch: {
        ...base,
        rateLimit: fields.rateLimit ?? null,
        tag: fields.tag ?? "",
        schedule: fields.schedule ?? null,
        ics: icsPatch,
      },
      preview: {
        ...base,
        id: rule.id,
        rateLimit: fields.rateLimit,
        tag: fields.tag,
        schedule: fields.schedule,
        ics: parts.value.ics,
      },
    };
  }

  function save() {
    const built = build();
    if (built) onSave(built.patch);
  }

  async function previewImpact() {
    const built = build();
    if (!built) return;
    setPreviewing(true);
    const res = await api.previewFirewallRule(built.preview);
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
      <div className="max-h-[95vh] w-full max-w-2xl overflow-y-auto rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
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
          <NoZonesHint zones={zones} />
          <select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="input-industrial">
            <option value="">Dest zone (any)</option>
            {zones.map((z) => (<option key={z.name} value={z.name}>{zoneLabel(z)}</option>))}
          </select>
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input type="checkbox" checked={log} onChange={(e) => setLog(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
            Log hits
            <InfoTip label={LOG_HELP} />
          </label>
          <input value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sources CIDR (csv)" className="input-industrial md:col-span-2" />
          <input value={destinations} onChange={(e) => setDestinations(e.target.value)} placeholder="destinations CIDR (csv)" className="input-industrial md:col-span-2" />
          <select value={proto} onChange={(e) => setProto(e.target.value)} className="input-industrial">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
          <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="port/range" className="input-industrial" />
        </div>

        <RulePolicyFields draft={policy} onChange={setPolicy} />

        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <ICSToggle draft={ics} onChange={setIcs} />
        </div>
        <ICSDraftFields draft={ics} onChange={setIcs} globalMode={globalMode} />

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

export function CreateRuleForm({
  zones,
  globalMode,
  tagsInUse,
  onCreate,
}: {
  zones: Zone[];
  globalMode: ICSMode | undefined;
  /** Distinct TAG labels of the existing rules. */
  tagsInUse: string[];
  onCreate: (rule: FirewallRule) => Promise<void>;
}) {
  const [id, setId] = useState("");
  const [description, setDescription] = useState("");
  const [log, setLog] = useState(false);
  const [srcZone, setSrcZone] = useState("");
  const [dstZone, setDstZone] = useState("");
  const [sources, setSources] = useState("");
  const [destinations, setDestinations] = useState("");
  const [proto, setProto] = useState("tcp");
  const [port, setPort] = useState("502");
  const [policy, setPolicy] = useState(() => policyDraftFrom());
  // New ICS filters start in learning mode, the safe default.
  const [ics, setIcs] = useState(() => icsDraftFrom(undefined, "learn"));
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit() {
    setError(null);
    if (!id.trim()) {
      setError("Rule ID is required.");
      return;
    }
    for (const [label, value] of [["Source", sources], ["Destination", destinations]] as const) {
      const err = value.trim() ? validateIPOrCIDRList(value) : null;
      if (err) {
        setError(`${label}: ${err}`);
        return;
      }
    }
    const parts = buildRuleParts(policy, ics, tagsInUse, globalMode);
    if (!parts.ok) {
      setError(parts.error);
      return;
    }
    const { fields } = parts.value;
    const rule: FirewallRule = {
      id: id.trim(),
      description: description.trim() || undefined,
      sourceZones: srcZone ? [srcZone] : undefined,
      destZones: dstZone ? [dstZone] : undefined,
      sources: splitCSV(sources),
      destinations: splitCSV(destinations),
      protocols: buildProtocols(proto, port),
      identities: fields.identities.length > 0 ? fields.identities : undefined,
      schedule: fields.schedule,
      ics: parts.value.ics,
      action: fields.action,
      rateLimit: fields.rateLimit,
      tag: fields.tag,
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
        <NoZonesHint zones={zones} />
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
        <label className="flex items-center gap-2 text-sm text-(--text)">
          <input type="checkbox" checked={log} onChange={(e) => setLog(e.target.checked)} className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
          Log hits
          <InfoTip label={LOG_HELP} />
        </label>
      </div>

      <RulePolicyFields draft={policy} onChange={setPolicy} />

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <ICSToggle draft={ics} onChange={setIcs} />
      </div>
      <ICSDraftFields draft={ics} onChange={setIcs} globalMode={globalMode} />

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
