"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";

import {
  api,
  type Zone,
  type NATConfig,
  type FirewallRule,
  type PortForward,
  type ICSPredicate,
  type Protocol,
} from "../../lib/api";
import { Shell } from "../../components/Shell";

/* ── ICS protocol metadata ────────────────────────────────────── */

const ICS_PROTOCOLS: Record<string, { label: string; port: number }> = {
  modbus: { label: "Modbus/TCP", port: 502 },
  dnp3: { label: "DNP3", port: 20000 },
  cip: { label: "CIP / EtherNet/IP", port: 44818 },
  s7comm: { label: "S7comm (Siemens)", port: 102 },
  bacnet: { label: "BACnet/IP", port: 47808 },
  opcua: { label: "OPC UA", port: 4840 },
  mms: { label: "IEC 61850 MMS", port: 102 },
};

/* ── helpers ───────────────────────────────────────────────────── */

function zoneLabel(zone: Zone): string {
  return zone.alias ? `${zone.alias} (${zone.name})` : zone.name;
}

function genId(): string {
  return `wiz-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/* ── types ─────────────────────────────────────────────────────── */

type WizardId = "lan-internet" | "publish-service" | "ics-comm" | "inter-zone";

type CardDef = {
  id: WizardId;
  title: string;
  description: string;
  color: string;
  steps: string[];
};

const CARDS: CardDef[] = [
  {
    id: "lan-internet",
    title: "Allow LAN Internet Access",
    description: "Enable internal hosts to reach the Internet via SNAT masquerade.",
    color: "bg-mint",
    steps: ["Select LAN zone", "Select WAN zone", "Review & Apply"],
  },
  {
    id: "publish-service",
    title: "Publish Internal Service",
    description: "Expose an internal server to external traffic with DNAT port forwarding.",
    color: "bg-amber",
    steps: ["Server details", "Select protocol", "Select ingress zone", "Review & Apply"],
  },
  {
    id: "ics-comm",
    title: "Allow ICS Communication",
    description: "Permit industrial protocol traffic between zones with DPI enforcement.",
    color: "bg-cyan-400",
    steps: ["Select ICS protocol", "Select zones", "Access level", "Review & Apply"],
  },
  {
    id: "inter-zone",
    title: "Inter-Zone Communication",
    description: "Allow traffic between two zones with optional protocol/port filtering.",
    color: "bg-purple-400",
    steps: ["Source zone", "Destination zone", "Protocols & ports", "Review & Apply"],
  },
];

/* ── common protocol options for inter-zone ────────────────────── */

const COMMON_PROTOCOLS: { label: string; name: string; port: string }[] = [
  { label: "HTTP (80)", name: "tcp", port: "80" },
  { label: "HTTPS (443)", name: "tcp", port: "443" },
  { label: "SSH (22)", name: "tcp", port: "22" },
  { label: "RDP (3389)", name: "tcp", port: "3389" },
  { label: "DNS (53)", name: "udp", port: "53" },
  { label: "SNMP (161)", name: "udp", port: "161" },
  { label: "NTP (123)", name: "udp", port: "123" },
  { label: "ICMP", name: "icmp", port: "" },
];

/* ── page ──────────────────────────────────────────────────────── */

export default function WizardPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [natConfig, setNatConfig] = useState<NATConfig>({ enabled: false });
  const [loading, setLoading] = useState(true);

  /* active wizard state */
  const [active, setActive] = useState<WizardId | null>(null);
  const [step, setStep] = useState(0);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  /* wizard form state */
  const [lanZone, setLanZone] = useState("");
  const [wanZone, setWanZone] = useState("");

  const [serverIp, setServerIp] = useState("");
  const [serverPort, setServerPort] = useState("");
  const [pubProto, setPubProto] = useState<"tcp" | "udp">("tcp");
  const [ingressZone, setIngressZone] = useState("");

  const [icsProto, setIcsProto] = useState("modbus");
  const [icsSrcZone, setIcsSrcZone] = useState("");
  const [icsDstZone, setIcsDstZone] = useState("");
  const [icsAccess, setIcsAccess] = useState<"readonly" | "readwrite" | "monitor">("readonly");

  const [izSrcZone, setIzSrcZone] = useState("");
  const [izDstZone, setIzDstZone] = useState("");
  const [izAny, setIzAny] = useState(true);
  const [izSelected, setIzSelected] = useState<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    setLoading(true);
    const [z, n] = await Promise.all([api.listZones(), api.getNAT()]);
    setZones(z ?? []);
    setNatConfig(n ?? { enabled: false });
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function reset() {
    setActive(null);
    setStep(0);
    setApplying(false);
    setError(null);
    setSuccess(null);
    setLanZone("");
    setWanZone("");
    setServerIp("");
    setServerPort("");
    setPubProto("tcp");
    setIngressZone("");
    setIcsProto("modbus");
    setIcsSrcZone("");
    setIcsDstZone("");
    setIcsAccess("readonly");
    setIzSrcZone("");
    setIzDstZone("");
    setIzAny(true);
    setIzSelected(new Set());
  }

  function openWizard(id: WizardId) {
    reset();
    setActive(id);
  }

  const card = active ? CARDS.find((c) => c.id === active) ?? null : null;
  const totalSteps = card ? card.steps.length : 0;

  /* ── apply handlers ──────────────────────────────────────────── */

  async function applyLanInternet() {
    setApplying(true);
    setError(null);
    try {
      // Create firewall allow rule LAN -> WAN
      const ruleRes = await api.createFirewallRule({
        id: genId(),
        description: `Allow ${lanZone} to ${wanZone} (wizard)`,
        sourceZones: [lanZone],
        destZones: [wanZone],
        action: "ALLOW",
      });
      if (!ruleRes.ok) {
        setError(`Firewall rule failed: ${ruleRes.error}`);
        setApplying(false);
        return;
      }

      // Enable SNAT masquerade
      const updatedNat: NATConfig = {
        ...natConfig,
        enabled: true,
        egressZone: wanZone,
        sourceZones: Array.from(new Set([...(natConfig.sourceZones ?? []), lanZone])),
      };
      const natRes = await api.setNAT(updatedNat);
      if (!natRes.ok) {
        setError(`NAT config failed: ${natRes.error}`);
        setApplying(false);
        return;
      }
      setNatConfig(natRes.data);
      setSuccess("LAN internet access configured. Firewall allow rule and SNAT masquerade created.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unexpected error");
    }
    setApplying(false);
  }

  async function applyPublishService() {
    setApplying(true);
    setError(null);
    try {
      const port = parseInt(serverPort, 10);
      if (!port || port < 1 || port > 65535) {
        setError("Invalid port number.");
        setApplying(false);
        return;
      }

      // Add port forward via NAT
      const pf: PortForward = {
        id: genId(),
        enabled: true,
        description: `Port forward ${pubProto.toUpperCase()}/${port} to ${serverIp} (wizard)`,
        ingressZone: ingressZone,
        proto: pubProto,
        listenPort: port,
        destIp: serverIp,
        destPort: port,
      };
      const updatedNat: NATConfig = {
        ...natConfig,
        enabled: true,
        portForwards: [...(natConfig.portForwards ?? []), pf],
      };
      const natRes = await api.setNAT(updatedNat);
      if (!natRes.ok) {
        setError(`NAT port forward failed: ${natRes.error}`);
        setApplying(false);
        return;
      }
      setNatConfig(natRes.data);

      // Create matching firewall allow rule
      const ruleRes = await api.createFirewallRule({
        id: genId(),
        description: `Allow inbound ${pubProto.toUpperCase()}/${port} to ${serverIp} (wizard)`,
        sourceZones: [ingressZone],
        destinations: [serverIp],
        protocols: [{ name: pubProto, port: String(port) }],
        action: "ALLOW",
      });
      if (!ruleRes.ok) {
        setError(`Firewall rule failed: ${ruleRes.error}`);
        setApplying(false);
        return;
      }
      setSuccess("Internal service published. Port forward (DNAT) and firewall allow rule created.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unexpected error");
    }
    setApplying(false);
  }

  async function applyIcsComm() {
    setApplying(true);
    setError(null);
    try {
      const ics: ICSPredicate = {
        protocol: icsProto,
        mode: icsAccess === "monitor" ? "learn" : "enforce",
        readOnly: icsAccess === "readonly",
      };

      const protoMeta = ICS_PROTOCOLS[icsProto];
      const protocols: Protocol[] = protoMeta
        ? [{ name: "tcp", port: String(protoMeta.port) }]
        : [];

      const ruleRes = await api.createFirewallRule({
        id: genId(),
        description: `ICS ${protoMeta?.label ?? icsProto} ${icsSrcZone} -> ${icsDstZone} (${icsAccess}) (wizard)`,
        sourceZones: [icsSrcZone],
        destZones: [icsDstZone],
        protocols,
        ics,
        action: "ALLOW",
      });
      if (!ruleRes.ok) {
        setError(`Firewall rule failed: ${ruleRes.error}`);
        setApplying(false);
        return;
      }
      setSuccess(`ICS communication rule created for ${protoMeta?.label ?? icsProto} (${icsAccess}).`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unexpected error");
    }
    setApplying(false);
  }

  async function applyInterZone() {
    setApplying(true);
    setError(null);
    try {
      const protocols: Protocol[] | undefined = izAny
        ? undefined
        : Array.from(izSelected).map((key) => {
            const found = COMMON_PROTOCOLS.find((p) => `${p.name}:${p.port}` === key);
            return found
              ? { name: found.name, port: found.port || undefined }
              : { name: key };
          });

      const ruleRes = await api.createFirewallRule({
        id: genId(),
        description: `Allow ${izSrcZone} -> ${izDstZone}${izAny ? "" : ` (${Array.from(izSelected).join(", ")})`} (wizard)`,
        sourceZones: [izSrcZone],
        destZones: [izDstZone],
        protocols,
        action: "ALLOW",
      });
      if (!ruleRes.ok) {
        setError(`Firewall rule failed: ${ruleRes.error}`);
        setApplying(false);
        return;
      }
      setSuccess("Inter-zone communication rule created.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unexpected error");
    }
    setApplying(false);
  }

  function handleApply() {
    if (!active) return;
    switch (active) {
      case "lan-internet":
        applyLanInternet();
        break;
      case "publish-service":
        applyPublishService();
        break;
      case "ics-comm":
        applyIcsComm();
        break;
      case "inter-zone":
        applyInterZone();
        break;
    }
  }

  /* ── step validation ─────────────────────────────────────────── */

  function canAdvance(): boolean {
    if (!active) return false;
    switch (active) {
      case "lan-internet":
        if (step === 0) return !!lanZone;
        if (step === 1) return !!wanZone;
        return true;
      case "publish-service":
        if (step === 0) return !!serverIp && !!serverPort;
        if (step === 1) return true;
        if (step === 2) return !!ingressZone;
        return true;
      case "ics-comm":
        if (step === 0) return !!icsProto;
        if (step === 1) return !!icsSrcZone && !!icsDstZone;
        if (step === 2) return true;
        return true;
      case "inter-zone":
        if (step === 0) return !!izSrcZone;
        if (step === 1) return !!izDstZone;
        if (step === 2) return izAny || izSelected.size > 0;
        return true;
    }
  }

  /* ── step content renderers ──────────────────────────────────── */

  function renderZoneSelect(
    label: string,
    value: string,
    onChange: (v: string) => void,
    exclude?: string,
  ) {
    const filtered = exclude ? zones.filter((z) => z.name !== exclude) : zones;
    return (
      <div>
        <label className="mb-2 block text-sm font-medium text-slate-200">{label}</label>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
        >
          <option value="">-- select zone --</option>
          {filtered.map((z) => (
            <option key={z.name} value={z.name}>
              {zoneLabel(z)}
            </option>
          ))}
        </select>
      </div>
    );
  }

  function renderStepContent(): React.ReactNode {
    if (!active) return null;

    /* ── LAN Internet ─────────────────────────────────────────── */
    if (active === "lan-internet") {
      if (step === 0) return renderZoneSelect("LAN zone (source)", lanZone, setLanZone);
      if (step === 1) return renderZoneSelect("WAN zone (destination)", wanZone, setWanZone, lanZone);
      return (
        <div className="space-y-3 text-sm text-slate-200">
          <h3 className="text-base font-semibold text-white">Summary</h3>
          <div className="rounded-xl border border-white/10 bg-white/5 p-4 space-y-2">
            <p>Firewall rule: <span className="text-mint">ALLOW</span> from <strong>{lanZone}</strong> to <strong>{wanZone}</strong></p>
            <p>NAT: Enable SNAT masquerade on <strong>{wanZone}</strong> for source zone <strong>{lanZone}</strong></p>
          </div>
        </div>
      );
    }

    /* ── Publish Service ──────────────────────────────────────── */
    if (active === "publish-service") {
      if (step === 0)
        return (
          <div className="space-y-3">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-200">Internal server IP</label>
              <input
                value={serverIp}
                onChange={(e) => setServerIp(e.target.value)}
                placeholder="e.g. 192.168.1.10"
                className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-200">Port</label>
              <input
                value={serverPort}
                onChange={(e) => setServerPort(e.target.value)}
                placeholder="e.g. 443"
                type="number"
                min={1}
                max={65535}
                className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
            </div>
          </div>
        );
      if (step === 1)
        return (
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-200">Protocol</label>
            <div className="flex gap-3">
              {(["tcp", "udp"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setPubProto(p)}
                  className={`rounded-lg border px-4 py-2 text-sm ${
                    pubProto === p
                      ? "border-mint bg-mint/20 text-mint"
                      : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10"
                  }`}
                >
                  {p.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        );
      if (step === 2) return renderZoneSelect("External (ingress) zone", ingressZone, setIngressZone);
      return (
        <div className="space-y-3 text-sm text-slate-200">
          <h3 className="text-base font-semibold text-white">Summary</h3>
          <div className="rounded-xl border border-white/10 bg-white/5 p-4 space-y-2">
            <p>Port forward (DNAT): <strong>{ingressZone}</strong> {pubProto.toUpperCase()}/{serverPort} &#8594; <strong>{serverIp}:{serverPort}</strong></p>
            <p>Firewall rule: <span className="text-mint">ALLOW</span> inbound from <strong>{ingressZone}</strong> to <strong>{serverIp}</strong> on {pubProto.toUpperCase()}/{serverPort}</p>
          </div>
        </div>
      );
    }

    /* ── ICS Communication ────────────────────────────────────── */
    if (active === "ics-comm") {
      if (step === 0)
        return (
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-200">ICS Protocol</label>
            <select
              value={icsProto}
              onChange={(e) => setIcsProto(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            >
              {Object.entries(ICS_PROTOCOLS).map(([key, meta]) => (
                <option key={key} value={key}>
                  {meta.label}
                </option>
              ))}
            </select>
          </div>
        );
      if (step === 1)
        return (
          <div className="space-y-3">
            {renderZoneSelect("Source zone", icsSrcZone, setIcsSrcZone)}
            {renderZoneSelect("Destination zone", icsDstZone, setIcsDstZone, icsSrcZone)}
          </div>
        );
      if (step === 2)
        return (
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-200">Access level</label>
            <div className="flex flex-col gap-2">
              {([
                { key: "readonly" as const, label: "Read-only", desc: "Only read function codes are permitted" },
                { key: "readwrite" as const, label: "Read / Write", desc: "Both read and write operations are allowed" },
                { key: "monitor" as const, label: "Monitor-only (learn mode)", desc: "Passively observe traffic without enforcement" },
              ]).map((opt) => (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => setIcsAccess(opt.key)}
                  className={`rounded-xl border p-3 text-left ${
                    icsAccess === opt.key
                      ? "border-mint bg-mint/10"
                      : "border-white/10 bg-white/5 hover:bg-white/10"
                  }`}
                >
                  <div className={`text-sm font-medium ${icsAccess === opt.key ? "text-mint" : "text-white"}`}>{opt.label}</div>
                  <div className="text-xs text-slate-400">{opt.desc}</div>
                </button>
              ))}
            </div>
          </div>
        );
      const protoMeta = ICS_PROTOCOLS[icsProto];
      return (
        <div className="space-y-3 text-sm text-slate-200">
          <h3 className="text-base font-semibold text-white">Summary</h3>
          <div className="rounded-xl border border-white/10 bg-white/5 p-4 space-y-2">
            <p>Protocol: <strong>{protoMeta?.label ?? icsProto}</strong> (port {protoMeta?.port})</p>
            <p>Direction: <strong>{icsSrcZone}</strong> &#8594; <strong>{icsDstZone}</strong></p>
            <p>Access: <strong>{icsAccess === "readonly" ? "Read-only" : icsAccess === "readwrite" ? "Read/Write" : "Monitor-only (learn)"}</strong></p>
            <p>Firewall rule: <span className="text-mint">ALLOW</span> with ICS predicate</p>
          </div>
        </div>
      );
    }

    /* ── Inter-Zone ───────────────────────────────────────────── */
    if (active === "inter-zone") {
      if (step === 0) return renderZoneSelect("Source zone", izSrcZone, setIzSrcZone);
      if (step === 1) return renderZoneSelect("Destination zone", izDstZone, setIzDstZone, izSrcZone);
      if (step === 2)
        return (
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={izAny}
                onChange={(e) => setIzAny(e.target.checked)}
                className="rounded"
              />
              Allow any protocol / port
            </label>
            {!izAny && (
              <div className="grid grid-cols-2 gap-2">
                {COMMON_PROTOCOLS.map((p) => {
                  const key = `${p.name}:${p.port}`;
                  const selected = izSelected.has(key);
                  return (
                    <button
                      key={key}
                      type="button"
                      onClick={() => {
                        setIzSelected((prev) => {
                          const next = new Set(prev);
                          if (selected) next.delete(key);
                          else next.add(key);
                          return next;
                        });
                      }}
                      className={`rounded-lg border px-3 py-2 text-left text-sm ${
                        selected
                          ? "border-mint bg-mint/20 text-mint"
                          : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10"
                      }`}
                    >
                      {p.label}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        );
      return (
        <div className="space-y-3 text-sm text-slate-200">
          <h3 className="text-base font-semibold text-white">Summary</h3>
          <div className="rounded-xl border border-white/10 bg-white/5 p-4 space-y-2">
            <p>Direction: <strong>{izSrcZone}</strong> &#8594; <strong>{izDstZone}</strong></p>
            <p>Protocols: {izAny ? <strong>Any</strong> : <strong>{Array.from(izSelected).map((k) => {
              const p = COMMON_PROTOCOLS.find((cp) => `${cp.name}:${cp.port}` === k);
              return p?.label ?? k;
            }).join(", ")}</strong>}</p>
            <p>Firewall rule: <span className="text-mint">ALLOW</span></p>
          </div>
        </div>
      );
    }

    return null;
  }

  /* ── render ──────────────────────────────────────────────────── */

  return (
    <Shell title="Policy Wizard">
      <p className="mb-6 text-sm text-slate-400">
        Select a common connectivity scenario below. The wizard will walk you through each step and create the necessary firewall rules and NAT configuration automatically.
      </p>

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm text-slate-300">
          Loading configuration...
        </div>
      )}

      {!loading && zones.length === 0 && (
        <div className="mb-6 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          No zones configured. Please{" "}
          <Link href="/zones/" className="font-semibold text-mint hover:text-mint/80">
            create zones
          </Link>{" "}
          before using the wizard.
        </div>
      )}

      {/* ── scenario cards ──────────────────────────────────────── */}
      {!loading && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {CARDS.map((c) => {
            const isActive = active === c.id;
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => (isActive ? reset() : openWizard(c.id))}
                disabled={zones.length === 0}
                className={`rounded-2xl border p-5 text-left transition ${
                  isActive
                    ? "border-mint/50 bg-mint/10"
                    : zones.length === 0
                      ? "cursor-not-allowed border-white/5 bg-white/[0.02] opacity-50"
                      : "border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/10"
                }`}
              >
                <div className="mb-3 flex items-center gap-3">
                  <div className={`h-4 w-4 shrink-0 rounded ${c.color}`} />
                  <h3 className="text-sm font-semibold text-white">{c.title}</h3>
                </div>
                <p className="text-xs text-slate-400">{c.description}</p>
              </button>
            );
          })}
        </div>
      )}

      {/* ── inline wizard flow ──────────────────────────────────── */}
      {active && card && !success && (
        <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-6">
          {/* step pills */}
          <div className="mb-6 flex flex-wrap gap-2">
            {card.steps.map((s, i) => (
              <button
                key={i}
                type="button"
                onClick={() => i < step && setStep(i)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  i === step
                    ? "bg-mint/20 text-mint"
                    : i < step
                      ? "bg-white/10 text-white cursor-pointer hover:bg-white/15"
                      : "bg-white/5 text-slate-500"
                }`}
              >
                {i + 1}. {s}
              </button>
            ))}
          </div>

          {/* step content */}
          <div className="min-h-[120px]">{renderStepContent()}</div>

          {/* error */}
          {error && (
            <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
              {error}
            </div>
          )}

          {/* navigation */}
          <div className="mt-6 flex items-center justify-between border-t border-white/10 pt-4">
            <button
              type="button"
              onClick={() => (step === 0 ? reset() : setStep(step - 1))}
              className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200 hover:bg-white/10"
            >
              {step === 0 ? "Cancel" : "Back"}
            </button>

            {step < totalSteps - 1 ? (
              <button
                type="button"
                onClick={() => setStep(step + 1)}
                disabled={!canAdvance()}
                className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-medium text-mint hover:bg-mint/30 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>
            ) : (
              <button
                type="button"
                onClick={handleApply}
                disabled={applying}
                className="rounded-lg bg-mint px-4 py-2 text-sm font-medium text-black hover:bg-mint/90 disabled:opacity-50"
              >
                {applying ? "Applying..." : "Apply"}
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── success message ─────────────────────────────────────── */}
      {success && (
        <div className="mt-6 rounded-2xl border border-mint/30 bg-mint/10 p-6">
          <h3 className="mb-2 text-sm font-semibold text-mint">Success</h3>
          <p className="mb-4 text-sm text-slate-200">{success}</p>
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href="/firewall/"
              className="rounded-lg bg-white/10 px-3 py-2 text-slate-200 hover:bg-white/20"
            >
              View firewall rules
            </Link>
            <Link
              href="/nat/"
              className="rounded-lg bg-white/10 px-3 py-2 text-slate-200 hover:bg-white/20"
            >
              View NAT config
            </Link>
            <button
              type="button"
              onClick={reset}
              className="rounded-lg bg-mint/20 px-3 py-2 text-mint hover:bg-mint/30"
            >
              Run another wizard
            </button>
          </div>
        </div>
      )}
    </Shell>
  );
}
