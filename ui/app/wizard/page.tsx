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
import { Card } from "../../components/Card";

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
    color: "bg-[var(--amber)]",
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
        <label className="mb-2 block text-sm font-medium text-[var(--text)]">{label}</label>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full input-industrial"
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
        <div className="space-y-3 text-sm text-[var(--text)]">
          <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 space-y-2">
            <p>Firewall rule: <span className="text-emerald-400">ALLOW</span> from <strong>{lanZone}</strong> to <strong>{wanZone}</strong></p>
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
              <label className="mb-2 block text-sm font-medium text-[var(--text)]">Internal server IP</label>
              <input
                value={serverIp}
                onChange={(e) => setServerIp(e.target.value)}
                placeholder="e.g. 192.168.1.10"
                className="w-full input-industrial"
              />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-[var(--text)]">Port</label>
              <input
                value={serverPort}
                onChange={(e) => setServerPort(e.target.value)}
                placeholder="e.g. 443"
                type="number"
                min={1}
                max={65535}
                className="w-full input-industrial"
              />
            </div>
          </div>
        );
      if (step === 1)
        return (
          <div>
            <label className="mb-2 block text-sm font-medium text-[var(--text)]">Protocol</label>
            <div className="flex gap-3">
              {(["tcp", "udp"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setPubProto(p)}
                  className={`rounded-sm border px-4 py-2 text-sm transition-ui ${
                    pubProto === p
                      ? "border-amber-500/40 bg-amber-500/[0.2] text-[var(--amber)]"
                      : "border-amber-500/[0.15] bg-[var(--surface)] text-[var(--text)] hover:bg-amber-500/[0.1]"
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
        <div className="space-y-3 text-sm text-[var(--text)]">
          <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 space-y-2">
            <p>Port forward (DNAT): <strong>{ingressZone}</strong> {pubProto.toUpperCase()}/{serverPort} &#8594; <strong>{serverIp}:{serverPort}</strong></p>
            <p>Firewall rule: <span className="text-emerald-400">ALLOW</span> inbound from <strong>{ingressZone}</strong> to <strong>{serverIp}</strong> on {pubProto.toUpperCase()}/{serverPort}</p>
          </div>
        </div>
      );
    }

    /* ── ICS Communication ────────────────────────────────────── */
    if (active === "ics-comm") {
      if (step === 0)
        return (
          <div>
            <label className="mb-2 block text-sm font-medium text-[var(--text)]">ICS Protocol</label>
            <select
              value={icsProto}
              onChange={(e) => setIcsProto(e.target.value)}
              className="w-full input-industrial"
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
            <label className="mb-2 block text-sm font-medium text-[var(--text)]">Access level</label>
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
                  className={`rounded-sm border p-3 text-left transition-ui ${
                    icsAccess === opt.key
                      ? "border-amber-500/40 bg-amber-500/[0.1]"
                      : "border-amber-500/[0.15] bg-[var(--surface)] hover:bg-amber-500/[0.08] hover:border-amber-500/30 cursor-pointer"
                  }`}
                >
                  <div className={`text-sm font-medium ${icsAccess === opt.key ? "text-[var(--amber)]" : "text-[var(--text)]"}`}>{opt.label}</div>
                  <div className="text-xs text-[var(--text-muted)]">{opt.desc}</div>
                </button>
              ))}
            </div>
          </div>
        );
      const protoMeta = ICS_PROTOCOLS[icsProto];
      return (
        <div className="space-y-3 text-sm text-[var(--text)]">
          <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 space-y-2">
            <p>Protocol: <strong>{protoMeta?.label ?? icsProto}</strong> (port {protoMeta?.port})</p>
            <p>Direction: <strong>{icsSrcZone}</strong> &#8594; <strong>{icsDstZone}</strong></p>
            <p>Access: <strong>{icsAccess === "readonly" ? "Read-only" : icsAccess === "readwrite" ? "Read/Write" : "Monitor-only (learn)"}</strong></p>
            <p>Firewall rule: <span className="text-emerald-400">ALLOW</span> with ICS predicate</p>
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
            <label className="flex items-center gap-2 text-sm text-[var(--text)]">
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
                      className={`rounded-sm border px-3 py-2 text-left text-sm transition-ui ${
                        selected
                          ? "border-amber-500/40 bg-amber-500/[0.2] text-[var(--amber)]"
                          : "border-amber-500/[0.15] bg-[var(--surface)] text-[var(--text)] hover:bg-amber-500/[0.1]"
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
        <div className="space-y-3 text-sm text-[var(--text)]">
          <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 space-y-2">
            <p>Direction: <strong>{izSrcZone}</strong> &#8594; <strong>{izDstZone}</strong></p>
            <p>Protocols: {izAny ? <strong>Any</strong> : <strong>{Array.from(izSelected).map((k) => {
              const p = COMMON_PROTOCOLS.find((cp) => `${cp.name}:${cp.port}` === k);
              return p?.label ?? k;
            }).join(", ")}</strong>}</p>
            <p>Firewall rule: <span className="text-emerald-400">ALLOW</span></p>
          </div>
        </div>
      );
    }

    return null;
  }

  /* ── render ──────────────────────────────────────────────────── */

  return (
    <Shell title="Policy Wizard">
      <p className="mb-6 text-sm text-[var(--text-muted)]">
        Select a common connectivity scenario below. The wizard will walk you through each step and create the necessary firewall rules and NAT configuration automatically.
      </p>

      {loading && (
        <Card>
          <p className="text-sm text-[var(--text)]">Loading configuration...</p>
        </Card>
      )}

      {!loading && zones.length === 0 && (
        <div className="mb-6 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          No zones configured. Please{" "}
          <Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
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
                className={`rounded-sm border p-5 text-left transition-ui ${
                  isActive
                    ? "border-amber-500/40 bg-amber-500/[0.1]"
                    : zones.length === 0
                      ? "cursor-not-allowed border-amber-500/[0.08] bg-[var(--surface)] opacity-50"
                      : "border-amber-500/[0.15] bg-[var(--surface)] hover:border-amber-500/30 hover:bg-amber-500/[0.08] cursor-pointer"
                }`}
              >
                <div className="mb-3 flex items-center gap-3">
                  <div className={`h-4 w-4 shrink-0 rounded ${c.color}`} />
                  <h3 className="text-sm font-semibold text-[var(--text)]">{c.title}</h3>
                </div>
                <p className="text-xs text-[var(--text-muted)]">{c.description}</p>
              </button>
            );
          })}
        </div>
      )}

      {/* ── inline wizard flow ──────────────────────────────────── */}
      {active && card && !success && (
        <div className="mt-6 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-6 shadow-card">
          {/* step pills */}
          <div className="mb-6 flex flex-wrap gap-2">
            {card.steps.map((s, i) => (
              <button
                key={i}
                type="button"
                onClick={() => i < step && setStep(i)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-ui ${
                  i === step
                    ? "bg-amber-500/[0.2] text-[var(--amber)]"
                    : i < step
                      ? "bg-amber-500/[0.1] text-[var(--text)] cursor-pointer hover:bg-amber-500/[0.12]"
                      : "bg-[var(--surface)] text-[var(--text-dim)]"
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
            <div className="mt-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          {/* navigation */}
          <div className="mt-6 flex items-center justify-between border-t border-amber-500/[0.15] pt-4">
            <button
              type="button"
              onClick={() => (step === 0 ? reset() : setStep(step - 1))}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-4 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.1]"
            >
              {step === 0 ? "Cancel" : "Back"}
            </button>

            {step < totalSteps - 1 ? (
              <button
                type="button"
                onClick={() => setStep(step + 1)}
                disabled={!canAdvance()}
                className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>
            ) : (
              <button
                type="button"
                onClick={handleApply}
                disabled={applying}
                className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
              >
                {applying ? "Applying..." : "Apply"}
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── success message ─────────────────────────────────────── */}
      {success && (
        <div className="mt-6 rounded-sm border border-emerald-500/30 bg-emerald-500/10 p-6">
          <h3 className="mb-2 text-sm font-semibold text-emerald-400">Success</h3>
          <p className="mb-4 text-sm text-[var(--text)]">{success}</p>
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href="/firewall/"
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-[var(--text)] transition-ui hover:bg-amber-500/[0.1]"
            >
              View firewall rules
            </Link>
            <Link
              href="/nat/"
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-[var(--text)] transition-ui hover:bg-amber-500/[0.1]"
            >
              View NAT config
            </Link>
            <button
              type="button"
              onClick={reset}
              className="rounded-sm bg-[var(--amber)] px-3 py-2 font-medium text-white transition-ui hover:brightness-110"
            >
              Run another wizard
            </button>
          </div>
        </div>
      )}
    </Shell>
  );
}
