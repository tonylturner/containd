"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";

import {
  api,
  type Zone,
  type NATConfig,
  type PortForward,
  type ICSPredicate,
  type Protocol,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";
import {
  CARDS,
  COMMON_PROTOCOLS,
  genId,
  ICS_PROTOCOLS,
  type WizardId,
} from "./wizard-shared";
import {
  WizardScenarioCards,
  WizardStepContent,
} from "./wizard-step-content";

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
        <WizardScenarioCards
          active={active}
          zones={zones}
          onReset={reset}
          onOpenWizard={openWizard}
        />
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
          <div className="min-h-[120px]">
            <WizardStepContent
              active={active}
              step={step}
              zones={zones}
              lanZone={lanZone}
              setLanZone={setLanZone}
              wanZone={wanZone}
              setWanZone={setWanZone}
              serverIp={serverIp}
              setServerIp={setServerIp}
              serverPort={serverPort}
              setServerPort={setServerPort}
              pubProto={pubProto}
              setPubProto={setPubProto}
              ingressZone={ingressZone}
              setIngressZone={setIngressZone}
              icsProto={icsProto}
              setIcsProto={setIcsProto}
              icsSrcZone={icsSrcZone}
              setIcsSrcZone={setIcsSrcZone}
              icsDstZone={icsDstZone}
              setIcsDstZone={setIcsDstZone}
              icsAccess={icsAccess}
              setIcsAccess={setIcsAccess}
              izSrcZone={izSrcZone}
              setIzSrcZone={setIzSrcZone}
              izDstZone={izDstZone}
              setIzDstZone={setIzDstZone}
              izAny={izAny}
              setIzAny={setIzAny}
              izSelected={izSelected}
              setIzSelected={setIzSelected}
            />
          </div>

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
          <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
            These changes were saved to the candidate config. Review and commit them before expecting runtime behavior to change.
          </div>
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href="/config/?tab=diff"
              className="rounded-sm bg-[var(--amber)] px-3 py-2 font-medium text-white transition-ui hover:brightness-110"
            >
              Review &amp; Commit
            </Link>
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
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-[var(--text)] transition-ui hover:bg-amber-500/[0.1]"
            >
              Run another wizard
            </button>
          </div>
        </div>
      )}
    </Shell>
  );
}
