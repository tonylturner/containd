"use client";

import type React from "react";

import type { Zone } from "../../lib/api";

import {
  CARDS,
  COMMON_PROTOCOLS,
  ICS_PROTOCOLS,
  type WizardId,
  zoneLabel,
} from "./wizard-shared";

type WizardStepContentProps = {
  active: WizardId | null;
  step: number;
  zones: Zone[];
  lanZone: string;
  setLanZone: (value: string) => void;
  wanZone: string;
  setWanZone: (value: string) => void;
  serverIp: string;
  setServerIp: (value: string) => void;
  serverPort: string;
  setServerPort: (value: string) => void;
  pubProto: "tcp" | "udp";
  setPubProto: (value: "tcp" | "udp") => void;
  ingressZone: string;
  setIngressZone: (value: string) => void;
  icsProto: string;
  setIcsProto: (value: string) => void;
  icsSrcZone: string;
  setIcsSrcZone: (value: string) => void;
  icsDstZone: string;
  setIcsDstZone: (value: string) => void;
  icsAccess: "readonly" | "readwrite" | "monitor";
  setIcsAccess: (value: "readonly" | "readwrite" | "monitor") => void;
  izSrcZone: string;
  setIzSrcZone: (value: string) => void;
  izDstZone: string;
  setIzDstZone: (value: string) => void;
  izAny: boolean;
  setIzAny: (value: boolean) => void;
  izSelected: Set<string>;
  setIzSelected: React.Dispatch<React.SetStateAction<Set<string>>>;
};

export function WizardStepContent({
  active,
  step,
  zones,
  lanZone,
  setLanZone,
  wanZone,
  setWanZone,
  serverIp,
  setServerIp,
  serverPort,
  setServerPort,
  pubProto,
  setPubProto,
  ingressZone,
  setIngressZone,
  icsProto,
  setIcsProto,
  icsSrcZone,
  setIcsSrcZone,
  icsDstZone,
  setIcsDstZone,
  icsAccess,
  setIcsAccess,
  izSrcZone,
  setIzSrcZone,
  izDstZone,
  setIzDstZone,
  izAny,
  setIzAny,
  izSelected,
  setIzSelected,
}: WizardStepContentProps): React.ReactNode {
  if (!active) {
    return null;
  }

  function renderZoneSelect(
    label: string,
    value: string,
    onChange: (v: string) => void,
    exclude?: string,
  ) {
    const filtered = exclude ? zones.filter((z) => z.name !== exclude) : zones;
    return (
      <div>
        <label className="mb-2 block text-sm font-medium text-[var(--text)]">
          {label}
        </label>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="input-industrial w-full"
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

  if (active === "lan-internet") {
    if (step === 0) {
      return renderZoneSelect("LAN zone (source)", lanZone, setLanZone);
    }
    if (step === 1) {
      return renderZoneSelect(
        "WAN zone (destination)",
        wanZone,
        setWanZone,
        lanZone,
      );
    }
    return (
      <div className="space-y-3 text-sm text-[var(--text)]">
        <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
        <div className="space-y-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4">
          <p>
            Firewall rule: <span className="text-emerald-400">ALLOW</span> from{" "}
            <strong>{lanZone}</strong> to <strong>{wanZone}</strong>
          </p>
          <p>
            NAT: Enable SNAT masquerade on <strong>{wanZone}</strong> for source
            zone <strong>{lanZone}</strong>
          </p>
        </div>
      </div>
    );
  }

  if (active === "publish-service") {
    if (step === 0) {
      return (
        <div className="space-y-3">
          <div>
            <label className="mb-2 block text-sm font-medium text-[var(--text)]">
              Internal server IP
            </label>
            <input
              value={serverIp}
              onChange={(e) => setServerIp(e.target.value)}
              placeholder="e.g. 192.168.1.10"
              className="input-industrial w-full"
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-[var(--text)]">
              Port
            </label>
            <input
              value={serverPort}
              onChange={(e) => setServerPort(e.target.value)}
              placeholder="e.g. 443"
              type="number"
              min={1}
              max={65535}
              className="input-industrial w-full"
            />
          </div>
        </div>
      );
    }
    if (step === 1) {
      return (
        <div>
          <label className="mb-2 block text-sm font-medium text-[var(--text)]">
            Protocol
          </label>
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
    }
    if (step === 2) {
      return renderZoneSelect(
        "External (ingress) zone",
        ingressZone,
        setIngressZone,
      );
    }
    return (
      <div className="space-y-3 text-sm text-[var(--text)]">
        <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
        <div className="space-y-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4">
          <p>
            Port forward (DNAT): <strong>{ingressZone}</strong>{" "}
            {pubProto.toUpperCase()}/{serverPort} &#8594;{" "}
            <strong>
              {serverIp}:{serverPort}
            </strong>
          </p>
          <p>
            Firewall rule: <span className="text-emerald-400">ALLOW</span>{" "}
            inbound from <strong>{ingressZone}</strong> to{" "}
            <strong>{serverIp}</strong> on {pubProto.toUpperCase()}/{serverPort}
          </p>
        </div>
      </div>
    );
  }

  if (active === "ics-comm") {
    if (step === 0) {
      return (
        <div>
          <label className="mb-2 block text-sm font-medium text-[var(--text)]">
            ICS Protocol
          </label>
          <select
            value={icsProto}
            onChange={(e) => setIcsProto(e.target.value)}
            className="input-industrial w-full"
          >
            {Object.entries(ICS_PROTOCOLS).map(([key, meta]) => (
              <option key={key} value={key}>
                {meta.label}
              </option>
            ))}
          </select>
        </div>
      );
    }
    if (step === 1) {
      return (
        <div className="space-y-3">
          {renderZoneSelect("Source zone", icsSrcZone, setIcsSrcZone)}
          {renderZoneSelect(
            "Destination zone",
            icsDstZone,
            setIcsDstZone,
            icsSrcZone,
          )}
        </div>
      );
    }
    if (step === 2) {
      return (
        <div>
          <label className="mb-2 block text-sm font-medium text-[var(--text)]">
            Access level
          </label>
          <div className="flex flex-col gap-2">
            {[
              {
                key: "readonly" as const,
                label: "Read-only",
                desc: "Only read function codes are permitted",
              },
              {
                key: "readwrite" as const,
                label: "Read / Write",
                desc: "Both read and write operations are allowed",
              },
              {
                key: "monitor" as const,
                label: "Monitor-only (learn mode)",
                desc: "Passively observe traffic without enforcement",
              },
            ].map((opt) => (
              <button
                key={opt.key}
                type="button"
                onClick={() => setIcsAccess(opt.key)}
                className={`rounded-sm border p-3 text-left transition-ui ${
                  icsAccess === opt.key
                    ? "border-amber-500/40 bg-amber-500/[0.1]"
                    : "cursor-pointer border-amber-500/[0.15] bg-[var(--surface)] hover:border-amber-500/30 hover:bg-amber-500/[0.08]"
                }`}
              >
                <div
                  className={`text-sm font-medium ${icsAccess === opt.key ? "text-[var(--amber)]" : "text-[var(--text)]"}`}
                >
                  {opt.label}
                </div>
                <div className="text-xs text-[var(--text-muted)]">
                  {opt.desc}
                </div>
              </button>
            ))}
          </div>
        </div>
      );
    }
    const protoMeta = ICS_PROTOCOLS[icsProto];
    return (
      <div className="space-y-3 text-sm text-[var(--text)]">
        <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
        <div className="space-y-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4">
          <p>
            Protocol: <strong>{protoMeta?.label ?? icsProto}</strong> (port{" "}
            {protoMeta?.port})
          </p>
          <p>
            Direction: <strong>{icsSrcZone}</strong> &#8594;{" "}
            <strong>{icsDstZone}</strong>
          </p>
          <p>
            Access:{" "}
            <strong>
              {icsAccess === "readonly"
                ? "Read-only"
                : icsAccess === "readwrite"
                  ? "Read/Write"
                  : "Monitor-only (learn)"}
            </strong>
          </p>
          <p>
            Firewall rule: <span className="text-emerald-400">ALLOW</span> with
            ICS predicate
          </p>
        </div>
      </div>
    );
  }

  if (active === "inter-zone") {
    if (step === 0) {
      return renderZoneSelect("Source zone", izSrcZone, setIzSrcZone);
    }
    if (step === 1) {
      return renderZoneSelect(
        "Destination zone",
        izDstZone,
        setIzDstZone,
        izSrcZone,
      );
    }
    if (step === 2) {
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
                        if (selected) {
                          next.delete(key);
                        } else {
                          next.add(key);
                        }
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
    }
    return (
      <div className="space-y-3 text-sm text-[var(--text)]">
        <h3 className="text-base font-semibold text-[var(--text)]">Summary</h3>
        <div className="space-y-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4">
          <p>
            Direction: <strong>{izSrcZone}</strong> &#8594;{" "}
            <strong>{izDstZone}</strong>
          </p>
          <p>
            Protocols:{" "}
            {izAny ? (
              <strong>Any</strong>
            ) : (
              <strong>
                {Array.from(izSelected)
                  .map((k) => {
                    const p = COMMON_PROTOCOLS.find(
                      (cp) => `${cp.name}:${cp.port}` === k,
                    );
                    return p?.label ?? k;
                  })
                  .join(", ")}
              </strong>
            )}
          </p>
          <p>
            Firewall rule: <span className="text-emerald-400">ALLOW</span>
          </p>
        </div>
      </div>
    );
  }

  return null;
}

export function WizardScenarioCards({
  active,
  zones,
  onReset,
  onOpenWizard,
}: {
  active: WizardId | null;
  zones: Zone[];
  onReset: () => void;
  onOpenWizard: (id: WizardId) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      {CARDS.map((c) => {
        const isActive = active === c.id;
        return (
          <button
            key={c.id}
            type="button"
            onClick={() => (isActive ? onReset() : onOpenWizard(c.id))}
            disabled={zones.length === 0}
            className={`rounded-sm border p-5 text-left transition-ui ${
              isActive
                ? "border-amber-500/40 bg-amber-500/[0.1]"
                : zones.length === 0
                  ? "cursor-not-allowed border-amber-500/[0.08] bg-[var(--surface)] opacity-50"
                  : "cursor-pointer border-amber-500/[0.15] bg-[var(--surface)] hover:border-amber-500/30 hover:bg-amber-500/[0.08]"
            }`}
          >
            <div className="mb-3 flex items-center gap-3">
              <div className={`h-4 w-4 shrink-0 rounded ${c.color}`} />
              <h3 className="text-sm font-semibold text-[var(--text)]">
                {c.title}
              </h3>
            </div>
            <p className="text-xs text-[var(--text-muted)]">{c.description}</p>
          </button>
        );
      })}
    </div>
  );
}
