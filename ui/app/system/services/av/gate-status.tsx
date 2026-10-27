"use client";

import type { AVGateStatus } from "../../../../lib/api-service-status";
import { StatusBadge } from "../../../../components/StatusBadge";

type Presentation = {
  variant: "success" | "warning" | "neutral";
  badge: string;
  description: string;
};

/** How each gate state reads: only open scans; refuse and pass are the fail policy acting. */
function present(gate: AVGateStatus): Presentation {
  switch (gate.state) {
    case "open":
      return gate.enabled
        ? { variant: "success", badge: "open", description: "Scanning the selected HTTP traffic." }
        : { variant: "success", badge: "open", description: "Ready; no traffic is selected." };
    case "pending":
      return { variant: "warning", badge: "pending", description: "The gate is up and waiting for the scanner to become ready." };
    case "refuse":
      return {
        variant: "warning",
        badge: "refusing",
        description: "Not scanning: a listener or the routing is down and the fail policy is closed, so selected connections are refused; ICS endpoints pass.",
      };
    case "pass":
      return {
        variant: "warning",
        badge: "passing",
        description: "Not scanning: a listener or the routing is down and the fail policy is open, so selected connections pass unscanned.",
      };
    default:
      return { variant: "neutral", badge: "off", description: "Off: the data plane is not enforcing." };
  }
}

/** The scanning gate's block of the live runtime status. */
export function GateStatus({ gate }: { gate: AVGateStatus | undefined }) {
  if (!gate) {
    return (
      <div className="mt-4 border-t pt-3 text-sm text-(--text-muted)" data-testid="gate-status">
        Scanning gate: not reported by this engine.
      </div>
    );
  }
  const view = present(gate);
  const up = gate.listeners.filter((l) => l.up).length;
  const down = gate.listeners.filter((l) => !l.up);
  // A scanner that is still starting is the pending state, not a failure.
  const scannerIssue = gate.scanner.ready ? "" : gate.scanner.error || "not ready";
  return (
    <div className="mt-4 border-t pt-3" data-testid="gate-status">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-(--text)">Scanning gate</h3>
        <StatusBadge variant={view.variant} dot>{view.badge}</StatusBadge>
        {gate.state === "pass" && <span className="text-xs text-(--amber)">not scanning</span>}
      </div>
      <p className="mt-1 text-xs text-(--text-muted)">{view.description}</p>
      <div className="mt-2 grid gap-2 text-sm text-(--text) md:grid-cols-3">
        <div>Selection active: <span className="text-(--text)">{gate.enabled ? "yes" : "no"}</span></div>
        <div>Listeners up: <span className="text-(--text)">{up}/{gate.listeners.length}</span></div>
        <div>
          Scanner ready: <span className={gate.scanner.ready ? "text-(--text)" : "text-(--amber)"}>{gate.scanner.ready ? "yes" : `no (${scannerIssue})`}</span>
        </div>
        <div>Active connections: <span className="text-(--text)">{gate.connections}</span></div>
        <div>Fail policy: <span className="text-(--text)">{gate.fail_policy || "open"}</span></div>
        <div>Admission applied: <span className="text-(--text)">{gate.admit}</span></div>
        {down.map((l) => (
          <div key={l.address} className="md:col-span-3 text-xs text-(--amber)">
            Listener {l.address}{l.masquerade ? " (masquerade)" : ""}: {l.unavailable ? "unavailable on this host" : "down"}{l.error ? ` — ${l.error}` : ""}
          </div>
        ))}
        {gate.routing_error && <div className="md:col-span-3 text-xs text-red-400">Routing: {gate.routing_error}</div>}
        {gate.admit_error && <div className="md:col-span-3 text-xs text-red-400">Admission: {gate.admit_error}</div>}
        {gate.warning && <div className="md:col-span-3 text-xs text-(--amber)">{gate.warning}</div>}
      </div>
    </div>
  );
}
