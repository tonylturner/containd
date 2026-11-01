import type { EnforcementHealth, HealthResponse } from "../../lib/api";
import type { ProtectionStatus } from "../../lib/api-protection";
import { protectionView } from "../../lib/protection-view";

/** The topology status chip: firewall enforcement as health reports it. */
export type TopologyStatus = { label: string; tone: "ok" | "warn" | "error" | "unknown"; reason?: string; action?: string };

const STATES: Record<EnforcementHealth["state"], Omit<TopologyStatus, "reason">> = {
  enforcing: { label: "ENFORCING", tone: "ok" },
  // A ruleset is in force but needs attention: amber, not red.
  degraded: { label: "DEGRADED", tone: "warn" },
  disabled: { label: "ENFORCEMENT OFF", tone: "unknown" },
  unavailable: { label: "UNAVAILABLE", tone: "error" },
  unknown: { label: "STATUS UNKNOWN", tone: "unknown" },
};

export const TONE_COLORS: Record<TopologyStatus["tone"], string> = {
  ok: "#22c55e",
  warn: "#f59e0b",
  error: "#ef4444",
  unknown: "#6b7280",
};

/**
 * Health owns the chip's state. Protection supplies its own reason/action
 * without joining component detail to the unversioned installed ruleset.
 */
export function topologyStatus(health: HealthResponse | undefined, protection?: ProtectionStatus): TopologyStatus {
  const enforcement = health?.enforcement;
  if (!enforcement) return { ...STATES.unknown, reason: "Health unavailable" };
  const view = STATES[enforcement.state];
  if (enforcement.state === "enforcing") return view;
  const detail = protectionView(protection);
  return { ...view, reason: detail.title, action: detail.action };
}
