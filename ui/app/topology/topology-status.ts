import type { EnforcementHealth, HealthResponse } from "../../lib/api";
import type { ProtectionStatus } from "../../lib/api-protection";
import { effectiveEnforcementState, enforcementDetail } from "../../components/enforcement-detail";

/** The topology status chip combines enforcement health and live readiness. */
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
 * The aggregate gates clean readiness; health retains recovery/schedule reasons.
 * Never join unversioned ruleset detail to a revision-bound observation.
 */
export function topologyStatus(health: HealthResponse | undefined, protection?: ProtectionStatus): TopologyStatus {
  const enforcement = health?.enforcement;
  if (!enforcement) return { ...STATES.unknown, reason: "Health unavailable" };
  const state = effectiveEnforcementState(enforcement, protection);
  const view = STATES[state];
  if (state === "enforcing") return view;
  const detail = enforcementDetail(enforcement, protection);
  return { ...view, reason: detail.title, action: detail.action };
}
