import type { EnforcementHealth, HealthResponse } from "../../lib/api";
import type { InstalledRulesetView } from "../../hooks/useInstalledRuleset";

/** The topology status chip: firewall enforcement as health reports it. */
export type TopologyStatus = { label: string; tone: "ok" | "warn" | "error" | "unknown"; reason?: string };

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

/** A failed apply or a degraded schedule planner in the installed ruleset's status. */
function rulesetFault(installed: InstalledRulesetView): string | undefined {
  if (installed.state !== "loaded") return undefined;
  const { error, schedulePlanner } = installed.status;
  if (error) return `Last apply failed: ${error}`;
  if (schedulePlanner?.state === "degraded") {
    return `Schedule planner degraded${schedulePlanner.reason ? `: ${schedulePlanner.reason}` : ""}`;
  }
  return undefined;
}

/**
 * The chip's state comes from health's firewall enforcement. Unless it is
 * enforcing, the reason is the installed ruleset's fault (a failed apply or
 * a degraded schedule planner), else health's own reason, else that no
 * ruleset is in force.
 */
export function topologyStatus(health: HealthResponse | undefined, installed: InstalledRulesetView): TopologyStatus {
  const enforcement = health?.enforcement;
  if (!enforcement) return { ...STATES.unknown, reason: "Health unavailable" };
  const view = STATES[enforcement.state];
  if (enforcement.state === "enforcing") return view;
  const noRuleset = installed.state === "loaded" && !installed.status.installed ? "No ruleset in force" : undefined;
  const reason = rulesetFault(installed) || enforcement.reason || noRuleset;
  return reason ? { ...view, reason } : view;
}
