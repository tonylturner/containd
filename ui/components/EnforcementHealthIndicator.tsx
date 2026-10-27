import type { EnforcementHealth } from "../lib/api";
import { StatusIndicator } from "./StatusBadge";

const VIEWS: Record<EnforcementHealth["state"], { status: "healthy" | "degraded" | "error" | "unknown"; label: string }> = {
  enforcing: { status: "healthy", label: "Firewall enforcing" },
  // A ruleset is in force but needs attention: amber, not red.
  degraded: { status: "degraded", label: "Firewall enforcement degraded" },
  disabled: { status: "unknown", label: "Firewall enforcement disabled" },
  unavailable: { status: "error", label: "Firewall enforcement unavailable" },
  unknown: { status: "unknown", label: "Firewall enforcement unknown" },
};

/** Health's general firewall enforcement state, with its reason. */
export function EnforcementHealthIndicator({ health }: { health: EnforcementHealth | undefined }) {
  if (!health) return <StatusIndicator status="unknown" label="Firewall enforcement" sublabel="status unavailable" />;
  const view = VIEWS[health.state];
  return <StatusIndicator status={view.status} label={view.label} sublabel={health.reason || undefined} />;
}
