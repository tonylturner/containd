import { useProtection } from "../hooks/useProtection";
import { isAdmin, type EnforcementHealth } from "../lib/api";
import { enforcementDetail } from "./enforcement-detail";
import { ProtectionRetry } from "./ProtectionNotice";
import { StatusIndicator } from "./StatusBadge";
import { TechnicalDetails } from "./TechnicalDetails";

const VIEWS: Record<EnforcementHealth["state"], { status: "healthy" | "degraded" | "error" | "unknown"; label: string }> = {
  enforcing: { status: "healthy", label: "Firewall enforcing" },
  // A ruleset is in force but needs attention: amber, not red.
  degraded: { status: "degraded", label: "Firewall enforcement degraded" },
  disabled: { status: "unknown", label: "Firewall enforcement disabled" },
  unavailable: { status: "error", label: "Firewall enforcement unavailable" },
  unknown: { status: "unknown", label: "Firewall enforcement unknown" },
};

/** Health owns the state; protection detail is a separate, whole observation. */
export function EnforcementHealthIndicator({ health }: { health: EnforcementHealth | undefined }) {
  const { status } = useProtection();
  if (!health) return <StatusIndicator status="unknown" label="Firewall enforcement" sublabel="status unavailable" />;
  const view = VIEWS[health.state];
  if (health.state === "enforcing") return <StatusIndicator status={view.status} label={view.label} />;
  const protection = enforcementDetail(health, status);
  return <div className="flex flex-wrap items-center gap-3">
    <StatusIndicator status={view.status} label={view.label}
      sublabel={status?.state === "protecting" ? "Protection needs attention" : protection.title} />
    {protection.action && <p className="text-xs text-(--text-dim)">{protection.action}</p>}
    {health.reason && <TechnicalDetails summary="Why protection needs attention">{health.reason}</TechnicalDetails>}
    <ProtectionRetry isAdmin={isAdmin()} />
  </div>;
}
