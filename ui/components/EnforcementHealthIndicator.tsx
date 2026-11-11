"use client";

import { useIsAdmin } from "../hooks/useIsAdmin";

import { useProtection } from "../hooks/useProtection";
import { type EnforcementHealth } from "../lib/api";
import { hasTrafficProtectionNotice } from "../lib/protection-view";
import { effectiveEnforcementState, enforcementDetail } from "./enforcement-detail";
import { ProtectionRetry } from "./ProtectionNotice";
import { StatusIndicator } from "./StatusBadge";

const VIEWS: Record<EnforcementHealth["state"], { status: "healthy" | "degraded" | "error" | "unknown"; label: string }> = {
  enforcing: { status: "healthy", label: "Firewall enforcing" },
  // A ruleset is in force but needs attention: amber, not red.
  degraded: { status: "degraded", label: "Firewall enforcement degraded" },
  disabled: { status: "unknown", label: "Firewall enforcement disabled" },
  unavailable: { status: "error", label: "Firewall enforcement unavailable" },
  unknown: { status: "unknown", label: "Firewall enforcement unknown" },
};

/** Packet enforcement health alone is not a clean-readiness certificate. */
export function EnforcementHealthIndicator({ health }: { health: EnforcementHealth | undefined }) {
  const isAdmin = useIsAdmin();
  const { status } = useProtection();
  if (!health) return <StatusIndicator status="unknown" label="Firewall enforcement" sublabel="status unavailable" />;
  const state = effectiveEnforcementState(health, status);
  const view = VIEWS[state];
  if (state === "enforcing") return <StatusIndicator status={view.status} label={view.label} />;
  const protection = enforcementDetail(health, status);
  const trafficNotice = hasTrafficProtectionNotice(status);
  return <div className="flex flex-wrap items-center gap-3">
    <StatusIndicator status={view.status} label={view.label}
      sublabel={trafficNotice ? undefined : status?.ready ? "Protection needs attention" : protection.title} />
    {!trafficNotice && protection.action && <p className="text-xs text-(--text-dim)">{protection.action}</p>}
    {health.reason && <p className="break-words text-xs text-amber">{health.reason}</p>}
    <ProtectionRetry isAdmin={isAdmin} />
  </div>;
}
