import type { EnforcementHealth } from "../lib/api";
import type { ProtectionStatus } from "../lib/api-protection";
import { protectionView } from "../lib/protection-view";

/** Healthy protection cannot explain a health-only override (e.g. scheduling).
 * Keep health's own reason rather than labeling a degraded indicator Protecting.
 */
export function enforcementDetail(health: EnforcementHealth, protection?: ProtectionStatus) {
  if (health.state !== "enforcing" && protection?.ready) {
    return { title: health.reason, action: "" };
  }
  return protectionView(protection);
}

/** Clean green requires the authenticated aggregate as well as health telemetry. */
export function effectiveEnforcementState(health: EnforcementHealth, protection?: ProtectionStatus): EnforcementHealth["state"] {
  if (health.state !== "enforcing") return health.state;
  if (protection?.ready) return "enforcing";
  if (!protection || protection.state === "unknown") return "unknown";
  if (protection.state === "failed") return "unavailable";
  if (protection.state === "disabled") return "disabled";
  return "degraded";
}
