import type { EnforcementHealth } from "../lib/api";
import type { ProtectionStatus } from "../lib/api-protection";
import { protectionView } from "../lib/protection-view";

/** Healthy protection cannot explain a health-only override (e.g. scheduling).
 * Keep health's own reason rather than labeling a degraded indicator Protecting.
 */
export function enforcementDetail(health: EnforcementHealth, protection?: ProtectionStatus) {
  if (health.state !== "enforcing" && protection?.state === "protecting") {
    return { title: health.reason, action: "" };
  }
  return protectionView(protection);
}
