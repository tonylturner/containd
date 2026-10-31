import type { ForwardPublishResult } from "./api";

/** Render the server's placement decision without inferring a permission. */
export function forwardPlacementMessage(result: ForwardPublishResult): string {
  const placement = result.placement;
  if (!placement) return "Port forward staged without a matching allow rule — commit to apply.";
  if (placement.rule) return `Port forward staged; matching allow rule ${placement.rule.id} inserted at position ${placement.index + 1} — commit to apply.`;
  if (placement.warning) {
    const { message, traffic } = placement.warning;
    return `Port forward staged — commit to apply. ${message} Traffic: sources ${traffic.sources.join(", ")}, ingress ${traffic.ingressZone}, backend zones ${traffic.backendZones}, ${traffic.protocol} ${traffic.listenAddress}:${traffic.listenPort} → ${traffic.backend}.`;
  }
  return `Port forward staged; no allow rule generated (${placement.reason}). Existing policy decides delivery — commit to apply.`;
}
