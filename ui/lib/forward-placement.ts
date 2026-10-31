import type { ForwardPublishResult } from "./api";

/** Render the server's placement decision without inferring a permission. */
export function forwardPlacementMessage(result: ForwardPublishResult): string {
  const placement = result.placement;
  if (!placement) return "Port forward staged without a matching allow rule — commit to apply.";
  const warning = placement.warning;
  const warningText = warning
    ? `${warning.message} Traffic: sources ${warning.traffic.sources.join(", ")}, ingress ${warning.traffic.ingressZone}, backend zones ${warning.traffic.backendZones}, ${warning.traffic.protocol} ${warning.traffic.listenAddress}:${warning.traffic.listenPort} → ${warning.traffic.backend}.`
    : "";
  switch (placement.reason) {
    case "generated":
      return `Port forward staged; matching allow rule ${placement.rule.id} inserted at position ${placement.index + 1} — commit to apply.`;
    case "inside":
      return `Port forward staged — commit to apply. Enforcing ICS ${placement.ruleIds.length === 1 ? "rule" : "rules"} ${placement.ruleIds.join(", ")} ${placement.ruleIds.length === 1 ? "governs" : "govern"} this traffic; no allow rule created.`;
    case "partial":
      return `Port forward staged — commit to apply. ${warningText}`;
  }
}
