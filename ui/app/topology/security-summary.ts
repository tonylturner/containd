import type { ConduitMap } from "../../lib/api";
import { type ZoneView, scoreZone } from "../../lib/security-scoring";

/** A zone whose achieved security level is below its target. */
export type ZoneBelowTarget = { id: string; name: string; sl_a: number; sl_t: number };

/** Every zone's achieved level against its target, not only the zones in the matrix. */
export type TargetSummary = { total: number; below: ZoneBelowTarget[] };

/** Zones below their SL target, in zone order, scored as the matrix scores them. */
export function summarizeTargets(zones: ZoneView[], conduits: ConduitMap): TargetSummary {
  const below: ZoneBelowTarget[] = [];
  for (const zone of zones) {
    const { sl_a } = scoreZone(zone, conduits);
    if (sl_a < zone.sl_t) below.push({ id: zone.id, name: zone.name, sl_a, sl_t: zone.sl_t });
  }
  return { total: zones.length, below };
}

/** The overview line: how many of all zones fall short of their target. */
export function targetSummaryText({ total, below }: TargetSummary): string {
  if (total === 0) return "No zones configured.";
  if (below.length === 0) return total === 1 ? "The zone meets its SL target." : `All ${total} zones meet their SL targets.`;
  return `${below.length} of ${total} zone${total === 1 ? "" : "s"} below SL target:`;
}
