import Link from "next/link";

import type { ManagementRecoveryHealth } from "../lib/api";

const TITLES: Record<Exclude<ManagementRecoveryHealth["state"], "inactive">, string> = {
  active: "Boot recovery active: new transit dropped",
  pending: "Boot recovery pending: recovery ruleset not applied",
  failed: "Boot recovery failed: recovery ruleset not applied",
  unknown: "Boot recovery state unknown",
};

/**
 * Health's boot recovery state, which needs an operator: the stored running
 * configuration was refused at boot and is not applied. Nothing when inactive.
 */
export function ManagementRecoveryBanner({ recovery }: { recovery: ManagementRecoveryHealth | undefined }) {
  if (!recovery || recovery.state === "inactive") return null;
  return (
    <aside role="status" aria-label="Boot recovery" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
      <p className="font-semibold">{TITLES[recovery.state]}</p>
      {recovery.reason && <p className="mt-1">{recovery.reason}</p>}
      <p className="mt-1 text-xs">
        {recovery.state === "unknown"
          ? "Health could not read whether a boot fault holds. Boot faults are shown on "
          : "The stored running configuration was refused at boot and is not applied. Commit a safe configuration, roll back to a safe snapshot, or factory reset to resume. The refusal is shown on "}
        <Link href="/interfaces/" className="font-semibold underline">Interfaces</Link>.
      </p>
    </aside>
  );
}
