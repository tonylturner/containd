"use client";

import Link from "next/link";

import { useHealth } from "../hooks/useHealth";
import type { ManagementRecoveryHealth } from "../lib/api";

const TITLES: Record<Exclude<ManagementRecoveryHealth["state"], "inactive">, string> = {
  active: "Startup recovery active: new through-traffic is blocked",
  pending: "Startup recovery pending: recovery protection is not active",
  failed: "Startup recovery failed: recovery protection is not active",
  unknown: "Boot recovery state unknown",
};

/**
 * Health's boot recovery state, which needs an operator: the stored running
 * configuration was refused at boot and is not applied. Nothing when inactive.
 */
function ManagementRecoveryBanner({ recovery }: { recovery: ManagementRecoveryHealth | undefined }) {
  if (!recovery || recovery.state === "inactive") return null;
  return (
    <aside role="status" aria-label="Boot recovery" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
      <p className="font-semibold">{TITLES[recovery.state]}</p>
      {recovery.reason && <p className="mt-1 whitespace-pre-wrap break-words">{recovery.reason}</p>}
      <p className="mt-1 text-xs">
        {recovery.state === "unknown"
          ? "Startup recovery status could not be checked. Startup faults are shown on "
          : "The saved active configuration was rejected at startup and is not applied. Commit a safe configuration, roll back to a safe previous version, or factory reset to resume. Management is serving; verify listener and interface access. The fault is shown on "}
        <Link href="/interfaces/" className="font-semibold underline">Interfaces</Link>.
      </p>
    </aside>
  );
}

/** The shell's banner, from the shared health poll. */
export function ShellRecoveryBanner() {
  const health = useHealth();
  return <ManagementRecoveryBanner recovery={health?.managementRecovery} />;
}
