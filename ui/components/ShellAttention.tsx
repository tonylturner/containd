"use client";

import { ConfigStatusBar } from "./ConfigStatusBar";
import { EvidenceBanner } from "./EvidenceBanner";
import { ShellRecoveryBanner } from "./ManagementRecoveryBanner";
import { ProtectionNotice } from "./ProtectionNotice";

/** Domains retain their own observations, timestamps and recovery actions. */
export function ShellAttention({ isAdmin }: { isAdmin: boolean }) {
  return (
    <section aria-label="Attention" className="mb-4 divide-y overflow-hidden rounded-xs border empty:hidden [&>aside]:mb-0 [&>aside]:rounded-none [&>aside]:border-0 [&>div]:mb-0 [&>div]:rounded-none [&>div]:border-0">
      <ProtectionNotice isAdmin={isAdmin} />
      <ShellRecoveryBanner />
      <EvidenceBanner />
      <ConfigStatusBar />
    </section>
  );
}
