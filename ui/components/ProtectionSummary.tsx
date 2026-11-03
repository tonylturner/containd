"use client";

import type { ProtectionStatus, ProtectionSubsystem } from "../lib/api-protection";
import { useProtection } from "../hooks/useProtection";

/** Live revision identities are separate from the editable draft and its CAS. */
export function ProtectionRevisions({ status }: { status?: ProtectionStatus }) {
  return <dl aria-label="Protection revisions" className="my-3 grid gap-x-4 gap-y-2 text-xs sm:grid-cols-[max-content_minmax(0,1fr)]">
    {([
      ["Desired configuration", status?.desiredRevision],
      ["Policy installed", status?.appliedRevision],
      ["Protecting now", status?.ready ? status.protectingRevision : null],
    ] as const).map(([label, revision]) => <div key={label} className="grid gap-1 sm:contents">
      <dt className="text-(--text-muted)">{label}</dt>
      <dd className="min-w-0 break-all font-mono">{revision ?? "Not verified"}</dd>
    </div>)}
  </dl>;
}

export function ProtectionOutcomes({ subsystems }: { subsystems: ProtectionSubsystem[] }) {
  return <div className="mt-2 space-y-2 text-xs">
    {subsystems.map(s => <div key={s.name}>
      <p><span className="font-semibold">{s.name}</span> · {s.owner} · {s.state} · {s.required ? "Required" : "Optional (non-gating)"}</p>
      {s.nextRetryAt && <p>Next automatic retry: <time dateTime={s.nextRetryAt}>{s.nextRetryAt}</time></p>}
      {(s.fault?.reason || s.reason) && <p>{s.fault?.reason || s.reason}</p>}
    </div>)}
  </div>;
}

export function LiveProtectionSummary() {
  const { status } = useProtection();
  return <section aria-label="Running protection summary" className="mt-4 border-t pt-1">
    <ProtectionRevisions status={status} />
    <p className="text-xs text-(--text-muted)">Live observations of the running configuration, not staged changes.</p>
  </section>;
}
