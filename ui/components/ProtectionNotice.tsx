"use client";

import { requestProtectionRetry, useProtection } from "../hooks/useProtection";
import { hasTrafficProtectionNotice, protectionView, serviceRepairDirection } from "../lib/protection-view";
import { canRetryProtection } from "../lib/protection-store";
import { ProtectionOutcomes, ProtectionRevisions } from "./ProtectionSummary";
import { Disclosure } from "./Disclosure";

/** Shared retry state prevents duplicate clicks across the shell and indicators. */
export function ProtectionRetry({ isAdmin }: { isAdmin: boolean }) {
  const { status, retrying, retryMessage } = useProtection();
  return <>
    {isAdmin && status && canRetryProtection(status) && (
      <button type="button" disabled={retrying} onClick={() => void requestProtectionRetry(status)}
        className="shrink-0 rounded-xs border border-current/30 px-3 py-1.5 text-xs font-semibold transition-ui hover:bg-white/8 disabled:cursor-wait disabled:opacity-50">
        {retrying ? "Retrying…" : "Retry now"}
      </button>
    )}
    {retryMessage && <p role="status" className="text-xs">{retryMessage}</p>}
  </>;
}

/** Runtime protection is independent of candidate edits and commit acknowledgements. */
export function ProtectionNotice({ isAdmin }: { isAdmin: boolean }) {
  const { status } = useProtection();
  if (!status) return null;
  const optional = status.subsystems.filter(s => !s.required && (s.fault || s.state === "failed" || s.state === "pending" || s.state === "unknown"));
  const trafficNotice = hasTrafficProtectionNotice(status);
  const view = protectionView(status);
  return <>
    {trafficNotice && <aside role="status" aria-label="Traffic protection"
      className={`mb-4 rounded-xs border px-4 py-3 text-sm ${status.state === "failed"
        ? "border-rose-400/30 bg-rose-400/10 text-rose-300"
        : "border-amber/30 bg-amber/10 text-amber"}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 break-words">
          <h2 className="mb-1 text-xs font-semibold">Traffic protection</h2>
          <p className="font-semibold">{view.title}</p>
          <p className="mt-1 text-xs">{view.action}</p>
          {status.components.some((c) => (c.state === "failed" || c.state === "pending") && c.reason) && (
            <div className="mt-2 space-y-1 text-xs">
              {status.components.filter((c) => c.state === "failed" || c.state === "pending").map((c) =>
                c.reason && <p key={c.name}>{c.name}: {c.reason}</p>)}
            </div>
          )}
          <ProtectionOutcomes subsystems={status.subsystems.filter(s => s.required && (s.fault || !["ready", "off"].includes(s.state)))} />
          <ProtectionRevisions status={status} />
          {status.observedAt && <Disclosure title="Technical details">
            <p>Observation: <time dateTime={status.observedAt}>{status.observedAt}</time></p>
            <p className="break-all">Boot ID: {status.bootId} · Apply ID: {status.applyId} · Installed apply ID: {status.installedApplyId}</p>
          </Disclosure>}
        </div>
        <ProtectionRetry isAdmin={isAdmin} />
      </div>
    </aside>}
    {optional.length > 0 && <aside role="status" aria-label="Service convergence" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-amber">
      <h2 className="text-xs font-semibold">Service configuration needs attention</h2>
      <p className="mt-1 text-xs">{serviceRepairDirection(optional)}</p>
      <ProtectionOutcomes subsystems={optional} />
      {!trafficNotice && <ProtectionRetry isAdmin={isAdmin} />}
    </aside>}
  </>;
}
