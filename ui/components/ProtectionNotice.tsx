"use client";

import { requestProtectionRetry, useProtection } from "../hooks/useProtection";
import { protectionView } from "../lib/protection-view";
import { TechnicalDetails } from "./TechnicalDetails";

/** Shared retry state prevents duplicate clicks across the shell and indicators. */
export function ProtectionRetry({ isAdmin }: { isAdmin: boolean }) {
  const { status, retrying, retryMessage } = useProtection();
  return <>
    {isAdmin && status?.retryable && (
      <button type="button" disabled={retrying} onClick={() => void requestProtectionRetry(status)}
        className="shrink-0 rounded-xs border border-current/30 px-3 py-1.5 text-xs font-semibold transition-ui hover:bg-white/8 disabled:cursor-wait disabled:opacity-50">
        {retrying ? "Retrying…" : "Retry protection"}
      </button>
    )}
    {retryMessage && <p role="status" className="text-xs">{retryMessage}</p>}
  </>;
}

/** Runtime protection is independent of candidate edits and commit acknowledgements. */
export function ProtectionNotice({ isAdmin }: { isAdmin: boolean }) {
  const { status } = useProtection();
  if (!status || status.state === "protecting" || status.state === "disabled") return null;
  const view = protectionView(status);
  return (
    <aside role="status" aria-label="Traffic protection"
      className={`mb-4 rounded-xs border px-4 py-3 text-sm ${status.state === "failed"
        ? "border-rose-400/30 bg-rose-400/10 text-rose-300"
        : "border-amber/30 bg-amber/10 text-amber"}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 break-words">
          <p className="font-semibold">{view.title}</p>
          <p className="mt-1 text-xs">{view.action}</p>
          {status.components.some((c) => (c.state === "failed" || c.state === "pending") && c.reason) && (
            <TechnicalDetails>
              {status.components.filter((c) => c.state === "failed" || c.state === "pending").map((c) =>
                c.reason && <p key={c.name}>{c.name}: {c.reason}</p>)}
            </TechnicalDetails>
          )}
        </div>
        <ProtectionRetry isAdmin={isAdmin} />
      </div>
    </aside>
  );
}
