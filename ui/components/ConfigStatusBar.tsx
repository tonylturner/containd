"use client";

import * as React from "react";
import Link from "next/link";
import { api, isAdmin } from "../lib/api";
import { useConfigRefresh } from "../lib/use-config-refresh";
import { ConfirmDialog, useConfirm } from "./ConfirmDialog";

/** Candidate status is not a runtime health indicator. */
export function ConfigStatusBar() {
  const [status, setStatus] = React.useState<"unknown" | "clean" | "dirty">("unknown");
  const [committing, setCommitting] = React.useState(false);
  const [confirmedPending, setConfirmedPending] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [warning, setWarning] = React.useState<string | null>(null);
  const request = React.useRef(0);
  const confirm = useConfirm();

  const check = React.useCallback(async () => {
    // A mutation arriving during a poll must start a new read, not be dropped.
    const id = ++request.current;
    try {
      const diff = await api.diffConfig();
      if (id !== request.current) return;
      setStatus(!diff ? "unknown" : JSON.stringify(diff.running ?? null) !== JSON.stringify(diff.candidate ?? null) ? "dirty" : "clean");
    } catch {
      if (id === request.current) setStatus("unknown");
    }
  }, []);

  const invalidateCheck = React.useCallback(() => { ++request.current; }, []);
  useConfigRefresh(check);
  React.useEffect(() => {
    void check();
    const timer = setInterval(check, 30_000);
    return () => { clearInterval(timer); invalidateCheck(); };
  }, [check, invalidateCheck]);

  function doCommit(confirmed: boolean) {
    if (committing || !isAdmin()) return;
    confirm.open({
      title: confirmed ? "Commit with auto-rollback" : "Commit configuration",
      message: confirmed
        ? 'Apply the candidate for 60 seconds. Open Config and click "Confirm" before the timer expires, or it will roll back automatically.'
        : "Apply all staged changes to the appliance now? Network changes may interrupt your connection.",
      confirmLabel: confirmed ? "Commit-confirmed" : "Commit",
      onConfirm: async () => {
        setCommitting(true);
        setError(null);
        setWarning(null);
        try {
          const result = await (confirmed ? api.commitConfirmed(60) : api.commit());
          if (!result.ok) setError(result.error || "Commit failed");
          else {
            setConfirmedPending(confirmed);
            setWarning(result.warning ?? null);
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Commit failed");
        } finally {
          setCommitting(false);
          void check();
        }
      },
    });
  }

  if (status === "clean" && !confirmedPending && !warning && !error) return null;
  const buttonClass = "rounded-lg bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-300 transition-ui hover:bg-amber-500/25 disabled:opacity-60";
  return (
    <>
      <div role="status" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/25 bg-amber-500/8 px-4 py-2.5 text-sm">
        <div className="text-amber-400">
          <span>{status === "unknown" ? "Configuration status unknown — unable to check pending changes." : status === "dirty" ? "Uncommitted changes — not active until you commit." : "No uncommitted changes."}</span>
          {confirmedPending && <span className="ml-2">Commit-confirmed requested (60s). Confirm in Config before the deadline to prevent rollback.</span>}
          {warning && <span className="ml-2">Warning: {warning}</span>}
          {error && <span className="ml-2 text-red-400">{error}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link href="/config/?tab=diff" className={buttonClass}>Review diff</Link>
          {confirmedPending && <Link href="/config/?tab=diff" className={buttonClass}>Confirm / rollback</Link>}
          {status === "unknown" && <button onClick={check} className={buttonClass}>Retry</button>}
          {status === "dirty" && isAdmin() && <>
            <button onClick={() => doCommit(false)} disabled={committing} className={buttonClass}>{committing ? "Committing…" : "Commit"}</button>
            <button onClick={() => doCommit(true)} disabled={committing} className={buttonClass}>Commit-confirmed</button>
          </>}
        </div>
      </div>
      <ConfirmDialog {...confirm.props} />
    </>
  );
}
