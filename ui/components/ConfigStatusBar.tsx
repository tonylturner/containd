"use client";

import * as React from "react";
import Link from "next/link";
import { useAsyncRefresh } from "../hooks/useAsyncRefresh";
import { api } from "../lib/api";
import { useConfigRefresh } from "../lib/use-config-refresh";

/** Candidate status is not a runtime health indicator. Commits require a
 * displayed diff, so this surface only navigates to the review page.
 */
export function ConfigStatusBar() {
  const [status, setStatus] = React.useState<"unknown" | "clean" | "dirty">("unknown");
  const [deadline, setDeadline] = React.useState<string | null>(null);
  const request = React.useRef(0);
  const { refresh: check } = useAsyncRefresh(React.useCallback(async () => {
    const id = ++request.current;
    try {
      const snapshot = await api.diffConfig();
      if (id !== request.current) return;
      const diff = snapshot?.data;
      setStatus(typeof diff?.changed !== "boolean" ? "unknown" : diff.changed ? "dirty" : "clean");
      setDeadline(diff?.pendingConfirm?.deadline ?? null);
    } catch {
      if (id === request.current) { setStatus("unknown"); setDeadline(null); }
    }
  }, []));
  useConfigRefresh(check);
  const invalidate = React.useCallback(() => { ++request.current; }, []);
  React.useEffect(() => {
    const timer = setInterval(check, 30_000);
    return () => { clearInterval(timer); invalidate(); };
  }, [check, invalidate]);
  if (status === "clean" && !deadline) return null;
  return (
    <div role="status" className={`mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-2.5 text-sm ${deadline ? "border-amber/30 bg-amber/10 text-amber" : ""}`}>
      <div className="min-w-0">
        {status !== "clean" && <p>{status === "unknown" ? "Configuration status unknown — unable to check pending changes." : "Saved changes are not active yet."}</p>}
        {deadline && <Link href="/config/?tab=diff" className="underline underline-offset-2">
          Commit-confirmed pending: confirm before <time dateTime={deadline} title={new Date(deadline).toLocaleString()}>
            {new Date(deadline).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" })}
          </time>
        </Link>}
        {deadline && <p className="mt-1 text-xs">Confirm before this deadline to keep these changes; otherwise they will be undone automatically.</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {!deadline && <Link href="/config/?tab=diff" className="rounded-lg px-3 py-1 text-xs font-semibold transition-ui">Review diff</Link>}
        {status === "unknown" && <button onClick={check} className="rounded-lg px-3 py-1 text-xs font-semibold transition-ui">Retry</button>}
      </div>
    </div>
  );
}
