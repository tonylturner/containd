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
  const request = React.useRef(0);
  const { refresh: check } = useAsyncRefresh(React.useCallback(async () => {
    const id = ++request.current;
    try {
      const snapshot = await api.diffConfig();
      if (id !== request.current) return;
      const diff = snapshot?.data;
      setStatus(typeof diff?.changed !== "boolean" ? "unknown" : diff.changed ? "dirty" : "clean");
    } catch {
      if (id === request.current) setStatus("unknown");
    }
  }, []));
  useConfigRefresh(check);
  const invalidate = React.useCallback(() => { ++request.current; }, []);
  React.useEffect(() => {
    const timer = setInterval(check, 30_000);
    return () => { clearInterval(timer); invalidate(); };
  }, [check, invalidate]);
  if (status === "clean") return null;
  return (
    <div role="status" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-2.5 text-sm">
      <span>{status === "unknown" ? "Configuration status unknown — unable to check pending changes." : "Uncommitted changes — not active until you commit."}</span>
      <div className="flex flex-wrap items-center gap-2">
        <Link href="/config/?tab=diff" className="rounded-lg px-3 py-1 text-xs font-semibold transition-ui">Review diff</Link>
        {status === "unknown" && <button onClick={check} className="rounded-lg px-3 py-1 text-xs font-semibold transition-ui">Retry</button>}
      </div>
    </div>
  );
}
