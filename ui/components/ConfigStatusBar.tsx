"use client";

import * as React from "react";
import Link from "next/link";
import { api } from "../lib/api";

/** Thin status bar shown when uncommitted config changes exist. */
export function ConfigStatusBar() {
  const [dirty, setDirty] = React.useState(false);
  const [committing, setCommitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const checkingRef = React.useRef(false);

  const check = React.useCallback(async () => {
    if (checkingRef.current) return;
    checkingRef.current = true;
    try {
      const diff = await api.diffConfig();
      if (!diff) {
        setDirty(false);
        return;
      }
      const r = JSON.stringify(diff.running ?? null);
      const c = JSON.stringify(diff.candidate ?? null);
      setDirty(r !== c);
    } catch {
      setDirty(false);
    } finally {
      checkingRef.current = false;
    }
  }, []);

  React.useEffect(() => {
    check();
    const timer = setInterval(check, 30_000);
    return () => clearInterval(timer);
  }, [check]);

  React.useEffect(() => {
    const onCommit = () => {
      setDirty(false);
      setTimeout(check, 1000);
    };
    window.addEventListener("containd:config:committed", onCommit);
    return () => window.removeEventListener("containd:config:committed", onCommit);
  }, [check]);

  // Commit the staged candidate from wherever the bar is shown (e.g. the
  // Firewall page), so the commit step isn't stranded on the Config page.
  const doCommit = React.useCallback(async () => {
    if (committing) return;
    setError(null);
    setCommitting(true);
    try {
      const result = await api.commit();
      if (result.ok) {
        setDirty(false);
        window.dispatchEvent(new CustomEvent("containd:config:committed"));
      } else {
        setError(result.error || "Commit failed");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Commit failed");
    } finally {
      setCommitting(false);
    }
  }, [committing]);

  if (!dirty) return null;

  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/25 bg-amber-500/8 px-4 py-2.5 text-sm animate-fade-in">
      <div className="flex items-center gap-2 text-amber-400">
        <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2}>
          <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
        </svg>
        <span>
          Candidate config differs from running config
          {error ? <span className="ml-2 text-red-400">— {error}</span> : null}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Link
          href="/config/?tab=diff"
          className="rounded-lg bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-300 transition-ui hover:bg-amber-500/25"
        >
          Review Candidate Diff
        </Link>
        <button
          type="button"
          onClick={doCommit}
          disabled={committing}
          className="rounded-lg bg-amber-500/90 px-3 py-1 text-xs font-semibold text-amber-950 transition-ui hover:bg-amber-400 disabled:opacity-60"
        >
          {committing ? "Committing…" : "Commit"}
        </button>
      </div>
    </div>
  );
}
