"use client";

import * as React from "react";
import Link from "next/link";
import { api } from "../lib/api";

/** Thin status bar shown when uncommitted config changes exist. */
export function ConfigStatusBar() {
  const [dirty, setDirty] = React.useState(false);
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
      // If the API is unreachable, don't show the bar.
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

  // Listen for custom events that indicate config was committed or changed.
  React.useEffect(() => {
    const onCommit = () => {
      setDirty(false);
      setTimeout(check, 1000);
    };
    window.addEventListener("containd:config:committed", onCommit);
    return () => window.removeEventListener("containd:config:committed", onCommit);
  }, [check]);

  if (!dirty) return null;

  return (
    <div className="mb-4 flex items-center justify-between rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-400">
      <span>Uncommitted configuration changes</span>
      <Link
        href="/config/"
        className="rounded-lg bg-amber-500/20 px-3 py-1 text-xs font-semibold text-amber-300 hover:bg-amber-500/30"
      >
        Review &amp; Commit
      </Link>
    </div>
  );
}
