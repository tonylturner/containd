"use client";

import * as React from "react";
import Link from "next/link";
import { api } from "../lib/api";

/** Simple FNV-1a-inspired string hash — fast, no allocations beyond the string itself. */
function fastHash(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

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
      // Fast pre-check: different lengths means definitely dirty.
      // Same length: compare hashes to avoid slow char-by-char string equality on large configs.
      if (r.length !== c.length) {
        setDirty(true);
      } else {
        setDirty(fastHash(r) !== fastHash(c));
      }
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

  if (!dirty) return null;

  return (
    <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-amber-500/25 bg-amber-500/8 px-4 py-2.5 text-sm animate-fade-in">
      <div className="flex items-center gap-2 text-amber-400">
        <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2}>
          <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
        </svg>
        <span>You have uncommitted configuration changes</span>
      </div>
      <Link
        href="/config/?tab=diff"
        className="rounded-lg bg-amber-500/20 px-3 py-1 text-xs font-semibold text-amber-300 transition-ui hover:bg-amber-500/30"
      >
        Review &amp; Commit
      </Link>
    </div>
  );
}
