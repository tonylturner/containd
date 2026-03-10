"use client";

import { useEffect, useMemo, useState } from "react";

import { clearDismissedTips, dismissTip, getDismissedTips, getShowTips } from "../lib/prefs";

export type Tip = {
  id: string;
  title: string;
  body: React.ReactNode;
  when?: () => boolean;
};

export function TipsBanner({ tips, className = "" }: { tips: Tip[]; className?: string }) {
  const [showTips, setShowTips] = useState(true);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const refresh = () => {
      setShowTips(getShowTips());
      setDismissed(getDismissedTips());
    };
    refresh();
    const onPrefs = () => refresh();
    window.addEventListener("containd:prefs", onPrefs);
    return () => {
      window.removeEventListener("containd:prefs", onPrefs);
    };
  }, []);

  const activeTips = useMemo(() => {
    return tips.filter((t) => {
      if (dismissed.has(t.id)) return false;
      if (t.when && !t.when()) return false;
      return true;
    });
  }, [dismissed, tips]);

  useEffect(() => {
    if (index >= activeTips.length) {
      setIndex(0);
    }
  }, [activeTips.length, index]);

  if (!showTips || activeTips.length === 0) return null;

  const tip = activeTips[index] ?? activeTips[0];
  const count = activeTips.length;

  function next() {
    if (count <= 1) return;
    setIndex((i) => (i + 1) % count);
  }

  function prev() {
    if (count <= 1) return;
    setIndex((i) => (i - 1 + count) % count);
  }

  function dismiss() {
    if (!tip) return;
    dismissTip(tip.id);
    setDismissed(getDismissedTips());
  }

  function clearAll() {
    clearDismissedTips();
    setDismissed(new Set());
  }

  return (
    <div className={`card-industrial rounded-sm border border-[var(--cyan)]/15 bg-[rgba(6,182,212,0.06)] px-4 py-2.5 text-sm ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-start gap-2.5">
          <svg viewBox="0 0 24 24" className="mt-0.5 h-4 w-4 shrink-0 text-[var(--cyan)]" fill="none" stroke="currentColor" strokeWidth={2}>
            <circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" />
          </svg>
          <div className="min-w-0">
            <div className="text-sm font-medium text-[var(--cyan)]">{tip.title}</div>
            <div className="text-[13px] text-[var(--text-muted)]">{tip.body}</div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[10px]">
          {count > 1 && (
            <>
              <button onClick={prev} className="rounded-sm px-2 py-1 text-[var(--text-dim)] transition-ui hover:bg-amber-500/[0.06] hover:text-[var(--text)]">
                Prev
              </button>
              <span className="tabular-nums text-[var(--text-dim)]">{index + 1}/{count}</span>
              <button onClick={next} className="rounded-sm px-2 py-1 text-[var(--text-dim)] transition-ui hover:bg-amber-500/[0.06] hover:text-[var(--text)]">
                Next
              </button>
              <span className="mx-1 text-[var(--text-dim)]">|</span>
            </>
          )}
          <button onClick={dismiss} className="rounded-sm px-2 py-1 text-[var(--text-dim)] transition-ui hover:bg-amber-500/[0.06] hover:text-[var(--text)]">
            Dismiss
          </button>
          <button onClick={clearAll} className="rounded-sm px-2 py-1 text-[var(--text-dim)] transition-ui hover:bg-amber-500/[0.06] hover:text-[var(--text-muted)]" title="Show all previously dismissed tips">
            Show all
          </button>
        </div>
      </div>
    </div>
  );
}
