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
    <div
      className={[
        "rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200",
        className,
      ].join(" ")}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-semibold text-white">{tip.title}</div>
          <div className="truncate text-slate-300">{tip.body}</div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400">
          {count > 1 && (
            <>
              <button
                onClick={prev}
                className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10"
              >
                Prev
              </button>
              <button
                onClick={next}
                className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10"
              >
                Next
              </button>
            </>
          )}
          <button
            onClick={dismiss}
            className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10"
          >
            Dismiss
          </button>
          <button
            onClick={clearAll}
            className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-slate-400 hover:bg-white/10"
          >
            Reset
          </button>
          {count > 1 && <span>{index + 1}/{count}</span>}
        </div>
      </div>
    </div>
  );
}
