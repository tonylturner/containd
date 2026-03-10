"use client";

import { useState } from "react";

/* ── Types ─────────────────────────────────────────────────────── */

type PreviewResult = {
  matchCount: number;
  timeRange: string;
  sampleEvents: PreviewEvent[];
};

type PreviewEvent = {
  id: number;
  timestamp: string;
  proto: string;
  srcIp?: string;
  dstIp?: string;
  kind: string;
  attributes?: Record<string, unknown>;
};

/* ── API helper ────────────────────────────────────────────────── */

async function previewRuleImpact(
  rule: Record<string, unknown>,
): Promise<PreviewResult | null> {
  try {
    const res = await fetch("/api/v1/firewall/rules/preview", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rule),
    });
    if (!res.ok) return null;
    return (await res.json()) as PreviewResult;
  } catch {
    return null;
  }
}

/* ── Component ─────────────────────────────────────────────────── */

export function RulePreviewButton({
  rule,
}: {
  rule: Record<string, unknown>;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PreviewResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  async function handlePreview() {
    if (open && result) {
      setOpen(false);
      return;
    }
    setError(null);
    setLoading(true);
    setOpen(true);
    const res = await previewRuleImpact(rule);
    setLoading(false);
    if (!res) {
      setError("Failed to preview rule impact.");
      return;
    }
    setResult(res);
  }

  return (
    <div className="relative inline-block">
      <button
        onClick={handlePreview}
        className="rounded-md border border-white/[0.08] bg-white/[0.04] px-2 py-1 text-xs text-slate-300 transition-ui hover:bg-white/[0.08] hover:text-white"
      >
        Preview Impact
      </button>

      {open && (
        <div className="absolute right-0 top-full z-40 mt-1 w-80 rounded-xl border border-white/[0.08] bg-surface-raised p-4 shadow-card-lg animate-fade-in">
          {loading && (
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-500 border-t-white" />
              Analyzing...
            </div>
          )}

          {error && (
            <div className="text-sm text-red-400">{error}</div>
          )}

          {result && !loading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm text-white">
                  <span className="font-mono text-blue-400">
                    {result.matchCount.toLocaleString()}
                  </span>{" "}
                  event(s) would match
                </div>
                <button
                  onClick={() => setOpen(false)}
                  className="rounded-md p-1 text-xs text-slate-400 transition-ui hover:bg-white/[0.06] hover:text-white"
                >
                  Close
                </button>
              </div>
              <div className="text-xs text-slate-500">
                Time range: {result.timeRange}
              </div>

              {result.sampleEvents.length > 0 && (
                <div>
                  <button
                    onClick={() => setExpanded(!expanded)}
                    className="text-xs text-blue-400 transition-ui hover:text-blue-300"
                  >
                    {expanded
                      ? "Hide sample events"
                      : `Show ${result.sampleEvents.length} sample event(s)`}
                  </button>

                  {expanded && (
                    <div className="mt-2 max-h-48 space-y-1 overflow-y-auto">
                      {result.sampleEvents.map((e) => (
                        <div
                          key={e.id}
                          className="rounded-lg border border-white/[0.06] bg-black/30 p-2 text-xs"
                        >
                          <div className="flex items-center justify-between text-slate-300">
                            <span>
                              {e.proto} / {e.kind}
                            </span>
                            <span className="text-slate-500">
                              {new Date(e.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          {(e.srcIp || e.dstIp) && (
                            <div className="mt-0.5 font-mono text-slate-500">
                              {e.srcIp ?? "?"} &rarr; {e.dstIp ?? "?"}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
