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
        className="rounded-md bg-white/5 px-2 py-1 text-xs text-slate-200 hover:bg-white/10"
      >
        Preview Impact
      </button>

      {open && (
        <div className="absolute right-0 top-full z-40 mt-1 w-80 rounded-xl border border-white/10 bg-ink p-4 shadow-2xl">
          {loading && (
            <div className="text-sm text-slate-400">Analyzing...</div>
          )}

          {error && (
            <div className="text-sm text-amber">{error}</div>
          )}

          {result && !loading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm text-white">
                  <span className="font-mono text-mint">
                    {result.matchCount.toLocaleString()}
                  </span>{" "}
                  event(s) would match
                </div>
                <button
                  onClick={() => setOpen(false)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Close
                </button>
              </div>
              <div className="text-xs text-slate-400">
                Time range: {result.timeRange}
              </div>

              {result.sampleEvents.length > 0 && (
                <div>
                  <button
                    onClick={() => setExpanded(!expanded)}
                    className="text-xs text-mint hover:text-mint/80"
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
                          className="rounded-lg border border-white/5 bg-black/30 p-2 text-xs"
                        >
                          <div className="flex items-center justify-between text-slate-200">
                            <span>
                              {e.proto} / {e.kind}
                            </span>
                            <span className="text-slate-400">
                              {new Date(e.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          {(e.srcIp || e.dstIp) && (
                            <div className="mt-0.5 font-mono text-slate-400">
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
