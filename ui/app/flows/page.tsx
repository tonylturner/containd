"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, type FlowSummary } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { SkeletonList } from "../../components/Skeleton";

function FlowsInner() {
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showAVOnly, setShowAVOnly] = useState(false);
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(false);

  async function refresh() {
    setError(null);
    setLoading(true);
    const list = await api.listFlows();
    if (!list) {
      setError("Failed to load flows.");
      setLoading(false);
      return;
    }
    setFlows(list);
    setLoading(false);
  }

  useEffect(() => {
    const avOnly = searchParams.get("av") === "1";
    if (avOnly) setShowAVOnly(true);
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [searchParams]);

  return (
    <Shell
      title="Flows"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-slate-200">
            <input
              type="checkbox"
              className="h-4 w-4"
              checked={showAVOnly}
              onChange={(e) => setShowAVOnly(e.target.checked)}
            />
            AV detections only
          </label>
        </div>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-left text-sm">
          <thead className="bg-white/5 text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">Flow</th>
              <th className="px-4 py-3">App/Proto</th>
              <th className="px-4 py-3">Endpoints</th>
              <th className="px-4 py-3">First Seen</th>
              <th className="px-4 py-3">Last Seen</th>
              <th className="px-4 py-3 text-right">Events</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={6} className="px-4 py-6">
                  <SkeletonList rows={4} />
                </td>
              </tr>
            )}
            {!loading && flows.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-6 text-center text-slate-400"
                >
                  No flows yet. Enable DPI mock or capture to generate events.
                </td>
              </tr>
            )}
            {!loading && flows
              .filter((f) => (showAVOnly ? f.avDetected || f.avBlocked : true))
              .map((f) => (
              <tr
                key={f.flowId}
                className={`border-t border-white/10 hover:bg-white/5 ${
                  f.avBlocked ? "bg-red/10" : f.avDetected ? "bg-amber/10" : ""
                }`}
              >
                <td className="px-4 py-3 font-mono text-xs text-slate-200">
                  {f.flowId.slice(0, 10)}…
                </td>
                <td className="px-4 py-3 text-slate-100">
                  {f.application || f.transport || "-"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {f.srcIp}:{f.srcPort} → {f.dstIp}:{f.dstPort}
                </td>
                <td className="px-4 py-3 text-slate-400">
                  {new Date(f.firstSeen).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-slate-400">
                  {new Date(f.lastSeen).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-right text-slate-100">
                  {f.eventCount}
                  {(f.avDetected || f.avBlocked) && (
                    <span className="ml-2 inline-flex items-center rounded-full bg-red/20 px-2 py-0.5 text-[10px] font-semibold text-red">
                      {f.avBlocked ? "AV blocked" : "AV detected"}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}

export default function FlowsPage() {
  return (
    <Suspense fallback={<div className="p-4 text-slate-200">Loading flows…</div>}>
      <FlowsInner />
    </Suspense>
  );
}
