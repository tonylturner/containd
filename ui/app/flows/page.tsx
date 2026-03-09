"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, type FlowSummary } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { SkeletonList } from "../../components/Skeleton";
import { StatusBadge } from "../../components/StatusBadge";
import { EmptyState } from "../../components/EmptyState";

function FlowsInner() {
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showAVOnly, setShowAVOnly] = useState(false);
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(false);

  const filteredFlows = useMemo(
    () => flows.filter((f) => (showAVOnly ? f.avDetected || f.avBlocked : true)),
    [flows, showAVOnly],
  );

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
            className="transition-ui rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06]"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-slate-200">
            <input
              type="checkbox"
              className="transition-ui h-4 w-4"
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

      {!loading && flows.length === 0 ? (
        <EmptyState
          title="No flows yet"
          description="Enable DPI capture or learning mode to generate events."
        />
      ) : (
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/[0.03] text-xs font-medium uppercase tracking-wider text-slate-500">
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
              {!loading && filteredFlows
                .map((f) => (
                <tr
                  key={f.flowId}
                  className={`table-row-hover transition-ui border-t border-white/[0.06] ${
                    f.avBlocked ? "bg-[color:var(--error)]/10" : f.avDetected ? "bg-amber/10" : ""
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
                    {f.avBlocked && (
                      <StatusBadge variant="error" dot className="ml-2">
                        AV blocked
                      </StatusBadge>
                    )}
                    {f.avDetected && !f.avBlocked && (
                      <StatusBadge variant="warning" dot className="ml-2">
                        AV detected
                      </StatusBadge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
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
