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

  const PAGE_SIZE = 100;
  const [showAll, setShowAll] = useState(false);

  const filteredFlows = useMemo(
    () => flows.filter((f) => (showAVOnly ? f.avDetected || f.avBlocked : true)),
    [flows, showAVOnly],
  );
  const avDetectedCount = useMemo(
    () => flows.filter((f) => f.avDetected && !f.avBlocked).length,
    [flows],
  );
  const avBlockedCount = useMemo(
    () => flows.filter((f) => f.avBlocked).length,
    [flows],
  );

  const visibleFlows = useMemo(
    () => showAll ? filteredFlows : filteredFlows.slice(0, PAGE_SIZE),
    [filteredFlows, showAll],
  );

  const hasMore = filteredFlows.length > PAGE_SIZE && !showAll;

  async function manualRefresh() {
    setError(null);
    setLoading(true);
    try {
      const list = await api.listFlows();
      if (!list) { setError("Failed to load flows."); setLoading(false); return; }
      setFlows(list);
      setLoading(false);
    } catch {
      setError("Failed to load flows.");
      setLoading(false);
    }
  }

  useEffect(() => {
    const avOnly = searchParams.get("av") === "1";
    if (avOnly) setShowAVOnly(true);
    const controller = new AbortController();

    async function refresh() {
      setError(null);
      setLoading(true);
      try {
        const list = await api.listFlows(200, controller.signal);
        if (!list) {
          setError("Failed to load flows.");
          setLoading(false);
          return;
        }
        setFlows(list);
        setLoading(false);
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setError("Failed to load flows.");
        setLoading(false);
      }
    }

    refresh();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, 10000);
    const onVisible = () => { if (!document.hidden) refresh(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [searchParams]);

  return (
    <Shell
      title="Active Flows"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={manualRefresh}
            className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.06]"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-[var(--text)]">
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

      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-xs text-[var(--text)]">
        <div className="w-full text-[var(--text-muted)]">
          Live flow summaries show active conversations and AV flags. Use Events for raw telemetry and Alerts for IDS investigations.
        </div>
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5">
          Total flows: {flows.length}
        </div>
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5">
          AV detected: {avDetectedCount}
        </div>
        <div className="rounded-lg border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5">
          AV blocked: {avBlockedCount}
        </div>
        <a
          href="/events/?av=1"
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06] transition-ui"
        >
          Open AV events
        </a>
      </div>

      {!loading && flows.length === 0 ? (
        <EmptyState
          title="No flows yet"
          description="Enable DPI capture or learning mode to generate flow records."
        />
      ) : (
        <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-[var(--surface)] text-xs font-medium uppercase tracking-wider text-[var(--text-dim)]">
              <tr>
                <th className="px-4 py-3">Flow</th>
                <th className="px-4 py-3">Detected app</th>
                <th className="px-4 py-3">Source → Destination</th>
                <th className="px-4 py-3">First Seen</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3 text-right">Signals</th>
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
              {!loading && visibleFlows
                .map((f) => (
                <tr
                  key={f.flowId}
                  className={`table-row-hover transition-ui border-t border-amber-500/[0.1] ${
                    f.avBlocked ? "bg-[color:var(--error)]/10" : f.avDetected ? "bg-amber/10" : ""
                  }`}
                >
                  <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                    {f.flowId.slice(0, 10)}…
                  </td>
                  <td className="px-4 py-3 text-slate-100">
                    {f.application || f.transport || "Unknown"}
                  </td>
                  <td className="px-4 py-3 text-[var(--text)]">
                    {f.srcIp}:{f.srcPort} → {f.dstIp}:{f.dstPort}
                  </td>
                  <td className="px-4 py-3 text-[var(--text-muted)]">
                    {new Date(f.firstSeen).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-[var(--text-muted)]">
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
          {!loading && filteredFlows.length > 0 && (
            <div className="flex items-center justify-between border-t border-amber-500/[0.1] px-4 py-2 text-xs text-[var(--text-muted)]">
              <span>Showing {visibleFlows.length} of {filteredFlows.length} flows</span>
              {hasMore && (
                <button
                  onClick={() => setShowAll(true)}
                  className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
                >
                  Show all {filteredFlows.length} flows
                </button>
              )}
              {showAll && filteredFlows.length > PAGE_SIZE && (
                <button
                  onClick={() => setShowAll(false)}
                  className="transition-ui rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.06]"
                >
                  Show first {PAGE_SIZE}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </Shell>
  );
}

export default function FlowsPage() {
  return (
    <Suspense fallback={<div className="p-4 text-[var(--text)]">Loading flows…</div>}>
      <FlowsInner />
    </Suspense>
  );
}
