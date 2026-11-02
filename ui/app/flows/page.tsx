"use client";

import { useCallback, useEffect, useMemo, useState, Fragment } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";
import Link from "next/link";

import { api, type FlowSummary } from "../../lib/api";
import { formatEndpoint } from "../../lib/endpoint";
import { Shell } from "../../components/Shell";
import { SkeletonList } from "../../components/Skeleton";
import { StatusBadge } from "../../components/StatusBadge";
import { EmptyState } from "../../components/EmptyState";
import { IdentificationBadge } from "./identification-badge";
import { FlowInspection } from "./flow-inspection";

const UNAVAILABLE = "Flows unavailable — live traffic monitoring could not be reached.";

/** Short form of an IEC 104 session ID ("<run>-<seq>"): run prefix and seq. */
function shortSessionID(id: string): string {
  const dash = id.lastIndexOf("-");
  return dash > 0 ? `${id.slice(0, 6)}…${id.slice(dash)}` : `${id.slice(0, 10)}…`;
}

function FlowsInner() {
  const searchParams = useSearchParams();
  return <FlowsContent key={searchParams.toString()} />;
}

function FlowsContent() {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const searchParams = useSearchParams();
  const [showAVOnly, setShowAVOnly] = useState(searchParams.get("av") === "1");
  // Until the first answer the list is unknown, not empty; polls keep the
  // current rows while they run.
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

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
  const iecSessionCount = useMemo(
    () => flows.filter((f) => f.session_id).length,
    [flows],
  );

  const visibleFlows = useMemo(
    () => showAll ? filteredFlows : filteredFlows.slice(0, PAGE_SIZE),
    [filteredFlows, showAll],
  );

  const hasMore = filteredFlows.length > PAGE_SIZE && !showAll;

  // A failed load clears the error only on the next success, so the earlier
  // list stays hidden instead of reappearing while a retry is in flight.
  const load = useCallback(async (signal?: AbortSignal) => {
    setBusy(true);
    try {
      const list = await api.listFlows(200, signal);
      if (list) {
        setError(null);
        setFlows(list);
      } else {
        setError(UNAVAILABLE);
      }
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      setError(UNAVAILABLE);
    } finally {
      setBusy(false);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const refresh = () => load(controller.signal);

    refresh();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, 10000);
    const onVisible = () => { if (!document.hidden) refresh(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [searchParams, load]);

  return (
    <Shell
      title="Active Flows"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => load()}
            className="transition-ui rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text)"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-(--text)">
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
        <div role="status" className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          <p>{error}</p>
          <button onClick={() => load()} disabled={busy} className="mt-2 rounded-xs border px-3 py-1 disabled:opacity-50">Retry</button>
        </div>
      )}

      {!error && (loading ? <SkeletonList rows={4} /> : <>
      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xs border bg-(--surface) px-4 py-3 text-xs text-(--text)">
        <div className="w-full text-(--text-muted)">
          Live flow summaries show active conversations, AV flags and the labels of the connection-label rules that matched them. These are observed conversations, not kernel connection state. Use Events for activity records and Alerts for IDS investigations.
        </div>
        <Link href="/sessions/" className="underline">Sessions — inspect kernel connections and revoke immediately</Link>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5">
          Total flows: {flows.length}
        </div>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5">
          AV detected: {avDetectedCount}
        </div>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5">
          AV blocked: {avBlockedCount}
        </div>
        <div className="rounded-lg border bg-(--surface2) px-3 py-1.5">
          IEC 104 sessions: {iecSessionCount}
        </div>
        <Link
          href="/events/?av=1"
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text) transition-ui"
        >
          Open AV events
        </Link>
      </div>

      {flows.length === 0 ? (
        <EmptyState
          title="No flows yet"
          description="Enable DPI capture to generate flow records."
        />
      ) : (
        <div className="rounded-xs border bg-(--surface) overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-(--surface) text-xs font-medium uppercase tracking-wider text-(--text-dim)">
              <tr>
                <th className="px-4 py-3">Flow</th>
                <th className="px-4 py-3">Detected app</th>
                <th className="px-4 py-3">Source → Destination</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3 text-right">Signals</th>
              </tr>
            </thead>
            <tbody>
              {visibleFlows.map((f) => (
                <Fragment key={f.session_id ?? f.flowId}>
                <tr
                  className={`table-row-hover transition-ui border-t ${
                    !f.avBlocked && f.avDetected ? "bg-amber/10" : ""
                  }`}
                >
                  <td className="px-4 py-3 font-mono text-xs text-(--text)">
                    <button type="button" aria-expanded={!!expanded[f.session_id ?? f.flowId]} aria-controls={`flow-detail-${f.session_id ?? f.flowId}`}
                      onClick={() => setExpanded(old => ({ ...old, [f.session_id ?? f.flowId]: !old[f.session_id ?? f.flowId] }))}
                      className="mb-1 block rounded-xs border px-2 py-1 font-sans">Inspect flow</button>
                    {!!f.tags?.length && <span className="block font-sans text-xs">Tags: {f.tags.length}</span>}
                    {f.session_id ? (
                      <span title={f.session_id}>
                        IEC {shortSessionID(f.session_id)}
                        <Link
                          href={`/events/?filter=iec104&session=${encodeURIComponent(f.session_id)}`}
                          className="ml-2 font-sans text-(--amber) hover:text-(--amber)"
                        >
                          Evidence
                        </Link>
                      </span>
                    ) : (
                      <>{f.flowId.slice(0, 10)}…</>
                    )}
                  </td>
                  <td className="px-4 py-3 text-slate-100">
                    {f.identification || f.application ? (
                      <IdentificationBadge identification={f.identification} application={f.application} />
                    ) : f.transport || "Unknown"}
                  </td>
                  <td className="px-4 py-3 text-(--text)">
                    {formatEndpoint(f.srcIp, f.srcPort)} → {formatEndpoint(f.dstIp, f.dstPort)}
                  </td>
                  <td className="px-4 py-3 text-(--text-muted)">
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
                <FlowInspection flow={f} open={!!expanded[f.session_id ?? f.flowId]} />
                </Fragment>
              ))}
            </tbody>
          </table>
          </div>
          {filteredFlows.length > 0 && (
            <div className="flex items-center justify-between border-t px-4 py-2 text-xs text-(--text-muted)">
              <span>Showing {visibleFlows.length} of {filteredFlows.length} flows</span>
              {hasMore && (
                <button
                  onClick={() => setShowAll(true)}
                  className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text)"
                >
                  Show all {filteredFlows.length} flows
                </button>
              )}
              {showAll && filteredFlows.length > PAGE_SIZE && (
                <button
                  onClick={() => setShowAll(false)}
                  className="transition-ui rounded-xs border bg-(--surface2) px-3 py-1.5 text-xs text-(--text)"
                >
                  Show first {PAGE_SIZE}
                </button>
              )}
            </div>
          )}
        </div>
      )}
      </>)}
    </Shell>
  );
}

export default function FlowsPage() {
  return (
    <Suspense fallback={<div className="p-4 text-(--text)">Loading flows…</div>}>
      <FlowsInner />
    </Suspense>
  );
}
