"use client";

import { useEffect, useState } from "react";
import { Card } from "../../components/Card";
import {
  fetchIEC104Pressure,
  type IEC104Pressure,
} from "../../lib/api-iec-pressure";

const reasons: Record<string, string> = {
  deny: "Denied command",
  timeout: "Pending timeout",
  bound: "Bound / saturation",
  midstream: "Midstream",
  fail_close: "Fail-closed steering",
  injector: "Injector unavailable",
  stream: "Stream error",
  framing: "Framing error",
  transport: "Transport error",
  policy: "Policy change",
  queue: "Queue closed",
  unhealthy: "Unhealthy enforcement",
};

export function IECPressurePanel() {
  const [data, setData] = useState<IEC104Pressure | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    // Schedule the next request only after completion; slow engines never pile up polls.
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await fetchIEC104Pressure(controller.signal);
        if (!controller.signal.aborted) {
          setData(next);
          setLoading(false);
        }
      } catch {
        if (!controller.signal.aborted) {
          setData(null);
          setLoading(false);
        }
      }
      if (!controller.signal.aborted) timer = setTimeout(poll, 5000);
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, []);

  return (
    <Card title="IEC 104 holdback pressure" padding="lg">
      <p className="text-xs text-[var(--text-muted)]">
        Incomplete APDUs wait for a decision. Queue pressure is not a denied
        command. Limits are fixed; totals last until the engine process
        restarts.
      </p>
      {loading ? (
        <p role="status" className="mt-4 text-sm">
          Loading IEC 104 diagnostics…
        </p>
      ) : !data ? (
        <p role="status" className="mt-4 text-sm text-amber-400">
          IEC 104 diagnostics unavailable. The engine could not be reached;
          retrying automatically.
        </p>
      ) : (
        <>
          <div className="mt-4 overflow-x-auto">
            <table
              className="w-full text-left text-sm"
              aria-label="IEC 104 current pressure"
            >
              <thead className="text-[var(--text-muted)]">
                <tr>
                  <th className="py-2 font-medium">Current pressure</th>
                  <th className="py-2 font-medium">Observed</th>
                  <th className="py-2 font-medium">Fixed limit</th>
                </tr>
              </thead>
              <tbody className="tabular-nums">
                {[
                  [
                    "Held packets",
                    data.heldPackets,
                    `${data.limits.heldPackets} global / ${data.limits.heldPacketsPerSession} per session`,
                  ],
                  [
                    "Held payload bytes",
                    data.heldBytes,
                    `${data.limits.heldBytesPerSession.toLocaleString()} per session`,
                  ],
                  [
                    "Oldest pending age",
                    `${data.oldestPendingSeconds.toFixed(3)} s`,
                    `${data.limits.pendingSeconds} s`,
                  ],
                  [
                    "Active sessions",
                    data.activeSessions,
                    `${data.limits.sessions} tuple slots`,
                  ],
                  [
                    "Tracked tuple slots",
                    data.trackedSessions,
                    `${data.limits.sessions} (includes closed / aborted)`,
                  ],
                ].map(([label, value, limit]) => (
                  <tr key={label} className="border-t border-amber-500/[0.1]">
                    <th className="py-2 font-normal">{label}</th>
                    <td className="py-2">{value}</td>
                    <td className="py-2 text-[var(--text-muted)]">{limit}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h3 className="mt-5 text-sm font-medium">
            Aborts and admission rejections by reason
          </h3>
          <dl className="mt-2 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(reasons).map(([reason, label]) => (
              <div key={reason} className="flex justify-between gap-4">
                <dt className="text-[var(--text-muted)]">{label}</dt>
                <dd className="tabular-nums">{data.aborts[reason]}</dd>
              </div>
            ))}
          </dl>
          <dl className="mt-4 space-y-2 border-t border-amber-500/[0.1] pt-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt>
                Reset-worker rejections{" "}
                <span className="text-[var(--text-muted)]">
                  (shared queue cap: {data.limits.resetWorkerJobs})
                </span>
              </dt>
              <dd className="tabular-nums">{data.resetWorkerRejections}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt>
                Inline verdict failures{" "}
                <span className="text-[var(--text-muted)]">
                  (excludes queue closure)
                </span>
              </dt>
              <dd className="tabular-nums">{data.verdictFailures}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt>Reset injection failures</dt>
              <dd className="tabular-nums">{data.injectorFailures}</dd>
            </div>
          </dl>
        </>
      )}
    </Card>
  );
}
