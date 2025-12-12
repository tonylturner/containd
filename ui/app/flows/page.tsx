"use client";

import { useEffect, useState } from "react";

import { api, type FlowSummary } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function FlowsPage() {
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    const list = await api.listFlows();
    if (!list) {
      setError("Failed to load flows.");
      return;
    }
    setFlows(list);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <Shell
      title="Flows"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
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
            {flows.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-6 text-center text-slate-400"
                >
                  No flows yet. Enable DPI mock or capture to generate events.
                </td>
              </tr>
            )}
            {flows.map((f) => (
              <tr
                key={f.flowId}
                className="border-t border-white/10 hover:bg-white/5"
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
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}

