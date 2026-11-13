"use client";

import { useEffect, useState } from "react";
import { Card } from "../../components/Card";
import { StatusBadge } from "../../components/StatusBadge";
import { fetchStateLimits, type StateLimits } from "../../lib/api-state-limits";

export function StateLimitsPanel() {
  const [data, setData] = useState<StateLimits | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await fetchStateLimits(controller.signal);
        if (!controller.signal.aborted) { setData(next); setLoading(false); }
      } catch {
        if (!controller.signal.aborted) { setData(null); setLoading(false); }
      }
      if (!controller.signal.aborted) timer = setTimeout(poll, 5000);
    }
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, []);

  return <Card title="Dataplane state limits" padding="lg">
    <p className="text-xs text-(--text-muted)">
      Pressure means a limit was hit in the last 60 seconds; hits last until the engine process restarts.
      High water uses entries (bytes for inspection_bytes). Flows count directional slots, two per connection.
      Charged bytes cover retained inspection allocations, not total engine memory. Occupancy resets on a dataplane rebuild.
    </p>
    {loading ? <p role="status" className="mt-4 text-sm">Loading state limits…</p> : !data ?
      <p role="status" className="mt-4 text-sm">State limits unavailable. Live engine information could not be reached; retrying automatically.</p> : <>
        <div className="mt-4 overflow-x-auto">
          <table aria-label="Dataplane state limits" className="w-full text-left text-sm">
            <thead className="text-(--text-muted)"><tr>
              {["Table", "Limit", "Entries", "Charged bytes", "High water", "Pressure", "Hits (reason / mode)"].map(label =>
                <th key={label} className="whitespace-nowrap px-2 py-2 font-medium first:pl-0">{label}</th>)}
            </tr></thead>
            <tbody className="tabular-nums">{data.tables.map(row => <tr key={row.table} className="border-t">
              <th className="py-2 pr-2 font-mono text-xs font-normal">{row.table}</th>
              {[row.limit === 0 ? "No aggregate cap" : row.limit.toLocaleString(), row.entries.toLocaleString(), row.chargedBytes.toLocaleString(), row.highWater.toLocaleString()].map((value, i) =>
                <td key={i} className="whitespace-nowrap px-2 py-2">{value}</td>)}
              <td className="px-2 py-2"><StatusBadge variant={row.pressure ? "warning" : "neutral"}>{row.pressure ? "Recent hit" : "No recent hit"}</StatusBadge></td>
              <td className="px-2 py-2 text-xs">{row.hits.length ? row.hits.map(hit => <div key={`${hit.reason}/${hit.mode}`} className="whitespace-nowrap">{hit.total.toLocaleString()} {hit.reason} / {hit.mode}</div>) : "0"}</td>
            </tr>)}</tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-(--text-muted)">Inspection charges by category: {Object.entries(data.budget.byCategory).map(([category, bytes]) => `${category} ${bytes.toLocaleString()} B`).join(" · ")}</p>
      </>}
  </Card>;
}
