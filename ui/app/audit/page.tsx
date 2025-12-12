 "use client";

import { useEffect, useState } from "react";

import { api, type AuditRecord } from "../../lib/api";
import { Shell } from "../../components/Shell";

export default function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    const list = await api.listAudit();
    if (!list) {
      setError("Failed to load audit records.");
      setRecords([]);
      return;
    }
    setRecords(list);
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Shell
      title="Audit Log"
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
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      <div className="overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Result</th>
            </tr>
          </thead>
          <tbody>
            {records.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={6}>
                  No audit records yet.
                </td>
              </tr>
            )}
            {records.map((r) => (
              <tr key={r.id} className="border-t border-white/5">
                <td className="px-4 py-3 text-slate-200">
                  {new Date(r.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-slate-200">{r.actor}</td>
                <td className="px-4 py-3 text-slate-200">{r.source}</td>
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {r.action}
                </td>
                <td className="px-4 py-3 text-slate-200">{r.target}</td>
                <td className="px-4 py-3 text-slate-200">{r.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}

