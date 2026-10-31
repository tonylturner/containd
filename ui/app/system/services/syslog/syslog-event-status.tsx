import type { SyslogEventProgress } from "../../../../lib/api-service-status";

export function SyslogEventStatusPanel({ events }: { events: SyslogEventProgress[] | undefined }) {
  return (
    <section aria-label="Telemetry forwarding" className="mb-4 rounded-xs border bg-(--surface) p-3 text-xs text-(--text)">
      <h2 className="text-sm font-semibold">Telemetry forwarding</h2>
      <p className="mt-1 text-(--text-muted)">
        Best effort with retries, independently per destination and source. New destinations start at the current tail, without backfill.
        Lost counts known retention or serialization loss; continuity gaps mean additional loss is unknown.
        Sent means accepted by the local transport, not acknowledged by the collector.
      </p>
      {!events ? <p className="mt-2 text-amber">Telemetry progress unknown.</p>
        : events.length === 0 ? <p className="mt-2">No active telemetry streams.</p>
          : <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left">
              <thead><tr>
                {["Destination / source", "Backlog", "Sent", "Failed", "Lost", "Continuity gaps", "Progress", "Current error"].map((label) =>
                  <th key={label} className="py-1 pr-3 whitespace-nowrap">{label}</th>)}
              </tr></thead>
              <tbody>{events.map((row) => (
                <tr key={`${row.destination}/${row.source}`} className="border-t">
                  <td className="py-2 pr-3 font-mono">{row.destination}<br />{row.source}</td>
                  <td className={`pr-3 ${row.backlog ? "text-amber" : ""}`}>{row.backlog}</td>
                  <td className="pr-3">{row.sent}</td>
                  <td className="pr-3">{row.failed}</td>
                  <td className={`pr-3 ${row.lost ? "text-rose-300" : ""}`}>{row.lost}</td>
                  <td className={`pr-3 ${row.continuity_unknown ? "text-amber" : ""}`}>{row.continuity_unknown}</td>
                  <td className="pr-3 font-mono">Epoch: {row.epoch || "unknown"}<br />Offset: {row.offset}</td>
                  <td className={row.last_error ? "text-rose-300" : "text-(--text-muted)"}>{row.last_error || "—"}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>}
    </section>
  );
}
