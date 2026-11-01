import type { SyslogAuditStatus } from "../../../../lib/api";
import { formatTimestamp } from "../../../../lib/utils";

function when(value: string): string {
  return value ? formatTimestamp(value) : "—";
}

/**
 * Audit record forwarding over the syslog forwarders. A backlog with an
 * error means records are waiting on a failing forwarder: amber, because
 * delivery resumes from the cursor once it recovers.
 */
export function SyslogAuditStatusPanel({ audit }: { audit: SyslogAuditStatus }) {
  const forwarders = audit.forwarders ?? [];
  const stalled = audit.backlog > 0 && (audit.last_error !== "" || forwarders.some((f) => f.last_error));
  return (
    <section aria-label="Audit forwarding" className="mb-4 rounded-xs border bg-(--surface) p-3 text-xs text-(--text)">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-sm font-semibold">Audit forwarding</h2>
        <span className="text-(--text-muted)">
          {audit.enabled
            ? "Audit records go to every forwarder, oldest first; each forwarder resumes where it left off."
            : "Audit records are not forwarded."}
        </span>
      </div>
      <div className="grid gap-2 md:grid-cols-4">
        <div>Sent: {audit.sent_total}</div>
        <div>Failed: {audit.failed_total}</div>
        <div className={stalled ? "text-amber" : undefined}>Backlog: {audit.backlog}</div>
        <div>Last send: {when(audit.last_flush)}</div>
      </div>
      {audit.last_error && (
        <p role="status" aria-label="Audit forwarding error" className="mt-2 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-amber wrap-break-word">
          Last error: {audit.last_error}
        </p>
      )}
      {forwarders.length > 0 && (
        <table className="mt-3 w-full text-left">
          <thead className="text-[10px] uppercase tracking-wider text-(--text-dim)">
            <tr>
              <th className="py-1 pr-3">Forwarder</th>
              <th className="py-1 pr-3">Last record</th>
              <th className="py-1 pr-3">Backlog</th>
              <th className="py-1 pr-3">Last sent</th>
              <th className="py-1">Last error</th>
            </tr>
          </thead>
          <tbody>
            {forwarders.map((f) => (
              <tr key={f.forwarder} className="border-t">
                <td className="py-1.5 pr-3 font-mono">{f.forwarder}</td>
                <td className="py-1.5 pr-3 font-mono"><details><summary className="cursor-pointer">Record position</summary><code>{f.last_id}</code></details></td>
                <td className={`py-1.5 pr-3 ${f.backlog > 0 && f.last_error ? "text-amber" : ""}`}>{f.backlog}</td>
                <td className="py-1.5 pr-3">{when(f.last_sent)}</td>
                <td className={`py-1.5 wrap-break-word ${f.last_error ? "text-amber" : "text-(--text-muted)"}`}>{f.last_error || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
