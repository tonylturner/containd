import type { SyslogStatus } from "../../../../lib/api-service-status";

/** Known loss is counted per destination/source, not as unique lost records. */
export function deliveryAttention(status: SyslogStatus | null): string | undefined {
  if (!status) return "Delivery status unavailable — use Refresh to retry";
  const issues: string[] = [];
  const events = status.events;
  if (status.last_error) issues.push(status.last_error);
  if (status.fault?.message) issues.push(status.fault.message);
  if (status.failed_total > 0) issues.push("Delivery failures reported");
  if (events?.some(row => row.lost > 0)) issues.push("Telemetry loss reported");
  if (events?.some(row => row.continuity_unknown > 0)) issues.push("Telemetry continuity gaps; additional loss unknown");
  if (events?.some(row => row.backlog > 0 || row.failed > 0 || row.last_error)) issues.push("Telemetry forwarding needs attention");
  const audit = status.audit;
  if (audit && (audit.backlog > 0 || audit.failed_total > 0 || audit.last_error || audit.forwarders?.some(row => row.last_error))) {
    issues.push("Audit forwarding needs attention");
  }
  return issues.length ? issues.join("; ") : undefined;
}

export function DeliverySummary({ status }: { status: SyslogStatus | null }) {
  const events = status?.events;
  const audit = status?.audit;
  return (
    <div className="text-(--text-muted)">
      <p>{events
        ? `Telemetry: ${events.reduce((sum, row) => sum + row.lost, 0)} known lost deliveries; ${events.reduce((sum, row) => sum + row.continuity_unknown, 0)} continuity gaps; ${events.reduce((sum, row) => sum + row.backlog, 0)} queued (summed per destination/source).`
        : "Telemetry loss and continuity: Unknown."}</p>
      <p>{audit
        ? `Audit forwarding: ${audit.enabled ? "enabled" : "disabled"}; ${audit.failed_total} failed attempts; ${audit.backlog} queued. Audit loss is not reported.`
        : "Audit forwarding: Unknown; audit loss is not reported."}</p>
    </div>
  );
}
