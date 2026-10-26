"use client";

import { StatusBadge } from "../../components/StatusBadge";
import type { TelemetryEvent } from "../../lib/api";
import type { EvidenceView } from "../events/iec104-evidence";
import { DetailRow, DetailSection, severityVariant } from "./alert-detail-parts";

/** Detail panel for IEC 104 enforcement evidence or APCI observations. */
export function IEC104EvidencePanel({
  event,
  evidence,
  onClose,
}: {
  event: TelemetryEvent;
  evidence: EvidenceView;
  onClose: () => void;
}) {
  return (
    <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] overflow-hidden flex flex-col h-[calc(100vh-240px)] sticky top-4">
      <div className="flex items-start justify-between gap-2 border-b border-amber-500/[0.1] px-4 py-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--text)] break-words">{evidence.headline}</h3>
          <div className="mt-1 flex items-center gap-2 flex-wrap">
            <StatusBadge variant={severityVariant(evidence.severity)} dot>{evidence.severity}</StatusBadge>
            <StatusBadge variant={evidence.variant}>{evidence.badge}</StatusBadge>
            <span className="rounded-sm border border-blue-500/20 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-400 uppercase">iec104</span>
          </div>
        </div>
        <button onClick={onClose} className="shrink-0 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-0.5 text-xs text-[var(--text-muted)] transition-ui hover:bg-amber-500/[0.08]">
          Close
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        <DetailSection label="IEC 104 Evidence">
          <DetailRow label="Event" value={event.kind} mono />
          {evidence.rows.map((row) => (
            <DetailRow key={row.label} label={row.label} value={row.value} mono />
          ))}
          <DetailRow label="Time" value={new Date(event.timestamp).toLocaleString()} />
          {evidence.sessionId && (
            <a
              href={`/events/?${event.proto === "ids" ? "" : "filter=iec104&"}session=${encodeURIComponent(evidence.sessionId)}`}
              className="inline-block text-xs text-[var(--amber)] hover:text-[var(--amber)]"
            >
              Open session events &rarr;
            </a>
          )}
        </DetailSection>

        <DetailSection label="Network">
          <DetailRow label="Source" value={`${event.srcIp}:${event.srcPort}`} mono />
          <DetailRow label="Destination" value={`${event.dstIp}:${event.dstPort}`} mono />
          {event.transport && <DetailRow label="Transport" value={event.transport.toUpperCase()} />}
          {event.flowId && <DetailRow label="Flow ID" value={event.flowId} mono />}
        </DetailSection>

        <DetailSection label="Meaning">
          <div className="text-xs text-[var(--text-muted)] leading-relaxed">
            A decision records what a rule decided, not proof of delivery. A
            decoded command is an attempt, not an actuation. APCI anomalies are
            observations and do not change firewall decisions.
          </div>
        </DetailSection>
      </div>
    </div>
  );
}
