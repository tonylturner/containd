"use client";

import { useState } from "react";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { StatusBadge } from "../../components/StatusBadge";
import { api, isAdmin, type TelemetryEvent } from "../../lib/api";
import { formatEndpoint } from "../../lib/endpoint";
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
  const confirm = useConfirm();
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const anomaly = event.proto === "ids" && event.kind === "anomaly";

  return (
    <div className="rounded-xs border bg-(--surface) overflow-hidden flex flex-col h-[calc(100vh-240px)] sticky top-4">
      <ConfirmDialog {...confirm.props} />
      <div className="flex items-start justify-between gap-2 border-b px-4 py-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-(--text) wrap-break-word">{evidence.headline}</h3>
          <div className="mt-1 flex items-center gap-2 flex-wrap">
            <StatusBadge variant={severityVariant(evidence.severity)} dot>{evidence.severity}</StatusBadge>
            <StatusBadge variant={evidence.variant}>{evidence.badge}</StatusBadge>
            <span className="rounded-xs border border-blue-500/20 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-400 uppercase">iec104</span>
          </div>
        </div>
        <button onClick={onClose} className="shrink-0 rounded-xs border bg-(--surface2) px-2 py-0.5 text-xs text-(--text-muted) transition-ui">
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
              className="inline-block text-xs text-(--amber) hover:text-(--amber)"
            >
              Open session events &rarr;
            </a>
          )}
        </DetailSection>

        <DetailSection label="Network">
          <DetailRow label="Source" value={formatEndpoint(event.srcIp, event.srcPort)} mono />
          <DetailRow label="Destination" value={formatEndpoint(event.dstIp, event.dstPort)} mono />
          {event.transport && <DetailRow label="Transport" value={event.transport.toUpperCase()} />}
          {event.flowId && <DetailRow label="Flow ID" value={event.flowId} mono />}
        </DetailSection>

        <DetailSection label="Meaning">
          <div className="text-xs text-(--text-muted) leading-relaxed">
            A decision records what a rule decided, not proof of delivery. A
            decoded command is an attempt, not an actuation. APCI anomalies are
            observations and do not change firewall decisions.
          </div>
        </DetailSection>
        {anomaly && (
          <DetailSection label="Anomaly store">
            <p className="text-xs text-(--text-muted)">
              Clearing resets all detected anomalies and detector tracking state,
              not historical alert events. New traffic can create more anomalies.
            </p>
            {isAdmin() && (
              <button
                disabled={clearing}
                className="mt-3 max-w-full rounded-xs border px-3 py-1.5 text-xs text-(--red) transition-ui disabled:opacity-50"
                onClick={() => confirm.open({
                  title: "Clear anomalies?",
                  message: "Immediately clear all detected protocol anomalies and reset detector tracking state, not just this observation. Historical alert events and configuration remain unchanged. New traffic can create more anomalies. This cannot be undone and does not require a commit.",
                  confirmLabel: "Clear anomalies",
                  variant: "danger",
                  onConfirm: async () => {
                    setClearing(true);
                    setError("");
                    setNotice("");
                    const result = await api.clearAnomalies();
                    if (result.ok) {
                      setNotice("Anomalies cleared immediately. Historical alert events remain. New traffic can create more anomalies.");
                    } else {
                      setError(result.error);
                    }
                    setClearing(false);
                  },
                })}
              >
                {clearing ? "Clearing anomalies…" : "Clear anomalies (immediate)"}
              </button>
            )}
            {error && <p role="alert" className="mt-3 text-xs text-(--red)">{error}</p>}
            {notice && <p role="status" className="mt-3 text-xs">{notice}</p>}
          </DetailSection>
        )}
      </div>
    </div>
  );
}
