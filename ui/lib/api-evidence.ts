import { getJSONShaped } from "./api-request";

export type EvidenceState = "ok" | "degraded" | "recovered" | "unknown";
export function evidenceState(value: unknown): EvidenceState {
  return value === "ok" || value === "degraded" || value === "recovered" ? value : "unknown";
}

/** Local persistence, independent of collector delivery. Counters are since process start. */
export type AuditPersistenceStatus = {
  state: EvidenceState;
  failures: number;
  lastFailureAt?: string;
  lastError?: string;
  lastSuccessAt?: string;
};

export type EvidenceStatus = {
  audit: AuditPersistenceStatus;
  forwarding: {
    destination: string;
    source: "engine" | "services" | "audit";
    state: EvidenceState;
    sentThrough?: string;
    backlog: number;
    lost: number;
    lastError?: string;
    lastSuccessAt?: string;
  }[];
};

export async function getEvidenceStatus(signal?: AbortSignal): Promise<EvidenceStatus | null> {
  const report = await getJSONShaped<EvidenceStatus>("/api/v1/evidence/status", {
    objects: ["audit"], lists: ["forwarding"],
  }, signal);
  if (!report) return null;
  return {
    ...report,
    audit: { ...report.audit, state: evidenceState(report.audit.state) },
    forwarding: report.forwarding.map((row) => ({ ...row, state: evidenceState(row?.state) })),
  };
}
