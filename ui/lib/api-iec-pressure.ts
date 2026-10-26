import { getJSON } from "./api-request";

export type IEC104Pressure = {
  heldPackets: number;
  heldBytes: number;
  oldestPendingSeconds: number;
  activeSessions: number;
  trackedSessions: number;
  limits: {
    heldPackets: number;
    heldPacketsPerSession: number;
    heldBytesPerSession: number;
    pendingSeconds: number;
    sessions: number;
    resetWorkerJobs: number;
  };
  aborts: Record<string, number>;
  resetWorkerRejections: number;
  verdictFailures: number;
  injectorFailures: number;
};

export function fetchIEC104Pressure(signal?: AbortSignal) {
  return getJSON<IEC104Pressure>("/api/v1/diagnostics/iec104", signal);
}
