import { getJSON, postJSON, postJSONResult, parseErrorBody } from "./api-request";
import { authHeaders, clearAuthExpired, fetchWithSession, handleUnauthorized } from "./api-core";

import type {
  ApiResult,
  CLIExecuteResponse,
  ConntrackEntry,
  FlowSummary,
  TelemetryEvent,
} from "./api";

export type EventQuery = {
  session?: string; flow?: string; kind?: string; protocol?: string;
  decision?: string; verdict?: string; since?: string; cursor?: string;
  apdu?: string; category?: string; detections?: string;
};
export type EventPage = {
  events: TelemetryEvent[]; nextCursor?: string;
  historyTruncated: boolean; engineError?: string;
};

export type ManagementReservation = {
  active: boolean;
  device?: string;
  local?: string;
  sources?: string[];
  port?: number;
  guard?: { active: boolean; error?: string; faults: number; lastFault?: { reason: string } };
  rollbackFault?: string;
  bootFault?: string;
  recovery?: string;
  listenerFaults?: string[] | null;
};

export type ConntrackKillRequest = {
  proto: string; src: string; dst: string; sport: number; dport: number;
  scope: "connection" | "client-service"; durationSecs: number;
};
export type ConntrackKillResult = {
  scope: "connection" | "client-service";
  matched: number; deleted: number; conntrackDeleted: boolean; deleteError?: string;
  revocationInstalled: boolean; revocationError?: string; blockedUntil?: string;
  closure: string;
};

async function listConntrack(limit: number): Promise<ApiResult<ConntrackEntry[]>> {
  try {
    const res = await fetchWithSession(`/api/v1/conntrack?limit=${limit}`, { cache: "no-store", headers: authHeaders() });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return { ok: true, data: await res.json() as ConntrackEntry[] };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Network error" };
  }
}

export const consoleAPI = {
  getManagementReservation: () => getJSON<ManagementReservation>("/api/v1/system/management-reservation"),
  listCLICommands: () => getJSON<string[]>("/api/v1/cli/commands"),
  executeCLI: (line: string) =>
    postJSON<CLIExecuteResponse>("/api/v1/cli/execute", { line }),
  completeCLI: (line: string) =>
    getJSON<string[]>(`/api/v1/cli/complete?line=${encodeURIComponent(line)}`),

  listEvents: (limit = 500, signal?: AbortSignal) =>
    getJSON<TelemetryEvent[]>(`/api/v1/events?limit=${limit}`, signal),
  queryEvents: (query: EventQuery, signal?: AbortSignal) => {
    const params = new URLSearchParams({ query: "1", limit: "500" });
    for (const [key, value] of Object.entries(query)) if (value) params.set(key, value);
    return getJSON<EventPage>(`/api/v1/events?${params}`, signal);
  },
  listFlows: (limit = 200, signal?: AbortSignal) =>
    getJSON<FlowSummary[]>(`/api/v1/flows?limit=${limit}`, signal),
  getEvent: (id: number) => getJSON<TelemetryEvent>(`/api/v1/events/${id}`),

  getSimulationStatus: (signal?: AbortSignal) =>
    getJSON<{ running: boolean }>("/api/v1/simulation", signal),
  startSimulation: () =>
    postJSON<{ running: boolean }>("/api/v1/simulation", { action: "start" }),
  stopSimulation: () =>
    postJSON<{ running: boolean }>("/api/v1/simulation", { action: "stop" }),

  listConntrack: (limit = 200) => listConntrack(limit),
  killConntrack: (req: ConntrackKillRequest) =>
    postJSONResult<ConntrackKillResult>("/api/v1/conntrack/kill", req),
};
