import { getJSON, postJSON } from "./api-request";

import type {
  CLIExecuteResponse,
  ConntrackEntry,
  FlowSummary,
  TelemetryEvent,
} from "./api";

export const consoleAPI = {
  listCLICommands: () => getJSON<string[]>("/api/v1/cli/commands"),
  executeCLI: (line: string) =>
    postJSON<CLIExecuteResponse>("/api/v1/cli/execute", { line }),
  completeCLI: (line: string) =>
    getJSON<string[]>(`/api/v1/cli/complete?line=${encodeURIComponent(line)}`),

  listEvents: (limit = 500, signal?: AbortSignal) =>
    getJSON<TelemetryEvent[]>(`/api/v1/events?limit=${limit}`, signal),
  listFlows: (limit = 200, signal?: AbortSignal) =>
    getJSON<FlowSummary[]>(`/api/v1/flows?limit=${limit}`, signal),
  getEvent: (id: number) => getJSON<TelemetryEvent>(`/api/v1/events/${id}`),

  getSimulationStatus: (signal?: AbortSignal) =>
    getJSON<{ running: boolean }>("/api/v1/simulation", signal),
  startSimulation: () =>
    postJSON<{ running: boolean }>("/api/v1/simulation", { action: "start" }),
  stopSimulation: () =>
    postJSON<{ running: boolean }>("/api/v1/simulation", { action: "stop" }),

  listConntrack: (limit = 200) =>
    getJSON<ConntrackEntry[]>(`/api/v1/conntrack?limit=${limit}`),
  killConntrack: (req: {
    proto: string;
    src: string;
    dst: string;
    sport?: number;
    dport?: number;
  }) => postJSON<{ status: string }>("/api/v1/conntrack/kill", req),
};
