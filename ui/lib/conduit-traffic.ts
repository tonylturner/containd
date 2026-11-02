import type { Conduit } from "./api";
import { decimalCounter } from "./api-telemetry";
import { isRecord } from "./api-request";

export function validConduitTraffic(value: unknown): value is Conduit["traffic"] {
  if (!isRecord(value)) return false;
  if (value.state === "unavailable") return typeof value.reason === "string";
  if (value.state !== "measured" || value.windowSeconds !== 3600 || value.coverage !== "routed" || typeof value.complete !== "boolean") return false;
  try { decimalCounter(value.bytes); decimalCounter(value.packets); return true; } catch { return false; }
}

export function trafficDescription(traffic: Conduit["traffic"]): string {
  return traffic.state === "unavailable" ? `Unavailable: ${traffic.reason}`
    : `${decimalCounter(traffic.bytes).toLocaleString()} bytes · ${decimalCounter(traffic.packets).toLocaleString()} packets${traffic.complete ? "" : " · Partial coverage"}`;
}
