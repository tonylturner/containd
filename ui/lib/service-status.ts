import { isRecord } from "./api-request";
import { serviceNames, type ServiceFault, type ServicesStatus } from "./api-service-status";

function isFault(value: unknown): value is ServiceFault {
  return isRecord(value) &&
    serviceNames.some((name) => value.service === name) &&
    (value.kind === "config" || value.kind === "runtime") &&
    typeof value.message === "string";
}

/**
 * Fault metadata is authoritative, not error-message wording. Reject malformed
 * responses rather than turning a broken fault list into a healthy empty one.
 */
export function parseServicesStatus(value: unknown): ServicesStatus | null {
  if (!isRecord(value) || !Array.isArray(value.faults) || !value.faults.every(isFault) ||
      !isRecord(value.av) || typeof value.av.available !== "boolean") return null;
  if (value.av.available
    ? typeof value.av.rate_per_min !== "number" || !Array.isArray(value.av.sparkline)
    : typeof value.av.error !== "string") return null;
  if (new Set(value.faults.map((fault) => fault.service)).size !== value.faults.length) return null;
  for (const name of [...serviceNames, "vpn", "envoy", "nginx"]) {
    const entry = value[name];
    if (entry === undefined) continue;
    if (!isRecord(entry)) return null;
    if (entry.state !== undefined && entry.state !== "faulted") return null;
    if (entry.state === "faulted" && !isFault(entry.fault)) return null;
    if (entry.fault !== undefined && (!isFault(entry.fault) || entry.state !== "faulted")) return null;
    if (entry.state === "faulted" && name !== "vpn" &&
        !value.faults.some((fault) => fault.service === name &&
          fault.kind === (entry.fault as ServiceFault).kind &&
          fault.message === (entry.fault as ServiceFault).message)) return null;
    for (const key of ["sparkline", "errors_sparkline"]) {
      const series = entry[key];
      if (series !== undefined &&
          (!Array.isArray(series) || !series.every((n: unknown) => typeof n === "number" && Number.isFinite(n)))) return null;
    }
    for (const key of ["rate_per_min", "errors_rate_per_min", "count", "errors_count"]) {
      if (entry[key] !== undefined && typeof entry[key] !== "number") return null;
    }
  }
  // Each fault must have its corresponding independent service entry.
  for (const fault of value.faults) {
    const entry = value[fault.service];
    if (!isRecord(entry) || entry.state !== "faulted" || !isFault(entry.fault) ||
        entry.fault.service !== fault.service || entry.fault.kind !== fault.kind ||
        entry.fault.message !== fault.message) return null;
  }
  const gate = value.av.gate;
  if (gate !== undefined && (!isRecord(gate) ||
      !["off", "refuse", "pass", "pending", "open"].includes(String(gate.state)) ||
      typeof gate.enabled !== "boolean" || typeof gate.fail_policy !== "string" ||
      typeof gate.admit !== "string" || typeof gate.connections !== "number" ||
      !isRecord(gate.scanner) || typeof gate.scanner.ready !== "boolean" ||
      !Array.isArray(gate.listeners) || !gate.listeners.every((listener: unknown) =>
        isRecord(listener) && typeof listener.address === "string" &&
        typeof listener.up === "boolean" && typeof listener.masquerade === "boolean"))) return null;
  return value as ServicesStatus;
}
