import type { SimulationStatus } from "./api-console";

/** Keep delivery faults visible even when the desired preference was saved. */
export function simulationDescription(status: SimulationStatus): string {
  if (status.error) return `Demo replay: ${status.error}${status.reason && status.reason !== status.error ? ` · ${status.reason}` : ""} · Preference: ${status.preference}`;
  if (status.reason) return `${status.preference === "auto" && !status.running ? "Demo auto stopped" : "Demo replay"}: ${status.reason}`;
  if (status.running) return `Replaying ${status.capture || status.captureSet || "recorded captures"} · ${status.loops} loops completed · Stop persists across restarts`;
  if (status.preference === "off") return "Demo replay stopped · Stop persists across restarts";
  return `Demo replay not running · Preference: ${status.preference}`;
}
