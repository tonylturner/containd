import type { SimulationStatus } from "../../lib/api-console";

export function simulationStatus(patch: Partial<SimulationStatus> = {}): SimulationStatus {
  return { preference: "off", running: false, loops: 0, captureSet: "", capture: "", error: "", reason: "", ...patch };
}
