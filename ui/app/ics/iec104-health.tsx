"use client";

import { StatusIndicator } from "../../components/StatusBadge";
import type { IEC104EnforcementHealth } from "../../lib/api";

type Indicator = {
  status: "healthy" | "degraded" | "unknown";
  label: string;
  sublabel?: string;
};

/**
 * Maps IEC104 enforcement health to the indicator. Unhealthy is amber with
 * its reason. Without an IEC 104 enforce envelope the object is unhealthy
 * only when the engine failed to reset an ICS connection of another
 * protocol, such as Modbus or DNP3, that it picked up mid-stream.
 */
export function iec104HealthIndicator(
  health: IEC104EnforcementHealth | undefined,
): Indicator {
  if (!health) {
    return { status: "unknown", label: "IEC 104 enforcement", sublabel: "status unavailable" };
  }
  if (!health.healthy) {
    return {
      status: "degraded",
      label: health.active ? "IEC 104 enforcement unhealthy" : "ICS connection reset unhealthy",
      sublabel: health.reason || "no reason reported",
    };
  }
  if (health.active) {
    return { status: "healthy", label: "IEC 104 enforcement active" };
  }
  return { status: "unknown", label: "IEC 104 enforcement inactive", sublabel: "no enforce envelope loaded" };
}

export function IEC104HealthIndicator({ health }: { health: IEC104EnforcementHealth | undefined }) {
  const view = iec104HealthIndicator(health);
  return <StatusIndicator status={view.status} label={view.label} sublabel={view.sublabel} />;
}
