"use client";

import { useEffect, useState } from "react";

import { StatusIndicator } from "../../components/StatusBadge";
import { fetchHealth, type IEC104EnforcementHealth } from "../../lib/api";

type Indicator = {
  status: "healthy" | "degraded" | "unknown";
  label: string;
  sublabel?: string;
};

/** Maps IEC104 enforcement health to the indicator. Unhealthy is amber with its reason. */
export function iec104HealthIndicator(
  health: IEC104EnforcementHealth | undefined,
): Indicator {
  if (!health) {
    return { status: "unknown", label: "IEC 104 enforcement", sublabel: "status unavailable" };
  }
  if (!health.healthy) {
    return {
      status: "degraded",
      label: "IEC 104 enforcement unhealthy",
      sublabel: health.reason || "no reason reported",
    };
  }
  if (health.active) {
    return { status: "healthy", label: "IEC 104 enforcement active" };
  }
  return { status: "unknown", label: "IEC 104 enforcement inactive", sublabel: "no enforce envelope loaded" };
}

/** Polls GET /api/v1/health and shows the runtime IEC 104 enforcement state. */
export function IEC104HealthStatus() {
  const [health, setHealth] = useState<IEC104EnforcementHealth | undefined>();

  useEffect(() => {
    const controller = new AbortController();
    async function refresh() {
      try {
        const res = await fetchHealth(controller.signal);
        setHealth(res?.iec104Enforcement);
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setHealth(undefined);
      }
    }
    refresh();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, 10000);
    return () => {
      controller.abort();
      clearInterval(id);
    };
  }, []);

  const view = iec104HealthIndicator(health);
  return <StatusIndicator status={view.status} label={view.label} sublabel={view.sublabel} />;
}
