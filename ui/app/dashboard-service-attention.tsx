"use client";

import Link from "next/link";
import { useTelemetry } from "../hooks/useTelemetry";
import { pointRate, responsePoints } from "../lib/api-telemetry";
import type { ServiceInfo } from "./dashboard-panels";

export function ServiceTelemetryAttention({ service }: { service: ServiceInfo }) {
  const read = useTelemetry([{ metric: "service.errors", service: service.name.toLowerCase() }]);
  const rate = read && !read.error ? pointRate(responsePoints(read.data).at(-1), true) : null;
  if (!rate || read?.demo) return null;
  return <p role="status" className="mb-3 text-sm text-amber">{service.name}: {service.detail} · {rate.toFixed(1)} err/min — <Link className="underline" href={service.href}>Check service</Link></p>;
}
