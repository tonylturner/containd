import type { Route } from "@playwright/test";
import { metricUnits, type Metric, type Origin, type Quality, type TelemetryRange } from "../../lib/api-telemetry";

// JSON exactly as emitted by telemetry.SeriesResponse, not client-decoded BigInts.
export type WirePoint = { t: string; q: Quality; v?: string; d?: number };
export type WireResponse = {
  metric: Metric; unit: string; origin: Origin; range: TelemetryRange; resolutionSeconds: number;
  from: string; to: string; retainedFrom?: string; realCovered: boolean; realActive: boolean;
  collector: { state: "running" | "stalled" | "unavailable"; droppedSeries: string; error?: string; lastSampleAt?: string };
  series: { dims?: Record<string, string>; points: WirePoint[] }[];
};
export function seriesResponse(url: URL, values: (number | null)[] = [0, 0, 0]): WireResponse {
  const metric = url.searchParams.get("metric") as Metric;
  const range = url.searchParams.get("range") as TelemetryRange;
  const origin = url.searchParams.get("origin") as Origin;
  const width = { "1h": 10, "24h": 60, "30d": 900 }[range];
  const seconds = { "1h": 3600, "24h": 86400, "30d": 30 * 86400 }[range];
  const to = Math.floor(Date.now() / (width * 1000)) * width * 1000;
  const from = to - seconds * 1000;
  const dims = Object.fromEntries([...url.searchParams].filter(([key]) => !["metric", "range", "origin", "group"].includes(key)));
  if (url.searchParams.get("group") === "protocol") dims.protocol = "modbus";
  const points: WirePoint[] = Array.from({ length: seconds / width }, (_, i) => {
    const v = values[i - (seconds / width - values.length)];
    const t = new Date(from + i * width * 1000).toISOString();
    return v === undefined || v === null ? { t, q: "gap" } : { t, q: "observed", v: String(v), d: width };
  });
  return {
    metric, unit: metricUnits[metric], origin, range, resolutionSeconds: width,
    from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    realCovered: values.some(v => v !== null), realActive: values.length > 0,
    collector: { state: "running", lastSampleAt: new Date(to).toISOString(), droppedSeries: "0" },
    series: values.length ? [{ dims, points }] : [],
  };
}
export async function fulfillSeries(route: Route, values?: (number | null)[]) {
  await route.fulfill({ json: seriesResponse(new URL(route.request().url()), values) });
}
