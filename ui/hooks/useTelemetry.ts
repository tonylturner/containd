"use client";

import { useEffect, useState } from "react";
import { getTelemetrySeries, responsePoints, type SeriesQuery, type SeriesResponse, type TelemetryRange } from "../lib/api-telemetry";

export type TelemetryRead = { data: SeriesResponse[]; demo: boolean; error?: string; unavailable?: string; noticeReasons?: string[]; noCurrentData?: boolean };
// Coalesce simultaneous readers, without preserving a failed or stale snapshot.
const pending = new Map<string, Promise<TelemetryRead>>();
function unavailableNotice(responses: SeriesResponse[]): Pick<TelemetryRead, "error" | "unavailable" | "noticeReasons"> {
  const reasons = [...new Set(responses.flatMap(r => r.collector.unavailable?.map(entry => entry.reason) ?? []))];
  const stopped = responses.find(r => r.collector.state !== "running");
  const lead = stopped
    ? `Collector ${stopped.collector.state}${stopped.collector.error ? `: ${stopped.collector.error}` : ""}`
    : reasons.length ? `Telemetry unavailable: ${reasons.shift()}` : undefined;
  const summary = lead ? `${lead}${reasons.length ? ` (+${reasons.length} more)` : ""}` : undefined;
  return {
    ...(stopped ? { error: summary } : { unavailable: summary }),
    noticeReasons: lead ? [lead, ...reasons] : undefined,
  };
}
export async function readTelemetry(queries: SeriesQuery[], range: TelemetryRange): Promise<TelemetryRead> {
  const real = await Promise.all(queries.map(q => getTelemetrySeries(q, range, "real")));
  const notice = unavailableNotice(real);
  // Retained real history is still useful, but current failures always outrank demo.
  if (notice.error || notice.unavailable) return { data: real, demo: false, ...notice };
  const quiet = real.every(r => !r.realActive);
  if (responsePoints(real).at(-1)?.q === "gap" ||
      (quiet && real.some(r => r.series.some(s => (s.points.at(-1)?.q ?? "gap") === "gap")))) {
    return { data: real, demo: false, noCurrentData: true };
  }
  if (quiet) {
    const demo = await Promise.all(queries.map(q => getTelemetrySeries(q, range, "demo")));
    const demoNotice = unavailableNotice(demo);
    if (demoNotice.error || demoNotice.unavailable) return { data: real, demo: false, ...demoNotice };
    if (responsePoints(demo).at(-1)?.v !== undefined) return { data: demo, demo: true };
  }
  return { data: real, demo: false };
}
export function useTelemetry(queries: SeriesQuery[], range: TelemetryRange = "1h") {
  const key = JSON.stringify([queries, range]);
  const [snapshot, setSnapshot] = useState<{ key: string; read: TelemetryRead }>();
  useEffect(() => {
    let active = true;
    let generation = 0;
    const [qs, window] = JSON.parse(key) as [SeriesQuery[], TelemetryRange];
    const load = async () => {
      const request = ++generation;
      try {
        let promise = pending.get(key);
        if (!promise) {
          promise = readTelemetry(qs, window).finally(() => pending.delete(key));
          pending.set(key, promise);
        }
        const result = await promise;
        // Validate multi-metric alignment/overflow before any renderer sees it.
        responsePoints(result.data);
        if (active && request === generation) setSnapshot({ key, read: result });
      } catch (e) {
        if (active && request === generation) setSnapshot({ key, read: { data: [], demo: false, error: `Telemetry unavailable: ${e instanceof Error ? e.message : "read failed"}` } });
      }
    };
    void load();
    const timer = setInterval(() => { if (!document.hidden) void load(); }, 10_000);
    const visible = () => { if (!document.hidden) void load(); };
    document.addEventListener("visibilitychange", visible);
    return () => { active = false; clearInterval(timer); document.removeEventListener("visibilitychange", visible); };
  }, [key]);
  return snapshot?.key === key ? snapshot.read : null;
}
