import { getJSONResult, isRecord } from "./api-request";

export const metricUnits = {
  "iface.rx_bytes": "bytes", "iface.tx_bytes": "bytes", "iface.rx_packets": "packets", "iface.tx_packets": "packets",
  "conduit.bytes": "bytes", "conduit.packets": "packets", "proto.packets": "packets", "proto.bytes": "bytes",
  "events.total": "events", "events.class": "events", "service.events": "events", "service.errors": "events",
  "av.scans": "scans", "av.scan_errors": "scans", "av.detections": "events",
} as const;
export type Metric = keyof typeof metricUnits;
export type TelemetryRange = "1h" | "24h" | "30d";
export type Origin = "real" | "demo";
export type Quality = "observed" | "partial" | "reset" | "gap";
export type Point = { t: string; q: Quality; v?: bigint; d?: number };
export type Series = { dims: Record<string, string>; points: Point[] };
export type SourceUnavailable = { source: string; metric?: Metric; dims?: Record<string, string>; reason: string };
export type SeriesResponse = {
  metric: Metric; unit: string; origin: Origin; range: TelemetryRange;
  resolutionSeconds: number; from: string; to: string; retainedFrom?: string;
  realCovered: boolean; realActive: boolean;
  collector: { state: "running" | "stalled" | "unavailable"; lastSampleAt?: string; error?: string; droppedSeries: bigint; unavailable?: SourceUnavailable[] };
  series: Series[];
};
export type SeriesQuery = { metric: Metric; group?: string } & Record<string, string>;
const resolution = { "1h": 10, "24h": 60, "30d": 900 };
const uint64Max = BigInt("18446744073709551615");

/** Exact wire counters. Reject numeric JSON, signs, fractions and overflow. */
export function decimalCounter(value: unknown): bigint {
  if (typeof value !== "string" || value.length > 20 || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("Invalid decimal counter");
  const n = BigInt(value);
  if (n > uint64Max) throw new Error("Counter overflow");
  return n;
}
function timestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

/** The sole parser of public history; a malformed read is unavailable, not zero. */
export function parseSeries(value: unknown): SeriesResponse {
  if (!isRecord(value) || typeof value.metric !== "string" || !(value.metric in metricUnits) ||
      value.unit !== metricUnits[value.metric as Metric] || !["real", "demo"].includes(String(value.origin)) ||
      !["1h", "24h", "30d"].includes(String(value.range)) ||
      value.resolutionSeconds !== resolution[value.range as TelemetryRange] ||
      !timestamp(value.from) || !timestamp(value.to) || Date.parse(value.from) > Date.parse(value.to) ||
      typeof value.realCovered !== "boolean" || typeof value.realActive !== "boolean" ||
      !isRecord(value.collector) || !["running", "stalled", "unavailable"].includes(String(value.collector.state)) ||
      !Array.isArray(value.series)) throw new Error("Malformed telemetry response");
  const width = value.resolutionSeconds as number;
  const from = Date.parse(value.from), to = Date.parse(value.to);
  const collector = value.collector;
  if ((value.retainedFrom !== undefined && !timestamp(value.retainedFrom)) ||
      (collector.lastSampleAt !== undefined && !timestamp(collector.lastSampleAt)) ||
      (collector.error !== undefined && typeof collector.error !== "string")) throw new Error("Malformed collector metadata");
  if (collector.unavailable !== undefined && (!Array.isArray(collector.unavailable) || collector.unavailable.some(entry =>
    !isRecord(entry) || typeof entry.source !== "string" || typeof entry.reason !== "string" ||
    (entry.metric !== undefined && (typeof entry.metric !== "string" || !Object.hasOwn(metricUnits, entry.metric))) ||
    (entry.dims !== undefined && (!isRecord(entry.dims) || !Object.values(entry.dims).every(v => typeof v === "string")))
  ))) throw new Error("Malformed collector unavailable metadata");
  const series = value.series.map((entry): Series => {
    if (!isRecord(entry) || !Array.isArray(entry.points) ||
        (entry.dims !== undefined && (!isRecord(entry.dims) || !Object.values(entry.dims).every(v => typeof v === "string")))) {
      throw new Error("Malformed telemetry series");
    }
    if (entry.points.length !== (to - from) / (width * 1000)) throw new Error("Incomplete telemetry buckets");
    const points = entry.points.map((p, i): Point => {
      if (!isRecord(p) || !timestamp(p.t) || Date.parse(p.t) !== from + i * width * 1000 ||
          !["observed", "partial", "reset", "gap"].includes(String(p.q))) throw new Error("Malformed telemetry point");
      if (p.q === "gap") {
        if (p.v !== undefined || p.d !== undefined) throw new Error("Gap contains a value");
        return { t: p.t, q: "gap" };
      }
      if (p.d === undefined ? p.q !== "partial" : typeof p.d !== "number" || !Number.isSafeInteger(p.d) || p.d <= 0 ||
          (p.q === "observed" && p.d !== width)) throw new Error("Invalid observation duration");
      return { t: p.t, q: p.q as Quality, v: decimalCounter(p.v), ...(p.d === undefined ? {} : { d: p.d as number }) };
    });
    return { dims: (entry.dims ?? {}) as Record<string, string>, points };
  });
  return { ...value, series, collector: { ...collector, droppedSeries: decimalCounter(collector.droppedSeries) } } as SeriesResponse;
}

export async function getTelemetrySeries(query: SeriesQuery, range: TelemetryRange, origin: Origin): Promise<SeriesResponse> {
  const params = new URLSearchParams({ ...query, range, origin });
  const response = await getJSONResult(`/api/v1/telemetry/series?${params}`);
  if (!response.ok) throw new Error(response.error);
  const data = parseSeries(response.data);
  if (data.metric !== query.metric || data.range !== range || data.origin !== origin) throw new Error("Mismatched telemetry response");
  return data;
}

/** Aggregate matching buckets conservatively; gaps never become quiet values. */
export function sumPoints(series: Series[]): Point[] {
  if (!series.length) return [];
  return series[0].points.map((first, i) => {
    const members = series.map(s => s.points[i]);
    if (members.some(p => !p || p.t !== first.t)) throw new Error("Unaligned telemetry buckets");
    const covered = members.filter(p => p.v !== undefined);
    if (!covered.length) return { t: first.t, q: "gap" };
    const v = covered.reduce((n, p) => n + p.v!, BigInt(0));
    if (v > uint64Max) throw new Error("Telemetry sum overflow");
    const d = covered[0].d;
    const commonDuration = d !== undefined && covered.every(p => p.d === d);
    const q = !commonDuration || covered.length !== members.length ? "partial" : members.some(p => p.q === "reset") ? "reset"
      : members.some(p => p.q === "partial") ? "partial" : "observed";
    return { t: first.t, v, ...(commonDuration ? { d } : {}), q };
  });
}

/** A missing metric in a combined view is missing coverage, not an additive zero. */
export function responsePoints(responses: SeriesResponse[]): Point[] {
  const template = responses.flatMap(r => r.series)[0];
  if (!template) return [];
  return sumPoints(responses.flatMap(r => r.series.length ? r.series : [{
    dims: {}, points: template.points.map(p => ({ t: p.t, q: "gap" as const })),
  }]));
}

/** Chart coordinates/rates are approximate floats; retained counts remain BigInt. */
export function pointRate(p: Point | undefined, perMinute = false): number | null {
  return p?.v === undefined || !p.d ? null : Number(p.v) / p.d * (perMinute ? 60 : 1);
}
