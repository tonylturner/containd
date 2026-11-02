"use client";

import { useId, useState } from "react";
import { pointRate, responsePoints, type SeriesQuery, type TelemetryRange } from "../lib/api-telemetry";
import { useTelemetry, type TelemetryRead } from "../hooks/useTelemetry";
import { Sparkline } from "./Sparkline";

export function DemoBadge({ origin }: { origin?: string }) {
  return origin === "demo" ? <span className="ml-1 rounded-xs border border-amber-400/40 px-1 text-[10px] text-amber">Demo</span> : null;
}

function TelemetryMessage({ text, reasons }: { text: string; reasons?: string[] }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  return <span role="status" title={reasons?.join("\n") ?? text} className="inline-block max-w-full align-bottom text-xs text-amber">
    <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}
      className="flex w-full min-w-0 items-center text-left focus-visible:outline-2 focus-visible:outline-(--amber)">
      <span className="truncate">{reasons?.[0] ?? text}</span>
      {reasons && reasons.length > 1 && <span className="shrink-0 whitespace-pre"> (+{reasons.length - 1} more)</span>}
    </button>
    {open && <span id={id} data-telemetry-details className="mt-1 block space-y-1 whitespace-normal wrap-anywhere">
      {(reasons ?? [text]).map((reason, index) => <span key={index} className="block">{reason}</span>)}
    </span>}
  </span>;
}

export function TelemetryNotice({ read, hideFault = false }: { read: TelemetryRead | null; hideFault?: boolean }) {
  if (!read) return <span className="text-xs text-(--text-muted)">Loading telemetry…</span>;
  const fault = read.error ?? read.unavailable;
  return <>{fault && !hideFault && <TelemetryMessage text={fault} reasons={read.noticeReasons} />}
    {read.noCurrentData && <span role="status" className="text-xs text-(--text-muted)">No current data</span>}
    {read.demo && <span className="rounded-xs border border-amber-400/40 px-1 text-[10px] text-amber">Demo data</span>}
    {read.data.some(r => r.collector.droppedSeries > BigInt(0)) && <span className="ml-1 text-xs text-amber">Series limit reached — coverage incomplete</span>}</>;
}

export function TelemetryLegend() {
  return <p data-telemetry-legend className="text-[10px] text-(--text-muted)">Gaps: breaks · Partial: dashed · ◆ Counter reset · Zero: baseline tick</p>;
}

export function TelemetryChart({ queries, title, ranges = false, perMinute = false, compact = false, showTrend = false, color, range: selectedRange, onRangeChange }: {
  queries: SeriesQuery[]; title: string; ranges?: boolean; perMinute?: boolean; compact?: boolean; color?: string;
  range?: TelemetryRange; onRangeChange?: (range: TelemetryRange) => void; showTrend?: boolean;
}) {
  const [localRange, setLocalRange] = useState<TelemetryRange>("1h");
  const range = selectedRange ?? localRange;
  const setRange = onRangeChange ?? setLocalRange;
  const read = useTelemetry(queries, range);
  return <div className="min-w-0 space-y-1">
    {ranges && <label className="flex flex-wrap items-center gap-2 text-xs text-(--text-muted)">Range
      <select aria-label={`${title} range`} value={range} onChange={e => setRange(e.target.value as TelemetryRange)} className="rounded-xs border bg-(--surface) px-2 py-1">
        <option value="1h">1 hour</option><option value="24h">24 hours</option><option value="30d">30 days</option>
      </select></label>}
    <TelemetryHistory {...{ read, title, perMinute, compact, showTrend, color }} />
  </div>;
}

/** Render a snapshot supplied by a panel that coordinates several chart notices. */
export function TelemetryHistory({ read, title, perMinute = false, compact = false, showTrend = false, color, hideFault = false }: {
  read: TelemetryRead | null; title: string; perMinute?: boolean; compact?: boolean;
  showTrend?: boolean; color?: string; hideFault?: boolean;
}) {
  const points = read ? responsePoints(read.data) : [];
  const covered = points.some(p => p.v !== undefined);
  const rate = read?.unavailable || read?.noCurrentData ? null : pointRate(points.at(-1), perMinute);
  const firstCovered = points.findIndex(p => p.v !== undefined);
  const continuous = firstCovered >= 0 ? points.slice(firstCovered) : [];
  const first = continuous.every(p => p.q === "observed") ? continuous[0] : undefined, last = points.at(-1);
  const trend = first?.q === "observed" && last?.q === "observed" ? pointRate(last, perMinute)! - pointRate(first, perMinute)! : null;
  return <div className="min-w-0 space-y-1" data-telemetry={title}>
    <TelemetryNotice read={read} hideFault={hideFault} />
    {read && !read.error && (covered ? <>
      <Sparkline points={points} title={title} perMinute={perMinute} color={color} className={compact ? "h-5" : "h-14"} />
      {!compact && <p className="text-xs text-(--text-muted)">Rate: {rate === null ? "Unknown" : rate.toFixed(1)} /{perMinute ? "min" : "s"}
        {showTrend && trend !== null && continuous.length > 1 && <span className="ml-2">Trend: {trend > 0 ? "▲" : trend < 0 ? "▼" : "•"} {Number(trend.toFixed(2))}</span>}
      </p>}
      {!read.unavailable && !read.noCurrentData && last?.v !== undefined && rate === null && <p className="wrap-anywhere text-xs text-amber">Count: {last.v.toLocaleString()} · Partial bucket — rate unavailable</p>}
    </> : <p className="text-xs text-(--text-muted)">{read.data.some(r => r.realCovered || r.realActive) ? "No observed coverage in this range" : "No traffic recorded yet"}</p>)}
  </div>;
}

export function TelemetryRate({ queries, perMinute = true, range = "1h" }: { queries: SeriesQuery[]; perMinute?: boolean; range?: TelemetryRange }) {
  const read = useTelemetry(queries, range);
  const points = read ? responsePoints(read.data) : [];
  const last = points.at(-1);
  const notice = read?.error ?? read?.unavailable;
  const rate = notice || read?.noCurrentData ? null : pointRate(last, perMinute);
  return <span className="wrap-anywhere">
    {rate === null ? "Unknown" : rate.toFixed(1)} /{perMinute ? "min" : "s"}
    {read?.demo && <span className="ml-1 text-amber">Demo data</span>}
    {last && last.q !== "observed" && rate !== null && <span className="ml-1 text-amber">({last.q === "reset" ? "counter reset" : "partial"})</span>}
    {!notice && !read?.noCurrentData && last?.v !== undefined && rate === null && <span className="ml-1 text-amber">(Partial bucket · Count: {last.v.toLocaleString()}; rate unavailable)</span>}
    {read?.noCurrentData && <span className="ml-1 text-(--text-muted)">No current data</span>}
    {notice && <span className="ml-1"><TelemetryMessage text={notice} reasons={read?.noticeReasons} /></span>}
  </span>;
}

export function ServiceHistory({ service, title, ranges = true, showTrend = false, legend = true }: {
  service: string; title: string; ranges?: boolean; showTrend?: boolean; legend?: boolean;
}) {
  const [range, setRange] = useState<TelemetryRange>("1h");
  return <div className="min-w-0 space-y-2">
    <TelemetryChart queries={[{ metric: service === "av" ? "av.scans" : "service.events", ...(service === "av" ? {} : { service }) }]} title={title} ranges={ranges} perMinute range={range} onRangeChange={setRange} showTrend={showTrend} />
    <p className="text-xs text-(--text-muted)">Errors: <TelemetryRate range={range} queries={[{ metric: service === "av" ? "av.scan_errors" : "service.errors", ...(service === "av" ? {} : { service }) }]} /></p>
    {service === "av" && <TelemetryChart queries={[{ metric: "av.detections" }]} title="Detections per minute" range={range} perMinute />}
    {legend && <TelemetryLegend />}
  </div>;
}
