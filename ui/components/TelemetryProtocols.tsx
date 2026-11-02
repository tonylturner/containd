"use client";

import { useTelemetry } from "../hooks/useTelemetry";
import { TelemetryNotice } from "./TelemetryChart";

export function TelemetryProtocols() {
  const read = useTelemetry([{ metric: "proto.packets", group: "protocol" }]);
  const rows = (read?.data.flatMap(r => r.series) ?? []).filter(s => s.points.some(p => p.v !== undefined)).map(s => ({
    protocol: s.dims.protocol || "unknown",
    count: s.points.reduce((n, p) => n + (p.v ?? BigInt(0)), BigInt(0)),
    complete: s.points.every(p => p.q === "observed"),
    reset: s.points.some(p => p.q === "reset"),
  })).sort((a, b) => a.count === b.count ? 0 : a.count > b.count ? -1 : 1).slice(0, 5);
  const max = rows.reduce((m, r) => r.count > m ? r.count : m, BigInt(1));
  return <div className="space-y-2 text-xs">
    <p className="text-(--text-muted)">Packets · last hour</p>
    <TelemetryNotice read={read} />
    {read && !read.error && (!rows.length ? <p>{read.data.some(r => r.realCovered || r.realActive) ? "No observed coverage in this range" : "No traffic recorded yet"}</p> : rows.map(row => <div key={row.protocol}>
      <div className="flex justify-between gap-2"><span className="uppercase">{row.protocol}</span><span>{row.count.toLocaleString()}{!row.complete && " · Partial coverage"}{row.reset && " · ◆ Counter reset"}</span></div>
      <div className="h-2 bg-(--surface)"><div className="h-2 bg-(--primary)" style={{ width: `${Number(row.count) / Number(max) * 100}%` }} /></div>
    </div>))}
  </div>;
}
