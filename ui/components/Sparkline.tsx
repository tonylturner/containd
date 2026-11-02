import { pointRate, type Point } from "../lib/api-telemetry";

type SparklineProps = { points: Point[]; color?: string; className?: string; title: string; perMinute?: boolean };

/** Empty slots break the trace; zero has no bar, just a baseline tick. */
export function Sparkline({ points, color = "var(--primary)", className = "h-14", title, perMinute = false }: SparklineProps) {
  if (!points.length) return null;
  const max = Math.max(...points.map(p => pointRate(p, perMinute) ?? 0), 1);
  return (
    <div title={title} role="img" aria-label={title} className={`flex min-w-0 items-end ${points.length > 60 ? "gap-0" : "gap-px"} overflow-hidden rounded-xs border border-white/8 bg-white/3 px-1 ${className}`}>
      {points.map(p => {
        const rate = pointRate(p, perMinute);
        const description = `${p.t}: ${p.q === "gap" ? "Gap — not observed" : `${p.v} counts; ${rate === null ? "duration unavailable; rate unavailable" : `over ${p.d}s; ${rate.toLocaleString()} /${perMinute ? "min" : "s"}`}; ${p.q === "reset" ? "Counter reset" : p.q === "partial" ? "Partial bucket" : "observed"}`}`;
        return <div key={p.t} data-quality={p.q} data-value={p.v?.toString()} aria-label={description} title={description}
          className="relative flex h-full min-w-0 flex-1 items-end"
          style={p.q === "gap" ? { borderBottom: "1px dashed var(--text-muted)" } : undefined}>
          {rate !== null && <span data-bar style={{ width: "100%", height: `${rate / max * 100}%`, background: color,
            opacity: p.q === "partial" ? 0.5 : 1, border: p.q === "partial" ? "1px dashed var(--text)" : undefined }} />}
          {rate === 0 && <span className="absolute bottom-0 w-full border-b border-current" />}
          {p.v !== undefined && rate === null && <span data-count-only aria-hidden className="absolute top-1/2 w-full border-t border-dashed border-amber" />}
          {p.q === "reset" && <span className="absolute top-0 text-[9px] text-amber" aria-hidden>◆</span>}
        </div>;
      })}
    </div>
  );
}
