import type { RulePreview, RuleWarning } from "../../lib/api";
import { ICSCoverageSection } from "../ics/ics-coverage";

function warningKind(w: RuleWarning): string {
  if (w.shadowedBy) return "shadowed";
  if (w.predicate === "identity") return "unbound identity";
  return "warning";
}

/**
 * Rules that do not act as written: an identity rule no bound address
 * satisfies matches nothing, and a DENY or RESET rule an ALLOW fully covers
 * never decides.
 */
export function RuleWarningList({ warnings }: { warnings?: RuleWarning[] }) {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div role="status" className="mt-3 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-xs text-amber">
      <p className="font-semibold">Rules that do not act as written</p>
      <ul className="mt-1 space-y-0.5">
        {warnings.map((w) => (
          <li key={`${w.ruleId}:${w.predicate ?? ""}:${w.shadowedBy ?? ""}`}>
            <span className="mr-1.5 rounded-xs border border-amber/30 px-1 font-mono text-[9px] uppercase tracking-wider">
              {warningKind(w)}
            </span>
            <span className="font-mono">{w.ruleId}</span>: {w.message}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Result of matching one rule in isolation against recent events. */
export function RuleImpactSummary({ preview }: { preview: RulePreview }) {
  return (
    <div aria-label="Rule impact preview" className="mt-3">
      <p className="text-sm text-(--text)">
        {preview.match_count} of {preview.total_events} recent events match this rule on its own.
      </p>
      <ICSCoverageSection coverage={preview.icsCoverage} />
      <RuleWarningList warnings={preview.warnings} />
    </div>
  );
}
