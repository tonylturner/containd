import type { RulePreview, RuleWarning } from "../../lib/api";
import { ICSCoverageSection } from "../ics/ics-coverage";

/** Rule predicates the dataplane resolves toward denial. */
export function RuleWarningList({ warnings }: { warnings?: RuleWarning[] }) {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div role="status" className="mt-3 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-xs text-amber">
      <p className="font-semibold">Rule predicates resolved toward denial</p>
      <ul className="mt-1 space-y-0.5">
        {warnings.map((w) => (
          <li key={`${w.ruleId}:${w.predicate}`}>
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
