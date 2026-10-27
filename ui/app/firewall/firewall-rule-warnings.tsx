import Link from "next/link";

import type { RulePreview, RuleWarning } from "../../lib/api";
import { ICSCoverageSection } from "../ics/ics-coverage";
import { RulePreviewEvents } from "./firewall-rule-samples";

function warningKind(w: RuleWarning): string {
  if (w.shadowedBy) return "shadowed";
  switch (w.predicate) {
    case "identity":
      return "unbound identity";
    case "zone":
      return "zone without interfaces";
    case "addressFamily":
      return "no shared address family";
    default:
      return "warning";
  }
}

/** Where to fix the part of the rule that matches nothing. */
function WarningFix({ warning }: { warning: RuleWarning }) {
  if (warning.predicate === "zone") {
    return <> <Link href="/interfaces/" className="underline">Assign an interface</Link> to {warning.zones?.length === 1 ? "it" : "one"}.</>;
  }
  if (warning.predicate === "identity") {
    return <> <Link href="/identities/" className="underline">Bind an address</Link>.</>;
  }
  return null;
}

const SCOPES = {
  candidate: { label: "Candidate", detail: "staged, not yet applied" },
  applied: { label: "Applied", detail: "the running ruleset" },
} as const;

/**
 * Rules that do not act as written: a rule matches nothing when no bound
 * address satisfies its identities, none of its zones has an interface, or
 * its sources and destinations share no address family; and a DENY or RESET
 * rule an ALLOW fully covers never decides. `scope` names the ruleset the warnings describe; a single
 * previewed rule has none.
 */
export function RuleWarningList({
  warnings,
  scope,
}: {
  warnings?: RuleWarning[];
  scope?: keyof typeof SCOPES;
}) {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div
      role="status"
      aria-label={scope ? `${SCOPES[scope].label} rule warnings` : undefined}
      className="mt-3 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-xs text-amber"
    >
      <p className="font-semibold">
        {scope && (
          <span className="mr-2 rounded-xs bg-amber/20 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider">
            {SCOPES[scope].label}
          </span>
        )}
        Rules that do not act as written
        {scope && <span className="ml-1 font-normal opacity-80">({SCOPES[scope].detail})</span>}
      </p>
      <ul className="mt-1 space-y-0.5">
        {warnings.map((w) => (
          <li key={`${w.ruleId}:${w.predicate ?? ""}:${w.shadowedBy ?? ""}`}>
            <span className="mr-1.5 rounded-xs border border-amber/30 px-1 font-mono text-[9px] uppercase tracking-wider">
              {warningKind(w)}
            </span>
            <span className="font-mono">{w.ruleId}</span>: {w.message}
            <WarningFix warning={w} />
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
        {preview.total_events === 0
          ? "No recent events to search: the engine has retained none yet."
          : `${preview.match_count} of ${preview.total_events} recent events match this rule on its own.`}
      </p>
      <RulePreviewEvents preview={preview} />
      <ICSCoverageSection coverage={preview.icsCoverage} />
      <RuleWarningList warnings={preview.warnings} />
    </div>
  );
}
