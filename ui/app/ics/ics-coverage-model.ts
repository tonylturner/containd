import {
  isExclusionReason,
  sameICSCoverage,
  type ICSCoverageReason,
  type ICSCoverageReport,
  type ICSCoverageRule,
  type ICSCoverageState,
  type ICSEnforcementHealth,
} from "../../lib/api-ics-coverage";

type BadgeVariant = "success" | "warning" | "error" | "neutral";

/** Per-rule coverage from GET /api/v1/dataplane/ics-coverage. */
export type ICSCoverageView =
  | { status: "loading" }
  | { status: "unavailable"; error: string }
  | {
      status: "loaded";
      // Null, with candidateError, when the candidate has no coverage.
      candidate: Map<string, ICSCoverageRule> | null;
      candidateError?: string;
      // Null, with appliedError, when the applied rules are unknown.
      applied: Map<string, ICSCoverageRule> | null;
      appliedError?: string;
      appliedAt?: string;
      applyError?: string;
    };

export type CoverageLine = {
  label: string;
  variant: BadgeVariant;
  reasons: ICSCoverageReason[];
};

const STATE_LABELS: Record<ICSCoverageState, string> = {
  enforcing: "enforcing",
  partial: "partial",
  not_enforcing: "not enforcing",
  monitoring: "monitoring",
  unknown: "unknown",
};

/** Only an enforcing rule is green; partial needs attention; not enforcing is critical. */
export function coverageVariant(state: ICSCoverageState): BadgeVariant {
  switch (state) {
    case "enforcing":
      return "success";
    case "partial":
      return "warning";
    case "not_enforcing":
      return "error";
    default:
      return "neutral";
  }
}

export function coverageStateLabel(state: ICSCoverageState): string {
  return STATE_LABELS[state];
}

function byRule(list: ICSCoverageRule[]): Map<string, ICSCoverageRule> {
  return new Map(list.map((r) => [r.ruleId, r]));
}

const NOT_REPORTED = "not reported by the server";

/** Builds the coverage view; a side without its list is unknown, never empty. */
export function coverageViewFromReport(report: ICSCoverageReport): ICSCoverageView {
  return {
    status: "loaded",
    candidate: report.candidate ? byRule(report.candidate) : null,
    candidateError: report.candidate ? undefined : report.candidateError || NOT_REPORTED,
    applied: report.applied ? byRule(report.applied) : null,
    appliedError: report.applied ? undefined : report.engineStatusError || NOT_REPORTED,
    appliedAt: report.appliedAt,
    applyError: report.applyError,
  };
}

function line(prefix: string, rule: ICSCoverageRule): CoverageLine {
  return {
    label: `${prefix}: ${coverageStateLabel(rule.state)}`,
    variant: coverageVariant(rule.state),
    reasons: rule.reasons,
  };
}

/**
 * The coverage lines of one rule: the applied state with every reason,
 * runtime faults included, then the candidate's when its configuration
 * differs. Never derives protection from the configured mode.
 */
export function describeRuleCoverage(view: ICSCoverageView, ruleId: string): CoverageLine[] {
  switch (view.status) {
    case "loading":
      return [{ label: "coverage: checking", variant: "neutral", reasons: [] }];
    case "unavailable":
      return [{ label: "coverage unavailable", variant: "neutral", reasons: [] }];
  }
  const applied = view.applied?.get(ruleId);
  const lines: CoverageLine[] = [];
  if (applied) lines.push(line("applied", applied));
  else if (view.applied) lines.push({ label: "not applied", variant: "neutral", reasons: [] });
  else lines.push({ label: "applied: unknown", variant: "neutral", reasons: [] });
  if (!view.candidate) {
    lines.push({ label: "candidate: unavailable", variant: "neutral", reasons: [] });
    return lines;
  }
  const candidate = view.candidate.get(ruleId);
  if (candidate && !(applied && sameICSCoverage(applied, candidate))) {
    lines.push(line("candidate", candidate));
  }
  return lines;
}

/**
 * A reason as one sentence, with the exclusion and the connections it
 * exempted; a runtime fault is marked as a fact about the running engine.
 */
export function formatReason(reason: ICSCoverageReason): string {
  let text = reason.runtime ? `Live inspection: ${reason.message}` : reason.message;
  if (reason.value && !text.includes(reason.value)) text += ` (${reason.value})`;
  if (reason.matches && isExclusionReason(reason)) {
    text += ` \u2014 ${reason.matches} ${reason.matches === 1 ? "connection" : "connections"} exempted since the last apply`;
  }
  return text;
}

type Indicator = {
  status: "healthy" | "degraded" | "error" | "unknown";
  label: string;
  sublabel?: string;
};

function healthCounts(h: ICSEnforcementHealth): string | undefined {
  const parts = [
    h.enforcing && `${h.enforcing} enforcing`,
    h.partial && `${h.partial} partial`,
    h.notEnforcing && `${h.notEnforcing} not enforcing`,
    h.monitoring && `${h.monitoring} monitoring`,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : undefined;
}

/** Maps the runtime aggregate in GET /api/v1/health to the indicator. */
export function icsEnforcementIndicator(health: ICSEnforcementHealth | undefined): Indicator {
  const label = "ICS protocol enforcement";
  if (!health) return { status: "unknown", label, sublabel: "status unavailable" };
  const sublabel = healthCounts(health);
  switch (health.state) {
    case "enforcing":
      return { status: "healthy", label: "ICS protocol rules enforcing", sublabel };
    case "partial":
      return { status: "degraded", label: "ICS protocol rules partially enforcing", sublabel };
    case "not_enforcing":
      return { status: "error", label: "ICS protocol rules not enforcing", sublabel };
    case "monitoring":
      return { status: "unknown", label: "ICS protocol rules monitoring only", sublabel };
    case "none":
      return { status: "unknown", label, sublabel: "no ICS protocol rules applied" };
    default:
      return { status: "unknown", label, sublabel: "live inspection status unknown" };
  }
}
