import {
  sameICSCoverage,
  type ICSCoverageReason,
  type ICSCoverageRule,
  type ICSCoverageState,
  type ICSEnforcementHealth,
} from "../../lib/api-ics-coverage";
import type { RulesetPreview } from "../../lib/api";

type BadgeVariant = "success" | "warning" | "error" | "neutral";

/** Where per-rule coverage comes from: the admin-only ruleset preview. */
export type ICSCoverageView =
  | { status: "loading" }
  | { status: "restricted" }
  | { status: "unavailable"; error: string }
  | {
      status: "loaded";
      candidate: Map<string, ICSCoverageRule>;
      // Null when the engine's applied status could not be read.
      applied: Map<string, ICSCoverageRule> | null;
      appliedError?: string;
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

/** Builds the coverage view from a ruleset preview response. */
export function coverageViewFromPreview(preview: RulesetPreview): ICSCoverageView {
  const status = preview.engineStatus;
  return {
    status: "loaded",
    candidate: byRule(preview.icsCoverage),
    applied: status ? byRule(status.icsCoverage) : null,
    appliedError: status ? undefined : preview.engineStatusError || "the engine reported no applied status",
    applyError: status?.error || undefined,
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
 * The coverage lines of one rule: the applied state, then the candidate's when
 * it differs. Never derives protection from the configured mode.
 */
export function describeRuleCoverage(view: ICSCoverageView, ruleId: string): CoverageLine[] {
  switch (view.status) {
    case "loading":
      return [{ label: "coverage: checking", variant: "neutral", reasons: [] }];
    case "restricted":
      return [{ label: "coverage: admin only", variant: "neutral", reasons: [] }];
    case "unavailable":
      return [{ label: "coverage unavailable", variant: "neutral", reasons: [] }];
  }
  const candidate = view.candidate.get(ruleId);
  const applied = view.applied?.get(ruleId);
  const lines: CoverageLine[] = [];
  if (applied) lines.push(line("applied", applied));
  else if (view.applied) lines.push({ label: "not applied", variant: "neutral", reasons: [] });
  else lines.push({ label: "applied: unknown", variant: "neutral", reasons: [] });
  if (candidate && !(applied && sameICSCoverage(applied, candidate))) {
    lines.push(line("candidate", candidate));
  }
  return lines;
}

/** A reason as one sentence, with the exclusion and its runtime matches. */
export function formatReason(reason: ICSCoverageReason): string {
  let text = reason.message;
  if (reason.value && !text.includes(reason.value)) text += ` (${reason.value})`;
  if (reason.matches) {
    text += ` — ${reason.matches} ${reason.matches === 1 ? "flow" : "flows"} bypassed inspection since apply`;
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
      return { status: "unknown", label, sublabel: "engine status unknown" };
  }
}
