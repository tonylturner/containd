"use client";

import { StatusBadge, StatusIndicator } from "../../components/StatusBadge";
import type { ICSCoverageReason, ICSCoverageRule, ICSEnforcementHealth } from "../../lib/api";
import {
  coverageStateLabel,
  coverageVariant,
  describeRuleCoverage,
  formatReason,
  icsEnforcementIndicator,
  type ICSCoverageView,
} from "./ics-coverage-model";

function ReasonList({ reasons }: { reasons: ICSCoverageReason[] }) {
  if (reasons.length === 0) return null;
  return (
    <ul className="mt-1 space-y-0.5 text-xs text-(--text-muted)">
      {reasons.map((r) => (
        <li key={`${r.code}:${r.value ?? ""}`}>{formatReason(r)}</li>
      ))}
    </ul>
  );
}

/** Applied coverage of one rule, plus the candidate's when it differs. */
export function ICSCoverageCell({ view, ruleId }: { view: ICSCoverageView; ruleId: string }) {
  return (
    <div aria-label={`ICS coverage of ${ruleId}`} className="space-y-1.5">
      {describeRuleCoverage(view, ruleId).map((l) => (
        <div key={l.label}>
          <StatusBadge variant={l.variant} dot>
            {l.label}
          </StatusBadge>
          <ReasonList reasons={l.reasons} />
        </div>
      ))}
    </div>
  );
}

/** Why per-rule coverage is missing or incomplete; nothing when it is complete. */
export function ICSCoverageNotice({ view }: { view: ICSCoverageView }) {
  let message: string | null = null;
  if (view.status === "restricted") {
    message = "Per-rule ICS coverage requires admin access. A configured mode alone does not show that a rule is enforced.";
  } else if (view.status === "unavailable") {
    message = `ICS coverage unavailable: ${view.error}. A configured mode alone does not show that a rule is enforced.`;
  } else if (view.status === "loaded" && view.appliedError) {
    message = `Applied ICS coverage unavailable: ${view.appliedError}. Candidate coverage is shown where known.`;
  }
  return (
    <>
      {message && (
        <div role="status" className="mb-3 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-xs text-amber">
          {message}
        </div>
      )}
      {view.status === "loaded" && view.applyError && (
        <div role="status" className="mb-3 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-400">
          The engine reported an apply error: {view.applyError}
        </div>
      )}
    </>
  );
}

/** Coverage of a previewed rule under the running settings. */
export function ICSCoverageSection({ coverage }: { coverage?: ICSCoverageRule }) {
  if (!coverage) return null;
  return (
    <div aria-label="ICS coverage" className="mt-3 rounded-xs border bg-(--surface) px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-(--text)">ICS coverage under the running settings</span>
        <StatusBadge variant={coverageVariant(coverage.state)} dot>
          {coverageStateLabel(coverage.state)}
        </StatusBadge>
        {coverage.mode && <span className="text-xs text-(--text-muted)">effective mode: {coverage.mode}</span>}
      </div>
      <ReasonList reasons={coverage.reasons} />
    </div>
  );
}

/** Runtime aggregate of semantic ICS enforcement from the health endpoint. */
export function ICSEnforcementIndicator({ health }: { health: ICSEnforcementHealth | undefined }) {
  const view = icsEnforcementIndicator(health);
  return <StatusIndicator status={view.status} label={view.label} sublabel={view.sublabel} />;
}
