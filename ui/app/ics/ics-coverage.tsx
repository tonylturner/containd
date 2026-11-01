"use client";

import { StatusBadge, StatusIndicator } from "../../components/StatusBadge";
import { TechnicalDetails } from "../../components/TechnicalDetails";
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
    <TechnicalDetails summary="Inspection details">
    <ul className="mt-1 space-y-0.5 text-xs text-(--text-muted)">
      {reasons.map((r) => (
        <li key={`${r.code}:${r.value ?? ""}`}>{formatReason(r)}</li>
      ))}
    </ul>
    </TechnicalDetails>
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

function formatTime(value: string): string {
  const t = new Date(value);
  return Number.isNaN(t.getTime()) ? value : t.toLocaleString();
}

const MODE_ALONE = "Choosing Enforce does not guarantee blocking is active.";

/** Why coverage is missing or stale; nothing when both sides are known. */
export function ICSCoverageNotice({ view }: { view: ICSCoverageView }) {
  const warnings: { message: string; detail: string }[] = [];
  if (view.status === "unavailable") {
    warnings.push({ message: `ICS coverage unavailable. ${MODE_ALONE}`, detail: view.error });
  } else if (view.status === "loaded") {
    if (view.candidateError) {
      warnings.push({ message: "Saved ICS inspection coverage unavailable.", detail: view.candidateError });
    }
    if (view.appliedError) {
      warnings.push({ message: `Active ICS inspection coverage unknown. ${MODE_ALONE}`, detail: view.appliedError });
    }
  }
  const loaded = view.status === "loaded" ? view : null;
  return (
    <>
      {warnings.map((w) => (
        <div key={w.message} role="status" className="mb-3 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-xs text-amber">
          {w.message}
          <TechnicalDetails>{w.detail}</TechnicalDetails>
        </div>
      ))}
      {loaded?.applyError && (
        <div role="status" className="mb-3 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-400">
          The last apply failed, so applied coverage describes the rules still in force from before it. The enforcement status shows why it failed.
        </div>
      )}
      {loaded?.appliedAt && (
        <p className="mb-3 text-xs text-(--text-muted)">Last activation attempt: {formatTime(loaded.appliedAt)}</p>
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
        <span className="text-xs font-semibold text-(--text)">What this rule would inspect with the running settings</span>
        <StatusBadge variant={coverageVariant(coverage.state)} dot>
          {coverageStateLabel(coverage.state)}
        </StatusBadge>
        {coverage.mode && <span className="text-xs text-(--text-muted)">mode in use: {coverage.mode}</span>}
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
