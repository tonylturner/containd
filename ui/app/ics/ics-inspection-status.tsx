"use client";

import type { HealthResponse } from "../../lib/api";
import type { InstalledRulesetView } from "../../hooks/useInstalledRuleset";
import { Card } from "../../components/Card";
import { StatusBadge } from "../../components/StatusBadge";
import { EnforcementHealthIndicator } from "../../components/EnforcementHealthIndicator";
import { RulesetFaults } from "../firewall/firewall-ruleset-status";
import { IEC104HealthIndicator } from "./iec104-health";
import { ICSCoverageNotice, ICSEnforcementIndicator } from "./ics-coverage";
import type { ICSCoverageView } from "./ics-coverage-model";
import { Disclosure } from "../../components/Disclosure";

function inspectionState(coverage: ICSCoverageView, health?: HealthResponse) {
  const aggregate = health?.icsEnforcement;
  if (coverage.status !== "loaded" || !coverage.applied || !aggregate) return "Unknown";
  if (coverage.applied.size === 0 && aggregate.state === "none") return "No ICS rules applied";
  if (aggregate.state === "unknown" || aggregate.state === "none") return "Unknown";
  const applied = [...coverage.applied.values()];
  if (applied.length === 0 || applied.some(rule => rule.state === "unknown")) return "Unknown";
  if (aggregate.state === "monitoring" && applied.every(rule => rule.state === "monitoring")) return "Monitoring";
  const hasActiveRules = applied.some(rule => rule.state === "enforcing" || rule.state === "partial");
  if (hasActiveRules && health?.enforcement && !["enforcing", "degraded"].includes(health.enforcement.state)) return "Unknown";
  if (aggregate.state === "not_enforcing") {
    // Health names the worst enforcing-rule state, not the state of every rule.
    if (!applied.some(rule => rule.state === "not_enforcing")) return "Unknown";
    return hasActiveRules ? "Partly active" : "Not enforcing";
  }
  if (!hasActiveRules) return "Unknown";
  if (aggregate.state === "enforcing" &&
      applied.every(rule => rule.state === "enforcing" || rule.state === "monitoring") &&
      health?.enforcement?.state !== "degraded" && health?.iec104Enforcement?.healthy !== false) return "Enforcing";
  return aggregate.state === "partial" || aggregate.state === "enforcing" ? "Partly active" : "Unknown";
}

/** Active observations lead; candidate settings never establish protection. */
export function ICSInspectionStatus({ coverage, health, installed }: {
  coverage: ICSCoverageView;
  health?: HealthResponse;
  installed: InstalledRulesetView;
}) {
  const state = inspectionState(coverage, health);
  return (
    <Card title="Active inspection" className="mb-4">
      <div className="flex flex-wrap items-center gap-3" aria-label="Active inspection state">
        <StatusBadge variant={state === "Enforcing" ? "success" : state === "Partly active" || state === "Not enforcing" ? "warning" : "neutral"} dot>{state}</StatusBadge>
        <span className="text-xs text-(--text-muted)">
          {state === "Monitoring" ? "Observation only — monitor rules do not protect traffic."
            : state === "Unknown" ? "Active inspection could not be established from coverage and health."
              : state === "No ICS rules applied" ? "Candidate filters are not active inspection."
              : "Applied inspection coverage, not the candidate mode or a guarantee of delivery."}
        </span>
      </div>
      <div className="mt-2 space-y-2">
        <ICSEnforcementIndicator health={health?.icsEnforcement} />
        {health?.enforcement?.state !== "enforcing" && <EnforcementHealthIndicator health={health?.enforcement} />}
        {health?.iec104Enforcement?.healthy !== true && <IEC104HealthIndicator health={health?.iec104Enforcement} />}
        <Disclosure title="Inspection details">
          {health?.enforcement?.state === "enforcing" && <EnforcementHealthIndicator health={health.enforcement} />}
          {health?.iec104Enforcement?.healthy === true && <IEC104HealthIndicator health={health.iec104Enforcement} />}
        </Disclosure>
        {installed.state === "loaded" && <RulesetFaults status={installed.status} />}
        {installed.state === "unavailable" && <p role="status" aria-label="Installed ruleset status" className="break-words text-xs text-red-400">Installed ruleset status unavailable. {installed.error}</p>}
        <ICSCoverageNotice view={coverage} reportedApplyError={installed.state === "loaded" ? installed.status.error : undefined} />
      </div>
    </Card>
  );
}
