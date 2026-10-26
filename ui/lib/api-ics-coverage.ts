// ICS coverage: whether a firewall rule with an ICS protocol predicate is
// actually enforced. The effective mode alone never proves that a prohibited
// command is stopped; coverage reports the state and the causes lowering it.

/** Protection a semantic ICS rule provides; "unknown" for an unrecognised value. */
export type ICSCoverageState =
  | "monitoring"
  | "enforcing"
  | "partial"
  | "not_enforcing"
  | "unknown";

/**
 * One cause lowering a rule's state, e.g. "no-inline-path" or
 * "exclusion-overlap". Value names the exclusion for exclusion codes; matches
 * counts connections the exclusion exempted since the last apply (applied
 * coverage only); runtime marks a fault only the running engine reports.
 */
export type ICSCoverageReason = {
  code: string;
  message: string;
  value?: string;
  matches?: number;
  runtime?: boolean;
};

/** Coverage of one rule; mode is the effective mode the server resolved. */
export type ICSCoverageRule = {
  ruleId: string;
  protocol: string;
  mode: string;
  state: ICSCoverageState;
  reasons: ICSCoverageReason[];
};

/**
 * GET /api/v1/dataplane/ics-coverage, readable by any authenticated user.
 * Each side is independent: candidate is absent exactly when candidateError
 * is set, applied exactly when engineStatusError is set. After a failed apply
 * (applyError), applied still describes the rules in force before it.
 */
export type ICSCoverageReport = {
  candidate?: ICSCoverageRule[];
  candidateError?: string;
  applied?: ICSCoverageRule[];
  appliedAt?: string;
  applyError?: string;
  engineStatusError?: string;
};

/** Aggregate semantic ICS enforcement in GET /api/v1/health (counts only). */
export type ICSEnforcementHealth = {
  state: "none" | "monitoring" | "enforcing" | "partial" | "not_enforcing" | "unknown";
  enforcing: number;
  partial: number;
  notEnforcing: number;
  monitoring: number;
};

const STATES: ReadonlySet<string> = new Set(["monitoring", "enforcing", "partial", "not_enforcing"]);
const HEALTH_STATES: ReadonlySet<string> = new Set([...STATES, "none", "unknown"]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asCount(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.trunc(value) : 0;
}

function normalizeReason(value: unknown): ICSCoverageReason | null {
  const record = asRecord(value);
  if (!record) return null;
  const code = asString(record.code);
  const message = asString(record.message);
  if (!code && !message) return null;
  const reason: ICSCoverageReason = { code, message: message || code };
  const v = asString(record.value);
  if (v) reason.value = v;
  const matches = asCount(record.matches);
  if (matches > 0) reason.matches = matches;
  if (record.runtime === true) reason.runtime = true;
  return reason;
}

/** Normalizes one wire coverage rule; null when it names no rule. */
export function normalizeICSCoverageRule(value: unknown): ICSCoverageRule | null {
  const record = asRecord(value);
  if (!record) return null;
  const ruleId = asString(record.ruleId);
  if (!ruleId) return null;
  const state = asString(record.state);
  return {
    ruleId,
    protocol: asString(record.protocol),
    mode: asString(record.mode).toLowerCase(),
    state: STATES.has(state) ? (state as ICSCoverageState) : "unknown",
    reasons: Array.isArray(record.reasons)
      ? record.reasons.map(normalizeReason).filter((r): r is ICSCoverageReason => r !== null)
      : [],
  };
}

/** Normalizes a wire coverage list; a missing or malformed list is empty. */
export function normalizeICSCoverageList(value: unknown): ICSCoverageRule[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(normalizeICSCoverageRule)
    .filter((r): r is ICSCoverageRule => r !== null);
}

/**
 * Normalizes the coverage report. A list that is neither present nor
 * explained by its error stays absent: the UI then reports that side as
 * unknown, never as "no rules".
 */
export function normalizeICSCoverageReport(value: unknown): ICSCoverageReport {
  const record = asRecord(value) ?? {};
  const report: ICSCoverageReport = {};
  const candidateError = asString(record.candidateError);
  if (candidateError) report.candidateError = candidateError;
  else if (Array.isArray(record.candidate)) report.candidate = normalizeICSCoverageList(record.candidate);
  const engineStatusError = asString(record.engineStatusError);
  if (engineStatusError) report.engineStatusError = engineStatusError;
  else if (Array.isArray(record.applied)) report.applied = normalizeICSCoverageList(record.applied);
  const appliedAt = asString(record.appliedAt);
  if (appliedAt) report.appliedAt = appliedAt;
  const applyError = asString(record.applyError);
  if (applyError) report.applyError = applyError;
  return report;
}

/** Normalizes the health aggregate; undefined when the server sent none. */
export function normalizeICSEnforcementHealth(value: unknown): ICSEnforcementHealth | undefined {
  const record = asRecord(value);
  if (!record) return undefined;
  const state = asString(record.state);
  return {
    state: HEALTH_STATES.has(state) ? (state as ICSEnforcementHealth["state"]) : "unknown",
    enforcing: asCount(record.enforcing),
    partial: asCount(record.partial),
    notEnforcing: asCount(record.notEnforcing),
    monitoring: asCount(record.monitoring),
  };
}

const EXCLUSION_CODES: ReadonlySet<string> = new Set(["exclusion-overlap", "domain-exclusion"]);

/** Whether a reason names an exclusion that exempts flows from inspection. */
export function isExclusionReason(reason: ICSCoverageReason): boolean {
  return EXCLUSION_CODES.has(reason.code);
}

/**
 * The configuration-derived part of a coverage: runtime reasons dropped,
 * match counts cleared and the state recomputed from what remains. Learn
 * stays monitoring; for enforce, any non-exclusion reason means not
 * enforcing, otherwise an exclusion means partial.
 */
export function staticICSCoverage(rule: ICSCoverageRule): ICSCoverageRule {
  const reasons = rule.reasons
    .filter((r) => !r.runtime)
    .map(({ code, message, value }) => (value ? { code, message, value } : { code, message }));
  let state: ICSCoverageState = rule.state;
  if (rule.mode === "learn") state = "monitoring";
  else if (rule.mode === "enforce") {
    if (reasons.some((r) => !isExclusionReason(r))) state = "not_enforcing";
    else state = reasons.length > 0 ? "partial" : "enforcing";
  }
  return { ...rule, state, reasons };
}

/**
 * Whether candidate and applied describe the same configuration. Runtime
 * reasons and match counts are facts about the running engine, not drift.
 */
export function sameICSCoverage(a: ICSCoverageRule, b: ICSCoverageRule): boolean {
  const left = staticICSCoverage(a);
  const right = staticICSCoverage(b);
  if (left.state !== right.state || left.mode !== right.mode) return false;
  const key = (r: ICSCoverageReason) => `${r.code}\u0000${r.value ?? ""}`;
  const leftKeys = left.reasons.map(key).sort();
  const rightKeys = right.reasons.map(key).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((k, i) => k === rightKeys[i]);
}
