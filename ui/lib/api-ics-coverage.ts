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
 * is the runtime count of flows the exclusion bypassed since apply.
 */
export type ICSCoverageReason = {
  code: string;
  message: string;
  value?: string;
  matches?: number;
};

/** Coverage of one rule; mode is the effective mode the server resolved. */
export type ICSCoverageRule = {
  ruleId: string;
  protocol: string;
  mode: string;
  state: ICSCoverageState;
  reasons: ICSCoverageReason[];
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

/**
 * Whether two evaluations of the same rule report the same protection.
 * Runtime match counts are ignored: a static candidate evaluation has none.
 */
export function sameICSCoverage(a: ICSCoverageRule, b: ICSCoverageRule): boolean {
  if (a.state !== b.state || a.mode !== b.mode) return false;
  const key = (r: ICSCoverageReason) => `${r.code}\u0000${r.value ?? ""}`;
  const left = a.reasons.map(key).sort();
  const right = b.reasons.map(key).sort();
  return left.length === right.length && left.every((k, i) => k === right[i]);
}
