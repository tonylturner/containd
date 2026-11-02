import { getJSONResult } from "./api-request";

export type ShadowRuleCount = { ruleId: string; shadowMatches: number; wouldAllow: number; wouldDeny: number };
export type ShadowCounters =
  | { available: false; reason: string }
  | { available: true; snapshotVersion: string; since: string; unit: "messages"; rules: ShadowRuleCount[] };

/** Never interpret missing or malformed telemetry as a zero observation. */
export function normalizeShadowCounters(value: unknown): ShadowCounters {
  const unavailable = { available: false as const, reason: "Monitor counts could not be read: malformed response" };
  if (!value || typeof value !== "object" || Array.isArray(value)) return unavailable;
  const v = value as Record<string, unknown>;
  if (v.available === false) return { available: false, reason: typeof v.reason === "string" ? v.reason : "Traffic-monitoring service unavailable" };
  if (v.available !== true || typeof v.snapshotVersion !== "string" || !v.snapshotVersion ||
      typeof v.since !== "string" || !Number.isFinite(Date.parse(v.since)) || v.unit !== "messages" || !Array.isArray(v.rules)) return unavailable;
  const rules: ShadowRuleCount[] = [];
  for (const raw of v.rules) {
    if (!raw || typeof raw !== "object") return unavailable;
    const r = raw as Record<string, unknown>;
    if (typeof r.ruleId !== "string" || !r.ruleId || rules.some((entry) => entry.ruleId === r.ruleId) ||
        ![r.shadowMatches, r.wouldAllow, r.wouldDeny].every((n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0)) return unavailable;
    rules.push({ ruleId: r.ruleId, shadowMatches: r.shadowMatches as number, wouldAllow: r.wouldAllow as number, wouldDeny: r.wouldDeny as number });
  }
  return { available: true, snapshotVersion: v.snapshotVersion, since: v.since, unit: "messages", rules };
}

export async function getShadowCounters(): Promise<ShadowCounters> {
  const result = await getJSONResult<Record<string, unknown>>("/api/v1/firewall/shadow-counters");
  return result.ok ? normalizeShadowCounters(result.data) : { available: false, reason: result.error };
}
