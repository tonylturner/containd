import type { ApiResult } from "./api";
import { getJSON, isRecord, postJSONResult } from "./api-request";

export type ProtectionState = "pending" | "protecting" | "degraded" | "failed" | "disabled" | "unknown";
export type ProtectionComponent = {
  name: string;
  required: boolean;
  state: "ready" | "pending" | "failed" | "off";
  reason: string;
  attempt?: number;
  maxAttempts?: number;
  since: string;
};
export type ProtectionEffect = {
  traffic: string;
  effect: "normal" | "fail_closed_drop" | "not_inspected" | "unknown";
};
export type ProtectionStatus = {
  bootId: string;
  applyId: string;
  installedApplyId: string;
  state: ProtectionState;
  retryable: boolean;
  observedAt: string;
  components: ProtectionComponent[];
  effects: ProtectionEffect[];
};

const STATES = new Set(["pending", "protecting", "degraded", "failed", "disabled", "unknown"]);
const COMPONENT_STATES = new Set(["ready", "pending", "failed", "off"]);
const EFFECTS = new Set(["normal", "fail_closed_drop", "not_inspected", "unknown"]);
const optionalCount = (value: unknown) => value === undefined || (Number.isInteger(value) && (value as number) >= 0);

/** Never accept a malformed observation as a verified protecting state. */
export function isProtectionStatus(value: unknown): value is ProtectionStatus {
  if (!isRecord(value)) return false;
  return ["bootId", "applyId", "installedApplyId", "observedAt"].every((key) => typeof value[key] === "string")
    && STATES.has(value.state as string) && typeof value.retryable === "boolean"
    && Array.isArray(value.components) && value.components.every((c: unknown) =>
      isRecord(c) && typeof c.name === "string" && typeof c.required === "boolean"
      && COMPONENT_STATES.has(c.state as string) && typeof c.reason === "string" && typeof c.since === "string"
      && optionalCount(c.attempt) && optionalCount(c.maxAttempts))
    && Array.isArray(value.effects) && value.effects.every((e: unknown) =>
      isRecord(e) && typeof e.traffic === "string" && EFFECTS.has(e.effect as string));
}

export async function fetchProtection(signal?: AbortSignal): Promise<ProtectionStatus | undefined> {
  const body = await getJSON<ProtectionStatus>("/api/v1/dataplane/protection", signal);
  return isProtectionStatus(body) ? body : undefined;
}

export function retryProtection(observation: Pick<ProtectionStatus, "bootId" | "applyId">): Promise<ApiResult<{ status: "retrying"; applyId: string }>> {
  return postJSONResult("/api/v1/dataplane/protection/retry", {
    bootId: observation.bootId,
    applyId: observation.applyId,
  });
}
